#!/usr/bin/python3

import random
import sec256k1.big

# 13th Mersenne Prime
PRIME = 2**521 - 1

def yval(poly, x):
    '''
    Calculate f(x) = a_0 + a_1x + a_2x^2 ... a_{k-1}x^{k-1}
    a0 is the secret
    '''
    accum = 0
    for coeff in reversed(poly):
        accum = big.modmul(accum, x, PRIME)
        accum = big.modadd(accum, coeff, PRIME)

    return accum


def make_shares(k, n, secret=None):
    '''
    Generates shares and optionally the secret
    '''
    if k > n:
        raise ValueError("secret not irrecoverable")

    # Generate polynomial
    poly = [random.SystemRandom().randint(0, PRIME - 1) for i in range(k)]
    # print("shimir.py kmc poly {}".format(poly))

    # poly[0] i.e. a_0 is the secret
    if secret is not None:
        poly[0] = secret

    # [(1,f(1)), (2,f(2), ... (n, f(n)]
    points = [(i, yval(poly, i)) for i in range(1, n + 1)]
    return poly[0], points


def product(vals):
    '''
    product of inputs
    '''
    accum = 1
    for v in vals:
        accum = big.modmul(accum, v, PRIME)
    return accum


def lagrange_interpolate1(x, x_s):
    '''
    Find the coefficients for multiplication
    '''
    p = PRIME
    k = len(x_s)
    assert k == len(set(x_s)), "points must be distinct"

    coefs = []
    for i in range(k):

        others = list(x_s)
        c = others.pop(i)

        # numerator
        num = product(others)

        # denominator
        v = []
        for o in others:
            s = big.modsub(o, c, PRIME)
            # print("shamir.py kmc o {} c {} s {}".format(o,c,hex(s)))            
            v.append(s)
        den = product(v)
        #print("shamir.py kmc den {}".format(hex(den)))                    

        coef = big.moddiv(num, den, PRIME)
        # print("shamir.py kmc coef {}".format(hex(coef)))            
        coefs.append(coef)

    return coefs


def lagrange_interpolate2(coef, y_s):
    '''
    Calculate the secret
    '''
    p = PRIME
    k = len(y_s)

    # Calculate of products of coefficient and y values.
    m = []
    for i in range(k):
        t = big.modmul(coef[i], y_s[i], PRIME)
        #print("shimir.py kmc coef[{}] {}".format(i, coef[i]))
        #print("shimir.py kmc y_s[{}] {}".format(i, y_s[i]))
        #print("shimir.py kmc t {}".format(t))                
        m.append(t)

    secret = 0
    for i in range(k):
        secret = big.modadd(secret, m[i], PRIME)

    return secret, m
