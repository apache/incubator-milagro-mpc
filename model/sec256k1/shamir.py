import random
import sec256k1.big as big
import sec256k1.ecp as ecp
import sec256k1.curve as curve

def eval(poly, x):
    '''
    Calculate f(x) = a_0 + a_1x + a_2x^2 ... a_{k-1}x^{k-1}
    a0 is the secret
    '''
    accum = 0
    for coeff in reversed(poly):
        accum = big.modmul(accum, x, curve.r)
        accum = big.modadd(accum, coeff, curve.r)

    return accum


def make_shares(k, n, check=False, secret=None):
    '''
        Generates shares and optionally the secret and checks

        The checks are left as [C_0, ..., C_(k-1)], where
        C_0 = (a_0).G = secret.G
    '''
    if k > n:
        raise ValueError("secret not irrecoverable")

    # Generate polynomial
    poly = [big.rand(curve.r) for i in range(k)]

    # poly[0] i.e. a_0 is the secret
    if secret is not None:
        poly[0] = secret

    # [(1,f(1)), (2,f(2), ... (n, f(n)]
    points = [(i, eval(poly, i)) for i in range(1, n + 1)]

    # Make consistency checks if necessary
    checks = []
    for coeff in poly:
        checks.append(coeff * ecp.generator())

    return poly[0], points, checks

def verify_share(checks, share):
    '''
        Verify a share with the distributed checks

        The checks are given as [C_0, ..., C_(k-1)], where
        C_0 = (a_0).G = secret.G

        The share is assumed to be a pair (x, f(x))
    '''

    (x, y) = share
    gy = y * ecp.generator()

    # accum = c_0^(x^0) * ... * c_(k-1)^(x^(k-1))
    accum = checks[0].copy()
    gexp = 1

    for check in checks[1:]:
        gexp = big.modmul(gexp, x, curve.r)
        accum.add(gexp * check)

    return accum == gy

def product(vals):
    '''
    product of inputs
    '''
    accum = 1
    for v in vals:
        accum = big.modmul(accum, v, curve.r)
    return accum


def lagrange_interpolate1(x_s):
    '''
    Find the coefficients for multiplication
    '''
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
            s = big.modsub(o, c, curve.r)
            v.append(s)
        den = product(v)

        coef = big.moddiv(num, den, curve.r)
        coefs.append(coef)

    return coefs

def lagrange_interpolate2(coef, y_s):
    '''
    Calculate the secret
    '''
    k = len(y_s)

    # Calculate of products of coefficient and y values.
    m = []
    for i in range(k):
        t = big.modmul(coef[i], y_s[i], curve.r)
        m.append(t)

    secret = 0
    for i in range(k):
        secret = big.modadd(secret, m[i], curve.r)

    return secret, m

def convert_to_additive_share(x_shares, i, y):
    others = list(x_shares)
    x_share = others.pop(i)

    num = product(others)

    den = 1
    for share in others:
        v = big.modsub(share, x_share, curve.r)
        den = big.modmul(den, v, curve.r)

    coef = big.moddiv(num, den, curve.r)

    return big.modmul(coef, y, curve.r)
