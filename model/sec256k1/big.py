
#
# Number Theoretic functions
# M Scott August 2013
#

import math
import types
import random

from sec256k1 import curve


def to_bytes(b):
    return b.to_bytes(curve.EFS, byteorder='big')


def from_bytes(B):
    return int.from_bytes(B, byteorder='big')


def bit(k, i):
    '''
        Extract i-th bit
    '''
    if i == 0:
        return k & 1
    return ((k >> i) & 1)


def gcd(x, y):
    a = x
    b = y
    while b != 0:
        a, b = b, a % b
    return a


def jacobi(a, p):
    '''
        Find Jacobi symbol for (x/p).
        Only defined for positive x and positive odd p.
        Otherwise returns 0
    '''
    if a < 1 or p < 2 or p % 2 == 0:
        return 0
    n = p
    x = a % n
    m = 0
    while n > 1:
        if x == 0:
            return 0
        n8 = n % 8
        k = 0
        while x % 2 == 0:
            k += 1
            x //= 2
        if k % 2 == 1:
            m += (n8 * n8 - 1) // 8
        m += (n8 - 1) * (x % 4 - 1) // 4
        t = n
        t %= x
        n = x
        x = t
        m %= 2
    if m == 0:
        return 1
    else:
        return -1


def isprime(p):
    '''
        Rabin Miller primality test
    '''
    sp = 4849845  # 3*5*.. *19

    if gcd(p, sp) != 1:
        return False

    d = p - 1
    r = 0
    while bit(d, 0) == 0:
        d = d >> 1
        r = r + 1

    for _ in range(10):
        g = rand(p - 1)
        x = pow(g, d, p)

        if x == 1 or x == p - 1:
            continue

        cont = False
        for _ in range(r - 1):
            x = x ^ 2 % p

            if x == p - 1:
                cont = True
                break

        if cont:
            continue

        return False

    return True


def issafeprime(p, P):
    '''
        Safe prime primality test
    '''
    sp = 4849845  # 3*5*.. *19

    # Sieve small primes for P before attempting MR on p
    if gcd(P, sp) != 1:
        return False

    if not isprime(p):
        return False

    # p prime, P = 2p+1, 2^(P-1) = 1 mod P => P prime
    if not pow(2, P-1, P) == 1:
        return False

    return True


def rand(m):
    return random.SystemRandom().randint(2, m - 1)


def generate_safe_prime(k):
    '''
        Generate safe prime P = 2p+1 for q prime.
        k is the desired length for P
    '''

    p = rand(1<<(k-1))

    while p%4 != 3:
        p = p + 1

    P = 2 * p + 1
    while not issafeprime(p, P):
        p = p + 4
        P = P + 8

    return p, P


## Modular arithmetic ##


def modmul(a1, b1, p):

    a = a1 % p
    b = b1 % p

    if a < 0:
        a += p
    if b < 0:
        b += p
    return a * b % p


def modadd(a, b, p):
    c = a + b
    if c >= p:
        c -= p
    return c


def modsub(a, b, p):
    c = a - b
    if c < 0:
        c += p
    return c


def moddiv(a, b, p):
    i = invmodp(b, p)
    if i != 0:
        return modmul(a, i, p)
    return 0


def sqrtmodp(a, p):
    '''
        Modular Square Root.
        Fails spectacularly if p != 3 mod 4
    '''
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    if p % 8 == 5:
        b = (p - 5) / 8
        i = a * 2
        v = pow(i, b, p)
        i = modmul(i, v, p)
        i = modmul(i, v, p)
        i -= 1
        r = modmul(a, v, p)
        r = modmul(r, i, p)
        return r

    return 0


def invmodp(a, p):
    '''
        Modular inverse mod p
    '''
    n = p
    x = a % n
    if x == 0:
        return x
    kn = n
    if x < 0:
        x += n
    if gcd(x, n) != 1:
        return 0
    a = 1
    la = 0
    while x > 1:
        q, r = divmod(n, x)
        t = la - a * q
        la = a
        a = t
        n = x
        x = r
    if a < 0:
        a += kn
    return a


def crt(rp, rq, p, q):
    '''
        Combine rp and rq using the Chinese Remainder Theorem.
        It assumes p and q are coprime
    '''
    n = p * q

    c = invmodp(p, q)

    t = modmul(c, rq - rp, n)
    t = modmul(t, p, n)

    return modadd(t, rp, n)
