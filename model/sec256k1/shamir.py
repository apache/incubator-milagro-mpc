import random
import sec256k1.big as big
import sec256k1.ecp as ecp
import sec256k1.curve as curve

# 13th Mersenne Prime
# PRIME = 2**521 - 1
#PRIME = 17
PRIME = curve.r

def eval(poly, i):
    """Calculate the value f(i) where

       .. math:: f(x) = a_0 + a_1x + a_2x^2 ... a_{k-1}x^{k-1}

       and the free term is the secret
    """
    accum = 0
    for coeff in reversed(poly):
        accum = big.modmul(accum, i, PRIME)
        accum = big.modadd(accum, coeff, PRIME)

    return accum


def make_shares(k, n, check=False, secret=None):
    """Generates shares (i, f(i)) and checks - v(x)

    .. math::

        v(x)=a_0G + a_1Gx + a_2Gx^2 ... a_{k-1}xG^{k-1}

    """    
    if k > n:
        raise ValueError("secret not irrecoverable")

    # Generate polynomial
    poly = [big.rand(PRIME) for i in range(k)]

    # poly[0] i.e. a_0 is the secret
    if secret is not None:
        poly[0] = secret

    # [(1,f(1)), (2,f(2), ... (n, f(n)]
    points = [(i, eval(poly, i)) for i in range(1, n + 1)]

    # Make consistency checks if necessary
    checks = []    
    if check:
        for coeff in poly:
            checks.append(coeff * ecp.generator())

    return poly[0], points, checks

def verify_share(checks, share):
    """Verify a share with the distributed checks

    .. math::

        f(i)G &= v(i) \\\\
              &= a_0G + a_1Gi + a_2Gi^2 ... a_{k-1}Gi^{k-1} \\\\
              &= (a_0 + a_1i + a_2i^2 ... a_{k-1}i^{k-1})G 

    """
    (x, y) = share
    gy = y * ecp.generator()

    # accum = c_0^(x^0) * ... * c_(k-1)^(x^(k-1))
    accum = checks[0].copy()
    gexp = 1

    for check in checks[1:]:
        gexp = big.modmul(gexp, x, PRIME)
        accum.add(gexp * check)

    return accum == gy

def product(vals):
    '''product of inputs
    '''
    accum = 1
    for v in vals:
        accum = big.modmul(accum, v, PRIME)
    return accum


def lagrange_interpolate1(x_s):
    """Calculate the coefficients for multiplication

    .. math::

       c(x_j)=\\prod _{\\begin{smallmatrix}m\\,=\\,0\\\\m\\,\\neq \\,j\\end{smallmatrix}}^{k-1}{\\frac {x_{m}}{x_{m}-x_{j}}}

    """        
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
            v.append(s)
        den = product(v)

        coef = big.moddiv(num, den, PRIME)
        coefs.append(coef)

    return coefs

def lagrange_interpolate2(coef, y_s):
    """Calculate the secret

    .. math::

       secret &=\\sum _{j=0}^{k-1}f(x_{j})\\prod _{\\begin{smallmatrix}m\\,=\\,0\\\\m\\,\\neq \\,j\\end{smallmatrix}}^{k-1}{\\frac {x_{m}}{x_{m}-x_{j}}} \\\\
              &=\\sum _{j=0}^{k-1}f(x_{j})c(x_j)

    """        
    k = len(y_s)

    # Calculate of products of coefficient and y values.
    m = []
    for i in range(k):
        t = big.modmul(coef[i], y_s[i], PRIME)
        m.append(t)

    secret = 0
    for i in range(k):
        secret = big.modadd(secret, m[i], PRIME)

    return secret, m

def convert_to_additive_share(x_shares, i, y):
    """Convert to additive shares

    .. math::

       y(x_j)=f(x_{j})\\prod _{\\begin{smallmatrix}m\\,=\\,0\\\\m\\,\\neq \\,j\\end{smallmatrix}}^{k-1}{\\frac {x_{m}}{x_{m}-x_{j}}}

    """        
    others = list(x_shares)
    x_share = others.pop(i)

    num = product(others)

    den = 1
    for share in others:
        v = big.modsub(share, x_share, PRIME)
        den = big.modmul(den, v, PRIME)

    coef = big.moddiv(num, den, PRIME)

    return big.modmul(coef, y, PRIME)
