import hashlib
import sec256k1.big as big
import sec256k1.ecp as ecp
import sec256k1.curve as curve

DEBUG = False

# Modified algorithm to prove knowledge of two dlogs
#
# s,l s.t. V = s.R + l.G


def d_commit(R, a=None, b=None):
    '''
        Commit C = a.R + b.G
    '''
    if a is None:
        a = big.rand(curve.r)

    if b is None:
        b = big.rand(curve.r)

    C = ecp.ECp.mul(R, a, ecp.generator(), b)

    return a, b, C


def d_challenge():
    return big.rand(curve.r)


def d_prove(a, b, c, s, l):
    t = (a + c * s) % curve.r
    u = (b + c * l) % curve.r

    return t, u


def d_verify(R, V, C, c, t, u):
    '''
        Verify t.R + u.G = C + c.V
    '''

    P = ecp.ECp.mul(R, t, ecp.generator(), u)

    Q = C.copy()
    Q.add(c * V)

    if DEBUG:
        print("P {}".format(P))
        print("Q {}".format(Q))

    return P == Q


# NIZK Schnorr algorithm to prove knowledge of a dlog
#
# s s.t. V = s.G


def commit(r=None):
    '''
        Commit C = r.G
    '''
    if r is None:
        r = big.rand(curve.r)

    C = r * ecp.generator()

    return r, C


def challenge(V, C):
    H = hashlib.new("sha256")

    H.update(ecp.generator().toBytes(True))
    H.update(C.toBytes(True))
    H.update(V.toBytes(True))

    e_bytes = H.digest()
    e = big.from_bytes(e_bytes)
    e = e % curve.r

    return e


def prove(r, c, x):
    return (r - c * x) % curve.r


def verify(V, C, c, p):
    '''
        Verify C = p.G + c.V
    '''

    P = V.mul(c,ecp.generator(),p)

    if DEBUG:
        print("P {}".format(P))

    return P == C


# Classical Schnorr algorithm in the setting of number groups
#
# s s.t. b1 = b0^s mod q


def n_commit(b0, q, r=None):
    '''
        Commit co = b0^r mod q
    '''

    if r is None:
        r = big.rand(q)

    return r, pow(b0, r, q)


def n_challenge(q):
    return big.rand(q)


def n_prove(r, c, x, phi):
    return (r + c * x) % phi


def n_verify(b0, b1, co, c, p, q):
    '''
        Verify b0^p = co * b1^c
    '''

    proof = pow(b0, p, q)
    gt    = big.modmul(co, pow(b1, c, q), q)

    return proof == gt
