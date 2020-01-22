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


# NIZK Schnorr algorithm in the setting of number groups
# with composite modulus.
#
# s s.t. b1 = b0^s mod PQ, P = 2p + 1, Q = 2q + 1, b0 generator of Z/pqZ


def n_commit(b0, pq, P, Q, r=None):
    '''
        Commit c = b0^r mod Q
    '''

    if r is None:
        r = big.rand(pq)

    cp = pow(b0 % P, r % (P-1), P)
    cq = pow(b0 % Q, r % (Q-1), Q)

    c = big.crt(cp, cq, P, Q)

    return r, c


def n_challenge(b0, b1, c, n):
    '''
        Generate challenge in [0, .., 2^256-1]

        n is the length in bytes of b0, b1 and c
    '''
    H = hashlib.new("sha256")

    H.update(b0.to_bytes(n, byteorder='big'))
    H.update(b1.to_bytes(n, byteorder='big'))
    H.update(c.to_bytes(n, byteorder='big'))

    e_bytes = H.digest()
    e = big.from_bytes(e_bytes)

    return e


def n_prove(r, e, x, q):
    return (r - e * x) % q


def n_verify(b0, b1, c, e, p, N):
    '''
        Verify c = b0^p * b1^e
    '''

    proof = big.modmul(pow(b0, p, N), pow(b1, e, N), N)

    return proof == c
