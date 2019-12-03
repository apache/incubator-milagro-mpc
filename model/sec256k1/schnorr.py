import sec256k1.big as big
import sec256k1.ecp as ecp
import sec256k1.curve as curve

DEBUG = False

## Modified algorithm to prove knowledge of two dlogs
#
# s,l s.t. V = s.R + l.G

# Commit C = a.R + b.G
def d_commit(R, a=None, b=None):
    if a is None:
        a = big.rand(curve.r)

    if b is None:
        b = big.rand(curve.r)

    C = ecp.ECp.mul(R,a,ecp.generator(),b)

    return a,b,C

def d_challenge():
    return big.rand(curve.r)

def d_prove(a,b,c,s,l):
    t = (a + c*s) % curve.r
    u = (b + c*l) % curve.r

    return t,u

# Verify t.R + u.G = C + c.V
def d_verify(R,V,C,c,t,u):
    P = ecp.ECp.mul(R,t,ecp.generator(),u)

    Q = C.copy()
    Q.add(c * V)

    if DEBUG:
        print("P {}".format(P))
        print("Q {}".format(Q))

    return P == Q

## Classic Schnorr algorithm to prove knowledge of a dlog
#
# s s.t. V = s.G

# Commit C = c.R
def commit(r=None):
    if r is None:
        r = big.rand(curve.r)

    C = r * ecp.generator()

    return r, C

def challenge():
    return big.rand(curve.r)

def prove(r,c,x):
    return (r + c*x) % curve.r

# Verify p.G = C + c.V
def verify(V,C,c,p):
    P = p * ecp.generator()

    Q = C.copy()
    Q.add(c * V)

    if DEBUG:
        print("P {}".format(P))
        print("Q {}".format(Q))

    return P == Q
