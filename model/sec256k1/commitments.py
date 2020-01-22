import hashlib
from sec256k1 import big, schnorr

DEBUG = False

# --- Bit commitment setup ---
#
#   Fujisaki, Okamoto
#
#   Statistical Zero Knowledge Protocols to Prove
#   Modular Polynomial Relations
#
#   https://link.springer.com/content/pdf/10.1007/BFb0052225.pdf
#
# Simplified version using only b0, b1. We only need two generators
# and the knowledge of the DLOG between them.


def bc_generator(p, P):
    '''
        Find random element of order p in Z/PZ.
        It assumes P = 2p+1, i.e. phi(P)=2p
    '''

    x = big.rand(P)

    # While the element has order 2 try the next candidate
    while pow(x,2,P) == 1:
        x = big.modadd(x,1,P)

    # If the element has order p (we already checked 2), return
    if pow(x,p,P) == 1:
        return x

    # Element has order 2p, just square it and return
    return pow(x,2,P)


def bc_setup(k, P=None, Q=None):
    '''
        Setup the bit commitment scheme. k is the desired
        length for the RSA modulus.
        It assumes 4|k
    '''

    # Generate p and Q safe primes if necessary.
    if P == None:
        p, P = big.generate_safe_prime(k//2)
    else:
        p = (P-1)//2

    if Q == None:
        q, Q = big.generate_safe_prime(k//2)
    else:
        q = (Q-1)//2

    # Find a generator of Gpq in Z/PQZ using the CRT
    # on generators of Gp, Gq in Z/PZ and Z/QZ
    gp = bc_generator(p,P)
    gq = bc_generator(q,Q)

    b0 = big.crt(gp,gq,P,Q)

    # Compute random power of b0
    pq = p*q
    N  = P*Q

    alpha = big.rand(pq)

    ialpha = big.invmodp(alpha, pq)
    while ialpha == 0:
        alpha  = alpha + 1
        ialpha = big.invmodp(alpha, pq)

    b1p = pow(gp, alpha % p, P)
    b1q = pow(gq, alpha % q, Q)

    b1 = big.crt(b1p, b1q, P, Q)

    if DEBUG:
        assert b0 == pow(b1, ialpha, N)

    return P, Q, pq, N, alpha, ialpha, b0, b1


# ZK proof that b0, b1 are of the correct form.
# Performed in a naive way as proofs:
#   * knowledge of a      s.t. b1 = b0^a
#   * knowldege of a^(-1) s.t. b0 = b1^(a^(-1))
#
# TODO This might not be valid in this setting.
# Needs more research
#

def bc_setup_commit(b0, b1, pq, P, Q, r0 = None, r1 = None):
    r0, c0 = schnorr.n_commit(b0, pq, P, Q, r0)
    r1, c1 = schnorr.n_commit(b1, pq, P, Q, r1)

    return r0, r1, c0, c1

def bc_setup_challenge(b0, b1, c0, c1, n):
    e0 = schnorr.n_challenge(b0, b1, c0, n)
    e1 = schnorr.n_challenge(b1, b0, c1, n)

    return e0, e1

def bc_setup_proof(r0, r1, e0, e1, alpha, ialpha, pq):
    p0 = schnorr.n_prove(r0, e0, alpha,  pq)
    p1 = schnorr.n_prove(r1, e1, ialpha, pq)

    return p0, p1

def bc_setup_verify(b0, b1, c0, c1, e0, e1, p0, p1, N):
    ok0 = schnorr.n_verify(b0, b1, c0, e0, p0, N)
    ok1 = schnorr.n_verify(b1, b0, c1, e1, p1, N)
    
    return ok0 and ok1

# --- General purpose commitment scheme ---
#
#   As described in the Threshold ECDSA paper, Section 2.4
#

# Security parameter
l = 256
L = 1 << l

# Chosen hash function
hf    = 'sha256'
hflen = 32

def commit(x, xlen, r=None):
    """Compute commitment for a value

    Args::
        x    : value to commit to
        xlen : length in bytes of the value to commit
        r    : random integer of length l, the security parameter. Optional

    Returns::
        r : random integer of length l used in the commitment
        C : commitment to the value x

    """
    H = hashlib.new(hf)

    if r is None:
        r = big.rand(L)

    x_bytes = x.to_bytes(xlen, byteorder='big')
    r_bytes = r.to_bytes(l//8, byteorder='big')

    if DEBUG:
        print("x = {}".format(x_bytes.hex()))
        print("r = {}".format(r_bytes.hex()))

    H.update(x_bytes)
    H.update(r_bytes)

    C = H.digest()

    return r, C

def decommit(C, r, x, xlen):
    """Verify a commitment

    Args::
        C    : commitment to verify
        r    : decommitment value
        x    : committed value
        xlen : length in bytes of the committed value

    Returns::
        True if the value is successfully decommitted, False otherwise
    """

    # Not checking the length of r, since it is padded/truncated
    # to be of the correct length. In C it might be worth to have
    # an explicit check since we use octets
    r, D = commit(x,xlen,r)

    if DEBUG:
        print("D = {}".format(D.hex()))

    return C == D
