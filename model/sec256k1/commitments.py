import sec256k1.big as big
import sec256k1.schnorr as schnorr

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

    # Compute random powers of b0
    pq = p*q
    N  = P*Q

    alpha = big.rand(pq)
    beta  = big.rand(pq)

    ialpha = big.invmodp(alpha, pq)
    while ialpha == 0:
        alpha  = alpha + 1
        ialpha = big.invmodp(alpha, pq)

    ibeta = big.invmodp(beta, pq)
    while ibeta == 0:
        beta  = beta + 1
        ibeta = big.invmodp(beta, pq)

    b1 = pow(b0, alpha, N)
    b2 = pow(b0, beta, N)

    if DEBUG:
        assert b0 == pow(b1, ialpha, N)
        assert b0 == pow(b2, ibeta, N)

    return P, Q, N, alpha, beta, ialpha, ibeta, b0, b1, b2


# ZK proof that b0, b1, b2 are of the correct form.
# Performed in a naive way as proofs:
#   * knowledge of a      s.t. b1 = b0^a
#   * knowldege of a^(-1) s.t. b0 = b1^(a^(-1))
#   * knowledge of b      s.t. b2 = b0^b
#   * knowldege of b^(-1) s.t. b0 = b2^(b^(-1))
#
# TODO investigate if there is a more efficient ZK
#   proof for this
#

def bc_setup_commit(b0, b1, b2, N):
    # TODO check if information is leaked by reusing
    # the same commitment for b0

    r0, co0 = schnorr.n_commit(b0, N)
    r1, co1 = schnorr.n_commit(b1, N)
    r2, co2 = schnorr.n_commit(b2, N)

    return r0, r1, r2, co0, co1, co2,

def bc_setup_challenge(N):
    # TODO check if information is leaked by reusing
    # the same challenge

    return schnorr.n_challenge(N)

def bc_setup_proof(r0, r1, r2, c, alpha, beta, ialpha, ibeta, phi):
    p0 = schnorr.n_prove(r0, c, alpha,  phi)
    p1 = schnorr.n_prove(r1, c, ialpha, phi)
    p2 = schnorr.n_prove(r0, c, beta,   phi)
    p3 = schnorr.n_prove(r2, c, ibeta,  phi)

    return p0, p1, p2, p3

def bc_setup_verify(b0, b1, b2, co0, co1, co2, c, p0, p1, p2, p3, N):
    if not schnorr.n_verify(b0, b1, co0, c, p0, N):
        return False

    if not schnorr.n_verify(b1, b0, co1, c, p1, N):
        return False

    if not schnorr.n_verify(b0, b2, co0, c, p2, N):
        return False

    return schnorr.n_verify(b2, b0, co2, c, p3, N)
