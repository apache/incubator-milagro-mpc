import hashlib
from sec256k1 import big, ecp, curve, paillier


DEBUG = False


def initiate(n, g, a, r=None):
    '''
        Step 1 of the MtA protocol, without range proof
    '''
    ca, r = paillier.encrypt(n, g, a, r)

    return ca, r


def receive(n, g, q, b, ca, beta1=None, r=None):
    '''
        Step 2 of the MtA protocol, without range check or range/ZK proofs
    '''
    t = paillier.mult(ca, b, n)

    if beta1 is None:
        beta1 = big.rand(q)
        if DEBUG:
            print("beta' {}".format(hex(beta1)[2:]))

    eb, r = paillier.encrypt(n, g, beta1, r)
    cb = paillier.add(t, eb, n)

    beta = big.modsub(q, beta1, q)

    if DEBUG:
        print("t    {}".format(hex(t)[2:]))
        print("eb   {}".format(hex(eb)[2:]))
        print("cb   {}".format(hex(cb)[2:]))
        print("beta {}".format(hex(beta)[2:]))

    return cb, beta, beta1, r


def complete(p, q, lp, mp, lq, mq, n, cb):
    '''
        Step 3 of the MtA protocol, without range/ZK check
    '''

    alpha = paillier.decrypt(p, q, lp, lq, mp, mq, cb)
    alpha = alpha % n

    if DEBUG:
        print("alpha {}".format(hex(alpha)))

    return alpha

### ZK proofs

# Remark 1: for the following proofs it would be nice to organize
# the terms in structs holding the commit/prove/parameters related terms
# to avoid bloating the function signatures and potentially facilitating
# transmission using golang

# Remark 2: Nt, h1, h2 are an additional RSA modulus and elements in Z/NtZ
# as generated in the bit commitment setup in 'commitments.py'

## Range proof


FS_2048 = 2048 // 8
DFS_2048 = 2 * FS_2048


def rp_commit(m, Gamma, h1, h2, q, P, Q, Nt, alpha=None, beta=None, gamma=None, rho=None):
    q3 = q**3

    N = P * Q
    P2 = P**2
    Q2 = Q**2

    if alpha is None:
        alpha = big.rand(q3)

    if beta is None:
        beta = big.rand(N)
    
    if gamma is None:
        gamma = big.rand(q3*Nt)
    
    if rho is None:
        rho = big.rand(q*Nt)

    # Compute u using CRT
    up = big.modmul(pow(Gamma, alpha, P2), pow(beta, N, P2), P2)
    uq = big.modmul(pow(Gamma, alpha, Q2), pow(beta, N, Q2), Q2)
    u = big.crt(up, uq, P2, Q2)

    z = big.modmul(pow(h1, m,     Nt), pow(h2, rho,   Nt), Nt)
    w = big.modmul(pow(h1, alpha, Nt), pow(h2, gamma, Nt), Nt)

    return alpha, beta, gamma, rho, z, u, w


def rp_challenge(Gamma, Nt, h1, h2, q, c, z, u, w):
    '''
        Use Fiat-Shamir to make this NIZK.

        Bind to public parameters:
         * Gamma (Paillier)
         * Nt, h1, h2 (BC commitment setup)
         * q - range
         * c - E_Gamma(m)

        Bind to commitment:
         * z, u, w

        Returns e = H(Gamma, Nt, h1, h2, q, c, z, u, w) mod q
    '''
    sha = hashlib.new('sha256')

    q_bytes = big.to_bytes(q)
    
    Gamma_bytes = Gamma.to_bytes(FS_2048, byteorder='big')
    Nt_bytes    = Nt.to_bytes(FS_2048,    byteorder='big')
    h1_bytes    = h1.to_bytes(FS_2048,    byteorder='big')
    h2_bytes    = h2.to_bytes(FS_2048,    byteorder='big')
    c_bytes     = c.to_bytes(DFS_2048,    byteorder='big')
    
    z_bytes = z.to_bytes(FS_2048,  byteorder='big')
    u_bytes = u.to_bytes(DFS_2048, byteorder='big')
    w_bytes = w.to_bytes(FS_2048,  byteorder='big')
    
    sha.update(Gamma_bytes)
    sha.update(Nt_bytes)
    sha.update(h1_bytes)
    sha.update(h2_bytes)
    sha.update(q_bytes)
    sha.update(c_bytes)

    sha.update(z_bytes)
    sha.update(u_bytes)
    sha.update(w_bytes)

    e_bytes = sha.digest()
    e = big.from_bytes(e_bytes)

    return e % q


def rp_prove(m, r, e, alpha, beta, gamma, rho, P, Q):
    # Compute s usig CRT
    sp = big.modmul(pow(r % P, e, P), beta % P, P)
    sq = big.modmul(pow(r % Q, e, Q), beta % Q, Q)
    s  = big.crt(sp, sq, P, Q)

    s1 = e * m + alpha
    s2 = e * rho + gamma

    return s, s1, s2


def rp_verify(c,s,s1,s2,z,u,w,e,Gamma,h1,h2,q,N,Pt, Qt):
    if s1 > q**3:
        return False

    N2 = N**2
    u_proof = big.modmul(pow(Gamma, s1, N2),pow(s, N, N2), N2)
    u_gt = big.modmul(u, pow(c, e, N2), N2)

    if u_gt != u_proof:
        return False

    # Compute w_proof using CRT
    w_proof_p = big.modmul(pow(h1 % Pt, s1, Pt), pow(h2 % Pt, s2 % (Pt-1), Pt), Pt)
    w_proof_q = big.modmul(pow(h1 % Qt, s1, Qt), pow(h2 % Qt, s2 % (Qt-1), Qt), Qt)
    w_proof = big.crt(w_proof_p, w_proof_q, Pt, Qt)

    # Compute w_gt using CRT
    w_gt_p = big.modmul(w % Pt, pow(z % Pt, e, Pt), Pt)
    w_gt_q = big.modmul(w % Qt, pow(z % Qt, e, Qt), Qt)
    w_gt = big.crt(w_gt_p, w_gt_q, Pt, Qt)

    return w_gt == w_proof


## MtA ZK proof


def mta_commit(x, y, c, Gamma, h1, h2, q, N, Nt):
    q3 = q**3
    N2 = N**2

    alpha = big.rand(q3)
    beta  = big.rand(N)
    gamma = big.rand(N)
    rho   = big.rand(q*Nt)
    rho1  = big.rand(q3*Nt)
    sigma = big.rand(q*Nt)
    tau   = big.rand(q*Nt)

    z  = big.modmul(pow(h1, x,     Nt), pow(h2, rho,   Nt), Nt)
    z1 = big.modmul(pow(h1, alpha, Nt), pow(h2, rho1,  Nt), Nt)
    t  = big.modmul(pow(h1, y,     Nt), pow(h2, sigma, Nt), Nt)
    w  = big.modmul(pow(h1, gamma, Nt), pow(h2, tau,   Nt), Nt)

    v = big.modmul(pow(c, alpha, N2), pow(Gamma, gamma, N2), N2)
    v = big.modmul(v, pow(beta, N, N2), N2)

    return alpha, beta, gamma, rho, rho1, sigma, tau, z, z1, t, v, w


def mta_challenge(q):
    return big.rand(q)


def mta_prove(x,y,r,e,alpha,beta,gamma,rho,rho1,sigma,tau,N):
    s  = big.modmul(pow(r,e,N),beta,N)

    s1 = e * x     + alpha
    s2 = e * rho   + rho1
    t1 = e * y     + gamma
    t2 = e * sigma + tau

    return s, s1, s2, t1, t2


def mta_verify(c1, c2, s, s1, s2, t1, t2, z, z1, t, v, w, e, Gamma, h1, h2, q, N, Nt):
    if s1 > q**3:
        return False

    s_proof = big.modmul(pow(h1, s1, Nt), pow(h2, s2, Nt), Nt)
    s_gt = big.modmul(pow(z, e, Nt),  z1, Nt)
    if s_proof != s_gt:
        return False

    t_proof = big.modmul(pow(h1, t1, Nt), pow(h2, t2, Nt), Nt)
    t_gt = big.modmul(pow(t, e, Nt),  w, Nt)
    if t_proof != t_gt:
        return False

    N2 = N**2
    c_proof = big.modmul(pow(c1, s1, N2), pow(s, N, N2), N2)
    c_proof = big.modmul(c_proof, pow(Gamma, t1, N2), N2)
    c_gt = big.modmul(pow(c2, e, N2), v, N2)

    return c_proof == c_gt


## MtAwC ZK proof


def mtawc_commit(x, y, c, Gamma, h1, h2, q, N, Nt):
    # Regular MtA range and DLOG knowledge proof commit
    alpha, beta, gamma, rho, rho1, sigma, tau, z, z1, t, v, w = mta_commit(
        x, y, c, Gamma, h1, h2, q, N, Nt
    )

    # Additional DLOG knowledge proof commit
    u = alpha * ecp.generator()

    return alpha, beta, gamma, rho, rho1, sigma, tau, u, z, z1, t, v, w


def mtawc_challenge(q):
    return big.rand(q)


def mtawc_prove(x,y,r,e,alpha,beta,gamma,rho,rho1,sigma,tau,N):
    # The additional knowledge of DLOG can be computed from values
    # already output from the MtA proof
    return mta_prove(x,y,r,e,alpha,beta,gamma,rho,rho1,sigma,tau,N)


def mtawc_verify(c1, c2, X, s, s1, s2, t1, t2, u, z, z1, t, v, w, e, Gamma, h1, h2, q, N, Nt):
    # Verify knowldege of DLOG
    dsa_proof = s1 * ecp.generator()
    dsa_gt = u.add(e * X)
    if dsa_proof != dsa_gt:
        return False

    # Carry on with the regular verification for the MtA
    return mta_verify(c1, c2, s, s1, s2, t1, t2, z, z1, t, v, w, e, Gamma, h1, h2, q, N, Nt)
