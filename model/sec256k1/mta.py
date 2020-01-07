import sec256k1.big as big
import sec256k1.ecp as ecp
import sec256k1.curve as curve
import sec256k1.paillier as paillier

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


def rp_commit(m, Gamma, h1, h2, q, N, Nt):
    q3 = q**3
    N2 = N**2

    alpha = big.rand(q3)
    beta  = big.rand(N)
    gamma = big.rand(q3*Nt)
    rho   = big.rand(q*Nt)

    u = big.modmul(pow(Gamma, alpha, N2), pow(beta, N, N2), N2)

    z = big.modmul(pow(h1, m,     Nt), pow(h2, rho,   Nt), Nt)
    w = big.modmul(pow(h1, alpha, Nt), pow(h2, gamma, Nt), Nt)

    return alpha, beta, gamma, rho, z, u, w


def rp_challenge(q):
    return big.rand(q)


def rp_prove(m,r,c,e,alpha,beta,gamma,rho,N):
    s  = big.modmul(pow(r,e,N),beta,N)
    s1 = e * m + alpha
    s2 = e * rho + gamma

    return s, s1, s2


def rp_verify(c,s,s1,s2,z,u,w,e,Gamma,h1,h2,q,N,Nt):
    if s1 > q**3:
        return False

    N2 = N**2
    u_proof = big.modmul(pow(Gamma, s1, N2),pow(s, N, N2), N2)
    u_gt = big.modmul(u, pow(c, e, N2), N2)

    if u_gt != u_proof:
        return False

    w_proof = big.modmul(pow(h1, s1, Nt), pow(h2, s2, Nt), Nt)
    w_gt = big.modmul(w, pow(z, e, Nt), Nt)

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
        print("a")
        return False

    s_proof = big.modmul(pow(h1, s1, Nt), pow(h2, s2, Nt), Nt)
    s_gt = big.modmul(pow(z, e, Nt),  z1, Nt)
    if s_proof != s_gt:
        print("b")
        return False

    t_proof = big.modmul(pow(h1, t1, Nt), pow(h2, t2, Nt), Nt)
    t_gt = big.modmul(pow(t, e, Nt),  w, Nt)
    if t_proof != t_gt:
        print(t_gt)
        print(t_proof)
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
