import sys
sys.path.append("../../")

from sec256k1 import mta, paillier, big, curve, commitments


def genMTAVector(test_no, p, q, ps, a=None, b=None, r1=None, r2=None, beta_in=None):
    """Generate a single test vector for the MTA protocol

        Use parameters to generate a single test vector

        Args::

            test_no: Test vector identifier
            p: prime number for Paillier
            q: prime number for Paillier
            ps: prime number for the multiplicative shares
            a: initiator multiplicative share
            b: receiver multiplicative share
            r1: random number for initiator encryption
            r2: random number for receiver encryption
            beta_in: receiver random value

        Returns::

            vector: A test vector

        Raises::

            Exception
    """

    vector = {}

    n, g, lp, lq, mp, mq = paillier.keys(p, q)

    if a is None:
        a = big.rand(ps)

    if b is None:
        b = big.rand(ps)

    ca, r1 = mta.initiate(n, g, a)
    cb, beta, beta_in, r2 = mta.receive(n, g, ps, b, ca, beta1=beta_in, r=r2)
    alpha = mta.complete(p, q, lp, mp, lq, mq, ps, cb)

    # Form test vector
    vector["TEST"] = test_no
    vector['P'] = hex(p)[2:].zfill(256)
    vector['Q'] = hex(q)[2:].zfill(256)
    vector['N'] = hex(n)[2:].zfill(512)
    vector['G'] = hex(g)[2:].zfill(512)
    vector['LP'] = hex(lp)[2:].zfill(256)
    vector['LQ'] = hex(lq)[2:].zfill(256)
    vector['MP'] = hex(mp)[2:].zfill(256)
    vector['MQ'] = hex(mq)[2:].zfill(256)
    vector["A"] = hex(a)[2:].zfill(128)
    vector["B"] = hex(b)[2:].zfill(128)
    vector["PS"] = hex(ps)[2:].zfill(128)
    vector["R1"] = hex(r1)[2:].zfill(512)
    vector["R2"] = hex(r2)[2:].zfill(512)
    vector["CA"] = hex(ca)[2:].zfill(512)
    vector["CB"] = hex(cb)[2:].zfill(512)
    vector["BETA_IN"] = hex(beta_in)[2:].zfill(128)
    vector["ALPHA"] = hex(alpha)[2:].zfill(128)
    vector["BETA"] = hex(beta)[2:].zfill(128)

    # Check consistency of test vector
    x = big.modmul(a, b, ps)
    x1 = big.modadd(alpha, beta, ps)

    assert x == x1, "x!=x1"

    return vector

def genRPVector(test_no, P, Q, Pt, Qt, h1 = None, h2 = None, m=None, r=None, c=None, alpha=None, beta=None, gamma=None, rho=None):
    """Generate a single test vector for the ZK Range Proof

        Use parameters to generate a single test vector

        Args::

            test_no: Test vector identifier
            P: prime number for Paillier
            Q: prime number for Paillier
            Pt: prime number for BC setup
            Qt: prime number for BC setup
            h1: generator for the BC setup
            h2: generator for the BC setup
            ps: prime number for the multiplicative shares
            m: private value argument of the range proof
            m: random value from the encryption of m
            c: public ciphertext for the range proof
            alpha: random value [0,..,q^3] for the commitment
            beta: random value [0,..,P*Q] for the commitment
            gamma: random value [0,..,Nt*q^3] for the commitment
            rho: random value [0,..,q*Nt] for the commitment

        Returns::

            vector: A test vector

        Raises::

            Exception
    """

    vector = {}

    Gamma = P*Q+1

    if h1 is None or h2 is None:
        _, _, _, _, _, _, h1, h2 = commitments.bc_setup(2048, Pt, Qt)

    if m is None:
        m = big.rand(curve.r)

        c, r = paillier.encrypt(P*Q, Gamma, m, r)




    alpha, beta, gamma, rho, z, u, w = mta.rp_commit(m, Gamma, h1, h2, curve.r, P, Q, Pt*Qt, alpha, beta, gamma, rho)
    e = mta.rp_challenge(Gamma, Pt*Qt, h1, h2, curve.r, c, z, u, w)
    s, s1, s2 = mta.rp_prove(m, r, e, alpha, beta, gamma, rho, P, Q)

    assert mta.rp_verify(c, s, s1, s2, z, u, w, e, Gamma, h1, h2, curve.r, P*Q, Pt, Qt), "Inconsistent test vector"

    vector['TEST'] = test_no
    vector['P']  = hex(P)[2:].zfill(256)
    vector['Q']  = hex(Q)[2:].zfill(256)
    vector['N']  = hex(P*Q)[2:].zfill(512)
    vector['G']  = hex(Gamma)[2:].zfill(512)
    vector['PT'] = hex(Pt)[2:].zfill(256)
    vector['QT'] = hex(Qt)[2:].zfill(256)
    vector['NT'] = hex(Pt*Qt)[2:].zfill(512)
    vector['H1'] = hex(h1)[2:].zfill(512)
    vector['H2'] = hex(h2)[2:].zfill(512)
    vector['M']  = hex(m)[2:].zfill(64)
    vector['R']  = hex(r)[2:].zfill(1024)
    vector['C']  = hex(c)[2:].zfill(1024)

    vector['ALPHA']  = hex(alpha)[2:].zfill(256)
    vector['BETA']   = hex(beta)[2:].zfill(512)
    vector['GAMMA']  = hex(gamma)[2:].zfill(768)
    vector['RHO']    = hex(rho)[2:].zfill(768)
    
    vector['Z'] = hex(z)[2:].zfill(512)
    vector['U'] = hex(u)[2:].zfill(1024)
    vector['W'] = hex(w)[2:].zfill(512)

    vector['E'] = hex(e)[2:].zfill(64)

    vector['S']  = hex(s)[2:].zfill(512)
    vector['S1'] = hex(s1)[2:].zfill(256)
    vector['S2'] = hex(s2)[2:].zfill(768)

    return vector
