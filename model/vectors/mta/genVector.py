import random

import sec256k1.mta as mta
import sec256k1.paillier as paillier
import sec256k1.big as big

def genVector(test_no, p,q, ps, a=None,b=None,r1=None,r2=None, beta_in=None):
    """Generate a single test vector

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

    n, g, l, m = paillier.keys(p,q)

    if a is None:
        a = big.rand(ps)

    if b is None:
        b = big.rand(ps)

    if r1 is None:
        r1 = big.rand(n)

    if r2 is None:
        r2 = big.rand(n)

    if beta_in is None:
        beta_in = big.rand(ps)

    ca = mta.initiate(n,g,a,r=r1)
    beta, cb = mta.receive(n,g,ps,b,ca,beta=beta_in,r=r2)
    alpha = mta.complete(n,l,m,ps,cb)

    # Form test vector
    vector["TEST"] = test_no
    vector["N"]  = hex(n)[2:].zfill(512)
    vector["G"]  = hex(g)[2:].zfill(512)
    vector["L"]  = hex(l)[2:].zfill(512)
    vector["M"]  = hex(m)[2:].zfill(512)
    vector["A"]  = hex(a)[2:].zfill(128)
    vector["B"]  = hex(b)[2:].zfill(128)
    vector["PS"] = hex(ps)[2:].zfill(128)
    vector["R1"] = hex(r1)[2:].zfill(512)
    vector["R2"] = hex(r2)[2:].zfill(512)
    vector["CA"] = hex(ca)[2:].zfill(512)
    vector["CB"] = hex(cb)[2:].zfill(512)
    vector["BETA_IN"] = hex(beta_in)[2:].zfill(128)
    vector["ALPHA"]   = hex(alpha)[2:].zfill(128)
    vector["BETA"]    = hex(beta)[2:].zfill(128)

    # Check consistency of test vector
    x  = big.modmul(a,b,ps)
    x1 = big.modadd(alpha,beta,ps)

    assert x == x1, "x!=x1"

    return vector