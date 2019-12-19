import sys
sys.path.append("../../")

import sec256k1.mta as mta
import sec256k1.paillier as paillier
import sec256k1.big as big


def genVector(test_no, p, q, ps, a=None, b=None, r1=None, r2=None, beta_in=None):
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
