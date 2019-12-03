import random

import sec256k1.big as big
import sec256k1.ecp as ecp
import sec256k1.curve as curve
import sec256k1.schnorr as schnorr

def genSchnorrVector(test_no, x=None, r=None,c=None):
    """Generate a single test vector

        Use parameters to generate a single test vector

        Args::

            test_no: Test vector identifier
            x: exponent for the DLOG
            r: random number for the commitment
            c: challenge

        Returns::

            vector: A test vector

        Raises::

            Exception
    """

    # Generate DLOG
    if x is None:
        x = big.rand(curve.r)

    V = x * ecp.generator()

    # ZK proof
    r, C = schnorr.commit(r)

    if c is None:
        c = schnorr.challenge()

    p = schnorr.prove(r,c,x)

    assert schnorr.verify(V,C,c,p), "inconsistent test vector"

    vector = {
        "TEST" : test_no,
        "X"    : hex(x)[2:].zfill(64),
        "V"    : "{}".format(V),
        "R"    : hex(r)[2:].zfill(64),
        "CO"   : "{}".format(C),
        "CH"   : hex(c)[2:].zfill(64),
        "P"    : hex(p)[2:].zfill(64),
    }

    return vector

def genDoubleSchnorrVector(test_no, R=None, s=None, l=None, a=None, b=None,c=None):
    """Generate a single test vector

        Use parameters to generate a single test vector

        Args::

            test_no: Test vector identifier
            R: point on the curve
            s: exponent for the DLOG with R
            l: exponent for the DLOG with G
            a: random number for the commitment
            b: random number for the commitment
            c: challenge

        Returns::

            vector: A test vector

        Raises::

            Exception
    """

    if R is None:
        R = big.rand(curve.r) * ecp.generator()

    # Generate DLOG
    if s is None:
        s = big.rand(curve.r)

    if l is None:
        l = big.rand(curve.r)

    V = ecp.ECp.mul(R, s, ecp.generator(), l)

    # ZK proof
    a,b, C = schnorr.d_commit(R,a,b)

    if c is None:
        c = schnorr.d_challenge()

    t,u = schnorr.d_prove(a,b,c,s,l)

    assert schnorr.d_verify(R,V,C,c,t,u), "inconsistent test vector"

    vector = {
        "TEST" : test_no,
        "R"    : "{}".format(R),
        "S"    : hex(s)[2:].zfill(64),
        "L"    : hex(l)[2:].zfill(64),
        "V"    : "{}".format(V),
        "A"    : hex(a)[2:].zfill(64),
        "B"    : hex(b)[2:].zfill(64),
        "CO"   : "{}".format(C),
        "CH"   : hex(c)[2:].zfill(64),
        "T"    : hex(t)[2:].zfill(64),
        "U"    : hex(u)[2:].zfill(64),
    }

    return vector
