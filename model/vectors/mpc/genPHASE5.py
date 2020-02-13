#!/usr/bin/env python3

"""
    Generates a set of test vectors for the schnorr zk proof.

    usage: genPHASE5.py -h
"""

import sys
sys.path.append("../../")

import json
import argparse
from sec256k1 import big, ecp, curve, mpc

def genVector(test_no):
    """Generate a single test vector

        Use parameters to generate a single test vector

        Args::

            test_no: Test vector identifier

        Returns::

            vector: A test vector

        Raises::

            Exception
    """

    # Generate distributed keypair
    x1 = big.rand(curve.r)
    x2 = big.rand(curve.r)
    x = (x1 + x2) % curve.r
    PK = x * ecp.generator()

    # Generate message
    M = "TEST_MESSAGE_{}".format(test_no).encode('utf-8')

    # Generate ki, sigma, r, R for signature
    k1 = big.rand(curve.r)
    k2 = big.rand(curve.r)
    k = (k1 + k2) % curve.r
    invk = big.invmodp(k, curve.r)

    R = invk * ecp.generator()
    r = R.getx() % curve.r

    # Fake additive split of sigma. This is not
    # what you would get from the MTA, but it is
    # fine here for testing purposes
    sigma1 = (k1 * x1 + k1 * x2) % curve.r
    sigma2 = (k2 * x2 + k2 * x1) % curve.r

    # Generate sigmature shares
    s1 = mpc.make_signature_share(M, k1, r, sigma1)
    s2 = mpc.make_signature_share(M, k2, r, sigma2)

    # Check consistency of signature values generated
    s = (s1 + s2) % curve.r
    s_gt = (k * (mpc.hashit(M) + r*x)) % curve .r
    assert s == s_gt, "inconsistent signature values generated"

    # Generate test vector
    phi1, rho1, V1, A1 = mpc.phase5_commit(s1, R)
    phi2, rho2, V2, A2 = mpc.phase5_commit(s2, R)

    Vs = [V1, V2]
    As = [A1, A2]

    U1, T1 = mpc.phase5_prove(rho1, phi1, Vs, As, PK, M, r)
    U2, T2 = mpc.phase5_prove(rho2, phi2, Vs, As, PK, M, r)

    Us = [U1, U2]
    Ts = [T1, T2]

    assert mpc.phase5_verify(Us, Ts), "inconsistent test vector"

    vector = {
        "TEST"  : test_no,
        "M"     : hex(mpc.hashit(M))[2:].zfill(64),
        "PK"    : PK.toBytes(True).hex(),
        "R"     : R.toBytes(True).hex(),
        "K"     : hex(k1)[2:].zfill(64),
        "S"     : hex(s1)[2:].zfill(64),
        "RX"    : hex(r)[2:].zfill(64),
        "PHI"   : hex(phi1)[2:].zfill(64),
        "RHO"   : hex(rho1)[2:].zfill(64),
        "A1"    : A1.toBytes(True).hex(),
        "A2"    : A2.toBytes(True).hex(),
        "V1"    : V1.toBytes(True).hex(),
        "V2"    : V2.toBytes(True).hex(),
        "U1"    : U1.toBytes(True).hex(),
        "U2"    : U2.toBytes(True).hex(),
        "T1"    : T1.toBytes(True).hex(),
        "T2"    : T2.toBytes(True).hex(),
    }

    return vector



vector_fields = {
    "commit": ["TEST", "S", "R", "PHI", "RHO", "V1", "A1"],
    "prove": ["TEST", "PHI", "RHO", "V1", "V2", "A1", "A2", "PK", "M", "RX", "U1", "T1"],
    "verify": ["TEST", "U1", "U2", "T1", "T2",],
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-t', dest='type', type=str, default='commit', choices=["commit", "prove", "verify"],
        help='test vector type')
    parser.add_argument('-n', dest='n', type=int, default=10,
        help='number of test vectors to generate')

    args = parser.parse_args()

    vec_type = args.type

    keys = vector_fields[vec_type]

    vectors = []

    for i in range(args.n):
        vector = genVector(i)

        vector = {k: vector[k] for k in keys}
        vectors.append(vector)

    json.dump(vectors, open("phase5_{}.json".format(vec_type), "w"), indent=2)

    with open("phase5_{}.txt".format(vec_type), "w") as f:
        for vector in vectors:
            for field in keys:
                f.write("{} = {},\n".format(field, vector[field]))
            f.write("\n")
