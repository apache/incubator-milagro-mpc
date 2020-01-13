#!/usr/bin/env python3

"""
    Generates a set of test vectors for the integer factoring zk proof.

    usage: genZKFACT.py --type prove 10
"""

import sys
sys.path.append("../../")

import json
import argparse
from Crypto.Util import number
from sec256k1 import big
from sec256k1 import factorization_zk as fact

vector_fields = {
    "setup": ["TEST", "N", "Z1", "Z2"],
    "prove": ["TEST", "N", "P", "Q", "R", "Z1", "Z2", "E", "Y"],
    "verify": ["TEST", "Z1", "Z2", "E", "Y"]
}

def genVector(test_no, tv_type):
    """Generate a single test vector

        Args::

            test_no: Test vector identifier

        Returns::

            v: A test vector

        Raises::

            Exception
    """
    P = number.getStrongPrime(fact.nlen//2)
    Q = number.getStrongPrime(fact.nlen//2)
    N    = P * Q

    Zi = fact.nizk_setup(N)

    # If it is only a setup, it should be simple enough to not go thorugh
    # the run to validate the generated tv. This saves a lot of time, since
    # the run is quite expensive
    if tv_type == "setup":
        v = {
            "TEST": test_no,
            "N":    hex(N)[2:].zfill(fact.nlen//4),
            "Z1":   hex(Zi[0])[2:].zfill(fact.nlen//4),
            "Z2":   hex(Zi[1])[2:].zfill(fact.nlen//4),
        }

        return v

    r   = big.rand(fact.A)
    e,y = fact.nizk_prove(N, P, Q, Zi, r=r)

    assert fact.nizk_verify(Zi, N, e, y)

    v = {
        "TEST": test_no,
        "N":    hex(N)[2:].zfill(fact.nlen//4),
        "P":    hex(P)[2:].zfill(fact.nlen//8),
        "Q":    hex(Q)[2:].zfill(fact.nlen//8),
        "R":    hex(r)[2:].zfill(fact.nlen//4),
        "Z1":   hex(Zi[0])[2:].zfill(fact.nlen//4),
        "Z2":   hex(Zi[1])[2:].zfill(fact.nlen//4),
        "E":    hex(e)[2:].zfill(fact.B//4),
        "Y":    hex(y)[2:].zfill(fact.nlen//4)
    }

    return v

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('--type', dest='type', type=str, default='commit',
                        help='test vector type', choices=["setup", "prove", "verify"])
    parser.add_argument(
        'nVec', type=int, help='number of test vectors to generate')

    args = parser.parse_args()

    print("Generate {} vector(s). Type '{}'".format(args.nVec, args.type))

    vectors = []

    for i in range(args.nVec):
        vector = genVector(i, args.type)

        vector = {k: vector[k] for k in vector_fields[args.type]}
        vectors.append(vector)

    json.dump(vectors, open("{}.json".format(args.type), "w"), indent=2)

    with open("{}.txt".format(args.type), "w") as f:
        for vector in vectors:
            for field in vector_fields[args.type]:
                f.write("{} = {},\n".format(field, vector[field]))
            f.write("\n")
