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
    "prove": ["TEST", "N", "PHI", "R", "Z1", "Z2", "E", "Y"],
    "verify": ["TEST", "Z1", "Z2", "Z3", "E", "Y"]
}

def genVector(test_no):
    """Generate a single test vector

        Args::

            test_no: Test vector identifier

        Returns::

            v: A test vector

        Raises::

            Exception
    """
    p = number.getStrongPrime(fact.nlen//2)
    q = number.getStrongPrime(fact.nlen//2)
    N    = p * q
    phiN = (p-1) * (q-1)

    Zi = fact.nizk_setup(N)

    r   = big.rand(fact.A)
    e,y = fact.nizk_prove(N,phiN,Zi,r=r)

    assert fact.nizk_verify(Zi,N,e,y)

    v = {
        "TEST": test_no,
        "N":    hex(N)[2:].zfill(fact.nlen//4),
        "PHI":  hex(phiN)[2:].zfill(fact.nlen//4),
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
        vector = genVector(i)

        vector = {k: vector[k] for k in vector_fields[args.type]}
        vectors.append(vector)

    json.dump(vectors, open("{}.json".format(args.type), "w"), indent=2)

    with open("{}.txt".format(args.type), "w") as f:
        for vector in vectors:
            for field in vector_fields[args.type]:
                f.write("{} = {},\n".format(field, vector[field]))
            f.write("\n")
