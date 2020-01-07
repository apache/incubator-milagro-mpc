#!/usr/bin/env python3

"""
    Generates a set of test vectors for the MtA third step.
    
    usage: genCOMPLETE.py
    """

import sys
import json
from Crypto.Util import number
from genVector import genVector

vector_fields = [
    "TEST",
    "P",
    "Q",
    "LP",
    "LQ",
    "MP",
    "MQ",
    "PS",
    "CB",
    "ALPHA",
]

if __name__ == '__main__':
    if len(sys.argv) == 2:
        nVec = int(sys.argv[1])
    else:
        print("Usage: genINITIATE.py [nVec]")
        sys.exit(1)

    print("Generate nVec = {}".format(nVec))

    vectors = []

    for i in range(nVec):
        # Generate random primes for Paillier
        p = number.getStrongPrime(1024)
        q = number.getStrongPrime(1024)

        # Generate random prime for multiplicative shares
        ps = number.getStrongPrime(512)

        vector = genVector(i, p, q, ps)

        # Prune test vector
        vector = {k: vector[k] for k in vector_fields}

        vectors.append(vector)

    json.dump(vectors, open("COMPLETE.json", "w"), indent=2)

    with open("COMPLETE.txt", "w") as f:
        for vector in vectors:
            for field in vector_fields:
                f.write("{} = {},\n".format(field, vector[field]))
            f.write("\n")
