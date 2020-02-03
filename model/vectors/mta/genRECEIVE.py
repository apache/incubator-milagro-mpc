#!/usr/bin/env python3

"""
    Generates a set of test vectors for the MtA second step.
    
    usage: genRECEIVE.py
    """

import sys
import json
from Crypto.Util import number
from genVector import genMTAVector

vector_fields = {
    "TEST": "TEST",
    "N": "N",
    "G": "G",
    "PS": "PS",
    "R2": "R",
    "BETA_IN": "BETA_IN",
    "B": "B",
    "CA": "CA",
    "CB": "CB",
    "BETA": "BETA",
}

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

        vector = genMTAVector(i, p, q, ps)

        # Prune test vector
        vector = {vector_fields[k]: vector[k] for k in vector_fields}

        vectors.append(vector)

    json.dump(vectors, open("RECEIVE.json", "w"), indent=2)

    with open("RECEIVE.txt", "w") as f:
        for vector in vectors:
            for field in vector_fields.values():
                f.write("{} = {},\n".format(field, vector[field]))
            f.write("\n")
