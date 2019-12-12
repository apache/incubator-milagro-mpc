#!/usr/bin/env python3

"""
   Generates a set of test vectors.

   usage: genEncryptVectors.py
"""

import sys
sys.path.append('../../')
import os
import random
import json
import sec256k1.paillier as paillier
from Crypto.PublicKey import RSA

if len(sys.argv) == 2:
    nVec = int(sys.argv[1])
else:
    print (
        "Usage: genVectors.py [nVec]")
    sys.exit(1)

print ("Generate nVec = {}".format(nVec))

def genVector(test_no, p, q):
    """Generate a single test vector

    Use parameters to generate a single test vector

    Args::

        test_no: Test vector identifier
        p: prime number
        q: prime number

    Returns::

        vector: A test vector

    Raises::

        Exception
    """
    vector = {}

    vector['TEST'] = test_no

    vector['P'] = hex(p)[2:].zfill(256)
    vector['Q'] = hex(q)[2:].zfill(256)

    n, g, lp, lq, mp, mq = paillier.keys(p,q)
    vector['N'] = hex(n)[2:].zfill(512)
    vector['G'] = hex(g)[2:].zfill(512)
    vector['LP'] = hex(lp)[2:].zfill(256)
    vector['LQ'] = hex(lq)[2:].zfill(256)
    vector['MP'] = hex(mp)[2:].zfill(256)
    vector['MQ'] = hex(mq)[2:].zfill(256)

    return vector

if __name__ == '__main__':
    # List of test vectors
    vectors = []

    # Generate test vectors
    for i in range(1, nVec):
        rsa_key = RSA.generate(2048)
        p = rsa_key.p
        q = rsa_key.q
        vector = genVector(i, p, q)
        vectors.append(vector)

    # Write to JSON file
    json.dump(vectors, open("KEYGEN.json", "w"))

    # Write vectors to text file
    with open("KEYGEN.txt", "w") as f:
        for vector in vectors:
            f.write("TEST = {},\n".format(vector['TEST']))
            f.write("P = {},\n".format(vector['P']))
            f.write("Q = {},\n".format(vector['Q']))
            f.write("N = {},\n".format(vector['N']))
            f.write("G = {},\n".format(vector['G']))
            f.write("LP = {},\n".format(vector['LP']))
            f.write("LQ = {},\n".format(vector['LQ']))
            f.write("MP = {},\n".format(vector['MP']))
            f.write("MQ = {},\n\n".format(vector['MQ']))
