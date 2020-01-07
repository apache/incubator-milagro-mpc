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
    print(
        "Usage: genVectors.py [nVec]")
    sys.exit(1)

print("Generate nVec = {}".format(nVec))


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

    n, g, lp, lq, mp, mq = paillier.keys(p, q)
    vector['N'] = hex(n)[2:].zfill(512)

    pt1 = random.randint(1, n)
    print("pt1 {}".format(pt1))
    ct1, _ = paillier.encrypt(n, g, pt1, None)
    vector['CIPHERTEXT1'] = hex(ct1)[2:].zfill(1024)

    pt2 = random.randint(1, n)
    print("pt2 {}".format(pt2))
    ct2, _ = paillier.encrypt(n, g, pt2, None)
    vector['CIPHERTEXT2'] = hex(ct2)[2:].zfill(1024)

    ct = paillier.add(ct1, ct2, n)
    vector['CIPHERTEXT'] = hex(ct)[2:].zfill(1024)

    pt = paillier.decrypt(p, q, lp, lq, mp, mq, ct)
    pt12 = (pt1 + pt2) % n
    print("pt12 {}".format(pt12))
    print("pt {}".format(pt))

    assert pt12 == pt, "pt12 != pt"

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
        print("i ", i)

    # Write to JSON file
    json.dump(vectors, open("ADD.json", "w"))

    # Write vectors to text file
    with open("ADD.txt", "w") as f:
        for vector in vectors:
            f.write("TEST = {},\n".format(vector['TEST']))
            f.write("N = {},\n".format(vector['N']))
            f.write("CIPHERTEXT1 = {},\n".format(vector['CIPHERTEXT1']))
            f.write("CIPHERTEXT2 = {},\n".format(vector['CIPHERTEXT2']))
            f.write("CIPHERTEXT = {},\n".format(vector['CIPHERTEXT']))
