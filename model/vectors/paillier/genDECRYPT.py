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

def genVector(test_no, p, q, pt, rin):
    """Generate a single test vector

    Use parameters to generate a single test vector

    Args::

        test_no: Test vector identifier
        p: prime number
        q: prime number
        pt: plaintext
        rin: random number < n

    Returns::

        vector: A test vector

    Raises::

        Exception
    """
    vector = {}

    vector['TEST'] = test_no

    n, g, lp, lq, mp, mq = paillier.keys(p,q)
    vector['P'] = hex(p)[2:].zfill(256)
    vector['Q'] = hex(q)[2:].zfill(256)
    vector['N'] = hex(n)[2:].zfill(512)
    vector['LP'] = hex(lp)[2:].zfill(256)
    vector['LQ'] = hex(lq)[2:].zfill(256)
    vector['MP'] = hex(mp)[2:].zfill(256)
    vector['MQ'] = hex(mq)[2:].zfill(256)

    if pt==None:
        pt = random.randint(1, n)

    ct, _ = paillier.encrypt(n, g, pt, rin)
    pt2 = paillier.decrypt(p, q, lp, lq, mp, mq, ct)

    vector['CIPHERTEXT'] = hex(ct)[2:].zfill(1024)
    vector['PLAINTEXT']  = hex(pt2)[2:].zfill(512)

    assert pt2 == pt, "pt2 != pt"

    return vector

if __name__ == '__main__':

    # Used to generate primes
    rsa_key = RSA.generate(2048)

    # List of test vectors
    vectors = []

    p = 0x94f689d07ba20cf7c7ca7ccbed22ae6b40c426db74eaee4ce0ced2b6f52a5e136663f5f1ef379cdbb0c4fdd6e4074d6cff21082d4803d43d89e42fd8dfa82b135aa31a8844ffea25f255f956cbc1b9d8631d01baf1010d028a190b94ce40f3b72897e8196df19edf1ff62e6556f2701d52cef1442e3301db7608ecbdcca703db
    q = 0x9a9ad73f246df853e129c589925fdad9df05606a61081e62e72be4fb33f6e5ec492cc734f28bfb71fbe2ba9a11e4c02e2c0d103a5cbb0a9d6402c07de63b1b995dd72ac8f29825d66923a088b421fb4d52b0b855d2f5dde2be9b0ca0cee6f7a94e5566735fe6cff1fcad3199602f88528d19aa8d0263adff8f5053c38254a2a3
    r = 0x0d789a7e48f97b19a6345ef330020d2b463370479e34e501b976a55fea49811ea883e978ae101b677f5bf85059a26da7a5659be2067d4c1a23da3f6180f6772611227152344df20b3fbaab21c5e44f6ecf58caeddf3cbd61c5421d60c1f5a830271d57834e258f9d31a279b691350134714dbc6ed40eddbc6a9b37df729ac919b91a6b6964106b0a901b5b6cc8e2d8cfe2e54bac731ab5db46f19933a3b5a20c794fa716c69323dabca2fe161560ac3daef333fb7d4fce5abbfb24993bdaf049745b4f18e96c00dddd2c667bb7ec54f005b3ea12f7a6cfc43405a91b61b8d63585b29cd0f5cb97e497405e9dee3d8e04e736ca918ddebd1c5b89f462281e3702
    pt = 2

    vector = genVector(0, p, q, pt, r)
    vectors.append(vector)

    # Generate test vectors
    for i in range(1, nVec):
        rsa_key = RSA.generate(2048)
        p = rsa_key.p
        q = rsa_key.q
        pt = None
        r = None
        vector = genVector(i, p, q, pt, r)
        vectors.append(vector)

    # Write to JSON file
    json.dump(vectors, open("DECRYPT.json", "w"))

    # Write vectors to text file
    with open("DECRYPT.txt", "w") as f:
        for vector in vectors:
            f.write("TEST = {},\n".format(vector['TEST']))
            f.write("N = {},\n".format(vector['N']))
            f.write("P = {},\n".format(vector['P']))
            f.write("Q = {},\n".format(vector['Q']))
            f.write("LP = {},\n".format(vector['LP']))
            f.write("LQ = {},\n".format(vector['LQ']))
            f.write("MP = {},\n".format(vector['MP']))
            f.write("MQ = {},\n".format(vector['MQ']))
            f.write("CIPHERTEXT = {},\n".format(vector['CIPHERTEXT']))
            f.write("PLAINTEXT = {},\n\n".format(vector['PLAINTEXT']))
