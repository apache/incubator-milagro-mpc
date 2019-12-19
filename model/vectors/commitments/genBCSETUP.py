#! /usr/bin/env python3

import sys
sys.path.append('../../')

import json
import argparse

import sec256k1.commitments as commitments

def generate_vector(test_no, k):
    '''
        Generate test vector for the bit commitment setup
    '''

    vector = {}

    vector['TEST'] = test_no

    P, Q, N, alpha, beta, ialpha, ibeta, b0, b1, b2 = commitments.bc_setup(k)
    vector['P']      = "{}".format(hex(P)[2:].zfill(k//8))
    vector['Q']      = "{}".format(hex(Q)[2:].zfill(k//8))
    vector['N']      = "{}".format(hex(N)[2:].zfill(k//4))
    vector['alpha']  = "{}".format(hex(alpha)[2:].zfill(k//4))
    vector['beta']   = "{}".format(hex(beta)[2:].zfill(k//4))
    vector['ialpha'] = "{}".format(hex(ialpha)[2:].zfill(k//4))
    vector['ibeta']  = "{}".format(hex(ibeta)[2:].zfill(k//4))
    vector['b0']     = "{}".format(hex(b0)[2:].zfill(k//4))
    vector['b1']     = "{}".format(hex(b1)[2:].zfill(k//4))
    vector['b2']     = "{}".format(hex(b2)[2:].zfill(k//4)) 

    return vector

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-n', dest='n', type=int, default=10,
        help='number of test vectors')
    parser.add_argument('-k', dest='k', type=int, choices=[1024, 2048, 4096], default=1024,
        help='length in bit of the RSA modulus')

    args = parser.parse_args()

    nVec = args.n
    k = args.k

    vectors = []

    for i in range(nVec):
        vectors.append(generate_vector(i, k))

    json.dump(vectors, open("BCSETUP.json", "w"), indent=2)

    with open("BCSETUP.txt", "w") as f:
        for vector in vectors:
            f.write("TEST = {},\n".format(vector['TEST']))
            f.write("P = {},\n".format(vector['P']))
            f.write("Q = {},\n".format(vector['Q']))
            f.write("N = {},\n".format(vector['N']))
            f.write("ALPHA = {},\n".format(vector['alpha']))
            f.write("BETA = {},\n".format(vector['beta']))
            f.write("IALPHA = {},\n".format(vector['ialpha']))
            f.write("IBETA = {},\n".format(vector['ibeta']))
            f.write("B0 = {},\n".format(vector['b0']))
            f.write("B1 = {},\n".format(vector['b1']))
            f.write("B2 = {},\n".format(vector['b2']))
            f.write("\n")
