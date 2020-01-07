#! /usr/bin/env python3

import sys
sys.path.append('../../')

import json
import argparse

from sec256k1 import commitments

def genVector(test_no, k, P=None, Q=None):
    '''
        Generate a full test vector for the bit commitment
        ZK proof
    '''

    vector = {
        'TEST': test_no
    }

    P, Q, N, alpha, beta, ialpha, ibeta, b0, b1, b2 = commitments.bc_setup(k, P, Q)
    vector['PHI']      = "{}".format(hex((P-1)*(Q-1))[2:].zfill(k//4))
    vector['N']      = "{}".format(hex(N)[2:].zfill(k//4))
    vector['alpha']  = "{}".format(hex(alpha)[2:].zfill(k//4))
    vector['beta']   = "{}".format(hex(beta)[2:].zfill(k//4))
    vector['ialpha'] = "{}".format(hex(ialpha)[2:].zfill(k//4))
    vector['ibeta']  = "{}".format(hex(ibeta)[2:].zfill(k//4))
    vector['b0']     = "{}".format(hex(b0)[2:].zfill(k//4))
    vector['b1']     = "{}".format(hex(b1)[2:].zfill(k//4))
    vector['b2']     = "{}".format(hex(b2)[2:].zfill(k//4)) 

    r0, r1, r2, co0, co1, co2, = commitments.bc_setup_commit(b0, b1, b2, N)
    vector['r0']  = "{}".format(hex(r0)[2:].zfill(k//4))
    vector['r1']  = "{}".format(hex(r1)[2:].zfill(k//4))
    vector['r2']  = "{}".format(hex(r2)[2:].zfill(k//4))
    vector['co0'] = "{}".format(hex(co0)[2:].zfill(k//4))
    vector['co1'] = "{}".format(hex(co1)[2:].zfill(k//4))
    vector['co2'] = "{}".format(hex(co2)[2:].zfill(k//4))

    c = commitments.bc_setup_challenge(N)
    vector["c"] = "{}".format(hex(c)[2:].zfill(k//4))

    p0, p1, p2, p3 = commitments.bc_setup_proof(r0, r1, r2, c, alpha, beta, ialpha, ibeta, (P-1)*(Q-1))
    vector['p0'] = "{}".format(hex(p0)[2:].zfill(k//4))
    vector['p1'] = "{}".format(hex(p1)[2:].zfill(k//4))
    vector['p2'] = "{}".format(hex(p2)[2:].zfill(k//4))
    vector['p3'] = "{}".format(hex(p3)[2:].zfill(k//4))

    assert commitments.bc_setup_verify(b0, b1, b2, co0, co1, co2, c, p0, p1, p2, p3, N), "inconsistent test vector"

    return vector

typeKeys = {
    'commit': [
        'TEST', 'b0', 'b1', 'b2', 'N', 'r0', 'r1', 'r2', 'co0','co1','co2'
    ],
    'prove': [
        'TEST', 'r0', 'r1', 'r2', 'c', 'alpha', 'beta', 'ialpha', 'ibeta', 'PHI', 'p0', 'p1', 'p2', 'p3'
    ],
    'verify': [
        'TEST', 'b0', 'b1', 'b2', 'co0', 'co1', 'co2', 'c', 'p0', 'p1', 'p2', 'p3', 'N' 
    ],
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-n', dest='n', type=int, default=10,
        help='number of test vectors')
    parser.add_argument('-k', dest='k', type=int, choices=[1024, 2048, 4096], default=1024,
        help='length in bit of the RSA modulus')
    parser.add_argument('-t', dest='t', type=str, choices=['commit', 'prove', 'verify'], default='commit',
        help='type of test vector to generate')

    args = parser.parse_args()

    nVec = args.n
    k = args.k
    k = 128
    tvType = args.t
    keys = typeKeys[tvType]

    vectors = []


    for i in range(nVec):
        vector = genVector(i,k)
        vector = {k: vector[k] for k in keys}

        vectors.append(vector)

    json.dump(vectors, open("{}.json".format(tvType.upper()), "w"), indent=2)

    with open("{}.txt".format(tvType.upper()), "w") as f:
        for vector in vectors:
            for k in keys:
                f.write("{} = {},\n".format(k.upper(), vector[k]))
            f.write("\n")
