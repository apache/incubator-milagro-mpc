#!/usr/bin/env python3

"""
    Generates a set of test vectors for the schnorr zk proof.

    usage: genSCHNORR.py --type prove 10
"""

import sys
sys.path.append("../../")

import json
import argparse
from genVector import genVector

from Crypto.Util import number

vector_fields = {
    "make_shares"    : ["TEST","T","N", "SECRET", "X", "Y"],
    "i_coefficients" : ["TEST","T","N","X","I_COEFFS"],
    "recover"        : ["TEST","T","N", "SECRET","X", "Y", "I_COEFFS","P_COEFFS"],
}

def make_params(nVec):
    params = [(2,2)]
    t = 2
    n = 2

    for _ in range(nVec):
        if t == n:
            n = n+1
            t = 2
        else:
            t = t+1

        params.append((t,n))

    return params

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('--type', dest='type', type=str, default='make_shares', help='test vector type', choices=["make_shares", "i_coefficients", "recover"])
    parser.add_argument('--check', action='store_true', help='generate VSS checks')
    parser.add_argument('nVec', type=int, help='number of test vectors to generate')

    args = parser.parse_args()

    print ("Generate {} vector(s). Type '{}', with checks: {}".format(args.nVec, args.type, args.check))

    if args.check:
        vector_fields["make_shares"].append("CHECKS")

    vectors = []

    params = make_params(args.nVec)

    for i in range(args.nVec):
        t,n, = params[i]

        vector = genVector(i,t,n, check=args.check)

        vector = {k: vector[k] for k in vector_fields[args.type]}
        vectors.append(vector)

    json.dump(vectors, open("{}.json".format(args.type), "w"), indent = 2)

    with open("{}.txt".format(args.type), "w") as f:
        for vector in vectors:
            for field in vector_fields[args.type]:
                f.write("{} = {},\n".format(field, vector[field]))
            f.write("\n")
