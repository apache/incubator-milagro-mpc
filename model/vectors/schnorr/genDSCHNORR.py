#!/usr/bin/env python3

"""
    Generates a set of test vectors for the double schnorr zk proof.

    usage: genDSCHNORR.py --type prove 10
"""

import sys
sys.path.append("../../")

import json
import argparse
from genVector import genDoubleSchnorrVector

from Crypto.Util import number

vector_fields = {
    "commit" : ["TEST","R","A","B","CO"],
    "prove"  : ["TEST","A","B","CH","S","L","T","U"],
    "verify" : ["TEST","R","V","CO","CH","T","U"],
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('--type', dest='type', type=str, default='commit', help='test vector type', choices=["commit", "prove", "verify"])
    parser.add_argument('nVec', type=int, help='number of test vectors to generate')

    args = parser.parse_args()

    print ("Generate {} vector(s). Type '{}'".format(args.nVec, args.type))

    vectors = []

    for i in range(args.nVec):
        vector = genDoubleSchnorrVector(i)

        vector = {k: vector[k] for k in vector_fields[args.type]}
        vectors.append(vector)

    json.dump(vectors, open("{}.json".format(args.type), "w"), indent = 2)

    with open("{}.txt".format(args.type), "w") as f:
        for vector in vectors:
            for field in vector_fields[args.type]:
                f.write("{} = {},\n".format(field, vector[field]))
            f.write("\n")
