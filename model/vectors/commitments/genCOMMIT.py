#! /usr/bin/env python3

import sys
sys.path.append('../../')

import json
import argparse

from sec256k1 import big, commitments

DETERMINISTIC = False

def genVector(test_no, length):
    """Generate a single test vector

        Use parameters to generate a single test vector

        Args::

            test_no : Test vector identifier
            length  : Length in bytes of the value to commit

        Returns::

            vector: A test vector
    """

    x = big.rand(1<<(8*length))
    r, C = commitments.commit(x, length)

    assert commitments.decommit(C, r, x, length)

    vector = {
        "TEST" : test_no,
        "X"    : "{}".format(hex(x)[2:].zfill(2 * length)),
        "R"    : "{}".format(hex(r)[2:].zfill(commitments.l//4)),
        "C"    : C.hex()
    }

    return vector

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-n', dest='n', type=int, default=10,
        help='number of test vectors')

    args = parser.parse_args()
    nVec = args.n

    # The test vectors are the same for the commitment and the decommitment
    vectors = [genVector(i, 8+i) for i in range(nVec)]

    json.dump(vectors, open("commitments.json", "w"), indent=2)

    with open("commitments.txt", "w") as f:
        for vector in vectors:
            for k, v in vector.items():
                f.write("{} = {},\n".format(k, v))
            f.write("\n")
