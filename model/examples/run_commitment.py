#! /usr/bin/env python3

import sys
sys.path.append('../')

from sec256k1 import big, commitments

DETERMINISTIC = False

if __name__ == "__main__":
    r = None
    if DETERMINISTIC:
        r = 0x03

    if DETERMINISTIC:
        xlen = 3
        x    = 0xC0FFEE
    else:
        xlen = 16
        x    = big.rand(1<<(8*xlen))

    print("Commitment scheme")
    print("\tx = {}".format(hex(x)[2:].zfill(32)))
    print("")

    r, C = commitments.commit(x, xlen, r)

    print("Commit to value x")
    print("\tCommitment value  : C = {}".format(C.hex()))
    print("\tDecommitment value: r = {}".format(hex(r)[2:].zfill(commitments.l//4)))
    print("")

    print("Decommit value")

    if commitments.decommit(C, r, x, xlen):
        print("\tSuccess!")
    else:
        print("\tFail!")
