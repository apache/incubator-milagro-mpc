#! /usr/bin/env python3

import sys
sys.path.append('../')

import argparse

import sec256k1.big as big
import sec256k1.schnorr as schnorr
import sec256k1.commitments as commitments

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-k', dest='k', type=int, default=2048,
        help='length in bits of the RSA modulus to generate.')

    args = parser.parse_args()

    k = args.k

    print("Generate RSA modulus and generators\n")

    P, Q, pq, N, alpha, ialpha, b0, b1 = commitments.bc_setup(k)
    print("\tP      = {}".format(hex(P)[2:].zfill(k//8)))
    print("\tQ      = {}".format(hex(Q)[2:].zfill(k//8)))
    print("\tN      = {}".format(hex(N)[2:].zfill(k//4)))
    print("\talpha  = {}".format(hex(alpha)[2:].zfill(k//4)))
    print("\tialpha = {}".format(hex(ialpha)[2:].zfill(k//4)))
    print("\tb0     = {}".format(hex(b0)[2:].zfill(k//4)))
    print("\tb1     = {}".format(hex(b1)[2:].zfill(k//4)))
    print("")

    print("Prove in ZK that b0, b1 are of the same order\n")

    r0, r1, c0, c1 = commitments.bc_setup_commit(b0, b1, pq, P, Q)
    print("[Prover]   Commit to values b0, b1")
    print("\tr0 = {}".format(hex(r0)[2:].zfill(k//4)))
    print("\tr1 = {}".format(hex(r1)[2:].zfill(k//4)))
    print("\tc0 = {}".format(hex(c0)[2:].zfill(k//4)))
    print("\tc1 = {}".format(hex(c1)[2:].zfill(k//4)))
    print("")

    e0, e1 = commitments.bc_setup_challenge(b0, b1, c0, c1, k)
    print("[Verifier] Issue challenge for the prover")
    print("\te0 = {}".format(hex(e0)[2:].zfill(64)))
    print("\te1 = {}".format(hex(e1)[2:].zfill(64)))
    print("")

    p0, p1 = commitments.bc_setup_proof(r0, r1, e0, e1, alpha, ialpha, pq)
    print("[Prover]   Prove that b1 = b0^alpha, b0 = b1^ialpha")
    print("\tp0 = {}".format(hex(p0)[2:].zfill(k//4)))
    print("\tp1 = {}".format(hex(p1)[2:].zfill(k//4)))
    print("")

    ok = commitments.bc_setup_verify(b0, b1, c0, c1, e0, e1, p0, p1, N)
    print("[Verifier] Verify proofs")

    if ok:
        print("\tOK")
    else:
        print("\tInvalid ZK proofs")
