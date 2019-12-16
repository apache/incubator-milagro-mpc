#!/usr/bin/env python3

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

    P, Q, N, alpha, beta, ialpha, ibeta, b0, b1, b2 = commitments.bc_setup(k)
    print("P =     {}".format(hex(P)[2:].zfill(k//8)))
    print("Q =     {}".format(hex(Q)[2:].zfill(k//8)))
    print("N =     {}".format(hex(N)[2:].zfill(k//4)))
    print("alpha = {}".format(hex(alpha)[2:].zfill(k//4)))
    print("beta  = {}".format(hex(beta)[2:].zfill(k//4)))
    print("ialpha = {}".format(hex(ialpha)[2:].zfill(k//4)))
    print("ibeta  = {}".format(hex(ibeta)[2:].zfill(k//4)))
    print("b0 =    {}".format(hex(b0)[2:].zfill(k//4)))
    print("b1 =    {}".format(hex(b1)[2:].zfill(k//4)))
    print("b2 =    {}".format(hex(b2)[2:].zfill(k//4)))
    print("")

    print("Prove in ZK that b0, b1, b2 are of the same order\n")

    r0, r1, r2, co0, co1, co2, = commitments.bc_setup_commit(b0, b1, b2, N)
    print("[Prover]   Commit to values b0, b1, b2")
    print("\tr0:  {}".format(hex(r0)[2:].zfill(k//4)))
    print("\tr1:  {}".format(hex(r1)[2:].zfill(k//4)))
    print("\tr2:  {}".format(hex(r2)[2:].zfill(k//4)))
    print("\tco0: {}".format(hex(co0)[2:].zfill(k//4)))
    print("\tco1: {}".format(hex(co1)[2:].zfill(k//4)))
    print("\tco2: {}".format(hex(co2)[2:].zfill(k//4)))
    print("")

    c = commitments.bc_setup_challenge(N)
    print("[Verifier] Issue challenge for the prover")
    print("\tc: {}".format(hex(c)[2:].zfill(k//4)))
    print("")

    p0, p1, p2, p3 = commitments.bc_setup_proof(r0, r1, r2, c, alpha, beta, ialpha, ibeta, (P-1)*(Q-1))
    print("[Prover]   Prove that b1 = b0^alpha, b0 = b1^ialpha and same for b2 and beta")
    print("\tp0: {}".format(hex(p0)[2:].zfill(k//4)))
    print("\tp1: {}".format(hex(p1)[2:].zfill(k//4)))
    print("\tp2: {}".format(hex(p2)[2:].zfill(k//4)))
    print("\tp3: {}".format(hex(p3)[2:].zfill(k//4)))
    print("")

    ok = commitments.bc_setup_verify(b0, b1, b2, co0, co1, co2, c, p0, p1, p2, p3, N)
    print("[Verifier] Verify proofs")

    if ok:
        print("\tOK")
    else:
        print("\tInvalid ZK proofs")
