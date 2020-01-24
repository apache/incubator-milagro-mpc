#!/usr/bin/env python3

import sys
sys.path.append('../')

import json
import argparse

import sec256k1.big as big
import sec256k1.ecp as ecp
import sec256k1.curve as curve
import sec256k1.paillier as paillier
import sec256k1.commitments as commitments
import sec256k1.mta as mta

from Crypto.Util import number

def prettyvalue(value):
    if isinstance(value, int):
        return hex(value)[2:]

    elif isinstance(value, list):
        prettyvalues = []
        for el in value:
            prettyvalues.append(prettyvalue(el))

        return prettyvalues

    else:
        return "{}".format(value)


def dumpgame(alice, bob):
    prettyalice = {}
    prettybob   = {}

    for key in alice.keys():
        prettyalice[key] = prettyvalue(alice[key])

    for key in bob.keys():
        prettybob[key] = prettyvalue(bob[key])

    game = {
        "alice" : prettyalice,
        "bob"   : prettybob
    }

    json.dump(game, open("game.json", "w"), indent=2)


def paillier_setup(player):
    '''
        Setup player Paillier modulus and private key
    '''

    p = number.getStrongPrime(1024)
    q = number.getStrongPrime(1024)

    n, g, lp, lq, mp, mq = paillier.keys(p, q)

    player["paillier_p"]  = p
    player["paillier_q"]  = q
    player["paillier_n"]  = n
    player["paillier_g"]  = g
    player["paillier_lp"] = lp
    player["paillier_mp"] = mp
    player["paillier_lq"] = lq
    player["paillier_mq"] = mq

def zk_setup(player, k):
    '''
        Setup player additional RSA modulus for ZK proofs
    '''

    P, Q, pq, N, alpha, ialpha, b0, b1 = commitments.bc_setup(k)

    player["zk_P"] = P
    player["zk_Q"] = Q
    player["zk_N"] = N
    player["zk_pq"] = pq

    player["zk_alpha"]  = alpha
    player["zk_ialpha"] = ialpha

    player["zk_b0"] = b0
    player["zk_b1"] = b1

def check_zk_setup(prover, verifier, k):
    '''
        ZK proof of correct ZK setup
    '''

    r0, r1, c0, c1 = commitments.bc_setup_commit(
        prover["zk_b0"],
        prover["zk_b1"],
        prover["zk_pq"],
        prover["zk_P"],
        prover["zk_Q"])
    
    prover["zk_r0"]  = r0
    prover["zk_r1"]  = r1
    prover["zk_c0"] = c0
    prover["zk_c1"] = c1

    # This is actually done by both, leaving only verifier for simplicity
    e0, e1 = commitments.bc_setup_challenge(
        prover["zk_b0"],
        prover["zk_b1"],
        prover["zk_c0"],
        prover["zk_c1"],
        k)
    
    verifier["zk_e0"] = e0
    verifier["zk_e1"] = e1
    
    p0, p1 = commitments.bc_setup_proof(
        prover["zk_r0"],
        prover["zk_r1"],
        verifier["zk_e0"], 
        verifier["zk_e1"],
        prover["zk_alpha"],
        prover["zk_ialpha"],
        prover["zk_pq"])

    prover["zk_p0"] = p0
    prover["zk_p1"] = p1

    return commitments.bc_setup_verify(
        prover["zk_b0"],
        prover["zk_b1"],
        prover["zk_c0"],
        prover["zk_c1"],
        verifier["zk_e0"],
        verifier["zk_e1"],
        prover["zk_p0"],
        prover["zk_p1"],
        prover["zk_N"])

if __name__ == "__main__":
    # Toy dimension, 2048 but safe prime generation is slow
    k = 512

    alice = {}
    bob   = {}

    # Setup Paillier private/public keys and additional
    # RSA moduli for the ZK proofs
    print("Paillier Setup")
    paillier_setup(alice)
    paillier_setup(bob)
    print("Done!\n")

    print("ZK Setup")
    zk_setup(alice, k)
    zk_setup(bob, k)

    print("Verify ZK Setup")
    if not check_zk_setup(alice, bob, k):
        dumpgame(alice, bob)
        print("Invalid ZK setup for Alice")
        sys.exit(1)

    if not check_zk_setup(bob, alice, k):
        dumpgame(alice, bob)
        print("Invalid ZK setup for Bob")
        sys.exit(1)

    print("Done!\n")

    # --- MtA(wC) protocol ---
    alice["mta_mult_share"] = big.rand(curve.r)
    bob["mta_mult_share"]   = big.rand(curve.r)

    # -- Step 1 -- same for both MtA and MtAwC
    print("MtA Step 1")
    alice["mta_CA"], alice["mta_r"] = mta.initiate(alice["paillier_n"], alice["paillier_g"], alice["mta_mult_share"])

    # ZK range proof
    print("MtA Range Proof")
    alpha, beta, gamma, rho, z, u, w = mta.rp_commit(
        alice["mta_mult_share"],
        alice["paillier_g"],
        alice["zk_b0"], alice["zk_b1"],
        curve.r, alice["paillier_n"], alice["zk_N"])

    alice["mta_rp_alpha"] = alpha
    alice["mta_rp_beta"]  = beta
    alice["mta_rp_gamma"] = gamma
    alice["mta_rp_rho"]   = rho

    alice["mta_rp_z"] = z
    alice["mta_rp_u"] = u
    alice["mta_rp_w"] = w

    bob["mta_rp_e"] = mta.rp_challenge(curve.r)

    s, s1, s2 = mta.rp_prove(
        alice["mta_mult_share"], alice["mta_r"], alice["mta_CA"],
        bob["mta_rp_e"],
        alice["mta_rp_alpha"], alice["mta_rp_beta"], alice["mta_rp_gamma"], alice["mta_rp_rho"],
        alice["paillier_n"])

    alice["mta_rp_s"]  = s
    alice["mta_rp_s1"] = s1
    alice["mta_rp_s2"] = s2

    if not mta.rp_verify(
        alice["mta_CA"],
        alice["mta_rp_s"], alice["mta_rp_s1"], alice["mta_rp_s2"],
        alice["mta_rp_z"], alice["mta_rp_u"],  alice["mta_rp_w"],
        bob["mta_rp_e"],
        alice["paillier_g"],
        alice["zk_b0"], alice["zk_b1"],
        curve.r, alice["paillier_n"], alice["zk_N"]):
        
        dumpgame(alice, bob)
        print("Range Rroof Failed")
        sys.exit(1)

    print("Done!\n")

    # -- Step 2 -- version for MtA
    print("MtA Step 2")

    bob["mta_CB"],bob["mta_add_share"], bob["mta_beta1"], bob["mta_r"] = mta.receive(
        alice["paillier_n"], alice["paillier_g"], curve.r,
        bob["mta_mult_share"], alice["mta_CA"])

    # ZK range proof for receiver
    print("MtA Receiver Range Proof")

    alpha, beta, gamma, rho, rho1, sigma, tau, z, z1, t, v, w = mta.mta_commit(
        bob["mta_mult_share"], bob["mta_beta1"], alice["mta_CA"],
        alice["paillier_g"],
        alice["zk_b0"], alice["zk_b1"],
        curve.r, alice["paillier_n"], alice["zk_N"])

    bob["mta_rrp_alpha"] = alpha
    bob["mta_rrp_beta"]  = beta
    bob["mta_rrp_gamma"] = gamma
    bob["mta_rrp_rho"]   = rho
    bob["mta_rrp_rho1"]  = rho1
    bob["mta_rrp_sigma"] = sigma
    bob["mta_rrp_tau"]   = tau

    bob["mta_rrp_z"]  = z
    bob["mta_rrp_z1"] = z1
    bob["mta_rrp_t"]  = t
    bob["mta_rrp_v"]  = v
    bob["mta_rrp_w"]  = w

    alice["mta_rrp_e"] = mta.mta_challenge(curve.r)

    s, s1, s2, t1, t2 = mta.mta_prove(
        bob["mta_mult_share"], bob["mta_beta1"], bob["mta_r"],
        alice["mta_rrp_e"],
        bob["mta_rrp_alpha"], bob["mta_rrp_beta"], bob["mta_rrp_gamma"], bob["mta_rrp_rho"],
        bob["mta_rrp_rho1"], bob["mta_rrp_sigma"], bob["mta_rrp_tau"],
        alice["paillier_n"])

    bob["mta_rrp_s"]  = s
    bob["mta_rrp_s1"] = s1
    bob["mta_rrp_s2"] = s2
    bob["mta_rrp_t1"] = t1
    bob["mta_rrp_t2"] = t2

    if not mta.mta_verify(
        alice["mta_CA"], bob["mta_CB"],
        bob["mta_rrp_s"], bob["mta_rrp_s1"], bob["mta_rrp_s2"], bob["mta_rrp_t1"], bob["mta_rrp_t2"],
        bob["mta_rrp_z"], bob["mta_rrp_z1"], bob["mta_rrp_t"],  bob["mta_rrp_v"],  bob["mta_rrp_w"],
        alice["mta_rrp_e"],
        alice["paillier_g"],
        alice["zk_b0"], alice["zk_b1"],
        curve.r, alice["paillier_n"], alice["zk_N"]):

        dumpgame(alice, bob)
        print("Receiver Range Proof Failed")
        sys.exit(1)

    print("Done!\n")

    # -- Step 3 -- version for MtA [same to step three for MtAwC]
    print("MtA Step 3")

    alice["mta_add_share"] = mta.complete(
        alice["paillier_p"],
        alice["paillier_q"],
        alice["paillier_lp"],
        alice["paillier_mp"],
        alice["paillier_lq"],
        alice["paillier_mq"],
        curve.r,
        bob["mta_CB"])

    mta_mult = big.modmul(alice["mta_mult_share"], bob["mta_mult_share"], curve.r)
    mta_add  = big.modadd(alice["mta_add_share"],  bob["mta_add_share"],  curve.r)

    if mta_mult != mta_add:
        dumpgame(alice, bob)
        print("MtA Failed")
        sys.exit(1)        

    print("Done!\n")

    # -- Step 2 -- version for MtawC
    print("MtAwC Step 2")

    bob["mtawc_CB"],bob["mtawc_add_share"], bob["mtawc_beta1"], bob["mtawc_r"] = mta.receive(
        alice["paillier_n"], alice["paillier_g"], curve.r,
        bob["mta_mult_share"], alice["mta_CA"])

    bob["mtawc_X"] = bob["mta_mult_share"] * ecp.generator()

    # ZK range proof for receiver
    print("MtAwC Receiver Range Proof")

    alpha, beta, gamma, rho, rho1, sigma, tau, u, z, z1, t, v, w = mta.mtawc_commit(
        bob["mta_mult_share"], bob["mtawc_beta1"], alice["mta_CA"],
        alice["paillier_g"],
        alice["zk_b0"], alice["zk_b1"],
        curve.r, alice["paillier_n"], alice["zk_N"])

    bob["mtawc_rrp_alpha"] = alpha
    bob["mtawc_rrp_beta"]  = beta
    bob["mtawc_rrp_gamma"] = gamma
    bob["mtawc_rrp_rho"]   = rho
    bob["mtawc_rrp_rho1"]  = rho1
    bob["mtawc_rrp_sigma"] = sigma
    bob["mtawc_rrp_tau"]   = tau

    bob["mtawc_rrp_u"]  = u
    bob["mtawc_rrp_z"]  = z
    bob["mtawc_rrp_z1"] = z1
    bob["mtawc_rrp_t"]  = t
    bob["mtawc_rrp_v"]  = v
    bob["mtawc_rrp_w"]  = w

    alice["mtawc_rrp_e"] = mta.mtawc_challenge(curve.r)

    s, s1, s2, t1, t2 = mta.mtawc_prove(
        bob["mta_mult_share"], bob["mtawc_beta1"], bob["mtawc_r"],
        alice["mtawc_rrp_e"],
        bob["mtawc_rrp_alpha"], bob["mtawc_rrp_beta"], bob["mtawc_rrp_gamma"], bob["mtawc_rrp_rho"],
        bob["mtawc_rrp_rho1"], bob["mtawc_rrp_sigma"], bob["mtawc_rrp_tau"],
        alice["paillier_n"])

    bob["mtawc_rrp_s"]  = s
    bob["mtawc_rrp_s1"] = s1
    bob["mtawc_rrp_s2"] = s2
    bob["mtawc_rrp_t1"] = t1
    bob["mtawc_rrp_t2"] = t2

    if not mta.mtawc_verify(
        alice["mta_CA"], bob["mtawc_CB"], bob["mtawc_X"],
        bob["mtawc_rrp_s"], bob["mtawc_rrp_s1"], bob["mtawc_rrp_s2"], bob["mtawc_rrp_t1"], bob["mtawc_rrp_t2"],
        bob["mtawc_rrp_u"], bob["mtawc_rrp_z"],  bob["mtawc_rrp_z1"], bob["mtawc_rrp_t"],  bob["mtawc_rrp_v"],  bob["mtawc_rrp_w"],
        alice["mtawc_rrp_e"],
        alice["paillier_g"],
        alice["zk_b0"], alice["zk_b1"],
        curve.r, alice["paillier_n"], alice["zk_N"]):

        dumpgame(alice, bob)
        print("Receiver Range Proof Failed")
        sys.exit(1)

    print("Done!\n")

    # -- Step 3 -- version for MtAwC [same to step three for MtA]
    print("MtAwC Step 3")

    alice["mtawc_add_share"] = mta.complete(
        alice["paillier_p"],
        alice["paillier_q"],
        alice["paillier_lp"],
        alice["paillier_mp"],
        alice["paillier_lq"],
        alice["paillier_mq"],
        curve.r,
        bob["mtawc_CB"])

    mtawc_mult = big.modmul(alice["mta_mult_share"], bob["mta_mult_share"], curve.r)
    mtawc_add  = big.modadd(alice["mtawc_add_share"],  bob["mtawc_add_share"],  curve.r)

    if mtawc_mult != mtawc_add:
        dumpgame(alice, bob)
        print("MtA Failed")
        sys.exit(1)    

    print("Done!\n")

    dumpgame(alice, bob)
    print("Success!")
