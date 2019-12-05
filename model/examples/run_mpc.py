#!/usr/bin/env python3

import sys
sys.path.append('../')

import json
import argparse

import math
import sec256k1.curve as curve
import sec256k1.ecdh as ecdh
import sec256k1.ecp as ecp
import sec256k1.big as big
import sec256k1.shamir as shamir
import sec256k1.paillier as paillier
import sec256k1.mta as mta
import sec256k1.mpc as mpc

from Crypto.Util import number

import hashlib

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

def dumpgame(players, m,r,s):
    prettyplayers = []

    for player in players:
        prettyplayer = {}

        for key in player.keys():
            prettyplayer[key] = prettyvalue(player[key])

        prettyplayers.append(prettyplayer)

    game = {
        "players": prettyplayers,
        "message": m.decode('utf-8'),
        "signature": [hex(r)[2:].zfill(64),hex(s)[2:].zfill(64)],
    }

    json.dump(game, open("game.json", "w"), indent=2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-n', dest='n', type=int, help='n value for the (t,n) MPC', default=2)
    parser.add_argument('-t', dest='t', type=int, help='t value for the (t,n) MPC', default=2)

    args = parser.parse_args()

    nPlayers = args.n
    t = args.t

    print("MPC players = {}, threshold = {}".format(nPlayers,t))

    # Players set
    all_players = [{} for i in range(nPlayers)]

    ### Key Setup

    ## Setup Paillier keys for participants
    for player in all_players:
        p = number.getStrongPrime(1024)
        q = number.getStrongPrime(1024)

        n,g,l,m = paillier.keys(p,q)

        player["n"] = n
        player["g"] = g
        player["l"] = l
        player["m"] = m

    ## Setup ECDSA secrets and public keys
    for player in all_players:
        player["w_shares"] = [(0,0) for i in range(nPlayers)]
        player["w_checks"] = [[] for i in range(nPlayers)]

    for i, player in enumerate(all_players):
        u = big.rand(curve.r)

        # VSS of u
        u, shares, checks = shamir.make_shares(t,nPlayers, check=True, secret=u)

        # Transmit shares and checks to all other players.
        #
        # Remark. Player i MUST get all and only shares i
        for j, recipient in enumerate(all_players):
            recipient["w_shares"][i] = shares[j]
            recipient["w_checks"][i] = checks

    # Each player checks the consistency of all its shares and adds them
    for i, player in enumerate(all_players):
        for j in range(nPlayers):
            ok = shamir.verify_share(player["w_checks"][j], player["w_shares"][j])

            (x,_) = player["w_shares"][j]

            assert x == i+1, "share {} is for the wrong player {} (want {})".format(j,x,i+1)
            assert ok, "inconsistent share {} for player {}".format(j,i)

        (_, y_shares) = zip(*player["w_shares"])
        player["w_shamir"] = mpc.combine_fp_shares(y_shares)

    # The Public key is the sum of the free terms in the exponent
    #
    # Computed for player_0, same for everyone else
    pk_shares = [checks[0] for checks in all_players[0]["w_checks"]]

    PK = mpc.combine_ecp_shares(pk_shares)

    ### Signature

    M = b'BANANA'

    ## Choose the t players coming together for signature.
    #
    # First t for simplicity. TODO randomize
    players = all_players[:t]

    ## Convert the players (t,n) Shamir shares to (t,t) additive shares
    x_s = []
    for player in players:
        (x,_) =player["w_shares"][0]
        x_s.append(x)

    for i, player in enumerate(players):
        player["w"] = shamir.convert_to_additive_share(x_s, i, player["w_shamir"])

    ## Generate random gamma_i, k_i
    for player in players:
        k,g,G = mpc.initiate()

        player["gamma"] = g
        player["Gamma"] = G
        player["k"] = k

    ## Run MtA instances for kgamma
    for player in players:
        player["alpha"] = [0 for i in range(t)]
        player["beta"] = [0 for i in range(t)]

    for i, player_i in enumerate(players):
        ci = mta.initiate(player_i["n"], player_i["g"], player_i["k"])

        for j, player_j in enumerate(players):
            if i == j:
                continue

            beta, cj = mta.receive(player_i["n"], player_i["g"], curve.r, player_j["gamma"], ci)

            alpha = mta.complete(player_i["n"], player_i["l"], player_i["m"], curve.r, cj)

            player_i["alpha"][j] = alpha
            player_j["beta"][i] = beta

    # Combine additive shares
    for i, player in enumerate(players):
        shares = player["alpha"] + player["beta"]
        player["delta"] = mpc.combine_fp_shares(shares, initial_value=player["k"] * player["gamma"])

    ## Run MtA instances for kw
    for player in players:
        player["mu"] = [0 for i in range(t)]
        player["nu"] = [0 for i in range(t)]

    for i, player_i in enumerate(players):
        ci = mta.initiate(player_i["n"], player_i["g"], player_i["k"])

        for j, player_j in enumerate(players):
            if i == j:
                continue

            nu, cj = mta.receive(player_i["n"], player_i["g"], curve.r, player_j["w"], ci)

            mu = mta.complete(player_i["n"], player_i["l"], player_i["m"], curve.r, cj)

            player_i["mu"][j] = mu
            player_j["nu"][i] = nu

    # Combine additive shares
    for i, player in enumerate(players):
        shares = player["mu"] + player["nu"]
        player["sigma"] = mpc.combine_fp_shares(shares, initial_value=player["k"] * player["w"])

    ## Broadcast Gamma_i, delta_i and reconstruct R, r [seoarately for each player]
    deltas = [player["delta"] for player in players]
    Gammas = [player["Gamma"] for player in players]

    r, R = mpc.reconciliate_r(deltas, Gammas)

    ## Compute signature shares
    for player in players:
        player["s"] = mpc.make_signature_share(M,player["k"],r,player["sigma"])

    ## Prove knowledge of the correct s_i
    for player in players:
        phi = big.rand(curve.r)
        rho = big.rand(curve.r)

        player["phi"] = phi
        player["rho"] = rho
        player["V"] = (player["s"] * R).add(phi * ecp.generator())
        player["A"] = rho * ecp.generator()

    # Broadcast V and A and combine them [separately for each player]
    Vs = [player["V"] for player in players]
    As = [player["A"] for player in players]

    A = mpc.combine_ecp_shares(As)
    V = mpc.combine_ecp_shares(Vs)

    # Remove (the supposed) R^s from the exponent of V [separately for each player]
    m = mpc.hashit(M)
    negm = big.modsub(curve.r,m,curve.r)

    negr = big.modsub(curve.r,r,curve.r)

    V.add(negm * ecp.generator())
    V.add(negr * PK)

    # Produce proof for the agreed V and A
    for player in players:
        player["U"] = player["rho"] * V
        player["T"] = player["phi"] * A

    # Broadcast T and U and combine them to complete the proof [separately for each player]
    Us = [player["U"] for player in players]
    Ts = [player["T"] for player in players]

    U = mpc.combine_ecp_shares(Us)
    T = mpc.combine_ecp_shares(Ts)

    assert U == T, "inconsistency detected in signature shares"

    ## Broadcast shares and reconstruct s [separately for each player]
    shares = [player["s"] for player in players]
    s = mpc.combine_fp_shares(shares)

    # Choose the smallest of -s,s mod curve.r
    sneg = curve.r - s
    if sneg < s:
        s = sneg

    # Dump game for inspection
    dumpgame(all_players, M,r,s)

    # Verify signature
    P = PK.toBytes(compress=True)
    C = big.to_bytes(r)
    D = big.to_bytes(s)

    assert ecdh.ECP_SvDSA(P,M,C,D), "invalid signature"

    print("Done!")