#!/usr/bin/env python3

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from amcl import core_utils, gg20_zkp


seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"

l_hex = "584edf9db99551ff2e0d56218a44fea0943032f7864b8359c213ec36465512c5"
s_hex = "843b282505357e075bd98104f42fe7ea6b41310da7c769b4c402442c1ede922b"

R_hex = "03e03cda61f087f9ba381695dc816a4ca42f38bbfc3fc88ffe897594b94ee7b80b"
T_hex = "02863528287942ab88dec016c2e1993bf9e459ffcbfcc48c25ef68f2ec750e55a8"
S_hex = "02ef03c8ecb7cf65b58d85f368c5fc2725b4e4fe93306f98cf53f8e1531cea2bc4"

ID = "unique_user_identifier".encode('utf-8')
AD = "additional_data".encode('utf-8')

if __name__ == "__main__":
    seed = bytes.fromhex(seed_hex)
    rng = core_utils.create_csprng(seed)

    print("Example GG20 ZKPs for Phase 3/6\n")

    # Phase 3 GG20 ZKP
    s = bytes.fromhex(s_hex)
    l = bytes.fromhex(l_hex)
    V = bytes.fromhex(T_hex)

    print("*** Phase 3 ZKP ***\n")
    print("Parameters")
    print("\ts  = {}".format(s.hex()))
    print("\tl  = {}".format(l.hex()))
    print("\tT  = {}".format(V.hex()))
    print("\tID = {}".format(ID.decode('utf-8')))
    print("\tAD = {}".format(AD.decode('utf-8')))
    print("")

    print("Begin Phase 3 ZK proof\n")

    ## Prover

    # Commitment
    rv, c = gg20_zkp.phase3_commit(rng)

    print("[Alice] Commit")
    print("\tC = {}".format(c))
    print("")

    # Challenge
    e = gg20_zkp.phase3_challenge(V, c,ID, AD = AD)

    print("[Alice] Challenge")
    print("\te = {}".format(e.hex()))
    print("")

    # Proof
    p = gg20_zkp.phase3_prove(rv, e, s, l)

    # Export proof to octets for transmission
    t, u = gg20_zkp.proof_to_octets(p)

    print("[Alice] Proof")
    print("\tt = {}".format(t.hex()))
    print("\tu = {}".format(u.hex()))
    print("")

    # Clean rv memory
    gg20_zkp.rv_kill(rv)

    ## Verifier

    # Import proof from received octets
    p = gg20_zkp.proof_from_octets(t, u)
    print("[Bob  ] Received Proof")
    print("\tt = {}".format(t.hex()))
    print("\tu = {}".format(u.hex()))
    print("")

    # Challenge
    e = gg20_zkp.phase3_challenge(V, c,ID, AD = AD)

    print("[Bob  ] Challenge")
    print("\te = {}".format(e.hex()))
    print("")

    # Verify proof
    rc = gg20_zkp.phase3_verify(V, c, e, p)

    print("[Bob  ] Verification")
    if rc == gg20_zkp.OK:
        print("\tSuccess")
    else:
        print("\tFailure: {}".format(rc))
        sys.exit(1)

    print("")

    # Phase 6 GG20 ZKP
    R = bytes.fromhex(R_hex)
    T = bytes.fromhex(T_hex)
    S = bytes.fromhex(S_hex)

    print("\n*** Phase 6 ZKP ***\n")
    print("Parameters")
    print("\ts  = {}".format(s.hex()))
    print("\tl  = {}".format(l.hex()))
    print("\tR  = {}".format(R.hex()))
    print("\tT  = {}".format(T.hex()))
    print("\tS  = {}".format(S.hex()))
    print("\tID = {}".format(ID.decode('utf-8')))
    print("\tAD = {}".format(AD.decode('utf-8')))
    print("")

    print("Begin Phase 3 ZK proof\n")

    ## Prover

    # Commitment
    rv, c, rc = gg20_zkp.phase6_commit(rng, R)

    if rc != gg20_zkp.OK:
        print("[Alice] Commit Error: {}".format(rc))
        sys.exit(1)

    # Export commitment to octets for transmission
    alpha, beta = gg20_zkp.phase6_commitment_to_octets(c)

    print("[Alice] Commit")
    print("\talpha = {}\n".format(alpha.hex()))
    print("\tbeta  = {}\n".format(beta.hex()))
    print("")

    # Challenge
    e = gg20_zkp.phase6_challenge(R, T, S, c, ID, AD=AD)

    print("[Alice] Challenge")
    print("\te = {}".format(e.hex()))
    print("")

    # Proof
    p = gg20_zkp.phase6_prove(rv, e, s, l)

    # Export proof to octets for transmission
    t, u = gg20_zkp.proof_to_octets(p)

    print("[Alice] Proof")
    print("\tt = {}".format(t.hex()))
    print("\tu = {}".format(u.hex()))
    print("")

    # Clean rv memory
    gg20_zkp.rv_kill(rv)

    ## Verifier

    # Import proof from received octets
    p = gg20_zkp.proof_from_octets(t, u)
    print("[Bob  ] Received Proof")
    print("\tt = {}".format(t.hex()))
    print("\tu = {}".format(u.hex()))
    print("")

    # Import commitment from received octets
    c, rc = gg20_zkp.phase6_commitment_from_octets(alpha, beta)

    if rc != gg20_zkp.OK:
        print("[Bob  ] Error importing Commitment: {}".format(rc))
        sys.exit(1)

    print("[Bob  ] Received Commitment")
    print("\talpha = {}\n".format(alpha.hex()))
    print("\tbeta  = {}\n".format(beta.hex()))
    print("")

    # Challenge
    e = gg20_zkp.phase6_challenge(R, T, S, c,ID, AD = AD)

    print("[Bob  ] Challenge")
    print("\te = {}".format(e.hex()))
    print("")

    # Verification
    rc = gg20_zkp.phase6_verify(R, T, S, c, e, p)

    print("[Bob  ] Verification")
    if rc == gg20_zkp.OK:
        print("\tSuccess")
    else:
        print("\tFailure: {}".format(rc))
        sys.exit(1)
