#!/usr/bin/env python3

import os
import sys
from bench import time_func

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

    # Generate quantities for Phase 3 Benchmark
    s = bytes.fromhex(s_hex)
    l = bytes.fromhex(l_hex)
    V = bytes.fromhex(T_hex)

    rv, c = gg20_zkp.phase3_commit(rng)
    e = gg20_zkp.phase3_challenge(V, c,ID, AD = AD)
    p = gg20_zkp.phase3_prove(rv, e, s, l)
    rc = gg20_zkp.phase3_verify(V, c, e, p)

    assert rc == gg20_zkp.OK, "Error Setting up Phase 3 ZKP"

    # Run Phase 3 ZKP Benchmark
    print(" *** Phase 3 ZKP ***")

    fncall = lambda: gg20_zkp.phase3_commit(rng, rv=rv)
    time_func("phase3_commit   ", fncall)

    fncall = lambda: gg20_zkp.phase3_challenge(V, c,ID, AD = AD)
    time_func("phase3_challenge", fncall)

    fncall = lambda: gg20_zkp.phase3_prove(rv, e, s, l)
    time_func("phase3_prove    ", fncall)

    fncall = lambda: gg20_zkp.phase3_verify(V, c, e, p)
    time_func("phase3_verify   ", fncall)

    print("")

    #  Generate quantities for Phase 6 benchmark
    R = bytes.fromhex(R_hex)
    T = bytes.fromhex(T_hex)
    S = bytes.fromhex(S_hex)

    rv, c, rc = gg20_zkp.phase6_commit(rng, R)

    assert rc == gg20_zkp.OK, "Error setting up Phase 6 Commit"

    e = gg20_zkp.phase6_challenge(R, T, S, c, ID, AD=AD)
    p = gg20_zkp.phase6_prove(rv, e, s, l)
    rc = gg20_zkp.phase6_verify(R, T, S, c, e, p)

    assert rc == gg20_zkp.OK, "Error Setting up Phase 6 ZKP"

    # Run Phase 6 ZKP Benchmark
    print(" *** Phase 6 ZKP ***")

    fncall = lambda: gg20_zkp.phase6_commit(rng, R, rv=rv)
    time_func("phase6_commit   ", fncall)

    fncall = lambda: gg20_zkp.phase6_challenge(R, T, S, c, ID, AD = AD)
    time_func("phase6_challenge", fncall)

    fncall = lambda: gg20_zkp.phase6_prove(rv, e, s, l)
    time_func("phase6_prove    ", fncall)

    fncall = lambda: gg20_zkp.phase6_verify(R, T, S, c, e, p)
    time_func("phase6_verify   ", fncall)

    # Generate quantities for additional benchmakrs
    t, u = gg20_zkp.proof_to_octets(p)

    alpha, beta = gg20_zkp.phase6_commitment_to_octets(c)
    c, rc = gg20_zkp.phase6_commitment_from_octets(alpha, beta)
    assert rc == gg20_zkp.OK, "Error setting up octets"

    gg20_zkp.rv_kill(rv)

    # Run Additional Benchmark
    print(" *** Additional functions ***")

    fncall = lambda: gg20_zkp.proof_to_octets(p)
    time_func("proof_to_octets              ", fncall)

    fncall = lambda: gg20_zkp.proof_from_octets(t, u)
    time_func("proof_from_octets            ", fncall)

    fncall = lambda: gg20_zkp.phase6_commitment_to_octets(c)
    time_func("phase6_commitment_to_octets  ", fncall)

    fncall = lambda: gg20_zkp.phase6_commitment_from_octets(alpha, beta)
    time_func("phase6_commitment_from_octets", fncall)

    fncall = lambda: gg20_zkp.rv_kill(rv)
    time_func("rv_kill                      ", fncall)
