#!/usr/bin/env python3

import sys
sys.path.append('../')

import sec256k1.big as big
import sec256k1.ecp as ecp
import sec256k1.curve as curve
import sec256k1.schnorr as schnorr

DETERMINISTIC = True

if __name__ == "__main__":
    # Single DLOG knowledge proof

    # Generate DLOG
    if DETERMINISTIC:
        x = 0x4fae328973e89cc97691d799eaf8022f94afa4886cfad2090ece42094c7dc7b7
    else:
        x = big.rand(curve.r)

    V = x * ecp.generator()

    print("Single DLOG knowledge ZK proof")
    print("x {}".format(hex(x).zfill(64)))
    print("V {}\n".format(V))

    # ZK proof
    print("Begin ZK proof\n")

    # Commitment
    r = None
    if DETERMINISTIC:
        r = 0x2286bee96c840d9b51ff2c47c048841756a5e7f5a019792190a3cb89c09728b3

    # C is the commitment, r is kept secret
    r, C = schnorr.commit(r)

    print("[Alice] Commit\n\tr {}\n\tC {}\n".format(hex(r)[2:].zfill(64), C))

    # Challenge
    if DETERMINISTIC:
        c = 0x5b6422696ac19b95727e95c3567450a9e65f2a43a5219712ad7b41a7382ca2b4
    else:
        c = schnorr.challenge()

    print("[Bob] Challenge {}\n".format(hex(c)[2:].zfill(64)))

    # Proof
    p = schnorr.prove(r, c, x)

    print("[Alice] Prove {}\n".format(hex(p)[2:].zfill(64)))

    # Verification
    ok = schnorr.verify(V, C, c, p)

    print("[Bob] Verify: {}\n".format(ok))

    # Double DLOG knowledge proof

    # Generate double DLOG
    #
    # R is a public point on the curve

    if DETERMINISTIC:
        r = 0x407032a334c1aff361b82c927bbeda429fa7659f186297d3e6b8c46d0d41752b
    else:
        r = big.rand(curve.r)

    R = r * ecp.generator()

    if DETERMINISTIC:
        s = 0x1cbf1c1ea9da2b382f523fe9e4546fe8e128edf77c2e8c0d8147a69fc7d7c1df
        l = 0x60e7fe5284c9ba6211c11cffa7aefdfa2e700c1107d5370dbca1d0e2ac39ba22
    else:
        s = big.rand(curve.r)
        l = big.rand(curve.r)

    V = ecp.ECp.mul(R, s, ecp.generator(), l)

    print("\nDouble DLOG knowledge ZK proof")
    print("r {}".format(hex(r)[2:].zfill(64)))
    print("s {}".format(hex(s)[2:].zfill(64)))
    print("l {}".format(hex(l)[2:].zfill(64)))
    print("R = r.G {}".format(R))
    print("V {}\n".format(V))

    # ZK proof

    # Commitment
    #     a = None
    b = None
    if DETERMINISTIC:
        a = 0x5d8eafb375a68220fb18e308a9a1444be79db9d45e5cf0e75813f51d4c22eb25
        b = 0x346d1ebf943a83323ad9fede6721b5dcc8352d8fc4ec170a7bc70def4a872bff

    # C is the commitment, a and b are kept secret
    a, b, C = schnorr.d_commit(R, a, b)

    print("[Alice] Commit")
    print("\ta {}".format(hex(a)[2:].zfill(64)))
    print("\tb {}".format(hex(b)[2:].zfill(64)))
    print("\tC {}\n".format(C))

    # Challenge
    if DETERMINISTIC:
        c = 0x52fad3d74fd4589f5792dd045626e23dd596b6e4c24c5af6dbb15cfa3c71b55a
    else:
        c = schnorr.d_challenge()

    print("[Bob] Challenge {}\n".format(hex(c)[2:].zfill(64)))

    # Proof
    t, u = schnorr.d_prove(a, b, c, s, l)

    print("[Alice] Prove\n\tt {}\n\tu {}\n".format(
        hex(t)[2:].zfill(64), hex(u)[2:].zfill(64)))

    # Verification
    ok = schnorr.d_verify(R, V, C, c, t, u)

    print("[Bob] Verify: {}".format(ok))
