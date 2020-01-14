#!/usr/bin/env python3

import sys
sys.path.append('../')

import json
from Crypto.Util import number

from sec256k1.mpc_v2 import Player
import sec256k1.mpc_v2 as mpc
import sec256k1.curve as curve
import sec256k1.big as big
import sec256k1.ecp as ecp
import sec256k1.ecdh as ecdh

DETERMINISTIC = True

if __name__ == "__main__":

    if DETERMINISTIC:
        p1 = 0x94f689d07ba20cf7c7ca7ccbed22ae6b40c426db74eaee4ce0ced2b6f52a5e136663f5f1ef379cdbb0c4fdd6e4074d6cff21082d4803d43d89e42fd8dfa82b135aa31a8844ffea25f255f956cbc1b9d8631d01baf1010d028a190b94ce40f3b72897e8196df19edf1ff62e6556f2701d52cef1442e3301db7608ecbdcca703db
        q1 = 0x9a9ad73f246df853e129c589925fdad9df05606a61081e62e72be4fb33f6e5ec492cc734f28bfb71fbe2ba9a11e4c02e2c0d103a5cbb0a9d6402c07de63b1b995dd72ac8f29825d66923a088b421fb4d52b0b855d2f5dde2be9b0ca0cee6f7a94e5566735fe6cff1fcad3199602f88528d19aa8d0263adff8f5053c38254a2a3
        sk1 = "248ea4e0ce968bdd1febd48e2d246f7268070eb468eca0c1e911cc1642bd8041"
        k1 = 0x52b7fe8435a2532b79ee252e5444c6a7178757f29a7ff17176ed9098ad168883
        gamma1 = 0xf757744e20d00dce6763b71ecb95f9fa9d4e788cfb9e39775d133e5e350ea93

        p2 = 0xc227a6d88ef469ceb323bcd95a18ab41d9cde9b349c093e7273e7d05f1636c517a21890f22785d45aeeb892da40a69267d3e2f1bd7e0f164cb23306402122512ed70d1cbb20c470d0c03a54adc47abfcc9eadff2ba175bb29aea70464f31f7804a8fc9c9fed60c505e11c594c9415fc96e1b44a3e5f437772bbce91e063827bf
        q2 = 0xe729b4e468f6076ad00dc9af0b820158be147727f4ead55b4d6268647d53c8f65e92338af9b24b819de20244e404800f659ce8595a8020ba941cf116b30ee31b0dc6367721714e511abae6157b3de5241ffd28ad309a70b9c316b5a40571808b85db4e00d82d80da4e7b5b6b37b10fd5c2c3815b7429f6eabddcd284d927352f
        sk2 = "0aec8feb32fd8bbb4526b6d5af6681519e195874ada7474255c89926efe53291"
        k2 = 0x6f6aa64cdf2f28bb081ec019b3a8e2eed89052441626172daf106f523b0b44cc
        gamma2 = 0x2f595fbef2fa542fd1d20d07f02c7d4c50b4abb2d1f76b4952219edf59f3ccf7

        r = 0x80d3ad592f04c3709aeebc9b1a91138cf0c54d0e9698325472104571094ab37ca31375ec0ed9a925ed934863f162fd2b710851e09c5bc964dae408237e6a498ed3880bf1f12fb8d2cfddf478d10afb241fe6496ef50456d6d68c03a7aac5fdcd6d7f02bd675ca25c475e05267aa7384ae868786f809a703b5d5725ae3061024baa00ec185dd1d0bf1b4883886d1513786383a55cf701c9bb4caad0b95790a6d96b234cfc74d2f918a2845676a8af2284a3da6c8b61da66eb4afd856476ad91559cacd4f9cc474fa5ab88948adbf537a4f131062566593865384cb744e6157ae53e44286fc387e03dbf585a016f5618ee5fb2c7a063533a6f66f930c166aee9c
        z = 0x56e8ae14b2d51be5e6c06dde8d17a35bace90b8e6324e3519e158dd133083db4

    else:
        p1 = number.getStrongPrime(1024)
        q1 = number.getStrongPrime(1024)
        sk1 = None
        k1 = None
        gamma1 = None

        p2 = number.getStrongPrime(1024)
        q2 = number.getStrongPrime(1024)
        sk2 = None
        k2 = None
        gamma2 = None

        r = None
        z = None

    alice = Player('Alice', p1, q1, sk1, k1, gamma1)
    bob = Player('Bob', p2, q2, sk2, k2, gamma2)

    Player.how_many()
    # print(alice)

    with open("MPC.txt", "w") as f:
        f.write(f"char* P1_hex = \"{hex(alice.p)[2:].zfill(256)}\";\n\n")
        f.write(f"char* Q1_hex = \"{hex(alice.q)[2:].zfill(256)}\";\n\n")
        f.write(f"char* SK1_hex = \"{hex(alice.w)[2:].zfill(64)}\";\n\n")
        f.write(f"char* K1_hex = \"{hex(alice.k)[2:].zfill(64)}\";\n\n")
        f.write(f"char* GAMMA1_hex = \"{hex(alice.gamma)[2:].zfill(64)}\";\n\n")
        f.write(f"char* P2_hex = \"{hex(bob.p)[2:].zfill(256)}\";\n\n")
        f.write(f"char* Q2_hex = \"{hex(bob.q)[2:].zfill(256)}\";\n\n")
        f.write(f"char* SK2_hex = \"{hex(bob.w)[2:].zfill(64)}\";\n\n")
        f.write(f"char* K2_hex = \"{hex(bob.k)[2:].zfill(64)}\";\n\n")
        f.write(f"char* GAMMA2_hex = \"{hex(bob.gamma)[2:].zfill(64)}\";\n\n")
        f.write(f"char* R_hex = \"{hex(r)[2:].zfill(1024)}\";\n\n")
        f.write(f"char* Z_hex = \"{hex(z)[2:].zfill(512)}\";\n\n")

    ### alice.k * bob.gamma ###

    print(f"alice.k {hex(alice.k)[2:].zfill(64)}")
    print(f"bob.gamma {hex(bob.gamma)[2:].zfill(64)}")

    expected = alice.k * bob.gamma % curve.r

    ca, r = alice.kgamma.client1(r)

    cb, r, z = bob.kgamma.server(alice.n, alice.g, ca, z, r)
    print(f"bob.kgamma.beta {hex(bob.kgamma.beta)[2:].zfill(64)}")

    alice.kgamma.client2(cb)
    print(f"alice.kgamma.alpha {hex(alice.kgamma.alpha)[2:].zfill(64)}\n\n")

    got = ( alice.kgamma.alpha + bob.kgamma.beta ) % curve.r

    #print(f"expected {hex(expected)}")
    #print(f"got {hex(got)}")
    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

    ### bob.k * alice.gamma ###

    print(f"bob.k {hex(bob.k)[2:].zfill(64)}")
    print(f"alice.gamma {hex(alice.gamma)[2:].zfill(64)}")

    expected = bob.k * alice.gamma % curve.r

    ca, r = bob.kgamma.client1(r)

    cb, r, z = alice.kgamma.server(bob.n, bob.g, ca, z, r)
    print(f"alice.kgamma.beta {hex(alice.kgamma.beta)[2:].zfill(64)}")

    bob.kgamma.client2(cb)
    print(f"bob.kgamma.alpha {hex(bob.kgamma.alpha)[2:].zfill(64)}\n\n")

    got = ( bob.kgamma.alpha + alice.kgamma.beta ) % curve.r

    #print(f"expected {hex(expected)}")
    #print(f"got {hex(got)}")
    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

    ### kgamma = (alice.k + bob.k)(alice.gamma + bob.gamma)

    k = (alice.k + bob.k) % curve.r
    gamma = (alice.gamma + bob.gamma) % curve.r
    expected = k * gamma % curve.r

    got = ( alice.kgamma.sum() + bob.kgamma.sum() ) % curve.r

    print(f"alice.kgamma.sum {hex(alice.kgamma.sum())[2:].zfill(64)}")
    print(f"bob.kgamma.sum {hex(bob.kgamma.sum())[2:].zfill(64)}")
    print(f"kgamma {hex(got)[2:].zfill(64)}\n\n")

    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

    kgamma = got

    with open("MPC.txt", "a") as f:
        f.write(f"char* KGAMMA1_hex = \"{hex(alice.kgamma.sum())[2:].zfill(64)}\";\n\n")
        f.write(f"char* KGAMMA2_hex = \"{hex(bob.kgamma.sum())[2:].zfill(64)}\";\n\n")
        f.write(f"char* KGAMMA_hex = \"{hex(got)[2:].zfill(64)}\";\n\n")

    ### alice.k * bob.w ###

    print(f"alice.k {hex(alice.k)}")
    print(f"bob.w {hex(bob.w)}")

    expected = alice.k * bob.w % curve.r

    ca, r = alice.kw.client1(r)

    cb, r, z = bob.kw.server(alice.n, alice.g, ca, z, r)
    print(f"bob.kw.beta {hex(bob.kw.beta)[2:].zfill(64)}")

    alice.kw.client2(cb)
    print(f"alice.kw.alpha {hex(alice.kw.alpha)[2:].zfill(64)}\n\n")

    got = ( alice.kw.alpha + bob.kw.beta ) % curve.r

    #print(f"expected {hex(expected)}")
    #print(f"got {hex(got)}")
    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

    ### bob.k * alice.w ###

    print(f"bob.k {hex(bob.k)[2:].zfill(64)}")
    print(f"alice.w {hex(alice.w)[2:].zfill(64)}")

    expected = bob.k * alice.w % curve.r

    ca, r = bob.kw.client1(r)

    cb, r, z = alice.kw.server(bob.n, bob.g, ca, z, r)
    #print(f"r1 = {hex(r)}")
    #print(f"z1 = {hex(z)}")
    print(f"alice.kw.beta {hex(alice.kw.beta)[2:].zfill(64)}")

    bob.kw.client2(cb)
    print(f"bob.kw.alpha {hex(bob.kw.alpha)[2:].zfill(64)}\n\n")

    got = ( bob.kw.alpha + alice.kw.beta ) % curve.r

    #print(f"expected {hex(expected)}")
    #print(f"got {hex(got)}")
    assert got == expected, f"expected {hex(expected)} got {hex(got)}"


    ### kw = (alice.k + bob.k)(alice.w + bob.w)

    k = (alice.k + bob.k) % curve.r
    w = (alice.w + bob.w) % curve.r
    expected = k * w % curve.r

    print(f"alice.kw.sum {hex(alice.kw.sum())[2:].zfill(64)}")
    print(f"bob.kw.sum {hex(bob.kw.sum())[2:].zfill(64)}")
    got = ( alice.kw.sum() + bob.kw.sum() ) % curve.r
    print(f"kw {hex(got)[2:].zfill(64)}\n\n")

    #print(f"expected {hex(expected)}")
    #print(f"got {hex(got)}")
    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

    ### Calculate r component of signature

    # Calculate (k.gamma)^{-1}
    invkgamma = big.invmodp(kgamma, curve.r)
    print(f"kgamma {hex(kgamma)[2:].zfill(64)}")
    print(f"invkgamma {hex(invkgamma)[2:].zfill(64)}")

    aliceGamma = alice.Gamma.toBytes(False).hex()
    bobGamma = bob.Gamma.toBytes(False).hex()
    print(f"aliceGamma {aliceGamma}")
    print(f"bobGamma {bobGamma}")

    # Add Gamma values
    R = ecp.ECp()
    R.add(alice.Gamma)
    R.add(bob.Gamma)
    RPT = R.toBytes(False).hex()
    print(f"alice.Gamma + bob.Gamma {RPT}")

    # Gamma by (k.gamma)^{-1}
    R = invkgamma * R
    INVKGAMMARPT = R.toBytes(False).hex()
    print(f"invkgamma * R {INVKGAMMARPT}")

    # x component is r value
    r = R.getx() % curve.r

    print(f"r {hex(r)[2:].zfill(64)}\n\n")

    invk = big.invmodp(k, curve.r)
    expected = invk * ecp.generator()

    #print(f"expected {expected}")
    #print(f"got {R}")
    assert R == expected, f"expected {expected} got {R}"

    with open("MPC.txt", "a") as f:
        f.write(f"char* INVKGAMMA_hex = \"{hex(invkgamma)[2:].zfill(64)}\";\n\n")
        f.write(f"char* GAMMAPT1_hex = \"{aliceGamma}\";\n\n")
        f.write(f"char* BOBPT1_hex = \"{bobGamma}\";\n\n")
        f.write(f"char* RPT_hex = \"{RPT}\";\n\n")
        f.write(f"char* INVKGAMMARPT_hex = \"{INVKGAMMARPT}\";\n\n")
        f.write(f"char* SIG_R_hex = \"{hex(r)[2:].zfill(64)}\";\n\n")

    ### Calculate s component of signature

    message = b'test message'
    m = mpc.hash(message)

    print(f"alice.s {hex(alice.s(m,r))}")
    print(f"bob.s {hex(bob.s(m,r))}")
    s = ( alice.s(m,r) + bob.s(m,r) ) % curve.r

    k = (alice.k + bob.k) % curve.r
    sk = (alice.w + bob.w) % curve.r
    expected = k * (m + sk * r) % curve.r

    #print(f"expected {hex(expected)}")
    #print(f"got {hex(s)}")
    assert s == expected, f"expected {hex(expected)} got {hex(s)}"

    ### Output

    print(f"\nalice (r,s) = ({hex(r)}, {hex(alice.s(m,r))})")
    print(f"bob (r,s) = ({hex(r)}, {hex(bob.s(m,r))})")
    print(f"(alice+bob) (r,s) = ({hex(r)}, {hex(s)})")

    ### Check result

    pk = ecp.ECp()
    pk.add(alice.pk)
    pk.add(bob.pk)

    PK = pk.toBytes(compress=False)
    R = big.to_bytes(r)
    S = big.to_bytes(s)

    print(f"\nsk {hex(sk)}")
    print(f"pk {PK.hex()}")
    print(f"k {hex(k)}")
    print(f"message {message.hex()}")

    if ecdh.ECP_SvDSA(PK, message, R, S):
        print("Signature is Valid")
    else:
        print("Signature is NOT Valid")
