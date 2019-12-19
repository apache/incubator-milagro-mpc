#!/usr/bin/env python3

import sys
sys.path.append('../')

import json
from Crypto.Util import number

from sec256k1.mpc_v1 import Player
import sec256k1.mpc_v1 as mpc
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
        r1 = 0x980dcee14556e2c40472c3544d46a6e34652ff1a4d9f99fdd7e8823aa39e332050431361bf618e5cfd248cd3ff3f03a32f8021eaf0d0b6d34bc3506f99e86a21dcc8237f66cd7d7aab0a1aad359da6580ea51b5c722d548e340617d512945c105a7a01756ffbcce91611bb8e3be4e36c24aa2c356fa7370515e359b5fd1075aa8628e07fcdb205e510dc1d464ced3805fd834d1ab82cd9086a5fe92bebef8900d5ca7269c9da58d732b7dda821c35cca5ce0a31c1ddb3f3d0b62e1117cd00bb54c3c03fd533a4d0148852703f83293def0f5c42a68b6deab4762ca6a7c448cbcf8a5156450d5441f961121f0220cae9af7844f9923fa4be52b3abbf3100a9dee
        z1 = 0x101c7abf2665c3f311a11c988798476216b28d576657fe0e7795e7024086051a

        p2 = 0xc227a6d88ef469ceb323bcd95a18ab41d9cde9b349c093e7273e7d05f1636c517a21890f22785d45aeeb892da40a69267d3e2f1bd7e0f164cb23306402122512ed70d1cbb20c470d0c03a54adc47abfcc9eadff2ba175bb29aea70464f31f7804a8fc9c9fed60c505e11c594c9415fc96e1b44a3e5f437772bbce91e063827bf
        q2 = 0xe729b4e468f6076ad00dc9af0b820158be147727f4ead55b4d6268647d53c8f65e92338af9b24b819de20244e404800f659ce8595a8020ba941cf116b30ee31b0dc6367721714e511abae6157b3de5241ffd28ad309a70b9c316b5a40571808b85db4e00d82d80da4e7b5b6b37b10fd5c2c3815b7429f6eabddcd284d927352f
        sk2 = "0aec8feb32fd8bbb4526b6d5af6681519e195874ada7474255c89926efe53291"
        k2 = 0x6f6aa64cdf2f28bb081ec019b3a8e2eed89052441626172daf106f523b0b44cc
        gamma2 = 0x2f595fbef2fa542fd1d20d07f02c7d4c50b4abb2d1f76b4952219edf59f3ccf7
        r2 = 0x8a0a6634ed02a76e647cb5a44636c4960e961cd3e11a1b32b42e51418e5738fe67aa182e617968c0a811bc5fe96623070d4e853c567710f468f5698610cc2cd1cccdad807e0011d607e7617977a5468ccd0a7a514ee60d7910297dfc17fe2b42a623eed640416e0cb9ed67ce9b79cf33174037a5e5a7bab4b367bf9ae62a5e2f6b6d51247fd2c39ea97f21afa2f010123486f8f26f3df92d59588ea8cebf617cd1e8fc2f7206f44eafdadde28e44aa27744bcef25b075451e930a1e1377943805b90780506bd7e86092e47fa892bd252f7eba090642501e28148540047d2f264a0b4855f48ab43ca4f75d728ba19585da77d7dcb402f5f3d040b8718faa0f361
        z2 = 0x0207c724d58036400bcb7d99286aeb835745711fcf18c124fedb14bb252870bc

    else:
        p1 = number.getStrongPrime(1024)
        q1 = number.getStrongPrime(1024)
        sk1 = None
        k1 = None
        gamma1 = None
        r1 = None
        z1 = None

        p2 = number.getStrongPrime(1024)
        q2 = number.getStrongPrime(1024)
        sk2 = None
        k2 = None
        gamma2 = None
        r2 = None
        z2 = None

    alice = Player('Alice', p1, q1, sk1, k1, gamma1)
    bob = Player('Bob', p2, q2, sk2, k2, gamma2)

    # Player.how_many()

    ### alice.k * bob.w ###

    print(f"alice.k: {hex(alice.k)[2:].zfill(512)}\n")
    print(f"bob.w {hex(bob.w)[2:].zfill(512)}\n")

    expected = alice.k * bob.w % curve.r
    print(f"s = alice.k * bob.w = {hex(expected)[2:].zfill(512)}\n")

    ca, r1 = alice.kw.client1(r1)
    print(f"alice ca {hex(ca)[2:].zfill(1024)}\n")
    print(f"alice r {hex(r1)[2:].zfill(512)}\n")

    cb, r2, z2 = bob.kw.server(alice.n, alice.g, ca, z2, r2)
    print(f"bob cb {hex(cb)[2:].zfill(1024)}\n")
    print(f"bob r2 {hex(r2)[2:].zfill(512)}\n")
    print(f"bob z2 {hex(z2)[2:].zfill(512)}\n")
    print(f"bob.kw.beta {hex(bob.kw.beta)[2:].zfill(512)}\n")

    alice.kw.client2(cb)
    print(f"alice.kw.alpha {hex(alice.kw.alpha)[2:].zfill(512)}\n")

    got = (alice.kw.alpha + bob.kw.beta) % curve.r

    print(f"expected {hex(expected)}")
    print(f"got {hex(got)}")
    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

    # Write vector to text file
    # CB12 means first pass and second actor i.e. bob
    with open("S.txt", "w") as f:
        f.write(f"char* N1_hex = \"{hex(alice.n)[2:].zfill(512)}\";\n\n")
        f.write(f"char* G1_hex = \"{hex(alice.g)[2:].zfill(512)}\";\n\n")
        f.write(f"char* L1_hex = \"{hex(alice.l)[2:].zfill(512)}\";\n\n")
        f.write(f"char* M1_hex = \"{hex(alice.m)[2:].zfill(512)}\";\n\n")
        f.write(f"char* K1_hex = \"{hex(alice.k)[2:].zfill(64)}\";\n\n")
        f.write(f"char* W2_hex = \"{hex(bob.w)[2:].zfill(64)}\";\n\n")
        f.write(f"char* CA11_hex = \"{hex(ca)[2:].zfill(1024)}\";\n\n")
        f.write(f"char* R11_hex = \"{hex(r1)[2:].zfill(512)}\";\n\n")
        f.write(f"char* CB12_hex = \"{hex(cb)[2:].zfill(1024)}\";\n\n")
        f.write(f"char* R12_hex = \"{hex(r2)[2:].zfill(512)}\";\n\n")
        f.write(f"char* Z12_hex = \"{hex(z2)[2:].zfill(64)}\";\n\n")
        f.write(f"char* BETA2_hex = \"{hex(bob.kw.beta)[2:].zfill(64)}\";\n\n")
        f.write(
            f"char* ALPHA1_hex = \"{hex(alice.kw.alpha)[2:].zfill(64)}\";\n\n")

    ### bob.k * alice.w ###

    print(f"k {hex(bob.k)}")
    print(f"w {hex(alice.w)}")

    expected = bob.k * alice.w % curve.r

    ca, r2 = bob.kw.client1(r2)

    cb, r1, z1 = alice.kw.server(bob.n, bob.g, ca, z1, r1)
    print(f"alice.kw.beta {alice.kw.beta}")

    bob.kw.client2(cb)
    print(f"bob.kw.alpha {bob.kw.alpha}")

    got = (bob.kw.alpha + alice.kw.beta) % curve.r

    print(f"expected {hex(expected)}")
    print(f"got {hex(got)}")
    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

    # Write vector to text file
    # CB21 means second pass and first actor i.e. alice
    with open("S.txt", "a") as f:
        f.write(f"char* N2_hex = \"{hex(bob.n)[2:].zfill(512)}\";\n\n")
        f.write(f"char* G2_hex = \"{hex(bob.g)[2:].zfill(512)}\";\n\n")
        f.write(f"char* L2_hex = \"{hex(bob.l)[2:].zfill(512)}\";\n\n")
        f.write(f"char* M2_hex = \"{hex(bob.m)[2:].zfill(512)}\";\n\n")
        f.write(f"char* K2_hex = \"{hex(bob.k)[2:].zfill(64)}\";\n\n")
        f.write(f"char* W1_hex = \"{hex(alice.w)[2:].zfill(64)}\";\n\n")
        f.write(f"char* CA22_hex = \"{hex(ca)[2:].zfill(1024)}\";\n\n")
        f.write(f"char* R22_hex = \"{hex(r2)[2:].zfill(512)}\";\n\n")
        f.write(f"char* CB21_hex = \"{hex(cb)[2:].zfill(1024)}\";\n\n")
        f.write(f"char* R21_hex = \"{hex(r1)[2:].zfill(512)}\";\n\n")
        f.write(f"char* Z21_hex = \"{hex(z1)[2:].zfill(64)}\";\n\n")
        f.write(
            f"char* BETA1_hex = \"{hex(alice.kw.beta)[2:].zfill(64)}\";\n\n")
        f.write(
            f"char* ALPHA2_hex = \"{hex(bob.kw.alpha)[2:].zfill(64)}\";\n\n")

    ### kw = (alice.k + bob.k)(alice.w + bob.w)

    k = (alice.k + bob.k) % curve.r
    w = (alice.w + bob.w) % curve.r
    expected = k * w % curve.r

    got = (alice.kw.sum() + bob.kw.sum()) % curve.r

    print(f"kw expected {hex(expected)}")
    assert got == expected, f"expected {hex(expected)} got {hex(kw)}"

    with open("S.txt", "a") as f:
        f.write(
            f"char* SUM1_hex = \"{hex(alice.kw.sum())[2:].zfill(64)}\";\n\n")
        f.write(f"char* SUM2_hex = \"{hex(bob.kw.sum())[2:].zfill(64)}\";\n\n")

    # Calculate r component of signature

    k = (alice.k + bob.k) % curve.r
    invk = big.invmodp(k, curve.r)
    R = invk * ecp.generator()
    r = R.getx() % curve.r

    with open("S.txt", "a") as f:
        f.write(f"char* SIG_R_hex = \"{hex(r)[2:].zfill(64)}\";\n\n")

    # Calculate s component of signature

    message = b'test message'
    m = mpc.hash(message)

    print(f"alice.s {hex(alice.s(m,r))}")
    print(f"bob.s {hex(bob.s(m,r))}")
    s = (alice.s(m, r) + bob.s(m, r)) % curve.r

    sk = (alice.w + bob.w) % curve.r
    expected = k * (m + sk * r) % curve.r

    #print(f"expected {hex(expected)}")
    #print(f"got {hex(s)}")
    assert s == expected, f"expected {hex(expected)} got {hex(s)}"

    with open("S.txt", "a") as f:
        f.write(f"char* M_hex = \"{message.hex()}\";\n\n")
        f.write(
            f"char* SIG_S1_hex = \"{hex(alice.s(m,r))[2:].zfill(64)}\";\n\n")
        f.write(f"char* SIG_S2_hex = \"{hex(bob.s(m,r))[2:].zfill(64)}\";\n\n")
        f.write(f"char* SIG_S_hex = \"{hex(s)[2:].zfill(64)}\";\n\n")

    print(f"\nalice (r,s) = ({hex(r)}, {hex(alice.s(m,r))})")
    print(f"bob (r,s) = ({hex(r)}, {hex(bob.s(m,r))})")
    print(f"(alice+bob) (r,s) = ({hex(r)}, {hex(s)})")

    # Check result

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
