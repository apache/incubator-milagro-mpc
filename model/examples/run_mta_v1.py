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
        sk1 = "00000000000000000000000000000000248ea4e0ce968bdd1febd48e2d246f7268070eb468eca0c1e911cc1642bd8041"
        k1 = 0x2
        gamma1 = 0x5
        r1 = 0x18c5947fda2edea04c1f87c207e0bab17aff5f77ac21d04cb194631efd1f7256dc37de9473fc86009df36206974859c09023ac8179b02aacea8d89a01f4de161db955d450cef55ce959897636973b952371e349778e67c61ef6fae5f73fd728d423a594b6a76d5faca97d59d6ae40c53f3bd42dfccc93183e355422ba7af308a87d32c0352d478156275f98bc74e9ed4f2c7a9853c9f35b996fafe765b56c7f2e83771c6b676b75436e5c1697b838b3908aee92001cbccf3bf6cfb7aaea27a358a12cfe1ddde886b975ae14517e5912eba3ff9792e46403a998edd371020bbc5fbd6a705e669383303030ef79653ce16e13122233c626bb101ee8dd27bf4ff86
        z1 = 0x4
        
        p2 = 0xc227a6d88ef469ceb323bcd95a18ab41d9cde9b349c093e7273e7d05f1636c517a21890f22785d45aeeb892da40a69267d3e2f1bd7e0f164cb23306402122512ed70d1cbb20c470d0c03a54adc47abfcc9eadff2ba175bb29aea70464f31f7804a8fc9c9fed60c505e11c594c9415fc96e1b44a3e5f437772bbce91e063827bf
        q2 = 0xe729b4e468f6076ad00dc9af0b820158be147727f4ead55b4d6268647d53c8f65e92338af9b24b819de20244e404800f659ce8595a8020ba941cf116b30ee31b0dc6367721714e511abae6157b3de5241ffd28ad309a70b9c316b5a40571808b85db4e00d82d80da4e7b5b6b37b10fd5c2c3815b7429f6eabddcd284d927352f
        sk2 = "000000000000000000000000000000000aec8feb32fd8bbb4526b6d5af6681519e195874ada7474255c89926efe53291"
        k2 = 0x4
        gamma2 = 0x3
        r2 = 0x18c5947fda2edea04c1f87c207e0bab17aff5f77ac21d04cb194631efd1f7256dc37de9473fc86009df36206974859c09023ac8179b02aacea8d89a01f4de161db955d450cef55ce959897636973b952371e349778e67c61ef6fae5f73fd728d423a594b6a76d5faca97d59d6ae40c53f3bd42dfccc93183e355422ba7af308a87d32c0352d478156275f98bc74e9ed4f2c7a9853c9f35b996fafe765b56c7f2e83771c6b676b75436e5c1697b838b3908aee92001cbccf3bf6cfb7aaea27a358a12cfe1ddde886b975ae14517e5912eba3ff9792e46403a998edd371020bbc5fbd6a705e669383303030ef79653ce16e13122233c626bb101ee8dd27bf4ff86        
        z2 = 0x4        
        
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

    #Player.how_many()

    ### alice.k * bob.gamma ###
    
    print(f"alice.k: {hex(alice.k)[2:].zfill(512)}\n")
    print(f"bob.gamma {hex(bob.gamma)[2:].zfill(512)}\n")

    expected = alice.k * bob.gamma % curve.r
    print(f"s = alice.k * bob.gamma = {hex(expected)[2:].zfill(512)}\n")
    
    ca, r1 = alice.kgamma.client1(r1)
    print(f"alice ca {hex(ca)[2:].zfill(1024)}\n")
    print(f"alice r {hex(r1)[2:].zfill(512)}\n")     

    cb, r2, z2 = bob.kgamma.server(alice.n, alice.g, ca, z2, r2)
    print(f"bob cb {hex(cb)[2:].zfill(1024)}\n")
    print(f"bob r2 {hex(r2)[2:].zfill(512)}\n")
    print(f"bob z2 {hex(z2)[2:].zfill(512)}\n")         
    print(f"bob.kgamma.beta {hex(bob.kgamma.beta)[2:].zfill(512)}\n")
    
    alice.kgamma.client2(cb)
    print(f"alice.kgamma.alpha {hex(alice.kgamma.alpha)[2:].zfill(512)}\n")

    got = ( alice.kgamma.alpha + bob.kgamma.beta ) % curve.r

    print(f"expected {hex(expected)}")    
    print(f"got {hex(got)}")
    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

    # Write vector to text file
    # CB12 means first pass and second actor i.e. bob
    with open("MtA.txt", "w") as f:
        f.write(f"char* N1_hex = \"{hex(alice.n)[2:].zfill(512)}\";\n\n")
        f.write(f"char* G1_hex = \"{hex(alice.g)[2:].zfill(512)}\";\n\n")
        f.write(f"char* L1_hex = \"{hex(alice.l)[2:].zfill(512)}\";\n\n")
        f.write(f"char* M1_hex = \"{hex(alice.m)[2:].zfill(512)}\";\n\n")        
        f.write(f"char* A1_hex = \"{hex(alice.k)[2:].zfill(64)}\";\n\n")
        f.write(f"char* B2_hex = \"{hex(bob.gamma)[2:].zfill(64)}\";\n\n")
        f.write(f"char* CA11_hex = \"{hex(ca)[2:].zfill(1024)}\";\n\n")
        f.write(f"char* R11_hex = \"{hex(r1)[2:].zfill(512)}\";\n\n")     
        f.write(f"char* CB12_hex = \"{hex(cb)[2:].zfill(1024)}\";\n\n")
        f.write(f"char* R12_hex = \"{hex(r2)[2:].zfill(512)}\";\n\n")
        f.write(f"char* Z12_hex = \"{hex(z2)[2:].zfill(64)}\";\n\n")         
        f.write(f"char* BETA2_hex = \"{hex(bob.kgamma.beta)[2:].zfill(64)}\";\n\n")
        f.write(f"char* ALPHA1_hex = \"{hex(alice.kgamma.alpha)[2:].zfill(64)}\";\n\n")
        f.write(f"char* A1B2_hex = \"{hex(expected)[2:].zfill(64)}\";\n\n")        
    

    ### bob.k * alice.gamma ###
    
    print(f"k {hex(bob.k)}")
    print(f"gamma {hex(alice.gamma)}")

    expected = bob.k * alice.gamma % curve.r
    
    ca, r2 = bob.kgamma.client1(r2)

    cb, r1, z1 = alice.kgamma.server(bob.n, bob.g, ca, z1, r1)
    print(f"alice.kgamma.beta {alice.kgamma.beta}")
    
    bob.kgamma.client2(cb)
    print(f"bob.kgamma.alpha {bob.kgamma.alpha}")

    got = ( bob.kgamma.alpha + alice.kgamma.beta ) % curve.r

    print(f"expected {hex(expected)}")    
    print(f"got {hex(got)}")
    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

    # Write vector to text file
    # CB21 means second pass and first actor i.e. alice
    with open("MtA.txt", "a") as f:
        f.write(f"char* N2_hex = \"{hex(bob.n)[2:].zfill(512)}\";\n\n")
        f.write(f"char* G2_hex = \"{hex(bob.g)[2:].zfill(512)}\";\n\n")
        f.write(f"char* L2_hex = \"{hex(bob.l)[2:].zfill(512)}\";\n\n")
        f.write(f"char* M2_hex = \"{hex(bob.m)[2:].zfill(512)}\";\n\n")        
        f.write(f"char* A2_hex = \"{hex(bob.k)[2:].zfill(64)}\";\n\n")
        f.write(f"char* B1_hex = \"{hex(alice.gamma)[2:].zfill(64)}\";\n\n")
        f.write(f"char* CA22_hex = \"{hex(ca)[2:].zfill(1024)}\";\n\n")
        f.write(f"char* R22_hex = \"{hex(r2)[2:].zfill(512)}\";\n\n")     
        f.write(f"char* CB21_hex = \"{hex(cb)[2:].zfill(1024)}\";\n\n")
        f.write(f"char* R21_hex = \"{hex(r1)[2:].zfill(512)}\";\n\n")
        f.write(f"char* Z21_hex = \"{hex(z1)[2:].zfill(64)}\";\n\n")         
        f.write(f"char* BETA1_hex = \"{hex(alice.kgamma.beta)[2:].zfill(64)}\";\n\n")
        f.write(f"char* ALPHA2_hex = \"{hex(bob.kgamma.alpha)[2:].zfill(64)}\";\n\n")
        f.write(f"char* A2B1_hex = \"{hex(expected)[2:].zfill(64)}\";\n\n")
        
    ### kgamma = (alice.k + bob.k)(alice.gamma + bob.gamma)

    #print(alice)
    #print(bob)        
    
    k = (alice.k + bob.k) % curve.r
    gamma = (alice.gamma + bob.gamma) % curve.r
    expected = k * gamma % curve.r

    got = ( alice.kgamma.sum() + bob.kgamma.sum() ) % curve.r 

    print(f"kgamma expected {expected} {hex(expected)}")
    print(f"kgamma got {got} {hex(got)}")        
    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

    with open("MtA.txt", "a") as f:
        f.write(f"char* SUM1_hex = \"{hex(alice.kgamma.sum())[2:].zfill(64)}\";\n\n")
        f.write(f"char* SUM2_hex = \"{hex(bob.kgamma.sum())[2:].zfill(64)}\";\n\n")                
        f.write(f"char* AB_hex = \"{hex(expected)[2:].zfill(64)}\";\n\n")
    



