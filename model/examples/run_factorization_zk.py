#! /usr/bin/env python3

import sys
sys.path.append('../')

from sec256k1 import factorization_zk as fact

from Crypto.Util import number

DETERMINISTIC = False

if __name__ == "__main__":

    # Generate P,Q,N
    if DETERMINISTIC:
        p = 0xff76981f3580a943c035653a7323a577f6e8d9eef8910805ae7cb09a9dd3e65c2803940d09190ecf3ed6f41fc20c0be95b6b2e572df9b4e96c41304320af3e71
        q = 0xfdd0d8fadc7d412a8db6e358958d2d4c97cb5cc0e77921493cdd2cfc8de2e7875684b3ee564f099c14cb343c90fad09d90de98d72f604a002f28f154f6e5916d
    else:
        p = number.getStrongPrime(fact.nlen//2)
        q = number.getStrongPrime(fact.nlen//2)

    N = p * q

    print("ZK proof of knowledge of factoring")
    print("\tP = {}".format(hex(p)[2:].zfill(fact.nlen//8)))
    print("\tQ = {}".format(hex(q)[2:].zfill(fact.nlen//8)))
    print("\tN = {}".format(hex(N)[2:].zfill(fact.nlen//4)))
    print("")

    # ZK proof setup (once for each n, can be reused)
    print("[Alice] ZK proof setup")

    if DETERMINISTIC:
        Zi = [
            0x7a481e48b9c5a8487db5c2b80b7abd0432647359b005b4bceadc0a2d5c7cb30337dcab894be6d4bf44100b236cebc6bd22adb0682b4d6633f09121d7a1410ed16e9fceb7effe1f71c6ae865604f55f8c9c566cd79dbf7079fff24d48dae9b43c0c6142483c58af44836e65225416a3fe00d0da96e691e02ba04a0b47563e7f6d,
            0xd5c685db97a7b6486d60a020035fcdf340dbc5ab5793a5e187284c29f10004dd4ca785eb4578721191a192bfe7076a928379da7970ef04e431ec43078540dd92c34d6951f4ca634dcc94239d6cca4a769bd2708f3869a4b05e2fcf8b4fa4fbe2e04ba3d8e66dd95fc140d8b52f43aed1a55cd393f21b11696b94af705e97776a,
            0x65af51d4f5237238b0e1c674ea13def2444a76a24d1bfe2741fbda01bf26691f65972677c195ad10acf5fa5da92b9b1f492ff2ef19059140943b8bf2268550d233e631dd24392e9b92e890abbcc9aaeb7e4e7da27c2f2c059924ade142600471edb403fa6063ddd9f8dda98bc078199aa1d09418610d29881d9cff468d579c53
        ]
    else:
        Zi = fact.nizk_setup(N)

    for i, Z in enumerate(Zi):
        print("\tZ_{} = {}".format(i, hex(Z)[2:].zfill(fact.nlen//4)))
    print("")

    # ZK proof. It assumes the Zi have already been broadcasted to any verifier
    print("[Alice] ZK proof")

    r = None
    if DETERMINISTIC:
        r = 0x01

    e,y = fact.nizk_prove(N,p,q,Zi,r=r)

    print("\tE = {}".format(hex(e)[2:].zfill(fact.B//4)))
    print("\tY = {}".format(hex(y)[2:].zfill(fact.nlen//4)))
    print("")

    # ZK verifiction
    print("[Bob] Verification")

    if fact.nizk_verify(Zi,N,e,y):
        print("\tSuccess!")
    else:
        print("\tFail!")
