#! /usr/bin/env python3

import sys
sys.path.append('../')

from sec256k1 import factorization_zk as fact

from Crypto.Util import number

DETERMINISTIC = False

if __name__ == "__main__":

    # Generate P,Q,N
    if DETERMINISTIC:
        p = 0xe008507e09c24d756280f3d94912fb9ac16c0a8a1757ee01a350736acfc7f65880f87eca55d6680253383fc546d03fd9ebab7d8fa746455180888cb7c17edf58d3327296468e5ab736374bc9a0fa02606ed5d3a4a5fb1677891f87fbf3c655c3e0549a86b17b7ddce07c8f73e253105e59f5d3ed2c7ba5bdf8495df40ae71a7f
        q = 0xdbffe278edd44c2655714e5a4cc82e66e46063f9ab69df9d0ed20eb3d7f2d8c7d985df71c28707f32b961d160ca938e9cf909cd77c4f8c630aec34b67714cbfd4942d7147c509db131bc2d6a667eb30df146f64b710f8f5247848b0a75738a38772e31014fd63f0b769209928d586499616dcc90700b393156e12eea7e15a835
    else:
        p = number.getStrongPrime(fact.nlen * 4)
        q = number.getStrongPrime(fact.nlen * 4)

    N = p * q

    print("ZK proof of knowledge of factoring")
    print("\tP = {}".format(hex(p)[2:].zfill(fact.nlen)))
    print("\tQ = {}".format(hex(q)[2:].zfill(fact.nlen)))
    print("\tN = {}".format(hex(N)[2:].zfill(fact.nlen * 2)))
    print("")

    # ZK proof setup (once for each n, can be reused)
    print("[Alice] ZK proof setup")

    Zi = fact.nizk_setup(N)

    for i, Z in enumerate(Zi):
        print("\tZ_{} = {}".format(i, hex(Z)[2:].zfill(fact.nlen * 2)))
    print("")

    # ZK proof. It assumes the Zi have already been broadcasted to any verifier
    print("[Alice] ZK proof")

    r = None
    if DETERMINISTIC:
        r = 0x279775a316e9e86c9e89116e80c6cc9843930f6a8c083ad0244b3c516ed224e2150ac3542ff525f7422bc4c5f64a52d2e925a9685391d1948dd4eb0fe2a517a5fcb4dec60979346d8475bceb1aa905f5540f0d01472fde3d5c1c3189c5f7e1fd5ac42ac7c5e5eb463c15b8a26ce66720dc0d51d60d70f671634b4e685ee7a9f173924954fd6e10bd885fc958a4f54c84e33ddb2d86bbe9dffa1d77a71fdb7dc3e40177b68fb9c36f3a8f82e943a14320c78b16c55e7f1e26dba64b6e7af4f96d81580bf3c12eb5fc4f171f4d6b6e568584c220254a271a9a3949aa8231ef96c52db2d4cf54aab52f73ea203de9addde2d693944e5b4f9cb8a8891a7c46335a10

    e,y = fact.nizk_prove(N,p,q,Zi,r=r)

    print("\tE = {}".format(hex(e)[2:].zfill(fact.B//4)))
    print("\tY = {}".format(hex(y)[2:].zfill(fact.nlen * 2)))
    print("")

    # ZK verifiction
    print("[Bob] Verification")

    if fact.nizk_verify(Zi,N,e,y):
        print("\tSuccess!")
    else:
        print("\tFail!")
