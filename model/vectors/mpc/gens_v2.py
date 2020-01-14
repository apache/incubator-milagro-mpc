#!/usr/bin/env python3

"""
   Generates a set of test vectors. 

   usage: gens_v1.py 
"""

import sys
sys.path.append('../../')
import json
from Crypto.Util import number
from sec256k1.mpc_v2 import Player
import sec256k1.mpc_v2 as mpc
import sec256k1.curve as curve
import sec256k1.big as big
import sec256k1.ecp as ecp
import sec256k1.ecdh as ecdh


if len(sys.argv) == 2:
    nVec = int(sys.argv[1])
else:
    print (
        "Usage: genVectors.py [nVec]")
    sys.exit(1)
    
print ("Generate nVec = {}".format(nVec))

def genVector(test_no):
    """Generate a single test vector

    Args::

        test_no: Test vector identifier

    Returns::

        vector: A test vector

    Raises::

        Exception
    """
    vector = {}

    vector['TEST'] = test_no 

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
        
    alice = Player('Alice', p1, q1, sk1, k1, gamma1)
    bob = Player('Bob', p2, q2, sk2, k2, gamma2)

    ### alice.k * bob.w ###

    vector['P1'] = hex(alice.p)[2:].zfill(256)
    vector['Q1'] = hex(alice.q)[2:].zfill(256)
    vector['K1'] = hex(alice.k)[2:].zfill(64)
    vector['W2'] = hex(bob.w)[2:].zfill(64)    

    ca, r = alice.kw.client1()
    vector['R11'] = hex(r)[2:].zfill(512)     

    cb, r, z = bob.kw.server(alice.n, alice.g, ca)
    vector['R12'] = hex(r)[2:].zfill(1024)
    vector['Z12'] = hex(z)[2:].zfill(64)         
    vector['BETA2'] = hex(bob.kw.beta)[2:].zfill(64)

    alice.kw.client2(cb)
    vector['ALPHA1'] = hex(alice.kw.alpha)[2:].zfill(64)

    expected = alice.k * bob.w % curve.r        
    got = ( alice.kw.alpha + bob.kw.beta ) % curve.r
    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

    ### bob.k * alice.w ###

    vector['P2'] = hex(bob.p)[2:].zfill(256)
    vector['Q2'] = hex(bob.q)[2:].zfill(256)
    vector['K2'] = hex(bob.k)[2:].zfill(64)
    vector['W1'] = hex(alice.w)[2:].zfill(64)

    ca, r = bob.kw.client1()
    vector['R22'] = hex(r)[2:].zfill(512)     

    cb, r, z = alice.kw.server(bob.n, bob.g, ca)
    vector['R21'] = hex(r)[2:].zfill(1024)
    vector['Z21'] = hex(z)[2:].zfill(64)         
    vector['BETA1'] = hex(alice.kw.beta)[2:].zfill(64)

    bob.kw.client2(cb)
    vector['ALPHA2'] = hex(bob.kw.alpha)[2:].zfill(64)

    expected = bob.k * alice.w % curve.r        
    got = ( bob.kw.alpha + alice.kw.beta ) % curve.r
    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

    ### kw = (alice.k + bob.k)(alice.w + bob.w)

    kw = ( alice.kw.sum() + bob.kw.sum() ) % curve.r
    
    vector['SUM1'] = hex(alice.kw.sum())[2:].zfill(64)
    vector['SUM2'] = hex(bob.kw.sum())[2:].zfill(64)
    vector['KW'] = hex(kw)[2:].zfill(64)        
    
    k = (alice.k + bob.k) % curve.r
    w = (alice.w + bob.w) % curve.r
    expected = k * w % curve.r

    assert kw == expected, f"expected {hex(expected)} got {hex(kw)}"

    ### Calculate r component of signature

    k = (alice.k + bob.k) % curve.r
    invk = big.invmodp(k, curve.r)
    R = invk * ecp.generator()
    r = R.getx() % curve.r
    vector['SIG_R'] = hex(r)[2:].zfill(64)

    ### Calculate s component of signature

    message = b'test message'
    m = mpc.hash(message)

    s = ( alice.s(m,r) + bob.s(m,r) ) % curve.r

    vector['M'] = message.hex()
    vector['SIG_S1'] = hex(alice.s(m,r))[2:].zfill(64)
    vector['SIG_S2'] = hex(bob.s(m,r))[2:].zfill(64)
    vector['SIG_S'] = hex(s)[2:].zfill(64)        

    sk = (alice.w + bob.w) % curve.r      
    expected = k * (m + sk * r) % curve.r
    assert s == expected, f"expected {hex(expected)} got {hex(s)}"    
        
    ### Check result

    pk = ecp.ECp()
    pk.add(alice.pk) 
    pk.add(bob.pk)

    PK = pk.toBytes(compress=False)
    R = big.to_bytes(r)
    S = big.to_bytes(s)

    rc = ecdh.ECP_SvDSA(PK, message, R, S)
    assert rc == True, f"Signature invalid"   

    
    return vector

if __name__ == '__main__':
    # List of test vectors
    vectors = []

    # Generate test vectors 
    for i in range(0, nVec):
        print(f"test {i}")
        vector = genVector(i)
        vectors.append(vector)

    # Write to JSON file
    json.dump(vectors, open("S.json", "w"))

    # Write vectors to text file 
    with open("S.txt", "w") as f:
        for vector in vectors:
            for key, val in vector.items():
                f.write(f"{key} = {val},\n")
            f.write(f"RESULT = 0,\n\n") 
