#!/usr/bin/env python3

"""
   Generates a set of test vectors. 

   usage: genEncryptVectors.py 
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

    ### alice.k * bob.gamma ###

    vector['P1'] = hex(alice.p)[2:].zfill(256)
    vector['Q1'] = hex(alice.q)[2:].zfill(256)
    vector['A1'] = hex(alice.k)[2:].zfill(64)
    vector['B2'] = hex(bob.gamma)[2:].zfill(64)

    ca, r = alice.kgamma.client1()
    vector['R11'] = hex(r)[2:].zfill(1024)     

    cb, r, z = bob.kgamma.server(alice.n, alice.g, ca)
    vector['R12'] = hex(r)[2:].zfill(1024)
    vector['Z12'] = hex(z)[2:].zfill(64)         
    vector['BETA2'] = hex(bob.kgamma.beta)[2:].zfill(64)

    alice.kgamma.client2(cb)
    vector['ALPHA1'] = hex(alice.kgamma.alpha)[2:].zfill(64)

    expected = alice.k * bob.gamma % curve.r        
    got = ( alice.kgamma.alpha + bob.kgamma.beta ) % curve.r
    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

    ### bob.k * alice.gamma ###

    vector['P2'] = hex(bob.p)[2:].zfill(256)
    vector['Q2'] = hex(bob.q)[2:].zfill(256)
    vector['A2'] = hex(bob.k)[2:].zfill(64)
    vector['B1'] = hex(alice.gamma)[2:].zfill(64)

    ca, r = bob.kgamma.client1()
    vector['R22'] = hex(r)[2:].zfill(1024)     

    cb, r, z = alice.kgamma.server(bob.n, bob.g, ca)
    vector['R21'] = hex(r)[2:].zfill(1024)
    vector['Z21'] = hex(z)[2:].zfill(64)         
    vector['BETA1'] = hex(alice.kgamma.beta)[2:].zfill(64)

    bob.kgamma.client2(cb)
    vector['ALPHA2'] = hex(bob.kgamma.alpha)[2:].zfill(64)

    expected = bob.k * alice.gamma % curve.r        
    got = ( bob.kgamma.alpha + alice.kgamma.beta ) % curve.r
    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

    ### kgamma = (alice.k + bob.k)(alice.gamma + bob.gamma)

    kgamma = ( alice.kgamma.sum() + bob.kgamma.sum() ) % curve.r
    
    vector['SUM1'] = hex(alice.kgamma.sum())[2:].zfill(64)
    vector['SUM2'] = hex(bob.kgamma.sum())[2:].zfill(64)
    vector['KGAMMA'] = hex(kgamma)[2:].zfill(64)        
    
    k = (alice.k + bob.k) % curve.r
    gamma = (alice.gamma + bob.gamma) % curve.r
    expected = k * gamma % curve.r

    assert kgamma == expected, f"expected {hex(expected)} got {hex(kgamma)}"

    ### Calculate r component of signature

    # Calculate (k.gamma)^{-1} 
    invkgamma = big.invmodp(kgamma, curve.r)

    aliceGamma = alice.Gamma.toBytes(False).hex()
    bobGamma = bob.Gamma.toBytes(False).hex()    
    
    # Add Gamma values
    R = ecp.ECp()
    R.add(alice.Gamma)
    R.add(bob.Gamma)
    SUMGAMMAPT = R.toBytes(False).hex()
    
    # Gamma by (k.gamma)^{-1}     
    R = invkgamma * R
    RPT = R.toBytes(False).hex()
    
    # x component is r value 
    r = R.getx() % curve.r

    vector['INVKGAMMA'] = hex(invkgamma)[2:].zfill(64)
    vector['GAMMAPT1'] = aliceGamma
    vector['GAMMAPT2'] = bobGamma
    vector['SUMGAMMAPT'] = SUMGAMMAPT
    vector['RPT'] = RPT
    vector['SIG_R'] = hex(r)[2:].zfill(64)

    invk = big.invmodp(k, curve.r)
    expected = invk * ecp.generator()
    assert R == expected, f"expected {expected} got {R}"   
        
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
    json.dump(vectors, open("R.json", "w"))

    # Write vectors to text file 
    with open("R.txt", "w") as f:
        for vector in vectors:
            for key, val in vector.items():
                f.write(f"{key} = {val},\n")
            f.write(f"RESULT = 0,\n\n") 
