#!/usr/bin/env python3

"""
   Generates a set of test vectors. 

   usage: genEncryptVectors.py 
"""

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

    vector['TEST'] = test_no + 1

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

    ### alice.k * bob.gamma ###

    vector['N'] = hex(alice.n)[2:].zfill(512)
    vector['G'] = hex(alice.g)[2:].zfill(512)
    vector['L'] = hex(alice.l)[2:].zfill(512)
    vector['M'] = hex(alice.m)[2:].zfill(512)        
    vector['A'] = hex(alice.k)[2:].zfill(64)
    vector['B'] = hex(bob.gamma)[2:].zfill(64)

    # vector['s = alice.k * bob.gamma'] = hex(expected)[2:].zfill(512)}\n")
    
    ca, r1 = alice.kgamma.client1()
    vector['CA'] = hex(ca)[2:].zfill(1024)
    vector['R1'] = hex(r1)[2:].zfill(512)     

    cb, r2, z = bob.kgamma.server(alice.n, alice.g, ca, z)
    vector['CB'] = hex(cb)[2:].zfill(1024)
    vector['R2'] = hex(r2)[2:].zfill(512)
    vector['Z'] = hex(z)[2:].zfill(64)         
    vector['BETA'] = hex(bob.kgamma.beta)[2:].zfill(64)

    alice.kgamma.client2(cb)
    vector['ALPHA'] = hex(alice.kgamma.alpha)[2:].zfill(64)

    expected = alice.k * bob.gamma % curve.r        
    got = ( alice.kgamma.alpha + bob.kgamma.beta ) % curve.r
    #print(f"expected {hex(expected)    
    #print(f"got {hex(got)
    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

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
    json.dump(vectors, open("MTA.json", "w"))

    # Write vectors to text file 
    with open("MTA.txt", "w") as f:
        for vector in vectors:
            for key, val in vector.items():
                f.write(f"{key} = {val},\n")
            f.write(f"RESULT = 0,\n\n") 
