#!/usr/bin/env python3

import hashlib

import sec256k1.paillier_v1 as paillier
import sec256k1.ecdh as ecdh
import sec256k1.big as big
import sec256k1.curve as curve
import sec256k1.ecp as ecp

def hash(M):
    """ Hash message to SHA256."""
    h = hashlib.new(curve.SHA)
    h.update(M)
    H = h.digest()
    HS = h.digest_size
    if HS >= curve.EFS:
        B = H[0:curve.EFS]
    else:
        B = bytearray(curve.EFS)
        for i in range(0, HS):
            B[i + curve.EFS - HS] = H[i]

    m = big.from_bytes(B)

    return m


class Share:
    """Represents a secret share in the MPC protocol.

    User to store the values to be tranformed from multiplicatative to 
    additive shares. Also, performs all the calculations.

    alice.alpha + bob.beta = alice.a * bob.b 

    """

    nshares = 0

    def __init__(self, n, g, l, m, a, b):
        """Initializes the instance."""        
        self.n = n
        self.g = g
        self.l = l
        self.m = m
        self.a = a        
        self.b = b
        self.z = 0
        self.r = 0        
        self.alpha = 0
        self.beta = 0        

    def client1(self, r=None):
        """Encrypt the a value."""
        # ca = E_A(a)

        if r is None:
            self.r = big.rand(curve.r)
        else:
            self.r = r
            
        ca, r = paillier.encrypt(self.n, self.g, self.a, self.r)
        
        return ca, self.r

    def client2(self, cb):
        """Decrypt the response for the other party."""
        # t = D_A(E_A(ab + z))
        t = paillier.decrypt(self.n, self.l, self.m, cb)
        self.alpha = t % curve.r

    def server(self, n, g, ca, z=None, r=None):
        """Calculate E_A(ab + z) and the beta value"""

        if z is None:
            self.z = big.rand(curve.r)
        else:
            self.z = z

        if r is None:
            self.r = big.rand(curve.r)
        else:
            self.r = r
            
        # t = E_A(ab)    
        t = paillier.mult(ca, self.b, n)

        # cz = E_A(z)
        cz, r = paillier.encrypt(n, g, self.z, self.r)

        # cb  = E_A(ab + z)
        cb = paillier.add(t, cz, n)

        # beta = -z
        self.beta = big.modsub(curve.r, self.z, curve.r)

        return cb, self.r, self.z

    def sum(self):
        """Sum component parts of product

           sum = a.b + alpha + beta
        """
        sum = ( (self.a * self.b) + self.alpha + self.beta) % curve.r
        
        return sum
    
    def __repr__(self):
        return {'a':self.a, 'b':self.b}

    def __str__(self):
        return f"z={hex(self.z)[2:].zfill(512)},\nr={hex(self.r)[2:].zfill(512)},\na={hex(self.a)[2:].zfill(512)},\nb={hex(self.b)[2:].zfill(512)},\nalpha={hex(self.alpha)[2:].zfill(512)},\nbeta={hex(self.beta)[2:].zfill(512)}"

    @classmethod
    def how_many(cls):
        """Prints number of shares"""
        print("{} shares".format(cls.nshares))
    
    

class Player:
    """Represents an actor in the MPC protocol.

       Generate Paillier keys and ECDSA key shares
    """

    nplayers = 0

    def __init__(self, name, p, q, sk=None, k=None, gamma=None):
        """Initializes the instance."""        
        self.name = name

        self.p = p
        self.q = q        
        self.n, self.g, self.l, self.m = paillier.keys(p,q)

        if sk:
            sk = bytes.fromhex(sk)
        W, PK = ecdh.ECP_KeyPairGenerate(sk)
        self.w = big.from_bytes(W) % curve.r
        self.pk = ecp.ECp()
        self.pk.fromBytes(PK)       
        
        if k is None:
            self.k = big.rand(curve.r)
        else:
            self.k = k
            
        if gamma is None:
            self.gamma = big.rand(curve.r)
        else:
            self.gamma = gamma
        self.Gamma = self.gamma * ecp.generator()

        self.kgamma = Share(self.n, self.g, self.l, self.m, self.k, self.gamma)
        self.kw = Share(self.n, self.g, self.l, self.m, self.k, self.w)

        Player.nplayers += 1

    def updateGamma(self, invkgamma):
        """Multiply Gamma by the inverse of kgamma."""
        self.Gamma = invkgamma * self.Gamma

    def s(self, m, r):
        """Calculate s component of signature.

           s = (k * (m + sk * r)) % curve.r
             = (k * m + k * sk * r) % curve.r 
             = (k * m + sigma * r) % curve.r      
        """
        km = self.k * m % curve.r
        sigma = self.kw.sum()
        rsigma = r * sigma  % curve.r
        return (km + rsigma) %  curve.r
        
    def __repr__(self):
        return {'name':self.name, 'n':self.n}
    
    def __str__(self):
        Gamma = self.Gamma.toBytes(False).hex()
        PK = self.pk.toBytes(False).hex()
        return f"\n{self.name} start:\n\nPaillier:\nn={hex(self.n)},\ng={hex(self.g)},\nl={hex(self.l)},\nm={hex(self.m)},\n\nECDSA:\nsk={hex(self.w)},\npk={PK},\n\nGamma={Gamma},\n\nkgamma:\n{self.kgamma},\n\nkw:\n{self.kw}\n\n{self.name} end:"    
    

    @classmethod
    def how_many(cls):
        """Prints number of players"""
        print("{} players".format(cls.nplayers))



