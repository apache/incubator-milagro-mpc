import hashlib
from sec256k1 import big


# --- Integer Factorization ZK proof ---
#
#   Poupard, Stern
#
#   Short Proofs of Knowledge for Factoring
#
#   https://link.springer.com/content/pdf/10.1007%2F978-3-540-46588-1_11.pdf
#

DEBUG = False

# Parameters for n ~ 1024 bit from paper

# nlen = 1024
# A = 1 << nlen
# B = 80
# # C = 1 << 42
# K = 3

# H_param = 'sha256'
# Hprime_param = 'sha1'

# Parameters for n ~ 4096 bit

nlen = 4096
A = 1 << nlen
B = 128
# C = 1 << 128
K = 2

H_param = 'sha256'
Hprime_param = 'sha256'

def nizk_setup(N):
    # TODO It might be possible to use h(n,i) to generate the
    # Zi, but I'm not sure it does not affect K or the non
    # interactive generation. Using the default random generation
    # since this is only done once
    return [big.rand(N) for i in range(K)]

def nizk_prove(N, phiN, Zi, r = None):
    if r is None:
        r = big.rand(A)

    # Compute commitment X = H(z1^r, ..., zK^r)
    H = hashlib.new(H_param)
    for i, Z in enumerate(Zi):
        Zr = pow(Z,r,N)

        if DEBUG:
            print("Z_{} = {}".format(i,Zr))

        H.update(Zr.to_bytes(nlen, byteorder='big'))

    X = H.digest()

    if DEBUG:
        print("X = {}".format(X.hex()))

    # Compute e = H'(N,z1,...,zK,X)
    Hprime = hashlib.new(Hprime_param)
    
    Hprime.update(N.to_bytes(nlen, byteorder='big'))

    for Z in Zi:
        Hprime.update(Z.to_bytes(nlen, byteorder='big'))

    Hprime.update(X)

    e = big.from_bytes(Hprime.digest()[:B//8])

    y = r + (N-phiN) * e

    return e,y

def nizk_verify(Zi, N, e, y):
    # Verifier exponent exp = y - N*e = r - phiN*e
    exp = y - N*e

    inv = False
    if exp < 0:
        exp = -exp
        inv = True

    # Compute verifier X = H(z1^exp,...,xK^exp) = H(z1^r,...,zK^r)
    H = hashlib.new(H_param)
    for i, Z in enumerate(Zi):
        Zr = pow(Z,exp,N)
    
        if inv:
            Zr = big.invmodp(Zr,N)

        if DEBUG:
            print("Z_{} = {}".format(i,Zr))

        H.update(Zr.to_bytes(nlen, byteorder='big'))
    
    X = H.digest()

    # Compute e_verifier = H'(N,z1,...,zK,X)
    Hprime = hashlib.new(Hprime_param)
    
    Hprime.update(N.to_bytes(nlen, byteorder='big'))

    for Z in Zi:
        Hprime.update(Z.to_bytes(nlen, byteorder='big'))

    Hprime.update(X)

    e_verifier = big.from_bytes(Hprime.digest()[:B//8])

    if DEBUG:
        print("E  = {}".format(hex(e)[2:].zfill(B//4)))
        print("EV = {}".format(hex(e_verifier)[2:].zfill(B//4)))

    return e == e_verifier
