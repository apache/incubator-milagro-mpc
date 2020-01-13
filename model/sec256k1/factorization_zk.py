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

# nlen = 1024 // 8
# A = 1 << (8 * nlen)
# B = 80
# K = 3

# H_param = 'sha256'
# Hprime_param = 'sha1'
# hlen = 32

# Parameters for n ~ 2048 bit estimated using
# the script in parameters/factorization_zk.py

nlen = 2048 // 8
A = 1 << (8 * nlen)
B = 128
K = 2

H_param = 'sha256'
Hprime_param = 'sha256'
hlen = 32

# Parameters for n ~ 4096 bit estimated using
# the script in parameters/factorization_zk.py

# nlen = 4096 // 8
# A = 1 << (8 * nlen)
# B = 128
# K = 2

# H_param = 'sha256'
# Hprime_param = 'sha256'
# hlen = 32

def nizk_setup(N):
    """ Compute the generators z_i deterministically

    The generators are computed using a one way function as
    outlined in Section 3.3 of the paper

    Args::

        N: public integer to prove the factorization

    Returns::

        Zi: public generators
    """

    # ceil(nlen//hlen)
    chunks = -(-nlen // hlen)

    Nbytes = N.to_bytes(nlen, byteorder='big')

    Zi = []

    i = 0
    for _ in range(K):
        Zk = b''
        for _ in range(chunks):
            H = hashlib.new(H_param)
            H.update(Nbytes)

            i_bytes = i.to_bytes(1, byteorder='big')
            H.update(i_bytes)

            Zk = Zk + H.digest()

            i = i+1

        Zk = int.from_bytes(Zk, byteorder='big')
        Zk = Zk % N
        Zi.append(Zk)

    return Zi

def nizk_prove(N, P, Q, Zi, r = None):
    """ Compute ZK proof of knowledge of factorization of N

    Args::

        N:  public integer to prove the factorization
        P:  first factor of N
        Q:  second factor of N
        Zi: public generators for the subgroups
        r:  random value in [0, ..., A]. Optional

    Returns::

        e: public challenge for the ZK proof
        y: proof of knowledge of factorization
    """

    if r is None:
        r = big.rand(A)

    # Compute commitment X = H(z1^r, ..., zK^r)
    H = hashlib.new(H_param)
    for i, Z in enumerate(Zi):
        Zrp = pow(Z % P, r, P)
        Zrq = pow(Z % Q, r, Q)

        Zr = big.crt(Zrp, Zrq, P, Q)

        if DEBUG:
            print("Z_{} = {}".format(i,Zr))

        H.update(Zr.to_bytes(nlen, byteorder='big'))

    X = H.digest()

    if DEBUG:
        print("X = {}".format(X.hex()))

    # Compute public challenge e = H'(N,z1,...,zK,X)
    Hprime = hashlib.new(Hprime_param)

    Hprime.update(N.to_bytes(nlen, byteorder='big'))

    for Z in Zi:
        Hprime.update(Z.to_bytes(nlen, byteorder='big'))

    Hprime.update(X)

    e = big.from_bytes(Hprime.digest()[:B//8])

    # Compute proof for the public challenge
    y = r + (N - (P-1) * (Q-1)) * e

    return e,y

def nizk_verify(Zi, N, e, y):
    """ Verify ZK proof of knowledge of factorization of N

    Args::

        Zi:   public generators for the subgroups
        N:    public integer to prove the factorization
        e: public challenge for the ZK proof
        y: proof of knowledge of factorization

    Returns::

        True if the ZK proof is correct, False otherwise
    """
    if y < 0 or y > A:
        return False

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
