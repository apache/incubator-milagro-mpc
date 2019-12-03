import sec256k1.paillier as paillier
import sec256k1.big as big

DEBUG = False

# Step 1 of the MtA protocol, without ZK proof
def initiate(n,g,a,r=None):
    ca, _ = paillier.encrypt(n,g,a,r)

    # TODO ZK proof a < K

    if DEBUG:
        print("ca {}".format(hex(ca)[2:]))

    return ca

# Step 2 of the MtA protocol, without ZK check or proofs
def receive(n,g,q,b,ca,beta=None,r=None):
    # TODO ZK check ca = E(a), a < K
    # TODO ZK proof b < K

    t = paillier.mult(ca,b,n)

    if beta is None:
        beta = big.rand(q)
        if DEBUG:
            print("beta' {}".format(hex(beta)[2:]))

    eb, _ = paillier.encrypt(n,g,beta,r)
    cb = paillier.add(t,eb,n)

    # TODO if MtAwC then ZK proof of knowledge of b, beta

    beta = big.modsub(q,beta,q)

    if DEBUG:
        print("t    {}".format(hex(t)[2:]))
        print("eb   {}".format(hex(eb)[2:]))
        print("cb   {}".format(hex(cb)[2:]))
        print("beta {}".format(hex(beta)[2:]))

    return beta, cb

# Step 3 of the MtA protocol, without ZK check
def complete(n,l,m,q,cb):
    # TODO ZK check cb = E(b), b < K
    # TODO if MtAwC ZK check knowledge of b, beta

    alpha = paillier.decrypt(n,l,m,cb)
    alpha = alpha % q

    if DEBUG:
        print("alpha {}".format(hex(alpha)))

    return alpha
