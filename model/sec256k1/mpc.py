import hashlib
import sec256k1.curve as curve
import sec256k1.ecdh as ecdh
import sec256k1.ecp as ecp
import sec256k1.big as big
import sec256k1.paillier as paillier
import sec256k1.mta as mta

def hashit(M):
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

    return big.from_bytes(B)

def initiate(k=None, g=None):
    if k is None:
        k = big.rand(curve.r)

    if g is None:
        g = big.rand(curve.r)

    G = g * ecp.generator()

    return k,g,G

def combine_fp_shares(shares, initial_value=0):
    '''Combine additive shares in F_(curve.r)

        Compute [initial_value +] sum(shares)

    '''
    c = initial_value
    for share in shares:
        c = c + share

    return c % curve.r

def combine_ecp_shares(shares, initial_value=None):
    '''Combine  additive shares in EC(Fp)

        Compute [initial_value +] sum(shares)

    '''
    if initial_value is None:
        initial_value = ecp.ECp()

    c = initial_value
    for share in shares:
        c.add(share)

    return c

def reconciliate_r(deltas,Gammas):
    kg = combine_fp_shares(deltas)
    invkg = big.invmodp(kg, curve.r)

    R = combine_ecp_shares(Gammas)
    R = invkg * R

    r = R.getx() % curve.r

    return r, R

def make_signature_share(M,k,r,s):
    m = hashit(M)
    return (k * m + r * s) % curve.r
