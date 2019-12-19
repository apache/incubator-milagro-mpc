import sec256k1.big as big

DEBUG = False


def keys(p, q):
    n = p * q
    g = n + 1

    lp = p - 1
    lq = q - 1

    mp = (pow(g, lp, p * p) - 1) // p
    mp = big.invmodp(mp, p)

    mq = (pow(g, lq, q * q) - 1) // q
    mq = big.invmodp(mq, q)

    return n, g, lp, lq, mp, mq


def encrypt(n, g, pt, r=None):
    n2 = n * n

    if r is None:
        r = big.rand(n2)

    rn = pow(r, n, n2)
    gpt = pow(g, pt, n2)
    ct = (rn * gpt) % n2

    return ct, r


def decrypt(p, q, lp, lq, mp, mq, ct):
    p2 = p * p
    ctp = (pow(ct, lp, p2) - 1) // p
    ptp = big.modmul(ctp, mp, p)

    q2 = q * q
    ctq = (pow(ct, lq, q2) - 1) // q
    ptq = big.modmul(ctq, mq, q)

    pt = big.crt(ptp, ptq, p, q)

    if DEBUG:
        print("decrypt q2 {}\n".format(hex(p2)))
        print("decrypt p2 {}\n".format(hex(q2)))
        print("decrypt ctp {}\n".format(hex(ctp)))
        print("decrypt ctq {}\n".format(hex(ctq)))
        print("decrypt ptp {}\n".format(hex(ptp)))
        print("decrypt ptq {}\n".format(hex(ptq)))
        print("decrypt pt {}\n".format(hex(pt)))

    return pt


def add(a, b, n):
    n2 = n * n
    c = a * b
    d = c % n2

    if DEBUG:
        print("add ct1: {}\n".format(hex(a)))
        print("add ct2: {}\n".format(hex(b)))
        print("add n: {}\n".format(hex(n)))
        print("add n^2: {}\n".format(hex(n2)))
        print("add ct1 * ct2: {}\n".format(hex(c)))
        print("add ct1 * ct2 mod n^2: {}\n".format(hex(d)))

    return d


def mult(a, b, n):
    n2 = n * n
    c = pow(a, b, n2)

    if DEBUG:
        print("add n: {}\n".format(hex(n)))
        print("add n^2: {}\n".format(hex(n2)))
        print("add a^b mod n^2: {}\n".format(hex(c)))

    return c
