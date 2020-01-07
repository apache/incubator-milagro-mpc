import sec256k1.big as big

DEBUG = False


def keys(p, q):
    n = p * q
    g = n + 1
    l = (p - 1) * (q - 1)
    m = big.invmodp(l, n)

    return n, g, l, m


def encrypt(n, g, pt, r=None):
    n2 = n * n

    if r is None:
        r = big.rand(n)

    if DEBUG:
        print("r {}".format(hex(r)))

    rn = pow(r, n, n2)
    gpt = pow(g, pt, n2)
    ct = (rn * gpt) % n2

    return ct, r


def decrypt(n, l, m, ct):
    n2 = n * n
    ctl = pow(ct, l, n2) - 1
    ctln = ctl // n
    pt = big.modmul(ctln, m, n)

    if DEBUG:
        print("decrypt n2 {}\n".format(hex(n2)))
        print("decrypt ctl {}\n".format(hex(ctl)))
        print("decrypt n {}\n".format(hex(n)))
        print("decrypt ctln {}\n".format(hex(ctln)))
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
