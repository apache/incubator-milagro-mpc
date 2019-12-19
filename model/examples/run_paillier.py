#!/usr/bin/env python3

import sys
sys.path.append('../')
import sec256k1.paillier as paillier

if __name__ == "__main__":

    # keys
    p = 0x94f689d07ba20cf7c7ca7ccbed22ae6b40c426db74eaee4ce0ced2b6f52a5e136663f5f1ef379cdbb0c4fdd6e4074d6cff21082d4803d43d89e42fd8dfa82b135aa31a8844ffea25f255f956cbc1b9d8631d01baf1010d028a190b94ce40f3b72897e8196df19edf1ff62e6556f2701d52cef1442e3301db7608ecbdcca703db
    q = 0x9a9ad73f246df853e129c589925fdad9df05606a61081e62e72be4fb33f6e5ec492cc734f28bfb71fbe2ba9a11e4c02e2c0d103a5cbb0a9d6402c07de63b1b995dd72ac8f29825d66923a088b421fb4d52b0b855d2f5dde2be9b0ca0cee6f7a94e5566735fe6cff1fcad3199602f88528d19aa8d0263adff8f5053c38254a2a3

    n, g, lp, lq, mp, mq = paillier.keys(p, q)
    print("n  {}".format(hex(n)[2:].zfill(256)))
    print("g  {}".format(hex(g)[2:].zfill(256)))
    print("lp {}".format(hex(lp)[2:].zfill(128)))
    print("mp {}".format(hex(mp)[2:].zfill(128)))
    print("lq {}".format(hex(lq)[2:].zfill(128)))
    print("mq {}".format(hex(mq)[2:].zfill(128)))

    # encrypt plaintext 1
    r1 = 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018c5947fda2edea04c1f87c207e0bab17aff5f77ac21d04cb194631efd1f7256dc37de9473fc86009df36206974859c09023ac8179b02aacea8d89a01f4de161db955d450cef55ce959897636973b952371e349778e67c61ef6fae5f73fd728d423a594b6a76d5faca97d59d6ae40c53f3bd42dfccc93183e355422ba7af308a87d32c0352d478156275f98bc74e9ed4f2c7a9853c9f35b996fafe765b56c7f2e83771c6b676b75436e5c1697b838b3908aee92001cbccf3bf6cfb7aaea27a358a12cfe1ddde886b975ae14517e5912eba3ff9792e46403a998edd371020bbc5fbd6a705e669383303030ef79653ce16e13122233c626bb101ee8dd27bf4ff86
    pt1 = 3
    print("pt1 {}".format(hex(pt1)[2:].zfill(256)))
    ct1, r = paillier.encrypt(n, g, pt1, r1)
    print("ct1 {}".format(hex(ct1)[2:].zfill(512)))
    print("r {}".format(hex(r)[2:].zfill(256)))
    assert r1 == r, "r1 != r"

    # encrypt plaintext 2
    r2 = 0x25b608a45a986bc8f304ba2354a83dc596bfe911defba7b1860f9edf0d20c1c20b379390f6f54f78cdd6219c90b2bd3f45d28d07fcdf9fcce0a7458e49f2bb265864281544898ad56aa7493adfaab58910472a8068c9ca65c652059dbec937290cc92a9014298b5535b79123817a7cc6e0c58755d5ff69efbf80b470bae0b434b01b9bbb83b932bd8743beb72a0d018bc137c9ead7a9aec1643d6cb78e7ae84e039c85f70fcc812c4e08d0f8f839803e48bb86f4fd3f79816a42fcc7a9b281d055152d5ed622c55d99ef7b1d62b96d3c4c22881a1a4fcfe496b704101c104f275bbac4068a3609ff4b1b29c58deb337f2f4d9446a9db6389658bde561910ee62
    pt2 = 7
    print("pt2 {}".format(hex(pt2)[2:].zfill(256)))
    ct2, r = paillier.encrypt(n, g, pt2, r2)
    print("ct2 {}".format(hex(ct2)[2:].zfill(512)))
    assert r2 == r, "r2 != r"
    print("r {}".format(hex(r)[2:].zfill(256)))

    # decrypt ciphertext 1
    dec1 = paillier.decrypt(p, q, lp, lq, mp, mq, ct1)
    print("dec {}".format(hex(dec1)[2:].zfill(256)))
    print("pt1 {}".format(hex(pt1)[2:].zfill(256)))
    print("pt1 {}".format(pt1))
    assert pt1 == dec1, "pt1 != dec1"

    # decrypt ciphertext 2
    pt2 = paillier.decrypt(p, q, lp, lq, mp, mq, ct2)
    print("pt2 {}".format(hex(pt2)[2:].zfill(256)))
    print("pt2 {}".format(pt2))

    # Homomorphic addition of plaintexts
    ct3 = paillier.add(ct1, ct2, n)
    print("ct3 {}".format(hex(ct3)[2:].zfill(512)))

    # decrypt ciphertext 3
    pt3 = paillier.decrypt(p, q, lp, lq, mp, mq, ct3)
    print("pt3 {}".format(hex(pt3)[2:].zfill(256)))
    print("pt3 {}".format(pt3))

    pt12 = (pt1 + pt2) % n
    print("pt12 {}".format(pt12))
    assert pt12 == pt3, "pt12 != pt3"

    # ct4 = ct1 * pt2
    ct4 = paillier.mult(ct1, pt2, n)
    print("ct4 {}".format(hex(ct4)[2:].zfill(512)))

    # decrypt ciphertext 4
    pt4 = paillier.decrypt(p, q, lp, lq, mp, mq, ct4)
    print("pt4 {}".format(hex(pt4)[2:].zfill(256)))
    print("pt4 {}".format(pt4))

    pt12 = (pt1 * pt2) % n
    print("pt12 {}".format(pt12))
    assert pt12 == pt4, "pt12 != pt4"
