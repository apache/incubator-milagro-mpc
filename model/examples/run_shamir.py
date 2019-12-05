#!/usr/bin/env python3

import sys
sys.path.append("../")

import argparse
import sec256k1.shamir as shamir

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-n', dest='n', type=int, default=4, help='n value for the (t,n) SSS/VSS')
    parser.add_argument('-t', dest='t', type=int, default=3, help='t value for the (t,n) SSS/VSS')

    args = parser.parse_args()
    t = args.t
    n = args.n

    print("Example ({},{}) secret sharing\n".format(t,n))

    ## Run Shamir without checks
    print("Run SSS")

    # Make secret shares
    secret1, shares, _ = shamir.make_shares(t, n)

    print("Shared secret {}\n".format(hex(secret1)[2:].zfill(64)))

    print("Secret shares\n")
    for share in shares:
        x,y = share
        print("\t({}, {})".format(x, hex(y)[2:].zfill(64)))
    print("")

    # Select t shares and reconcile secret
    x_s, y_s = zip(*shares[:t])
    coef = shamir.lagrange_interpolate1(x_s)

    print("Interpolation coefficients\n")
    for c in coef:
        print("\t{}".format(hex(c)[2:].zfill(64)))
    print("")

    secret2, m = shamir.lagrange_interpolate2(coef, y_s)
    print("Polynomial coefficients\n")
    for c in m:
        print("\t{}".format(hex(c)[2:].zfill(64)))
    print("")

    print("Recovered secret {}".format(hex(secret2)[2:].zfill(64)))

    assert secret1 == secret2, "secret1 != secret2"

    ## Run Shamir with checks
    print("\nRun VSS")

    # Make secret shares
    secret1, shares, checks = shamir.make_shares(t, n, check=True)

    print("Shared secret {}".format(hex(secret1)[2:].zfill(64)))

    print("Secret shares\n")
    for share in shares:
        x,y = share
        print("\t{} {}".format(x, hex(y)[2:].zfill(64)))
    print("")

    # Check shares consistency
    for share in shares:
        (x,y) = share

        assert shamir.verify_share(checks, share), "inconsistent share ({}, {})".format(x, hex(y)[2:].zfill(64))

    print("All shares consistent\n")

    # Select t shares and reconcile secret
    x_s, y_s = zip(*shares[:t])
    coef = shamir.lagrange_interpolate1(x_s)

    print("Interpolation coefficients\n")
    for c in coef:
        print("\t{}".format(hex(c)[2:].zfill(64)))
    print("")

    secret2, m = shamir.lagrange_interpolate2(coef, y_s)
    print("Polynomial coefficients\n")
    for c in m:
        print("\t{}".format(hex(c)[2:].zfill(64)))
    print("")

    print("Recovered secret {}".format(hex(secret2)[2:].zfill(64)))

    assert secret1 == secret2, "secret1 != secret2"
