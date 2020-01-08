#!/usr/bin/env python3

import sys
sys.path.append("../")

import argparse
import sec256k1.shamir as shamir

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-n', dest='n', type=int, default=6, help='n value for the (t,n) SSS/VSS')
    parser.add_argument('-t', dest='t', type=int, default=3, help='t value for the (t,n) SSS/VSS')

    args = parser.parse_args()
    t = args.t
    n = args.n

    print(f"Example ({t},{n}) transform (t,n) to (t,t)\n")

    # Make secret shares from polynomial one
    secret1, shares1, _ = shamir.make_shares(t, n, secret=9)

    print(f"secret1: {secret1}");
    print("shares1:")     
    for share in shares1:
        print(share) 

    # Select t shares and reconcile secret
    x_s, y_s = zip(*shares1[:t])
    coef = shamir.lagrange_interpolate1(x_s)

    secret2, m = shamir.lagrange_interpolate2(coef, y_s)

    print(f"\n\nRecovered secret2 {secret2}\n")
    assert secret1 == secret2, "secret1 != secret2"

    # Convert to (t,t)
    tt = []
    for index, value in enumerate(y_s):
        a = shamir.convert_to_additive_share(x_s, index, value)
        tt.append(a)

    secret3 = 0
    print("additive share:")         
    for _, value in enumerate(tt):
        print(value)
        secret3 = (secret3 + value) % shamir.PRIME

    print(f"\nRecovered secret3 {secret3}\n")
    assert secret1 == secret3, "secret1 != secret3"

        
