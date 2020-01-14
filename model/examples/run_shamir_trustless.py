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

    print(f"Example ({t},{n}) Trustless setup\n")

    # Make secret shares from polynomial one
    secret1, shares1, _ = shamir.make_shares(t, n, secret=9)

    print(f"secret1: {secret1}");
    print("shares1:")     
    for share in shares1:
        print(share) 

    # Make secret shares from polynomial two
    secret2, shares2, _ = shamir.make_shares(t, n, secret=16)

    print(f"\n\nsecret2: {secret2}");    
    print("shares2:")         
    for share in shares2:
        print(share) 

    secret =  (secret1 + secret2) % shamir.PRIME

    shares = []
    for index, _ in enumerate(shares1):
        # print(index, shares1[index][1],  shares2[index][1])
        sum = (shares1[index][1] +  shares2[index][1]) % shamir.PRIME
        share = (shares1[index][0], sum)
        shares.append(share)

    print(f"\n\ncombined secret: {secret}");
    print("combined shares:")         
    for share in shares:
        print(share) 
    
    # Select t shares and reconcile secret
    x_s, y_s = zip(*shares[:t])
    coef = shamir.lagrange_interpolate1(x_s)

    secret3, m = shamir.lagrange_interpolate2(coef, y_s)

    print(f"\n\nRecovered secret {secret3}\n")

    assert secret3 == secret, "secret3 != secret"
