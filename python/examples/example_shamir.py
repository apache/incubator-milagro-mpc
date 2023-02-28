#!/usr/bin/env python3

"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from amcl import core_utils, shamir

seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"

k = 5
n = 10

q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

if __name__ == "__main__":
    # random number generator
    seed = bytes.fromhex(seed_hex)
    rng = core_utils.create_csprng(seed)

    ## Shamir Secret Sharing
    print("Example Shamir Secret Sharing")
    print(f"k = {k}, n = {n}")

    # Generate secret and compute shares
    shares, S = shamir.make_shares(k, n, rng)

    print("\n[Dealer] Generate secret and shares")
    print(f"\tS = {S.hex()}\n")

    for i, (x, y) in enumerate(shares):
        print(f"\tshare[{i}].X = {x.hex()}")
        print(f"\tshare[{i}].Y = {y.hex()}")
        print("")

    # Recover Secret using k of the shares
    S_rec = shamir.recover_secret(shares[:k])

    print("[Player] Recover secret using k shares")
    for i, (x, y) in enumerate(shares[:k]):
        print(f"\tshare[{i}].X = {x.hex()}")
        print(f"\tshare[{i}].Y = {y.hex()}")
        print("")

    print("[Player] Recovered Secret:")
    print(f"\tS = {S_rec.hex()}")

    if S_rec != S:
        print("[Player] Failure Recovering Secret")
        sys.exit(1)

    ## Shamir to Additive Conversion
    #
    # Participants need the X component of the other players shares
    print("\nExample Shamir to Additive Shares conversion")
    print("Using the same shares as above")
    print("\nConvert Shares")
    additive_shares = []
    for i in range (k):
        # Select X component of shares for other participants
        (X, _) = zip(*(shares[:k]))
        X = [x for x in X]
        X.pop(i)

        additive_share = shamir.to_additive(shares[i], X)
        additive_shares.append(additive_share)

    additive_secret = 0
    for i, share in enumerate(additive_shares):
        print(f"\tshare[{i}] = {share.hex()}")
        additive_share = int.from_bytes(share, byteorder='big')
        additive_secret = (additive_secret + additive_share) % q

    additive_secret = additive_secret.to_bytes(shamir.EGS, byteorder='big')
    print("\nReconstructed secret")
    print(f"\tS = {additive_secret.hex()}")

    if additive_secret != S:
        print("[Dealer] Failure Recovering Additive Secret")
        sys.exit(1)

    ## Verifiable Secret Sharing
    print("\nExample Verifiable Secret Sharing")
    print(f"k = {k}, n = {n}")

    # Reuse secret from above, make shares and checks
    shares, checks, _ = shamir.vss_make_shares(k, n, rng, S = S)

    print("\n[Dealer] Make shares and Checks")
    print(f"\tS = {S.hex()}\n")

    for i, (x, y) in enumerate(shares):
        print(f"\tshare[{i}].X = {x.hex()}")
        print(f"\tshare[{i}].Y = {y.hex()}")
        print("")

    for i, c in enumerate(checks):
        print(f"\tcheck[{i}] = {c.hex()}")

    # Verify received share
    for i, share in enumerate(shares):
        rc = shamir.vss_verify_shares(share, checks)
        print(f"\n[Player] {i}-th player - verify received share")
        if rc == shamir.OK:
            print("\tSuccess")
        else:
            print(f"\tFailure: {rc}")
            sys.exit(1)

    # Recover Secret using k of the shares
    S_rec = shamir.recover_secret(shares[:k])

    print("\n[Player] Recover secret using k shares")
    for i, (x, y) in enumerate(shares[:k]):
        print(f"\tshare[{i}].X = {x.hex()}")
        print(f"\tshare[{i}].Y = {y.hex()}")
        print("")

    print("[Player] Recovered Secret:")
    print(f"\tS = {S_rec.hex()}")

    if S_rec != S:
        print("[Player] Failure Recovering Secret")
        sys.exit(1)
