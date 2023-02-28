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
from bench import time_func

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from amcl import core_utils, shamir

seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"

k = 5
n = 10


if __name__ == "__main__":
    # random number generator
    seed = bytes.fromhex(seed_hex)
    rng = core_utils.create_csprng(seed)

    ## Shamir Secret Sharing

    # Generate quantities for benchmark
    shares, S = shamir.make_shares(k, n, rng)
    S_rec = shamir.recover_secret(shares[:k])
    assert S == S_rec, "Error generating quantities for SSS benchmark"

    (X, _) = zip(*(shares[:k]))
    X = [x for x in X]
    X.pop(0)

    # Run benchmark
    fncall = lambda: shamir.make_shares(k, n, rng)
    time_func("make_shares      ", fncall, unit="ms")

    fncall = lambda: shamir.recover_secret(shares[:k])
    time_func("recover_secret   ", fncall, unit="ms")

    fncall = lambda: shamir.to_additive(shares[0], X)
    time_func("to_additive      ", fncall, unit="us")

    ## Verifiable Secret Sharing

    # Generate quantities for benchmark
    shares, checks, S = shamir.vss_make_shares(k, n, rng)
    rc = shamir.vss_verify_shares(shares[0], checks)

    assert rc == shamir.OK, "Error generating quantities for VSS benchmark - Share verification"

    S_rec = shamir.recover_secret(shares[:k])
    assert S == S_rec, "Error generating quantities for VSS benchmark - wrong recovered secret"

    # Run benchmark
    fncall = lambda: shamir.vss_make_shares(k, n, rng)
    time_func("vss_make_shares  ", fncall, unit="ms")

    fncall = lambda: shamir.vss_verify_shares(shares[0], checks)
    time_func("vss_verify_shares", fncall, unit="ms")
