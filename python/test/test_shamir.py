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
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from amcl import core_utils, shamir


q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class TestShamir(unittest.TestCase):
    """ Test Shamir Secret Sharing """

    def setUp(self):
        self.k = 10
        self.n = 15

        # Deterministic PRNG for testing purposes
        seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"
        seed = bytes.fromhex(seed_hex)
        self.rng = core_utils.create_csprng(seed)

        S_hex = "fab4ce512dff74bd9c71c89a14de5b877af45dca0329ee3fcb72611c0784fef3"
        self.S = bytes.fromhex(S_hex)

    def test_deterministic(self):
        """ Test using provided secret """

        shares, _ = shamir.make_shares(self.k, self.n, self.rng, self.S)

        s = shamir.recover_secret(shares[:self.k])

        self.assertEqual(s, self.S, "Recovered wrong secret")

    def test_random(self):
        """ Test generating random secret """

        shares, s_golden = shamir.make_shares(self.k, self.n, self.rng)
        s = shamir.recover_secret(shares)

        self.assertEqual(s, s_golden, "Recovered wrong secret")


class TestToAdditive(unittest.TestCase):
    """ Test conversion to additive shares """

    def setUp(self):
        self.k = 10
        self.n = 15

        # Deterministic PRNG for testing purposes
        seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"
        seed = bytes.fromhex(seed_hex)
        rng = core_utils.create_csprng(seed)

        self.shares, self.S = shamir.make_shares(self.k, self.n, rng)

        # Unzip shares into list and trim to k elements
        self.x, _ = zip(*self.shares)
        self.x = [x for x in self.x]
        self.x = self.x[:self.k]

    def test_conversion(self):
        """ Test conversion """

        accum = 0
        for i in range(self.k):
            # Remove current share from other participant shares
            other_x = self.x.copy()
            other_x.pop(i)

            a_share = shamir.to_additive(self.shares[i], other_x)

            sh = int.from_bytes(a_share, byteorder='big')
            accum = (accum + sh) % q

        recovered_s = accum.to_bytes(shamir.EGS, byteorder='big')

        self.assertEqual(self.S, recovered_s, "Recovered wrong secret")


class TestVSS(unittest.TestCase):
    """ Test Verifiable Secret Sharing """

    def setUp(self):
        self.k = 10
        self.n = 15

        # Deterministic PRNG for testing purposes
        seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"
        seed = bytes.fromhex(seed_hex)
        self.rng = core_utils.create_csprng(seed)

        S_hex = "fab4ce512dff74bd9c71c89a14de5b877af45dca0329ee3fcb72611c0784fef3"
        self.S = bytes.fromhex(S_hex)

    def test_deterministic(self):
        """ Test using provided secret """

        shares, _, _ = shamir.vss_make_shares(self.k, self.n, self.rng, self.S)
        s = shamir.recover_secret(shares)

        self.assertEqual(s, self.S, "Recovered wrong secret")

    def test_random(self):
        """ Test generating random secret """

        shares, _, s_golden = shamir.vss_make_shares(self.k, self.n, self.rng)
        s = shamir.recover_secret(shares)

        self.assertEqual(s, s_golden, "Recovered wrong secret")

    def test_verify(self):
        """ Test shares verification """

        shares, checks, _ = shamir.vss_make_shares(self.k, self.n, self.rng)

        for i, share in enumerate(shares):
            rc = shamir.vss_verify_shares(share, checks)

            self.assertEqual(rc, shamir.OK, f"Invalid Share {i}: {rc}")


if __name__ == '__main__':
    unittest.main()
