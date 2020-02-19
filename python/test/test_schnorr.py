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

from amcl import core_utils, schnorr


class TestCommit(unittest.TestCase):
    """ Test Schnorr's Proof Commitment """

    def setUp(self):
        # Deterministic PRNG for testing purposes
        seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"
        seed = bytes.fromhex(seed_hex)
        self.rng = core_utils.create_csprng(seed)

        r_hex = "e8a04212cc20520429d854a5bb02b51b4281e663c90a4a4ec0b505171f9bc26a"
        C_hex = "028fe6cafe6e6cef6c47be31cb449faa9495d22a6cb47e057b91c97d807882c439"
        self.r_golden = bytes.fromhex(r_hex)
        self.C_golden = bytes.fromhex(C_hex)

        with open("schnorr/commit.json", "r") as f:
            self.tv = json.load(f)

    def test_tv(self):
        """ Test using test vectors """

        for vector in self.tv:
            r_golden = bytes.fromhex(vector["R"])
            C_golden = bytes.fromhex(vector["C"])

            r, C = schnorr.commit(None, r_golden)

            self.assertEqual(r, r_golden)
            self.assertEqual(C, C_golden)

    def test_random(self):
        """ Test using pseudo random r """

        r, C = schnorr.commit(self.rng)

        self.assertEqual(r, self.r_golden)
        self.assertEqual(C, self.C_golden)


class TestChallenge(unittest.TestCase):
    """ Test Schnorr's Proof Deterministic Challenge """

    def setUp(self):
        with open("schnorr/challenge.json", "r") as f:
            self.tv = json.load(f)

    def test_tv(self):
        """ Test using test vectors """

        for vector in self.tv:
            V = bytes.fromhex(vector["V"])
            C = bytes.fromhex(vector["C"])

            e_golden = bytes.fromhex(vector["E"])

            e = schnorr.challenge(V, C)

            self.assertEqual(e, e_golden)


class TestProve(unittest.TestCase):
    """ Test Schnorr's Proof Proof generation """

    def setUp(self):
        with open("schnorr/prove.json", "r") as f:
            self.tv = json.load(f)

    def test_tv(self):
        """ Test using test vectors """

        for vector in self.tv:
            r = bytes.fromhex(vector["R"])
            e = bytes.fromhex(vector["E"])
            x = bytes.fromhex(vector["X"])

            p_golden = bytes.fromhex(vector["P"])

            p = schnorr.prove(r, e, x)

            self.assertEqual(p, p_golden)


class TestVerify(unittest.TestCase):
    """ Test Schnorr's Proof Verification """

    def setUp(self):
        with open("schnorr/verify.json", "r") as f:
            self.tv = json.load(f)

    def test_tv(self):
        """ Test using test vectors """

        for vector in self.tv:
            V = bytes.fromhex(vector["V"])
            C = bytes.fromhex(vector["C"])
            e = bytes.fromhex(vector["E"])
            p = bytes.fromhex(vector["P"])

            ec = schnorr.verify(V, C, e, p)

            self.assertEqual(ec, schnorr.OK)

    def test_error_code(self):
        """ Test error codes are propagated """

        vector = self.tv[0]

        V = bytes.fromhex(vector["C"])
        C = bytes.fromhex(vector["V"])
        e = bytes.fromhex(vector["E"])
        p = bytes.fromhex(vector["P"])

        ec = schnorr.verify(V, C, e, p)

        self.assertEqual(ec, schnorr.FAIL)


if __name__ == '__main__':
    unittest.main()
