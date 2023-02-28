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

from amcl import core_utils
from amcl import nm_commitment as nm

# Load and preprocess test vectors
with open("nm_commitment/commit.json", "r") as f:
    vectors = json.load(f)

for vector in vectors:
    for key, val in vector.items():
        if key != "TEST":
            vector[key] = bytes.fromhex(val)


class TestNMCommit(unittest.TestCase):
    """ Test NM Commitment Commit """

    def setUp(self):
        # Deterministic PRNG for testing purposes
        seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"
        seed = bytes.fromhex(seed_hex)
        self.rng = core_utils.create_csprng(seed)

        self.msg = b'BANANA'

        r_hex = "296f910bde4530efe3533ed3b74475d6022364db2e57773207734b6daf547ac8"
        c_hex = "b60ebd5193252d22c771a7702724e9922662aae5f634494225cdd3a9e22f9826"
        self.r_golden = bytes.fromhex(r_hex)
        self.c_golden = bytes.fromhex(c_hex)

    def test_tv(self):
        """ Test using test vectors """

        for vector in vectors:
            r, c = nm.commit(None, vector['X'], vector['R'])

            self.assertEqual(vector['R'], r)
            self.assertEqual(vector['C'], c)

    def test_random(self):
        """ Test using rng """
        r, c = nm.commit(self.rng, self.msg)

        self.assertEqual(r, self.r_golden)
        self.assertEqual(c, self.c_golden)


class TestNMDecommit(unittest.TestCase):
    """ Test NM Commitment Decommit """

    def test_tv(self):
        """ Test using test vectors """

        for vector in vectors:
            rc = nm.decommit(vector['X'], vector['R'], vector['C'])

            self.assertEqual(rc, nm.OK)

    def test_failure(self):
        """ Test error codes are propagated correctly """

        rc = nm.decommit(vector['X'], vector['X'], vector['C'])

        self.assertEqual(rc, nm.FAIL)

if __name__ == '__main__':
    # Run tests
    unittest.main()
