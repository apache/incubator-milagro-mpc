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
from amcl import bit_commitment as bc

# Load and preprocess test vectors
with open("bit_commitment/setup.json", "r") as f:
    vectors = json.load(f)

for vector in vectors:
    for key, val in vector.items():
        if key != "TEST":
            vector[key] = bytes.fromhex(val)

class TestBCSetup(unittest.TestCase):
    """ Test BC Setup """

    def setUp(self):
        # Deterministic PRNG for testing purposes
        seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"
        seed = bytes.fromhex(seed_hex)
        self.rng = core_utils.create_csprng(seed)

    def test_tv(self):
        """ Test using test vector """

        for vector in vectors:
            priv = bc.setup(self.rng, vector['P'], vector['Q'], vector['B0'], vector['ALPHA'])

            pub = bc.priv_to_pub(priv)

            n, b0, b1 = bc.pub_to_octets(pub)

            self.assertEqual(vector['N'],  n)
            self.assertEqual(vector['B0'], b0)
            self.assertEqual(vector['B1'], b1)


class TestBCPubOctetFuncs(unittest.TestCase):
    """ Test BC_pub Octet Functions """

    def test_tv(self):
        """ Test using test vector """

        for vector in vectors:
            pub = bc.pub_from_octets(vector['N'], vector['B0'], vector['B1'])

            n, b0, b1 = bc.pub_to_octets(pub)

            self.assertEqual(vector['N'],  n)
            self.assertEqual(vector['B0'], b0)
            self.assertEqual(vector['B1'], b1)


class TestBCPrivOctetFuncs(unittest.TestCase):
    """ Test BC_priv Octet Functions """

    def test_tv(self):
        """ Test using test vector """

        for vector in vectors:
            priv = bc.priv_from_octets(vector['P'], vector['Q'], vector['B0'], vector['ALPHA'])
            p, q, b0, alpha = bc.priv_to_octets(priv)

            self.assertEqual(vector['P'],  p)
            self.assertEqual(vector['Q'],  q)
            self.assertEqual(vector['B0'], b0)
            self.assertEqual(vector['ALPHA'], alpha)


class TestBCZKP(unittest.TestCase):
    """ Test BC well formedness ZKP """

    def setUp(self):
        # Deterministic PRNG for testing purposes
        seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"
        seed = bytes.fromhex(seed_hex)
        self.rng = core_utils.create_csprng(seed)
        self.id = b'unique_identifier'
        self.ad = b'additional_data'

    def test_tv_happy_path(self):
        """ Test happy path """
        vector = vectors[0]

        priv = bc.priv_from_octets(vector['P'], vector['Q'], vector['B0'], vector['ALPHA'])
        pub = bc.priv_to_pub(priv)

        proof = bc.setup_prove(self.rng, priv, self.id, self.ad)
        rc = bc.setup_verify(pub, proof, self.id, self.ad)

        self.assertEqual(rc, bc.OK)

    def test_invalid_proof(self):
        """ Invalid b0 ZKP """
        vector = vectors[0]
        priv = bc.priv_from_octets(vector['P'], vector['Q'], vector['B0'], vector['ALPHA'])
        pub = bc.priv_to_pub(priv)
        proof = bc.setup_prove(self.rng, priv, self.id, self.ad)

        rho, irho, t, it = bc.setup_proof_to_octets(proof)
        invalid_b0_proof, _ = bc.setup_proof_from_octets(t, irho, rho, it)
        invalid_b1_proof, _ = bc.setup_proof_from_octets(rho, it, t, irho)

        rc = bc.setup_verify(pub, invalid_b0_proof, self.id, self.ad)
        self.assertEqual(rc, bc.INVALID_PROOF)

        rc = bc.setup_verify(pub, invalid_b1_proof, self.id, self.ad)
        self.assertEqual(rc, bc.INVALID_PROOF)


class TestBCZKPOctetFunc(unittest.TestCase):
    """ Test BC well formedness ZKP octet functions """

    def setUp(self):
        # Deterministic PRNG for testing purposes
        seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"
        seed = bytes.fromhex(seed_hex)
        rng = core_utils.create_csprng(seed)

        vector = vectors[0]
        priv = bc.priv_from_octets(vector['P'], vector['Q'], vector['B0'], vector['ALPHA'])

        proof = bc.setup_prove(rng, priv, b'id')

        self.proof = proof
        self.pub   = bc.priv_to_pub(priv)


    def test_ok(self):
        """ Test export/import is still valid """
        rho, irho, t, it = bc.setup_proof_to_octets(self.proof)
        proof, rc = bc.setup_proof_from_octets(rho, irho, t, it)
        self.assertEqual(rc, bc.OK)

        rc = bc.setup_verify(self.pub, proof, b'id')
        self.assertEqual(rc, bc.OK)

    def test_invalid(self):
        """ Test importing invalid HDLOG values """
        rho, irho, t, it = bc.setup_proof_to_octets(self.proof)

        invalid = b'BANANA'

        _, rc = bc.setup_proof_from_octets(invalid, irho, t, it)
        self.assertEqual(rc, bc.INVALID_FORMAT)

        _, rc = bc.setup_proof_from_octets(rho, invalid, t, it)
        self.assertEqual(rc, bc.INVALID_FORMAT)

        _, rc = bc.setup_proof_from_octets(rho, irho, invalid, it)


        self.assertEqual(rc, bc.INVALID_FORMAT)

        _, rc = bc.setup_proof_from_octets(rho, irho, t, invalid)
        self.assertEqual(rc, bc.INVALID_FORMAT)


if __name__ == '__main__':
    # Run tests
    unittest.main()
