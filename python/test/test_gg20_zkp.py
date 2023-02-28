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
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from amcl import core_utils, gg20_zkp



class TestPhase3(unittest.TestCase):
    """ Test Phase 3 ZKP """

    def setUp(self):
        # Deterministic PRNG for testing purposes
        seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"
        seed = bytes.fromhex(seed_hex)
        self.rng = core_utils.create_csprng(seed)

        # Proof input
        self.s = bytes.fromhex("00f1f45c44eb4298562677dfc945064ac5d45d683ec2d87efbd2f527bb5a768c")
        self.l = bytes.fromhex("ab5aa1e7740f849b974fcaaa98840d828a42b16dd59be32f39e3c637730ee9e4")

        self.v = bytes.fromhex("02879452f0c552b01c2cc91101062ca02a1ff3eab1e9c18873992670198bf54f3e")

        self.id = b'user-id'
        self.ad = b'more-data'

        # Pre-generate rv for deterministic test
        self.rv, self.c = gg20_zkp.phase3_commit(self.rng)


    def test(self):
        """ Test Phase 3 ZKP """

        rv, c = gg20_zkp.phase3_commit(self.rng)
        e = gg20_zkp.phase3_challenge(self.v, c, self.id, AD = self.ad)
        p = gg20_zkp.phase3_prove(rv, e, self.s, self.l)

        gg20_zkp.rv_kill(self.rv)

        t, u = gg20_zkp.proof_to_octets(p)
        p = gg20_zkp.proof_from_octets(t, u)

        rc = gg20_zkp.phase3_verify(self.v, c, e, p)

        self.assertEqual(rc, gg20_zkp.OK, "Invalid Proof")


    def test_no_ad(self):
        """ Test Phase 3 ZKP without AD """

        rv, c = gg20_zkp.phase3_commit(self.rng)
        e = gg20_zkp.phase3_challenge(self.v, c, self.id)
        p = gg20_zkp.phase3_prove(rv, e, self.s, self.l)

        gg20_zkp.rv_kill(self.rv)

        t, u = gg20_zkp.proof_to_octets(p)
        p = gg20_zkp.proof_from_octets(t, u)

        rc = gg20_zkp.phase3_verify(self.v, c, e, p)

        self.assertEqual(rc, gg20_zkp.OK, "Invalid Proof")


    def test_deterministic(self):
        """ Test Phase 3 ZKP commitment with pre-generated rv"""

        rv, c = gg20_zkp.phase3_commit(self.rng, rv = self.rv)

        self.assertEqual(c, self.c, "Inconsistent commitment")

        e = gg20_zkp.phase3_challenge(self.v, c, self.id, AD = self.ad)
        p = gg20_zkp.phase3_prove(rv, e, self.s, self.l)

        gg20_zkp.rv_kill(self.rv)

        t, u = gg20_zkp.proof_to_octets(p)
        p = gg20_zkp.proof_from_octets(t, u)

        rc = gg20_zkp.phase3_verify(self.v, c, e, p)

        self.assertEqual(rc, gg20_zkp.OK, "Invalid Proof")


class TestPhase6(unittest.TestCase):
    """ Test Phase 6 ZKP """

    def setUp(self):
        # Deterministic PRNG for testing purposes
        seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"
        seed = bytes.fromhex(seed_hex)
        self.rng = core_utils.create_csprng(seed)

        # Proof input
        self.s = bytes.fromhex("843b282505357e075bd98104f42fe7ea6b41310da7c769b4c402442c1ede922b")
        self.l = bytes.fromhex("584edf9db99551ff2e0d56218a44fea0943032f7864b8359c213ec36465512c5")

        self.R = bytes.fromhex("03e03cda61f087f9ba381695dc816a4ca42f38bbfc3fc88ffe897594b94ee7b80b")
        self.T = bytes.fromhex("02863528287942ab88dec016c2e1993bf9e459ffcbfcc48c25ef68f2ec750e55a8")
        self.S = bytes.fromhex("02ef03c8ecb7cf65b58d85f368c5fc2725b4e4fe93306f98cf53f8e1531cea2bc4")

        self.id = b'user-id'
        self.ad = b'more-data'

        # Pre-generate rv for deterministic test
        self.rv, c, rc = gg20_zkp.phase6_commit(self.rng, self.R)
        self.assertEqual(rc, gg20_zkp.OK, f"Commitment error. RC: {rc}")

        self.alpha, self.beta = gg20_zkp.phase6_commitment_to_octets(c)


    def test(self):
        """ Test Phase 6 ZKP """

        rv, c, rc = gg20_zkp.phase6_commit(self.rng, self.R)
        self.assertEqual(rc, gg20_zkp.OK, f"Commitment error. RC: {rc}")

        e = gg20_zkp.phase6_challenge(self.R, self.T, self.S, c, self.id, AD = self.ad)
        p = gg20_zkp.phase3_prove(rv, e, self.s, self.l)

        gg20_zkp.rv_kill(self.rv)

        t, u = gg20_zkp.proof_to_octets(p)
        p = gg20_zkp.proof_from_octets(t, u)

        alpha, beta = gg20_zkp.phase6_commitment_to_octets(c)
        c, rc = gg20_zkp.phase6_commitment_from_octets(alpha, beta)
        self.assertEqual(rc, gg20_zkp.OK, f"Commitment octet functions error. RC: {rc}")

        rc = gg20_zkp.phase6_verify(self.R, self.T, self.S, c, e, p)

        self.assertEqual(rc, gg20_zkp.OK, "Invalid Proof")


    def test_no_ad(self):
        """ Test Phase 6 ZKP without AD """

        rv, c, rc = gg20_zkp.phase6_commit(self.rng, self.R)
        self.assertEqual(rc, gg20_zkp.OK, f"Commitment error. RC: {rc}")

        e = gg20_zkp.phase6_challenge(self.R, self.T, self.S, c, self.id)
        p = gg20_zkp.phase3_prove(rv, e, self.s, self.l)

        gg20_zkp.rv_kill(self.rv)

        t, u = gg20_zkp.proof_to_octets(p)
        p = gg20_zkp.proof_from_octets(t, u)

        alpha, beta = gg20_zkp.phase6_commitment_to_octets(c)
        c, rc = gg20_zkp.phase6_commitment_from_octets(alpha, beta)
        self.assertEqual(rc, gg20_zkp.OK, f"Commitment octet functions error. RC: {rc}")

        rc = gg20_zkp.phase6_verify(self.R, self.T, self.S, c, e, p)

        self.assertEqual(rc, gg20_zkp.OK, "Invalid Proof")


    def test_deterministic(self):
        """ Test Phase 6 ZKP commitment with pre-generated rv"""

        rv, c, rc = gg20_zkp.phase6_commit(self.rng, self.R, rv = self.rv)
        self.assertEqual(rc, gg20_zkp.OK, f"Commitment error. RC: {rc}")

        alpha, beta = gg20_zkp.phase6_commitment_to_octets(c)
        self.assertEqual(alpha, self.alpha, "Inconsistent commitment alpha")
        self.assertEqual(beta,  self.beta,  "Inconsistent commitment beta")

        e = gg20_zkp.phase6_challenge(self.R, self.T, self.S, c, self.id, AD = self.ad)
        p = gg20_zkp.phase3_prove(rv, e, self.s, self.l)

        gg20_zkp.rv_kill(self.rv)

        t, u = gg20_zkp.proof_to_octets(p)
        p = gg20_zkp.proof_from_octets(t, u)

        alpha, beta = gg20_zkp.phase6_commitment_to_octets(c)
        c, rc = gg20_zkp.phase6_commitment_from_octets(alpha, beta)
        self.assertEqual(rc, gg20_zkp.OK, f"Commitment octet functions error. RC: {rc}")

        rc = gg20_zkp.phase6_verify(self.R, self.T, self.S, c, e, p)

        self.assertEqual(rc, gg20_zkp.OK, "Invalid Proof")


    def test_error_propagation(self):
        """ Test Error Code propagation for invalid ECP """

        rv, c, rc = gg20_zkp.phase6_commit(self.rng, self.l)

        self.assertEqual(rv, gg20_zkp._ffi.NULL, "Commit rv not NULL")
        self.assertEqual(c,  gg20_zkp._ffi.NULL, "Commit c not NULL")
        self.assertEqual(rc, gg20_zkp.INVALID_ECP, "Commit error code not propagated")

        c = "not_none"
        c, rc = gg20_zkp.phase6_commitment_from_octets(self.l, self.s)

        self.assertEqual(c,  gg20_zkp._ffi.NULL, "Octets c not NULL")
        self.assertEqual(rc, gg20_zkp.INVALID_ECP, "Octets error code not propagated")


if __name__ == '__main__':
    unittest.main()
