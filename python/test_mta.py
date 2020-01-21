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
import unittest
import json
import amcl_mpc


class TestMtA(unittest.TestCase):
    """Tests MPC MtA"""

    def setUp(self):
        seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"
        seed = bytes.fromhex(seed_hex)
        self.rng = amcl_mpc.create_csprng(seed)

    def test_1(self):
        """test_1 Test Vector test"""
        with open("MTA.json", "r") as f:
            vectors = json.load(f)
        for vector in vectors:
            print(f"Test vector {vector['TEST']}")
            test = {}
            for key, val in vector.items():
                if key != "TEST":
                    # print(f"{key} = {val}\n")
                    test[key] = bytes.fromhex(val)
            paillier_pk, paillier_sk = amcl_mpc.paillier_key_pair(self.rng, test['P'], test['Q'])

            ca = amcl_mpc.mpc_mta_client1(self.rng, paillier_pk, test['A'], test['R1'])
            self.assertEqual(vector['CA'], ca.hex())

            cb, beta = amcl_mpc.mpc_mta_server(self.rng, paillier_pk, test['B'], test['CA'], test['Z'], test['R2'])
            self.assertEqual(vector['CB'], cb.hex())
            self.assertEqual(vector['BETA'], beta.hex())

            alpha = amcl_mpc.mpc_mta_client2(paillier_sk, test['CB'])
            self.assertEqual(vector['ALPHA'], alpha.hex())            

if __name__ == '__main__':
    # Run tests
    unittest.main()
