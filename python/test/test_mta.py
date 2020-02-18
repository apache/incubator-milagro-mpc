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
from context import mpc


class TestMtA(unittest.TestCase):
    """Tests MPC MtA"""

    def setUp(self):
        with open("mpc/MTA.json", "r") as f:
            self.tv = json.load(f)

        for vector in self.tv:
            for key, val in vector.items():
                if key != "TEST":
                    vector[key] = bytes.fromhex(val)

    def test_1(self):
        """test_1 Test Vector test"""

        for vector in self.tv:
            print(f"Test vector {vector['TEST']}")

            paillier_pk, paillier_sk = mpc.paillier_key_pair(None, vector['P'], vector['Q'])

            ca = mpc.mpc_mta_client1(None, paillier_pk, vector['A'], vector['R1'])

            self.assertEqual(vector['CA'], ca)

            cb, beta = mpc.mpc_mta_server(None, paillier_pk, vector['B'], vector['CA'], vector['Z'], vector['R2'])

            self.assertEqual(vector['CB'], cb)
            self.assertEqual(vector['BETA'], beta)

            alpha = mpc.mpc_mta_client2(paillier_sk, vector['CB'])

            self.assertEqual(vector['ALPHA'], alpha)


if __name__ == '__main__':
    # Run tests
    unittest.main()
