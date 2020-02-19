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

from amcl import mpc


class TestS(unittest.TestCase):
    """Tests MPC S"""

    def setUp(self):
        with open("mpc/S.json", "r") as f:
            self.tv = json.load(f)

        for vector in self.tv:
            for key, val in vector.items():
                if key != "TEST":
                    vector[key] = bytes.fromhex(val)

    def test_1(self):
        """test_1 Test Vector test"""

        for vector in self.tv:
            print(f"Test vector {vector['TEST']}")

            PUB1, PRIV1 = mpc.paillier_key_pair(None, vector['P1'], vector['Q1'])
            PUB2, PRIV2 = mpc.paillier_key_pair(None, vector['P2'], vector['Q2'])

            # ALPHA1 + BETA2 = K1 * W2
            ca11 = mpc.mpc_mta_client1(None, PUB1, vector['K1'], vector['R11'])
            cb12, beta2 = mpc.mpc_mta_server(None, PUB1, vector['W2'], ca11, vector['Z12'], vector['R12'])
            alpha1 = mpc.mpc_mta_client2(PRIV1, cb12)

            self.assertEqual(vector['ALPHA1'], alpha1)
            self.assertEqual(vector['BETA2'], beta2)

            # ALPHA2 + BETA1 = K2 * W1
            ca22 = mpc.mpc_mta_client1(None, PUB2, vector['K2'], vector['R22'])
            cb21, beta1 = mpc.mpc_mta_server(None, PUB2, vector['W1'], ca22, vector['Z21'], vector['R21'])
            alpha2 = mpc.mpc_mta_client2(PRIV2, cb21)

            self.assertEqual(vector['ALPHA2'], alpha2)
            self.assertEqual(vector['BETA1'], beta1)

            # sum1 = K1.W1 + alpha1 + beta1
            SUM1 = mpc.mpc_sum_mta(vector['K1'], vector['W1'],  alpha1,  beta1)

            self.assertEqual(vector['SUM1'], SUM1)

            # sum2 = K2.W2 + alpha2 + beta2
            SUM2 = mpc.mpc_sum_mta(vector['K2'], vector['W2'],  alpha2,  beta2)

            self.assertEqual(vector['SUM2'], SUM2)

            # Calculate the message hash
            HM = mpc.mpc_hash(vector['M'])

            # Calculate the S1 signature component
            rc, SIG_S1 = mpc.mpc_s(HM, vector['SIG_R'], vector['K1'], SUM1)
            self.assertEqual(vector['SIG_S1'], SIG_S1)
            self.assertEqual(rc, 0)

            # Calculate the S2 signature component
            rc, SIG_S2 = mpc.mpc_s(HM, vector['SIG_R'], vector['K2'], SUM2)
            self.assertEqual(vector['SIG_S2'], SIG_S2)
            self.assertEqual(rc, 0)

            # Sum S signature component
            SIG_S = mpc.mpc_sum_s(SIG_S1, SIG_S2)
            self.assertEqual(vector['SIG_S'], SIG_S)
            self.assertEqual(rc, 0)


if __name__ == '__main__':
    # Run tests
    unittest.main()
