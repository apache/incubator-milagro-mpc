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


class TestR(unittest.TestCase):
    """Tests MPC R"""

    def setUp(self):
        with open("mpc/R.json", "r") as f:
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

            # ALPHA1 + BETA2 = A1 * B2
            ca11 = mpc.mta_client1(None, PUB1, vector['A1'], vector['R11'])
            cb12, beta2 = mpc.mta_server(None, PUB1, vector['B2'], ca11, vector['Z12'], vector['R12'])
            alpha1 = mpc.mta_client2(PRIV1, cb12)

            self.assertEqual(vector['ALPHA1'], alpha1)
            self.assertEqual(vector['BETA2'], beta2)

            # ALPHA2 + BETA1 = A2 * B1
            ca22 = mpc.mta_client1(None, PUB2, vector['A2'], vector['R22'])
            cb21, beta1 = mpc.mta_server(None, PUB2, vector['B1'], ca22, vector['Z21'], vector['R21'])
            alpha2 = mpc.mta_client2(PRIV2, cb21)

            self.assertEqual(vector['ALPHA2'], alpha2)
            self.assertEqual(vector['BETA1'], beta1)

            # sum1 = A1.B1 + alpha1 + beta1
            sum1 = mpc.mpc_sum_mta(vector['A1'], vector['B1'],  alpha1,  beta1)

            self.assertEqual(vector['SUM1'], sum1)

            # sum2 = A2.B2 + alpha2 + beta2
            sum2 = mpc.mpc_sum_mta(vector['A2'], vector['B2'],  alpha2,  beta2)

            self.assertEqual(vector['SUM2'], sum2)

            # Calculate the inverse of kgamma
            invkgamma= mpc.mpc_invkgamma(sum1, sum2)

            self.assertEqual(vector['INVKGAMMA'], invkgamma)

            # Calculate the R signature component
            rc, sig_r, _ = mpc.mpc_r(invkgamma, vector['GAMMAPT1'], vector['GAMMAPT2'])

            self.assertEqual(vector['SIG_R'], sig_r)
            self.assertEqual(rc, 0)


if __name__ == '__main__':
    # Run tests
    unittest.main()
