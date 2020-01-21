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


class TestS(unittest.TestCase):
    """Tests MPC S"""

    def setUp(self):
        seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"
        seed = bytes.fromhex(seed_hex)
        self.rng = amcl_mpc.create_csprng(seed)

    def test_1(self):
        """test_1 Test Vector test"""
        with open("S.json", "r") as f:
            vectors = json.load(f)
        for vector in vectors:
            print(f"Test vector {vector['TEST']}")
            test = {}
            for key, val in vector.items():
                if key != "TEST":
                    #print(f"{key} = {val}\n")
                    test[key] = bytes.fromhex(val)
            PUB1, PRIV1 = amcl_mpc.paillier_key_pair(self.rng, test['P1'], test['Q1'])
            PUB2, PRIV2 = amcl_mpc.paillier_key_pair(self.rng, test['P2'], test['Q2'])            

            # ALPHA1 + BETA2 = K1 * W2
            ca11 = amcl_mpc.mpc_mta_client1(self.rng, PUB1, test['K1'], test['R11'])
            cb12, beta2 = amcl_mpc.mpc_mta_server(self.rng, PUB1, test['W2'], ca11, test['Z12'], test['R12'])
            alpha1 = amcl_mpc.mpc_mta_client2(PRIV1, cb12)
            
            self.assertEqual(vector['ALPHA1'], alpha1.hex())
            self.assertEqual(vector['BETA2'], beta2.hex())             

            # ALPHA2 + BETA1 = K2 * W1
            ca22 = amcl_mpc.mpc_mta_client1(self.rng, PUB2, test['K2'], test['R22'])
            cb21, beta1 = amcl_mpc.mpc_mta_server(self.rng, PUB2, test['W1'], ca22, test['Z21'], test['R21'])
            alpha2 = amcl_mpc.mpc_mta_client2(PRIV2, cb21)
            
            self.assertEqual(vector['ALPHA2'], alpha2.hex())
            self.assertEqual(vector['BETA1'], beta1.hex())             

            # sum1 = K1.W1 + alpha1 + beta1

            SUM1 = amcl_mpc.mpc_sum_mta(test['K1'], test['W1'],  alpha1,  beta1)
            self.assertEqual(vector['SUM1'], SUM1.hex())            

            # sum2 = K2.W2 + alpha2 + beta2

            SUM2 = amcl_mpc.mpc_sum_mta(test['K2'], test['W2'],  alpha2,  beta2)
            self.assertEqual(vector['SUM2'], SUM2.hex())            

            # Calculate the message hash
    
            HM = amcl_mpc.mpc_hash(test['M'])

            # Calculate the S1 signature component

            rc, SIG_S1 = amcl_mpc.mpc_s(HM, test['SIG_R'], test['K1'], SUM1)
            self.assertEqual(vector['SIG_S1'], SIG_S1.hex())
            self.assertEqual(rc, 0)            

            # Calculate the S2 signature component

            rc, SIG_S2 = amcl_mpc.mpc_s(HM, test['SIG_R'], test['K2'], SUM2)
            self.assertEqual(vector['SIG_S2'], SIG_S2.hex())
            self.assertEqual(rc, 0)            

            # Sum S signature component

            SIG_S = amcl_mpc.mpc_sum_s(SIG_S1, SIG_S2)
            self.assertEqual(vector['SIG_S'], SIG_S.hex())
            self.assertEqual(rc, 0)            
            
if __name__ == '__main__':
    # Run tests
    unittest.main()
