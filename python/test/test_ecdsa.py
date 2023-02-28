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

from amcl import core_utils, mpc


class TestECDSA(unittest.TestCase):
    """Tests MPC ECDSA"""

    def test_1(self):
        """test_1 Test MPC ECDSA"""
        for i in range(1,11):
            print(f"Test {i}")

            seed = os.urandom(16)
            rng = core_utils.create_csprng(seed)

            # Paillier keys
            paillier_pk1, paillier_sk1 = mpc.paillier_key_pair(rng)
            paillier_pk2, paillier_sk2 = mpc.paillier_key_pair(rng)

            # ECDSA keys
            PK1, W1 = mpc.mpc_ecdsa_key_pair_generate(rng)
            PK2, W2 = mpc.mpc_ecdsa_key_pair_generate(rng)

            # Gamma values
            GAMMAPT1, GAMMA1 = mpc.mpc_ecdsa_key_pair_generate(rng)
            GAMMAPT2, GAMMA2 = mpc.mpc_ecdsa_key_pair_generate(rng)

            # K values
            K1 = mpc.mpc_k_generate(rng)
            K2 = mpc.mpc_k_generate(rng)

            # Message
            M = b'test message'

            # ALPHA1 + BETA2 = K1 * GAMMA2
            CA11 = mpc.mta_client1(rng, paillier_pk1, K1)
            CB12, BETA2 = mpc.mta_server(rng, paillier_pk1, GAMMA2, CA11)
            ALPHA1 = mpc.mta_client2(paillier_sk1, CB12)

            # ALPHA2 + BETA1 = K2 * GAMMA1
            CA22 = mpc.mta_client1(rng, paillier_pk2, K2)
            CB21, BETA1 = mpc.mta_server(rng, paillier_pk2, GAMMA1, CA22)
            ALPHA2 = mpc.mta_client2(paillier_sk2, CB21)

            # sum = K1.GAMMA1 + alpha1  + beta1
            SUM1 = mpc.mpc_sum_mta(K1, GAMMA1,  ALPHA1,  BETA1)

            # sum = K2.GAMMA2 + alpha2  + beta2
            SUM2 = mpc.mpc_sum_mta(K2, GAMMA2, ALPHA2, BETA2)

            # Calculate the inverse of kgamma
            INVKGAMMA = mpc.mpc_invkgamma(SUM1, SUM2)

            # Calculate the R signature component
            rc, SIG_R, _ = mpc.mpc_r(INVKGAMMA, GAMMAPT1, GAMMAPT2)

            # ALPHA1 + BETA2 = K1 * W2
            CA11 = mpc.mta_client1(rng, paillier_pk1, K1)
            CB12, BETA2 = mpc.mta_server(rng, paillier_pk1, W2, CA11)
            ALPHA1 = mpc.mta_client2(paillier_sk1, CB12)

            # ALPHA2 + BETA1 = K2 * W1
            CA22 = mpc.mta_client1(rng, paillier_pk2, K2)
            CB21, BETA1 = mpc.mta_server(rng, paillier_pk2, W1, CA22)
            ALPHA2 = mpc.mta_client2(paillier_sk2, CB21)

            # sum = K1.W1 + alpha1  + beta1
            SUM1 = mpc.mpc_sum_mta(K1, W1,  ALPHA1,  BETA1)

            # sum = K2.W2 + alpha2  + beta2
            SUM2 = mpc.mpc_sum_mta(K2, W2, ALPHA2, BETA2)

            # Calculate the message hash
            HM = mpc.mpc_hash(M)

            # Calculate the S1 signature component
            rc, SIG_S1 = mpc.mpc_s(HM, SIG_R, K1, SUM1)

            # Calculate the S2 signature component
            rc, SIG_S2 = mpc.mpc_s(HM, SIG_R, K2, SUM2)

            # Sum S signature component
            SIG_S = mpc.mpc_sum_s(SIG_S1, SIG_S2)

            # Sum ECDSA public keys
            rc, PK = mpc.mpc_sum_pk(PK1, PK2)

            # Verify final signature
            rc = mpc.mpc_ecdsa_verify(HM, PK, SIG_R, SIG_S)

            self.assertEqual(rc, 0)


if __name__ == '__main__':
    # Run tests
    unittest.main()
