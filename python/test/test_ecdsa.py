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
import os
from context import mpc


class TestECDSA(unittest.TestCase):
    """Tests MPC ECDSA"""

    def test_1(self):
        """test_1 Test MPC ECDSA"""
        for i in range(1,11):
            print(f"Test {i}")

            seed = os.urandom(16)
            rng = mpc.create_csprng(seed)

            # Paillier keys
            paillier_pk1, paillier_sk1 = mpc.paillier_key_pair(rng)
            paillier_pk2, paillier_sk2 = mpc.paillier_key_pair(rng)

            # ECDSA keys
            rc, PK1, W1 = mpc.ecp_secp256k1_key_pair_generate(rng)
            rc = mpc.ecp_secp256k1_public_key_validate(PK1)
            assert rc == 0, f"Invalid ECDSA public key"

            rc, PK2, W2 = mpc.ecp_secp256k1_key_pair_generate(rng)
            rc = mpc.ecp_secp256k1_public_key_validate(PK2)
            assert rc == 0, f"Invalid ECDSA public key"

            # Gamma values
            rc, GAMMAPT1, GAMMA1 = mpc.ecp_secp256k1_key_pair_generate(rng)
            rc, GAMMAPT2, GAMMA2 = mpc.ecp_secp256k1_key_pair_generate(rng)

            # K values
            rc, _, K1 = mpc.ecp_secp256k1_key_pair_generate(rng)
            rc, _, K2 = mpc.ecp_secp256k1_key_pair_generate(rng)

            # Message
            M = b'test message'

            # ALPHA1 + BETA2 = K1 * GAMMA2
            CA11 = mpc.mpc_mta_client1(rng, paillier_pk1, K1)
            CB12, BETA2 = mpc.mpc_mta_server(rng, paillier_pk1, GAMMA2, CA11)
            ALPHA1 = mpc.mpc_mta_client2(paillier_sk1, CB12)

            # ALPHA2 + BETA1 = K2 * GAMMA1
            CA22 = mpc.mpc_mta_client1(rng, paillier_pk2, K2)
            CB21, BETA1 = mpc.mpc_mta_server(rng, paillier_pk2, GAMMA1, CA22)
            ALPHA2 = mpc.mpc_mta_client2(paillier_sk2, CB21)

            # sum = K1.GAMMA1 + alpha1  + beta1
            SUM1 = mpc.mpc_sum_mta(K1, GAMMA1,  ALPHA1,  BETA1)

            # sum = K2.GAMMA2 + alpha2  + beta2
            SUM2 = mpc.mpc_sum_mta(K2, GAMMA2, ALPHA2, BETA2)

            # Calculate the inverse of kgamma
            INVKGAMMA = mpc.mpc_invkgamma(SUM1, SUM2)

            # Calculate the R signature component
            rc, SIG_R, _ = mpc.mpc_r(INVKGAMMA, GAMMAPT1, GAMMAPT2)

            # ALPHA1 + BETA2 = K1 * W2
            CA11 = mpc.mpc_mta_client1(rng, paillier_pk1, K1)
            CB12, BETA2 = mpc.mpc_mta_server(rng, paillier_pk1, W2, CA11)
            ALPHA1 = mpc.mpc_mta_client2(paillier_sk1, CB12)

            # ALPHA2 + BETA1 = K2 * W1
            CA22 = mpc.mpc_mta_client1(rng, paillier_pk2, K2)
            CB21, BETA1 = mpc.mpc_mta_server(rng, paillier_pk2, W1, CA22)
            ALPHA2 = mpc.mpc_mta_client2(paillier_sk2, CB21)

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
