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

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import amcl.core_utils
import amcl.mpc

seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"

if __name__ == "__main__":
    seed = bytes.fromhex(seed_hex)

    # random number generator
    rng = amcl.core_utils.create_csprng(seed)

    # Paillier keys
    paillier_pk1, paillier_sk1 = amcl.mpc.paillier_key_pair(rng)
    paillier_pk2, paillier_sk2 = amcl.mpc.paillier_key_pair(rng)

    # ECDSA keys
    PK1, W1 = amcl.mpc.mpc_ecdsa_key_pair_generate(rng)
    rc = amcl.mpc.ecp_secp256k1_public_key_validate(PK1)
    assert rc == 0, f"Invalid ECDSA public key"

    PK2, W2 = amcl.mpc.mpc_ecdsa_key_pair_generate(rng)
    rc = amcl.mpc.ecp_secp256k1_public_key_validate(PK2)
    assert rc == 0, f"Invalid ECDSA public key"

    # Gamma values
    GAMMAPT1, GAMMA1 = amcl.mpc.mpc_ecdsa_key_pair_generate(rng)
    GAMMAPT2, GAMMA2 = amcl.mpc.mpc_ecdsa_key_pair_generate(rng)

    # K values
    K1 = amcl.mpc.mpc_k_generate(rng)
    K2 = amcl.mpc.mpc_k_generate(rng)

    # Message
    M = b'test message'

    # ALPHA1 + BETA2 = K1 * GAMMA2
    CA11 = amcl.mpc.mta_client1(rng, paillier_pk1, K1)
    CB12, BETA2 = amcl.mpc.mta_server(rng, paillier_pk1, GAMMA2, CA11)
    ALPHA1 = amcl.mpc.mta_client2(paillier_sk1, CB12)

    # ALPHA2 + BETA1 = K2 * GAMMA1
    CA22 = amcl.mpc.mta_client1(rng, paillier_pk2, K2)
    CB21, BETA1 = amcl.mpc.mta_server(rng, paillier_pk2, GAMMA1, CA22)
    ALPHA2 = amcl.mpc.mta_client2(paillier_sk2, CB21)

    # sum = K1.GAMMA1 + alpha1  + beta1
    SUM1 = amcl.mpc.mpc_sum_mta(K1, GAMMA1,  ALPHA1,  BETA1)

    # sum = K2.GAMMA2 + alpha2  + beta2
    SUM2 = amcl.mpc.mpc_sum_mta(K2, GAMMA2, ALPHA2, BETA2)

    # Calculate the inverse of kgamma
    INVKGAMMA = amcl.mpc.mpc_invkgamma(SUM1, SUM2)

    # Calculate the R signature component
    rc, SIG_R, _ = amcl.mpc.mpc_r(INVKGAMMA, GAMMAPT1, GAMMAPT2)

    # ALPHA1 + BETA2 = K1 * W2
    CA11 = amcl.mpc.mta_client1(rng, paillier_pk1, K1)
    CB12, BETA2 = amcl.mpc.mta_server(rng, paillier_pk1, W2, CA11)
    ALPHA1 = amcl.mpc.mta_client2(paillier_sk1, CB12)

    # ALPHA2 + BETA1 = K2 * W1
    CA22 = amcl.mpc.mta_client1(rng, paillier_pk2, K2)
    CB21, BETA1 = amcl.mpc.mta_server(rng, paillier_pk2, W1, CA22)
    ALPHA2 = amcl.mpc.mta_client2(paillier_sk2, CB21)

    # sum = K1.W1 + alpha1  + beta1
    SUM1 = amcl.mpc.mpc_sum_mta(K1, W1,  ALPHA1,  BETA1)

    # sum = K2.W2 + alpha2  + beta2
    SUM2 = amcl.mpc.mpc_sum_mta(K2, W2, ALPHA2, BETA2)

    # Calculate the message hash
    HM = amcl.mpc.mpc_hash(M)

    # Calculate the S1 signature component
    rc, SIG_S1 = amcl.mpc.mpc_s(HM, SIG_R, K1, SUM1)

    # Calculate the S2 signature component
    rc, SIG_S2 = amcl.mpc.mpc_s(HM, SIG_R, K2, SUM2)

    # Sum S signature component
    SIG_S = amcl.mpc.mpc_sum_s(SIG_S1, SIG_S2)

    print(f"r component {SIG_R.hex()}")
    print(f"s component {SIG_S.hex()}")

    # Sum ECDSA public keys
    rc, PK = amcl.mpc.mpc_sum_pk(PK1, PK2)

    # Verify final signature
    rc = amcl.mpc.mpc_ecdsa_verify(HM, PK, SIG_R, SIG_S)
    assert rc == 0, f"Invalid ECDSA signature"

    print("SUCCESS")

    # Clear memory
    amcl.core_utils.kill_csprng(rng)
