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

P_hex = "94f689d07ba20cf7c7ca7ccbed22ae6b40c426db74eaee4ce0ced2b6f52a5e136663f5f1ef379cdbb0c4fdd6e4074d6cff21082d4803d43d89e42fd8dfa82b135aa31a8844ffea25f255f956cbc1b9d8631d01baf1010d028a190b94ce40f3b72897e8196df19edf1ff62e6556f2701d52cef1442e3301db7608ecbdcca703db"
Q_hex = "9a9ad73f246df853e129c589925fdad9df05606a61081e62e72be4fb33f6e5ec492cc734f28bfb71fbe2ba9a11e4c02e2c0d103a5cbb0a9d6402c07de63b1b995dd72ac8f29825d66923a088b421fb4d52b0b855d2f5dde2be9b0ca0cee6f7a94e5566735fe6cff1fcad3199602f88528d19aa8d0263adff8f5053c38254a2a3"

a_hex = "0000000000000000000000000000000000000000000000000000000000000002"
b_hex = "0000000000000000000000000000000000000000000000000000000000000003"
ca_hex = "19c8b725dbd74b7dcaf72bd9ff2cd207b47cb1095393685906171af9e2f2959e7f68729e0e40f97a22bbca93373d618ad51dd077c0d102938598a8ecc8a656e978ebd14007da99db8e691d85fc18a428097ee8a63dcf95b84b660294474a20ed2edcf2b1b4f305c1cc25860a08d1348c2a4d24cc1a97b51f920e2985b8108b3392a5eafc443cf3449e288eb49dbde2228a56233afa5a6643e5ae6ec6aa8937a666ef74a30625c35bb22c3cc57b700f8eae7690f8d37edbfd27ccb2e882f70d0d85e0cc825347453a28e98e877ab1eeaa6efa09f034bc8976bffb86420106978066ff52221b315f71eb32cbf608d2b72cfa4c88e43282598f175b48ba3b5c14d72b2d90baabc00025450740ac89fc0dcd7d2f80cf12c721b6ec493c2025d7adc683b78f1d711b639a1b0dd043b9defa7ff928e257599dd95525bc8b45e1b88470311e11feb72749e5fc98f69051ddd1101b1bcc92f649681bd7ae316575444625d9d73d3684789142650951321e17f6b2f92103f36dbbd004cd66cda366e80faa4f57b71b9abb042f6cc932716fa3e6fdf50674e3d1e6d871f723d3f4f672c1270b41e7cdd5930a2572ddfc8ce370576a7a75ee6924f53122d717146c74eb6167811a2488bb899cc2da9dc2e29df66b5a03ed986fdad6ef177151ddd2698055050709c475b4ed5a2ab0be00c8b03e24193fb79f91cfd81fbcb838e45c25f8ba05"
R_hex = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018c5947fda2edea04c1f87c207e0bab17aff5f77ac21d04cb194631efd1f7256dc37de9473fc86009df36206974859c09023ac8179b02aacea8d89a01f4de161db955d450cef55ce959897636973b952371e349778e67c61ef6fae5f73fd728d423a594b6a76d5faca97d59d6ae40c53f3bd42dfccc93183e355422ba7af308a87d32c0352d478156275f98bc74e9ed4f2c7a9853c9f35b996fafe765b56c7f2e83771c6b676b75436e5c1697b838b3908aee92001cbccf3bf6cfb7aaea27a358a12cfe1ddde886b975ae14517e5912eba3ff9792e46403a998edd371020bbc5fbd6a705e669383303030ef79653ce16e13122233c626bb101ee8dd27bf4ff86"

cb_hex = "1f1f087e749c85aacdacaace8659a33b53baad5eec1e56628435d335a8b150f96865d6e090f53146e120e7089b6f4a91c762622b24d0d2fba0e703301170a0b826a1336d4d6bb83dccd29ad9ef0936614bf14e992ea4daa202c63ace9bd3f95b9a8a6edd7949e89ec165541e7c01bd41395baf3e2fe7f3a9611af8b5ed8639c02a2bfc236c17a136bef6d09f966db718f3df9d6f4f40b618b4b6058b4e4ec241e6c2424404d0aee0ef5cd666e5c4253a62ae9deb09289fb84657109e0b933f58871ba7ea77190d6ea45a04be68360478adf43a85851cf583c5575543578635996d2dcd020aeceabf18be6ff8b45e4ecd63c899cbfe353bc6be246aa421f54bb1f6aad797b36e435e2f33a3a049aeab894b851c5ce1076aa6e19316e3da6f539197e00e17e7a3025b53490a9d1210b900c1cac32a3bdc31d4c4866e7499a2858942e057be2840cf8ad4b1dcd914c64ac7d4b89e3f1b1a010096ecb62bb5837d9e79018870002962838bc46d7a70c23494985c300b4f8a7352a412bfc4134378d23343b3c8a77f65c234c8586e5fb0731881cb756e994c82773261f2a2321e45df45a08830e67b6c983e3f01a464b9ca6cc78ec7f170782748d114889656377e86a1e3b3c28616f3b4b73693867fefd7459fe99e9892435f0902ad74ceebac99c4f67340344f128b1f55fdb85acdc64891b77d9961653361f5264d5f1e0b67173b"
z_hex = "0000000000000000000000000000000000000000000000000000000000000004"
beta_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413d"

alpha_hex = "000000000000000000000000000000000000000000000000000000000000000a"

if __name__ == "__main__":
    seed = bytes.fromhex(seed_hex)
    p = bytes.fromhex(P_hex)
    q = bytes.fromhex(Q_hex)
    a = bytes.fromhex(a_hex)
    b = bytes.fromhex(b_hex)
    z = bytes.fromhex(z_hex)
    r = bytes.fromhex(R_hex)

    ai = int(a_hex, 16)
    bi = int(b_hex, 16)
    expected = ai * bi % amcl.mpc.curve_order
    print(f"expected {hex(expected)}")

    # random number generator
    rng = amcl.core_utils.create_csprng(seed)

    # Deterministic
    paillier_pk, paillier_sk = amcl.mpc.paillier_key_pair(None, p, q)

    ca = amcl.mpc.mta_client1(rng, paillier_pk, a, r)
    ca1_hex = ca.hex()
    assert ca_hex == ca1_hex, f"expected {ca_hex} got {ca1_hex}"

    cb, beta = amcl.mpc.mta_server(rng, paillier_pk, b, ca, z, r)
    cb1_hex = cb.hex()
    assert cb_hex == cb1_hex, f"expected {cb_hex} got {cb1_hex}"

    alpha = amcl.mpc.mta_client2(paillier_sk, cb)

    print(f"alpha {alpha.hex()}")
    print(f"beta {beta.hex()}")

    alphai = int(alpha.hex(), 16)
    betai = int(beta.hex(), 16)
    got = ( alphai + betai ) % amcl.mpc.curve_order

    print(f"got {hex(got)}")

    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

    # Random
    paillier_pk, paillier_sk = amcl.mpc.paillier_key_pair(rng)
    ca = amcl.mpc.mta_client1(rng, paillier_pk, a)
    cb, beta = amcl.mpc.mta_server(rng, paillier_pk, b, ca)
    alpha = amcl.mpc.mta_client2(paillier_sk, cb)

    print(f"alpha {alpha.hex()}")
    print(f"beta {beta.hex()}")

    alphai = int(alpha.hex(), 16)
    betai = int(beta.hex(), 16)
    got = ( alphai + betai ) % amcl.mpc.curve_order

    print(f"got {hex(got)}")

    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

    # Clear memory
    amcl.core_utils.kill_csprng(rng)
    amcl.mpc.paillier_private_key_kill(paillier_sk)
