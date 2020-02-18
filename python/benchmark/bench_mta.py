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

from context import mpc
from bench import time_func

seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"

P_hex = "94f689d07ba20cf7c7ca7ccbed22ae6b40c426db74eaee4ce0ced2b6f52a5e136663f5f1ef379cdbb0c4fdd6e4074d6cff21082d4803d43d89e42fd8dfa82b135aa31a8844ffea25f255f956cbc1b9d8631d01baf1010d028a190b94ce40f3b72897e8196df19edf1ff62e6556f2701d52cef1442e3301db7608ecbdcca703db"
Q_hex = "9a9ad73f246df853e129c589925fdad9df05606a61081e62e72be4fb33f6e5ec492cc734f28bfb71fbe2ba9a11e4c02e2c0d103a5cbb0a9d6402c07de63b1b995dd72ac8f29825d66923a088b421fb4d52b0b855d2f5dde2be9b0ca0cee6f7a94e5566735fe6cff1fcad3199602f88528d19aa8d0263adff8f5053c38254a2a3"

a_hex = "0000000000000000000000000000000000000000000000000000000000000002"
b_hex = "0000000000000000000000000000000000000000000000000000000000000003"

if __name__ == "__main__":
    seed = bytes.fromhex(seed_hex)
    p = bytes.fromhex(P_hex)
    q = bytes.fromhex(Q_hex)
    a = bytes.fromhex(a_hex)
    b = bytes.fromhex(b_hex)

    # random number generator
    rng = mpc.create_csprng(seed)

    # Generate quantities for benchmark
    paillier_pk, paillier_sk = mpc.paillier_key_pair(rng)
    ca = mpc.mpc_mta_client1(rng, paillier_pk, a)
    cb, beta = mpc.mpc_mta_server(rng, paillier_pk, b, ca)
    alpha = mpc.mpc_mta_client2(paillier_sk, cb)

    # Check consistency of the generated quantities
    ai = int(a_hex, 16)
    bi = int(b_hex, 16)
    expected = ai * bi % mpc.curve_order

    alphai = int(alpha.hex(), 16)
    betai = int(beta.hex(), 16)
    got = ( alphai + betai ) % mpc.curve_order

    assert got == expected, f"expected {hex(expected)} got {hex(got)}"

    # Run benchmark
    fncall = lambda: mpc.mpc_mta_client1(rng, paillier_pk, a)
    time_func("mpc_mta_client1", fncall)

    fncall = lambda: mpc.mpc_mta_server(rng, paillier_pk, b, ca)
    time_func("mpc_mta_server ", fncall)

    fncall = lambda: mpc.mpc_mta_client2(paillier_sk, cb)
    time_func("mpc_mta_client2", fncall)

    # Clear memory
    mpc.kill_csprng(rng)
