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

from context import schnorr

seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"

x_hex = "fab4ce512dff74bd9c71c89a14de5b877af45dca0329ee3fcb72611c0784fef3"
V_hex = "032cf4b348c9d00718f01ed98923e164df53b5e8bc4c2250662ed2df784e1784f4"

if __name__ == "__main__":
    seed = bytes.fromhex(seed_hex)

    x = bytes.fromhex(x_hex)
    V = bytes.fromhex(V_hex)

    # random number generator
    rng = schnorr.create_csprng(seed)

    print("Example Schnorr Protocol")
    print("DLOG: V = x.G")
    print(f"\tx = {x_hex}")
    print(f"\tV = {V_hex}")

    # Generate commitment C = r.G, r random in [0, ..., q]
    r, C = schnorr.commit(rng)

    print("\n[Prover] Commitment C = r.G")
    print(f"\tr = {r.hex()}")
    print(f"\tC = {C.hex()}")

    # Generate deterministic challenge e = H(G, V, C)
    e = schnorr.challenge(V, C)

    print("\n[Prover] Deterministic Challenge e = H(G, V, C)")
    print(f"\te = {e.hex()}")

    # Generate proof p = r - ex mod q
    p = schnorr.prove(r, e, x)

    print("\n[Prover] Generate proof p = r - ex")
    print(f"\tp = {p.hex()}")

    # Verifier regenerates deterministic challenge
    e = schnorr.challenge(V, C)
    print("\n[Verifier] Deterministic Challenge e = H(G, V, C)")
    print(f"\te = {e.hex()}")

    # Verify
    rc = schnorr.verify(V, C, e, p)

    print("\n[Verifier] Verify proof p")
    if rc == schnorr.OK:
        print("\tSuccess")
    else:
        print("\tFailure")
