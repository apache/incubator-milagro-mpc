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

from amcl import core_utils, commitments

seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"

if __name__ == "__main__":
    seed = bytes.fromhex(seed_hex)
    rng = core_utils.create_csprng(seed)

    print("Example Non Malleable Commitment")
    print("Message: BANANA")

    x = b'BANANA'

    # Commitment Phase
    r, c = commitments.nm_commit(rng, x)

    print("\nCommitment")
    print(f"\tr = {r.hex()}")
    print(f"\tc = {c.hex()}")

    # Decommitment Phase. After both c, r and x have been revealed
    rc = commitments.nm_decommit(x, r, c)

    print("\nDecommitment")
    if rc == commitments.OK:
        print("\tSuccess")
    else:
        print("\tFailure")
