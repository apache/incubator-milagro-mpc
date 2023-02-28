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

from amcl import core_utils
from amcl import bit_commitment as bc

seed_hex = "78d0fb6705ce77dee47d03eb5b9c4d30"

if __name__ == "__main__":
    seed = bytes.fromhex(seed_hex)
    rng = core_utils.create_csprng(seed)

    id = b'unique_identifier'
    ad = b'additional_data'

    print("Example Bit Commitment Setup and ZKP")
    print("\tID = {}".format(id))
    print("\tAD = {}".format(ad))

    print("\nSetup Bit Commitment Parameters (this might take a while)")
    priv = bc.setup(rng)

    p, q, b0, alpha = bc.priv_to_octets(priv)
    print("\tp     = {}".format(p.hex()))
    print("\tq     = {}".format(q.hex()))
    print("\tb0    = {}".format(b0.hex()))
    print("\talpha = {}".format(alpha.hex()))

    print("\nExport Public Portion of Parameters")
    pub = bc.priv_to_pub(priv)

    n, b0, b1 = bc.pub_to_octets(pub)
    print("\tn  = {}".format(n.hex()))
    print("\tb0 = {}".format(b0.hex()))
    print("\tb1 = {}".format(b1.hex()))

    print("\nProve well formedness of Parameters")
    proof = bc.setup_prove(rng, priv, id, ad=ad)

    print("\tProof omitted for briefness. See test vectors for an example")

    print("\nVerify proof")
    rc = bc.setup_verify(pub, proof, id, ad=ad)

    if rc == bc.OK:
        print("\tSuccess!")
    else:
        print("\tFailure!")
