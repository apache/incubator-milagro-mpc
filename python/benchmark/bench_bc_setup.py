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
from bench import time_func

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from amcl import core_utils
from amcl import bit_commitment as bc

seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"

p_hex = "CA5F37B7C0DDF6530B30A41116588218DE95F1F36B807FD7C28E4C467EE3F35967BC01D28B71F8A627A353675A81C86A1FF03DCECAF1686891183FA317BA34A4A1148D40A89F1F3AC0C200511C6CFE02342CD75354C25A2E069886DD4FB73BD365660D163F1282B143119AB8F375A73875EC16B634F52593B73BC6D875F2D3EF"
q_hex = "C2FC545C1C803F6C7625FBC4ECF9355734D6B6058FD714816D3ECFB93F1F705C9CE90D4F8796A05148AB5ABC201F90889231CC6BF5F68ED15EE4D901F603930A280EEABF10C613BFCB67A816363C839EB902B02607EB48AB8325E2B72620D4D294A232803217090DFB50AF8C620D4679E77CE3053437ED518F4F68840DCF1AA3"

if __name__ == "__main__":
    p = bytes.fromhex(p_hex)
    q = bytes.fromhex(q_hex)

    seed = bytes.fromhex(seed_hex)
    rng = core_utils.create_csprng(seed)

    id = b'unique_identifier'
    ad = b'additional_data'

    # Generate quantities for benchmark
    priv = bc.setup(rng, p=p, q=q)
    pub = bc.priv_to_pub(priv)
    proof = bc.setup_prove(rng, priv, id, ad=ad)
    rc = bc.setup_verify(pub, proof, id, ad=ad)

    assert rc == bc.OK

    # Run benchmark
    fncall = lambda: bc.setup(rng, p=p, q=q)
    time_func("bc_setup       ", fncall, unit="ms")

    fncall = lambda: bc.priv_to_pub(priv)
    time_func("bc_priv_to_pub ", fncall, unit="us")

    fncall = lambda: bc.setup_prove(rng, priv, id, ad=ad)
    time_func("bc_setup_prove ", fncall, unit="ms")

    fncall = lambda: bc.setup_verify(pub, proof, id, ad=ad)
    time_func("bc_setup_verify", fncall, unit="ms")