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

from amcl import schnorr

r_hex = "803ccd21cddad626e15f21b1ad787949e9beef08e6e68a9e00df59dec16ed290"
x_hex = "fab4ce512dff74bd9c71c89a14de5b877af45dca0329ee3fcb72611c0784fef3"
V_hex = "032cf4b348c9d00718f01ed98923e164df53b5e8bc4c2250662ed2df784e1784f4"

ID = b"unique_user_identifier"
AD_hex = "d7d3155616778fb436a1eb2070892205"

if __name__ == "__main__":
    r  = bytes.fromhex(r_hex)
    x  = bytes.fromhex(x_hex)
    V  = bytes.fromhex(V_hex)
    AD = bytes.fromhex(AD_hex)

    # Generate quantities for benchmark
    r, C = schnorr.commit(None, r)
    e = schnorr.challenge(V, C, ID, AD=AD)
    p = schnorr.prove(r, e, x)

    # Check consistency of the generated quantities
    assert schnorr.verify(V, C, e, p) == schnorr.OK

    # Run benchmark
    fncall = lambda: schnorr.commit(None, r)
    time_func("commit   ", fncall, unit="us")

    fncall = lambda: schnorr.challenge(V, C, ID, AD=AD)
    time_func("challenge", fncall, unit="us")

    fncall = lambda: schnorr.prove(r, e, x)
    time_func("prove    ", fncall, unit="us")

    fncall = lambda: schnorr.verify(V, C, e, p)
    time_func("verify   ", fncall, unit="us")
