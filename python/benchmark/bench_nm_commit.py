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

from amcl import nm_commitment as nm

x_hex = "40576370e36018f6bfaffc4c66780303a361f0c5f4a18a86a74fb179ca0fcf22"
r_hex = "296f910bde4530efe3533ed3b74475d6022364db2e57773207734b6daf547ac8"

if __name__ == "__main__":
    x = bytes.fromhex(x_hex)
    r = bytes.fromhex(r_hex)

    # Generate quantities for benchmark
    r, c = nm.commit(None, x, r)

    assert nm.decommit(x, r, c) == nm.OK

    # Run benchmark
    fncall = lambda: nm.commit(None, x, r)
    time_func("nm_commit  ", fncall, unit="us")

    fncall = lambda: nm.decommit(x, r, c)
    time_func("nm_decommit", fncall, unit="us")
