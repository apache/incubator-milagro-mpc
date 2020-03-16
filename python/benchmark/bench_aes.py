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

from amcl import core_utils, aes

key_hex    = "2768a4f5a75344fee0ed46faaf7b020111fe5f0e80a88c0fd27abfcc15bc9d68"
header_hex = "1554a69ecbf04e507eb6985a234613246206c85f8af73e61ab6e2382a26f457d"
iv_hex     = "2b213af6b0edf6972bf996fb"

if __name__ == "__main__":
    key    = bytes.fromhex(key_hex)
    header = bytes.fromhex(header_hex)
    iv     = bytes.fromhex(iv_hex)
    
    plaintext = b'test message'
    
    # Generate quantities for bench run
    ciphertext, tag = aes.gcm_encrypt(key, iv, header, plaintext)
    dec_plaintext, dec_tag = aes.gcm_decrypt(key, iv, header, ciphertext)
    assert tag == dec_tag, 'Inconsistent decryption tag'
    
    # Run benchmark
    fncall = lambda: aes.gcm_encrypt(key, iv, header, plaintext)
    time_func("aes.gcm_encrypt", fncall, unit = 'us')

    fncall = lambda: aes.gcm_decrypt(key, iv, header, ciphertext)
    time_func("aes.gcm_decrypt", fncall, unit = 'us')
