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
import amcl.aes

seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"

if __name__ == "__main__":

    # CSPRNG
    seed    = bytes.fromhex(seed_hex)
    # seed = os.urandom(16)
    rng = amcl.core_utils.create_csprng(seed)
    iv = amcl.core_utils.generate_random(rng, amcl.aes.IVL)
    key = amcl.core_utils.generate_random(rng, amcl.aes.KEYL)
    aad = b"hello world"
    plaintext1 = b'test message'

    print("Encrypt message")
    print(f"\tplaintext: {plaintext1.decode('utf-8')}")
    print(f"\tiv: {iv.hex()}")
    print(f"\tkey: {key.hex()}")
    print(f"\taad: {aad.hex()}")

    ciphertext, tag1 = amcl.aes.gcm_encrypt(key, iv, aad, plaintext1)

    print("\nEncrypted message")
    print(f"\tciphertext: {ciphertext.hex()}")
    print(f"\ttag: {tag1.hex()}")

    plaintext2, tag2 = amcl.aes.gcm_decrypt(key, iv, aad, ciphertext)
    assert tag1 == tag2, 'tags are not equal!'
    assert plaintext1 == plaintext2, 'Plaintext are not equal!'

    print("\nDecrypted message")
    print(f"\tplaintext: {plaintext2.decode('utf-8')}")
    print(f"\ttag: {tag2.hex()}")

    # Create ciphertext error
    ciphertext_hex = ciphertext.hex()
    new = list(ciphertext_hex)
    new[0] = "a" if (new[0] != "a") else "b"
    ciphertext_bad_hex = ''.join(new)
    ciphertext_bad = bytes.fromhex(ciphertext_bad_hex)

    plaintext3, tag3 = amcl.aes.gcm_decrypt(key, iv, aad, ciphertext_bad)
    assert tag1 != tag3, 'tags are equal!'
    assert plaintext1 != plaintext3, 'Plaintext not equal!'

    # Create aad error
    aad_hex = aad.hex()
    new = list(aad_hex)
    new[0] = "a" if (new[0] != "a") else "b"
    aad_bad_hex = ''.join(new)
    aad_bad = bytes.fromhex(aad_bad_hex)

    plaintext4, tag4 = amcl.aes.gcm_decrypt(key, iv, aad_bad, ciphertext)
    assert tag1 != tag4, 'tags are equal!'
    assert plaintext1 == plaintext4, 'Plaintext are not equal!'

    # Create iv error
    iv_hex = iv.hex()
    new = list(iv_hex)
    new[0] = "a" if (new[0] != "a") else "b"
    iv_bad_hex = ''.join(new)
    iv_bad = bytes.fromhex(iv_bad_hex)

    plaintext5, tag5 = amcl.aes.gcm_decrypt(key, iv_bad, aad, ciphertext)
    assert tag1 != tag5, 'tags are equal!'
    assert plaintext1 != plaintext5, 'Plaintext are equal!'

    # Create key error
    key_hex = key.hex()
    new = list(key_hex)
    new[0] = "a" if (new[0] != "a") else "b"
    key_bad_hex = ''.join(new)
    key_bad = bytes.fromhex(key_bad_hex)

    plaintext6, tag6 = amcl.aes.gcm_decrypt(key_bad, iv, aad, ciphertext)
    assert tag1 != tag6, 'tags are equal!'
    assert plaintext1 != plaintext6, 'Plaintext are equal!'

