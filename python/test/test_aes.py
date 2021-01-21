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
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from amcl import core_utils, aes


class TestEncrypt(unittest.TestCase):
    """ Test AES-GCM encryption """

    def setUp(self):
        with open("gcm/encrypt.json", "r") as f:
            self.tv = json.load(f)

        for vector in self.tv:
            for key, val in vector.items():
                vector[key] = bytes.fromhex(val)

    def test_tv(self):
        """ Test using test vectors """

        for vector in self.tv:
            tag_golden = vector['tag']

            ct, tag = aes.gcm_encrypt(
              vector['key'],
              vector['iv'],
              vector['aad'],
              vector['pt'])

            # Cut tag to match length of test vector tag
            tag = tag[:len(tag_golden)]

            self.assertEqual(ct,  vector['ct'])
            self.assertEqual(tag, tag_golden)


class TestDecrypt(unittest.TestCase):
    """ Test AES-GCM decryption """

    def setUp(self):
        with open("gcm/decrypt.json", "r") as f:
            self.tv = json.load(f)

        for vector in self.tv:
            for key, val in vector.items():
                if key != "fail":
                    vector[key] = bytes.fromhex(val)

    def test_tv(self):
        """ Test using test vectors """

        for vector in self.tv:
            tag_golden = vector['tag']

            pt, tag = aes.gcm_decrypt(
              vector['key'],
              vector['iv'],
              vector['aad'],
              vector['ct'])

            # Cut tag to match length of test vector tag
            tag = tag[:len(tag_golden)]

            if vector.get('fail', False):
                self.assertNotEqual(tag, tag_golden)
            else:
                self.assertEqual(pt,  vector['pt'])
                self.assertEqual(tag, tag_golden)

if __name__ == '__main__':
    # Run tests
    unittest.main()
