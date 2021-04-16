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

from amcl import core_utils, gmr


p_hex  = "e008507e09c24d756280f3d94912fb9ac16c0a8a1757ee01a350736acfc7f65880f87eca55d6680253383fc546d03fd9ebab7d8fa746455180888cb7c17edf58d3327296468e5ab736374bc9a0fa02606ed5d3a4a5fb1677891f87fbf3c655c3e0549a86b17b7ddce07c8f73e253105e59f5d3ed2c7ba5bdf8495df40ae71a7f"
q_hex  = "d344c02d8379387e773ab6fa6de6b92b395d5b7f0c41660778766a1ec4740468203bff2d05f263ff6f22740d4b2e799fd1fd2e2339e328c62d31eeecba30fd4892e0c1637e0f62b4de34f5d778a7dfd181b94464f3669751264a0058708a360552535653efc75e3035485e966df30a17146d692747e20b2f04f3877dd1f56dcf"
id_str = "unique_identifier"
ad_hex = "d7d3155616778fb436a1eb2070892205"


def process_tv(vector):
    for key, val in vector.items():
        if key == "TEST":
            vector[key] = val
        elif not val:
            vector[key] = None
        else:
            vector[key] = bytes.fromhex(val)

    return vector


class TestProve(unittest.TestCase):
    """ Test GMR SF Proof """

    def setUp(self):
        with open("gmr/prove.json", "r") as f:
            self.tv = json.load(f)

        for vector in self.tv:
            process_tv(vector)

    def test(self):
        """ test using test vector """

        for vector in self.tv:
            p  = vector['P']
            q  = vector['Q']
            ID = vector['ID']
            AD = vector['AD']

            y = gmr.prove(p, q, ID, AD=AD)
            y_oct = gmr.proof_to_octet(y)

            self.assertEqual(y_oct, vector['Y'])


class TestVerify(unittest.TestCase):
    """ Test GMR SF Verification """

    def setUp(self):
        with open("gmr/verify.json", "r") as f:
            self.tv = json.load(f)

        for vector in self.tv:
            process_tv(vector)

    def test(self):
        """ test using test vector """

        for vector in self.tv:
            n  = vector['N']
            ID = vector['ID']
            AD = vector['AD']

            y, rc = gmr.proof_from_octet(vector['Y'])
            self.assertEqual(rc, gmr.OK)

            rc = gmr.verify(n, y, ID, AD=AD)
            self.assertEqual(rc, gmr.OK)


class TestOctets(unittest.TestCase):
    """ Test GMR octet functions """

    def setUp(self):
        with open("gmr/verify.json", "r") as f:
            self.tv = json.load(f)

        for vector in self.tv:
            process_tv(vector)

    def test(self):
        """ test using test vector """

        for vector in self.tv:
            y, rc = gmr.proof_from_octet(vector['Y'])
            self.assertEqual(rc, gmr.OK)

            y_str = gmr.proof_to_octet(y)
            self.assertEqual(y_str, vector['Y'])


if __name__ == '__main__':
    # Run tests
    unittest.main()
