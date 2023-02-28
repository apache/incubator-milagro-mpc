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

from amcl import core_utils, gmr


p_hex = "e008507e09c24d756280f3d94912fb9ac16c0a8a1757ee01a350736acfc7f65880f87eca55d6680253383fc546d03fd9ebab7d8fa746455180888cb7c17edf58d3327296468e5ab736374bc9a0fa02606ed5d3a4a5fb1677891f87fbf3c655c3e0549a86b17b7ddce07c8f73e253105e59f5d3ed2c7ba5bdf8495df40ae71a7f"
q_hex = "d344c02d8379387e773ab6fa6de6b92b395d5b7f0c41660778766a1ec4740468203bff2d05f263ff6f22740d4b2e799fd1fd2e2339e328c62d31eeecba30fd4892e0c1637e0f62b4de34f5d778a7dfd181b94464f3669751264a0058708a360552535653efc75e3035485e966df30a17146d692747e20b2f04f3877dd1f56dcf"
n_hex = "b8e304bb5468c17ccd3994d2c5946d5033d58853123fe43b9cf9d95315eac9f8797a31737cc5804d9273d83de0a5cc8614737b439348f99d3698071ef686b97d89543569078c1f392cbc6a7d37776139bbee82325d97542e78a35cd545feb86ebbf830016f0aedb920b5c69c829e3cfaaaa774cf44722d2b668fdaa05c20dd1dbf156abfd4a52953947fd46abaf5150dd4f4ed0d28660d0f13e003bc7428c13ad92d4bafd6cb8f60a4790d00931306dda5edf191a3e9dd3db7862d281e14e587b3e907a3b0447ef1e4d6335d097ce6fe10016e5d6731d634fecae718aade2fd3423d935da7ecdb33e219e37133b47c0118696127caef45407c26e5ca41b17fb1"


if __name__ == "__main__":
    ID = b'unique_identifier'
    AD = b'additional_data'

    p = bytes.fromhex(p_hex)
    q = bytes.fromhex(q_hex)
    n = bytes.fromhex(n_hex)

    print("Example GMR Square Freeness ZKP")
    print("\tID = {}".format(ID.decode('utf-8')))
    print("\tAD = {}".format(AD.decode('utf-8')))
    print("\tP  = {}".format(p.hex()))
    print("\tQ  = {}".format(q.hex()))
    print("\tN  = {}".format(n.hex()))
    print("")

    print("Prove n = p*q is Square Free")
    y = gmr.prove(p, q, ID, AD=AD)
    y_str = gmr.proof_to_octet(y)

    print("\tY = {}".format(y_str.hex()))
    print("")

    print("Verify GMR Proof")
    y, rc = gmr.proof_from_octet(y_str)

    if rc != gmr.OK:
        print("\tInvalid Proof Format")
        sys.exit(1)

    rc = gmr.verify(n, y, ID, AD=AD)

    if rc == gmr.OK:
        print("\tSuccess")
    else:
        print("\tFailure")
        sys.exit(1)
