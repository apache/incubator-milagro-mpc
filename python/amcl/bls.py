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


"""
bls

This module use cffi to access the c functions in the BLS library.

There is also an example usage program in this file.

"""

import platform
from amcl import core_utils

_ffi = core_utils._ffi
_ffi.cdef("""
extern int BLS_BLS381_KEY_PAIR_GENERATE(csprng *RNG,octet* S,octet *W);
extern int BLS_BLS381_SIGN(octet *SIG,octet *m,octet *S);
extern int BLS_BLS381_VERIFY(octet *SIG,octet *m,octet *W);
extern int BLS_BLS381_ADD_G1(octet *R1,octet *R2,octet *R);
extern int BLS_BLS381_ADD_G2(octet *W1,octet *W2,octet *W);
""")

if (platform.system() == 'Windows'):
    _libamcl_bls_BLS381 = _ffi.dlopen("libamcl_bls_BLS381.dll")
elif (platform.system() == 'Darwin'):
    _libamcl_bls_BLS381 = _ffi.dlopen("libamcl_bls_BLS381.dylib")
else:
    _libamcl_bls_BLS381 = _ffi.dlopen("libamcl_bls_BLS381.so")

# Group Size
BGS = 48
# Field Size
BFS = 48

CURVE_SECURITY = 128

G1LEN = BFS + 1

if CURVE_SECURITY == 128:
    G2LEN = 4 * BFS

if CURVE_SECURITY == 192:
    G2LEN = 8 * BFS

if CURVE_SECURITY == 256:
    G2LEN = 16 * BFS


def key_pair_generate(rng, sk=None):
    """Generate key pair

    Generate key pair

    Args::

        rng: Pointer to cryptographically secure pseudo-random number generator instance
        sk: secret key. Externally generated

    Returns::

        error_code: error from the C function
        sk: secret key
        pk: public key

    Raises:

    """
    if sk:
        sk1, sk1_val = core_utils.make_octet(None, sk)
        rng = _ffi.NULL
    else:
        sk1, sk1val = core_utils.make_octet(BGS)

    pk1, pk1val = core_utils.make_octet(G2LEN)
    error_code = _libamcl_bls_BLS381.BLS_BLS381_KEY_PAIR_GENERATE(rng, sk1, pk1)

    sk = core_utils.to_str(sk1)
    pk = core_utils.to_str(pk1)

    # clear memory
    core_utils.clear_octet(sk1)
    core_utils.clear_octet(pk1)

    return error_code, sk, pk


def sign(message, sk):
    """Calculate a signature

    Generate key pair

    Args::

        message: Message to sign
        sk: BLS secret key

    Returns::

        error_code: Zero for success or else an error code
        signature: BLS signature

    Raises:

    """
    m, m_val = core_utils.make_octet(None, message)
    sk1, sk1_val = core_utils.make_octet(None, sk)
    signature1, signature1_val = core_utils.make_octet(G1LEN)
    error_code = _libamcl_bls_BLS381.BLS_BLS381_SIGN(signature1, m, sk1)

    signature = core_utils.to_str(signature1)

    # clear memory
    core_utils.clear_octet(sk1)
    core_utils.clear_octet(signature1)

    return error_code, signature


def verify(signature, message, pk):
    """Verify a signature

    Verify a signature

    Args::

        message: Message to verify
        signature: BLS signature
        pk: BLS public key

    Returns::

        error_code: Zero for success or else an error code

    Raises:

    """
    m, m_val = core_utils.make_octet(None, message)
    pk1, pk1_val = core_utils.make_octet(None, pk)
    signature1, signature1_val = core_utils.make_octet(None, signature)
    error_code = _libamcl_bls_BLS381.BLS_BLS381_VERIFY(signature1, m, pk1)

    # clear memory
    core_utils.clear_octet(pk1)
    core_utils.clear_octet(signature1)

    return error_code


def add_G1(R1, R2):
    """Add two members from the group G1

    Add two members from the group G1

    Args::

        R1:   member of G1
        R2:   member of G1

    Returns::

        R:          member of G1. R = R1+R2
        error_code: Zero for success or else an error code

    Raises:

    """
    R11, R11_val = core_utils.make_octet(None, R1)
    R21, R21_val = core_utils.make_octet(None, R2)
    R1, R1_val = core_utils.make_octet(G1LEN)
    error_code = _libamcl_bls_BLS381.BLS_BLS381_ADD_G1(R11, R21, R1)

    R = core_utils.to_str(R1)

    # clear memory
    core_utils.clear_octet(R11)
    core_utils.clear_octet(R21)
    core_utils.clear_octet(R1)

    return error_code, R


def add_G2(R1, R2):
    """Add two members from the group G2

    Add two members from the group G2

    Args::

        R1:   member of G2
        R2:   member of G2

    Returns::

        R:          member of G2. R = R1+R2
        error_code: Zero for success or else an error code

    Raises:

    """
    R11, R11_val = core_utils.make_octet(None, R1)
    R21, R21_val = core_utils.make_octet(None, R2)
    R1, R1_val = core_utils.make_octet(G2LEN)
    error_code = _libamcl_bls_BLS381.BLS_BLS381_ADD_G2(R11, R21, R1)

    R = core_utils.to_str(R1)

    # clear memory
    core_utils.clear_octet(R11)
    core_utils.clear_octet(R21)
    core_utils.clear_octet(R1)

    return error_code, R

