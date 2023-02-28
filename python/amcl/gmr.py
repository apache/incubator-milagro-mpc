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

This module use cffi to access the c functions in the amcl_mpc library.

"""

import platform
from . import core_utils

_ffi = core_utils._ffi
_ffi.cdef("""
#define GMR_n_iters 10

typedef BIG_1024_58 GMR_proof[GMR_n_iters][FFLEN_2048];

void GMR_prove(MODULUS_priv *m, const octet *ID, const octet *AD, GMR_proof Y);
int GMR_verify(octet *N, GMR_proof Y, const octet *ID, const octet *AD);
void GMR_proof_toOctet(octet *O, GMR_proof p);
int GMR_proof_fromOctet(GMR_proof p, octet *O);
""")

if (platform.system() == 'Windows'):
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.dll")
elif (platform.system() == 'Darwin'):
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.dylib")
else:
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.so")

# Constants
FS_2048 = 256               # Size of an FF_2048 in bytes
HFS_2048 = 128              # Half-size of an FF_2048 in bytes

SHA256 = 32                 # Chosen hash function size in bytes

OK            = 0           # Proof successfully verified
FAIL          = 111         # Invalid proof
INVALID_PROOF = 112         # Invalid proof bounds */

PROOF_SIZE = 10 * FS_2048   # 10 Iterations are necessary for the GMR proof


def prove(p, q, ID, AD=None):
    """ Generate GMR Square Freeness Proof of n = p*q

    Args::
        p  : First prime factor of n. HFS_2048 bytes long
        q  : Second prime factor of n. HFS_2048 bytes long
        ID : Unique identifier of the prover
        AD : Additional data to bind in the proof. Optional

    Returns::
        y  : GMR Proof of Square Freeness of n

    Raises::

    """

    if AD is None:
        ad_oct = _ffi.NULL
    else:
        ad_oct, ad_val = core_utils.make_octet(None, AD)
        _ = ad_val # Suppress warning

    p_oct, p_val   = core_utils.make_octet(None, p)
    q_oct, q_val   = core_utils.make_octet(None, q)
    id_oct, id_val = core_utils.make_octet(None, ID)
    _ = p_val, q_val, id_val # Suppress warnings

    y = _ffi.new('GMR_proof')

    modulus = _ffi.new('MODULUS_priv*')

    _libamcl_mpc.MODULUS_fromOctets(modulus, p_oct, q_oct)
    _libamcl_mpc.GMR_prove(modulus, id_oct, ad_oct, y)

    # Clear memory
    _libamcl_mpc.MODULUS_kill(modulus)
    core_utils.clear_octet(p_oct)
    core_utils.clear_octet(q_oct)

    return y


def verify(n, y, ID, AD=None):
    """ Verify GMR Proof of Square Freeness of y

    Args::
        n  : public modulus
        y  : Proof of Square Freeness
        ID : Unique identifier of the prover
        AD : Additional data to bind in the challenge. Optional

    Returns::
        rc : OK if the verification is successful or an error code

    Raises::

    """

    if AD is None:
        ad_oct = _ffi.NULL
    else:
        ad_oct, ad_val = core_utils.make_octet(None, AD)
        _ = ad_val # Suppress warning

    n_oct, n_val   = core_utils.make_octet(None, n)
    id_oct, id_val = core_utils.make_octet(None, ID)
    _ = n_val, id_val # Suppress warning

    rc = _libamcl_mpc.GMR_verify(n_oct, y, id_oct, ad_oct)

    return rc


def proof_to_octet(p):
    """ Write a GMR Proof to a string

    Args::
        p     : GMR Proof

    Returns::
        p_str : string encoding the GMR Proof

    Raises::

    """

    p_oct, _ = core_utils.make_octet(PROOF_SIZE)

    _libamcl_mpc.GMR_proof_toOctet(p_oct, p)

    return core_utils.to_str(p_oct)


def proof_from_octet(p_str):
    """ Read a GMR Proof from a string

    Args::
        p_str : string encoding the GMR Proof

    Returns::
        p     : GMR Proof
        rc    : OK or an error code

    Raises::

    """

    p_oct, _ = core_utils.make_octet(None, p_str)

    p = _ffi.new('GMR_proof')

    rc = _libamcl_mpc.GMR_proof_fromOctet(p, p_oct)

    if rc != OK:
        return _ffi.NULL, rc

    return p, rc
