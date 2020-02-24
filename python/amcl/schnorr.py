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
extern void SCHNORR_random_challenge(csprng *RNG, octet *E);
extern void SCHNORR_commit(csprng *RNG, octet *R, octet *C);
extern void SCHNORR_challenge(octet *V, octet *C, octet *E);
extern void SCHNORR_prove(octet *R, octet *E, octet *X, octet *P);
extern int  SCHNORR_verify(octet *V, octet *C, octet *E, octet *P);
""")

if (platform.system() == 'Windows'):
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.dll")
    _libamcl_curve_secp256k1 = _ffi.dlopen("libamcl_curve_SECP256K1.dll")
elif (platform.system() == 'Darwin'):
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.dylib")
    _libamcl_curve_secp256k1 = _ffi.dlopen("libamcl_curve_SECP256K1.dylib")
else:
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.so")
    _libamcl_curve_secp256k1 = _ffi.dlopen("libamcl_curve_SECP256K1.so")

# Constants
EGS = 32      # Size of a Z/qZ element in bytes
EFS = 32      # Size of a Fp element in bytes
PTS = EFS + 1 # Size of a ECP in compressed form

OK          = 0
FAIL        = 51
INVALID_ECP = 52


def random_challenge(rng):
    """Generate a random challenge for the Schnorr's Proof

    Generates a random value e in [0, .., q] suitable as a
    random challenge for Schnorr's Proofs

    Args::

        rng: Pointer to cryptographically secure pseudo-random
             number generator instance

    Returns::

        e: Random challenge

    Raises:

    """

    e, e_val = core_utils.make_octet(EGS)
    _ = e_val # Suppress warning

    _libamcl_mpc.SCHNORR_random_challenge(rng, e)

    return core_utils.to_str(e)


def commit(rng, r=None):
    """Generate a commitment for the Schnorr's proof

    Generates a random value r in [0, .., q] and masks it
    with a DLOG

    Args::

        rng : Pointer to cryptographically secure pseudo-random
              number generator instance
        r   : Deterministic value for r

    Returns::

        r : Generated random value
        C : Public ECP of the DLOG. r.G

    Raises:

    """
    if r is None:
        r_oct, r_val = core_utils.make_octet(EGS)
    else:
        r_oct, r_val = core_utils.make_octet(None, r)
        rng = _ffi.NULL

    C, C_val = core_utils.make_octet(PTS)
    _ = r_val, C_val # Suppress warning

    _libamcl_mpc.SCHNORR_commit(rng, r_oct, C)

    r = core_utils.to_str(r_oct)

    # Clean memory
    core_utils.clear_octet(r_oct)

    return r, core_utils.to_str(C)


def challenge(V, C):
    """Generate a deterministic challenge for the Schnorr's Proof

    Generates a deterministic value r in [0, .., q] suitable as a
    random challenge for Schnorr's Proofs. It is generated as
    described in RFC8235#section-3.3

    Args::

        V : Public ECP of the DLOG. V = x.G
        C : Commitment for the Schnorr's Proof

    Returns::

        e : Deterministic challenge

    Raises:

    """
    V_oct, V_val = core_utils.make_octet(None, V)
    C_oct, C_val = core_utils.make_octet(None, C)
    _ = V_val, C_val # Suppress warning

    e, e_val = core_utils.make_octet(EGS)
    _ = e_val # Suppress warning

    _libamcl_mpc.SCHNORR_challenge(V_oct, C_oct, e)

    return core_utils.to_str(e)


def prove(r, e, x):
    """Generate proof

    Generates the proof for the Schnorr protocol.
    P = r - e * x mod q

    Args::

        r : Secret value used in the commitment
        e : Challenge for the Schnorr's protocol
        x : Secret exponent of the DLOG V = x.G

    Returns::

        p : Proof for the Schnorr's protocol

    Raises:

    """
    r_oct, r_val = core_utils.make_octet(None, r)
    e_oct, e_val = core_utils.make_octet(None, e)
    x_oct, x_val = core_utils.make_octet(None, x)
    _ = r_val, e_val, x_val # Suppress warning

    p, p_val = core_utils.make_octet(EGS)
    _ = p_val # Suppress warning

    _libamcl_mpc.SCHNORR_prove(r_oct, e_oct, x_oct, p)

    # Clean memory
    core_utils.clear_octet(r_oct)
    core_utils.clear_octet(x_oct)

    return core_utils.to_str(p)


def verify(V, C, e, p):
    """Verify a Schnorr's proof

    Check that C = p.G + e.V

    Args::

        V : Public ECP of the DLOG. V = x.G
        C : Commitment for the Schnorr's Proof
        e : Challenge for the Schnorr's Proof
        p : Proof

    Returns::

        ec : OK if the verification is successful, or an error code

    Raises:

    """
    V_oct, V_val = core_utils.make_octet(None, V)
    C_oct, C_val = core_utils.make_octet(None, C)
    e_oct, e_val = core_utils.make_octet(None, e)
    p_oct, p_val = core_utils.make_octet(None, p)
    _ = V_val, C_val, e_val, p_val # Suppress warning

    ec = _libamcl_mpc.SCHNORR_verify(V_oct, C_oct, e_oct, p_oct)

    return ec
