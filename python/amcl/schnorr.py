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

This module use cffi to access the c functions in the amcl_mpc library.

"""
import cffi
import platform
import os

import gc

ffi = cffi.FFI()
ffi.cdef("""
typedef long unsigned int BIG_512_60[9];
typedef long unsigned int BIG_1024_58[18];

typedef struct {
unsigned int ira[21];  /* random number...   */
int rndptr;   /* ...array & pointer */
unsigned int borrow;
int pool_ptr;
char pool[32];    /* random pool */
} csprng;

typedef struct
{
  int len;
  int max;
  char *val;
} octet;

extern void RAND_seed(csprng *R,int n,char *b);
extern void RAND_clean(csprng *R);
extern void OCT_clear(octet *O);

extern void SCHNORR_random_challenge(csprng *RNG, octet *E);

extern void SCHNORR_commit(csprng *RNG, octet *R, octet *C);
extern void SCHNORR_challenge(octet *V, octet *C, octet *E);
extern void SCHNORR_prove(octet *R, octet *E, octet *X, octet *P);
extern int  SCHNORR_verify(octet *V, octet *C, octet *E, octet *P);
""")

if (platform.system() == 'Windows'):
    libamcl_mpc = ffi.dlopen("libamcl_mpc.dll")
    libamcl_curve_secp256k1 = ffi.dlopen("libamcl_curve_SECP256K1.dll")
    libamcl_core = ffi.dlopen("libamcl_core.dll")
elif (platform.system() == 'Darwin'):
    libamcl_mpc = ffi.dlopen("libamcl_mpc.dylib")
    libamcl_curve_secp256k1 = ffi.dlopen("libamcl_curve_SECP256K1.dylib")
    libamcl_core = ffi.dlopen("libamcl_core.dylib")
else:
    libamcl_mpc = ffi.dlopen("libamcl_mpc.so")
    libamcl_curve_secp256k1 = ffi.dlopen("libamcl_curve_SECP256K1.so")
    libamcl_core = ffi.dlopen("libamcl_core.so")

# Constants
EGS = 32
EFS = 32
PTS = EFS + 1

OK          = 0
FAIL        = 51
INVALID_ECP = 52

def to_str(octet_value):
    """Converts an octet type into a string

    Add all the values in an octet into an array.

    Args::

        octet_value. An octet pointer type

    Returns::

        String

    Raises:
        Exception
    """
    i = 0
    val = []
    while i < octet_value.len:
        val.append(octet_value.val[i])
        i = i + 1
    out = b''
    for x in val:
        out = out + x
    return out


def make_octet(length, value=None):
    """Generates an octet pointer

    Generates an empty octet or one filled with the input value

    Args::

        length: Length of empty octet
        value:  Data to assign to octet

    Returns::

        oct_ptr: octet pointer
        val: data associated with octet to prevent garbage collection

    Raises:

    """
    oct_ptr = ffi.new("octet*")
    if value:
        val = ffi.new("char [%s]" % len(value), value)
        oct_ptr.val = val
        oct_ptr.max = len(value)
        oct_ptr.len = len(value)
    else:
        val = ffi.new("char []", length)
        oct_ptr.val = val
        oct_ptr.max = length
        oct_ptr.len = 0
    return oct_ptr, val


def create_csprng(seed):
    """Make a Cryptographically secure pseudo-random number generator instance

    Make a Cryptographically secure pseudo-random number generator instance

    Args::

        seed:   random seed value

    Returns::

        rng: Pointer to cryptographically secure pseudo-random number generator instance

    Raises:

    """
    seed_val = ffi.new("char [%s]" % len(seed), seed)
    seed_len = len(seed)

    # random number generator
    rng = ffi.new('csprng*')
    libamcl_core.RAND_seed(rng, seed_len, seed_val)

    return rng


def kill_csprng(rng):
    """Kill a random number generator

    Deletes all internal state

    Args::

        rng: Pointer to cryptographically secure pseudo-random number generator instance

    Returns::

    Raises:

    """
    libamcl_core.RAND_clean(rng)

    return 0


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

    e, e_val = make_octet(EGS)
    _ = e_val # Suppress warning

    libamcl_mpc.SCHNORR_random_challenge(rng, e)

    return to_str(e)


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
        r_oct, r_val = make_octet(EGS)
    else:
        r_oct, r_val = make_octet(None, r)
        rng = ffi.NULL

    C, C_val = make_octet(PTS)
    _ = r_val, C_val # Suppress warning


    libamcl_mpc.SCHNORR_commit(rng, r_oct, C)

    r = to_str(r_oct)

    # Clean memory
    libamcl_core.OCT_clear(r_oct)

    return r, to_str(C)


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
    V_oct, V_val = make_octet(None, V)
    C_oct, C_val = make_octet(None, C)
    _ = V_val, C_val # Suppress warning

    e, e_val = make_octet(EGS)
    _ = e_val # Suppress warning

    libamcl_mpc.SCHNORR_challenge(V_oct, C_oct, e)

    return to_str(e)


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
    r_oct, r_val = make_octet(None, r)
    e_oct, e_val = make_octet(None, e)
    x_oct, x_val = make_octet(None, x)
    _ = r_val, e_val, x_val # Suppress warning

    p, p_val = make_octet(EGS)
    _ = p_val # Suppress warning

    libamcl_mpc.SCHNORR_prove(r_oct, e_oct, x_oct, p)

    # Clean memory
    libamcl_core.OCT_clear(r_oct)
    libamcl_core.OCT_clear(x_oct)

    return to_str(p)


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
    V_oct, V_val = make_octet(None, V)
    C_oct, C_val = make_octet(None, C)
    e_oct, e_val = make_octet(None, e)
    p_oct, p_val = make_octet(None, p)
    _ = V_val, C_val, e_val, p_val # Suppress warning

    ec = libamcl_mpc.SCHNORR_verify(V_oct, C_oct, e_oct, p_oct)

    return ec
