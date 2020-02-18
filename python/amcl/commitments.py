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
import platform
from amcl import core_utils

_ffi = core_utils._ffi
_ffi.cdef("""
extern void COMMITMENTS_NM_commit(csprng *RNG, octet *X, octet *R, octet *C);
extern int COMMITMENTS_NM_decommit(octet* X, octet* R, octet* C);
""")

if (platform.system() == 'Windows'):
    libamcl_mpc = _ffi.dlopen("libamcl_mpc.dll")
    libamcl_core = _ffi.dlopen("libamcl_core.dll")
elif (platform.system() == 'Darwin'):
    libamcl_mpc = _ffi.dlopen("libamcl_mpc.dylib")
    libamcl_core = _ffi.dlopen("libamcl_core.dylib")
else:
    libamcl_mpc = _ffi.dlopen("libamcl_mpc.so")
    libamcl_core = _ffi.dlopen("libamcl_core.so")

# Constants
SHA256 = 32

OK   = 0
FAIL = 81


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
    oct_ptr = _ffi.new("octet*")
    if value:
        val = _ffi.new("char [%s]" % len(value), value)
        oct_ptr.val = val
        oct_ptr.max = len(value)
        oct_ptr.len = len(value)
    else:
        val = _ffi.new("char []", length)
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
    seed_val = _ffi.new("char [%s]" % len(seed), seed)
    seed_len = len(seed)

    # random number generator
    rng = _ffi.new('csprng*')
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


def nm_commit(rng, x, r=None):
    """ Commit to the value x

    Generate a commitment c to the value x, using the value r.
    If r is empty it is randomly generated

    Args::

        rng : Pointer to cryptographically secure pseudo-random generator instance
        x   : value to commit
        r   : random value for the commitment. If empty it is randomly generated
              If not empty it must be 256 bit long

    Returns::

    Raises::

    """

    if r is None:
        r_oct, r_val = make_octet(SHA256)
    else:
        r_oct, r_val = make_octet(None, r)
        rng = _ffi.NULL

    _ = r_val # Suppress warning

    x_oct, x_val = make_octet(None, x)
    c_oct, c_val = make_octet(SHA256)
    _ = x_val, c_val # Suppress warning

    libamcl_mpc.COMMITMENTS_NM_commit(rng, x_oct, r_oct, c_oct)

    r = to_str(r_oct)

    # Clean memory
    libamcl_core.OCT_clear(x_oct)
    libamcl_core.OCT_clear(r_oct)

    return r, to_str(c_oct)

def nm_decommit(x, r, c):
    """ Decommit commitment c

    Decommit a commitment c to the value x, using the value r.

    Args::

        x : value to commit
        r : random value for the commitment. It must be 256 bit
        c : commitment value

    Returns::

    Raises::

    """

    x_oct, x_val = make_octet(None, x)
    r_oct, r_val = make_octet(None, r)
    c_oct, c_val = make_octet(None, c)
    _ = x_val, r_val, c_val # Suppress warning

    ec = libamcl_mpc.COMMITMENTS_NM_decommit(x_oct, r_oct, c_oct)

    return ec
