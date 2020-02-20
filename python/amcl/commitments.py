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
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.dll")
elif (platform.system() == 'Darwin'):
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.dylib")
else:
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.so")

# Constants
SHA256 = 32

OK   = 0
FAIL = 81

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
        r_oct, r_val = core_utils.make_octet(SHA256)
    else:
        r_oct, r_val = core_utils.make_octet(None, r)
        rng = _ffi.NULL

    _ = r_val # Suppress warning

    x_oct, x_val = core_utils.make_octet(None, x)
    c_oct, c_val = core_utils.make_octet(SHA256)
    _ = x_val, c_val # Suppress warning

    _libamcl_mpc.COMMITMENTS_NM_commit(rng, x_oct, r_oct, c_oct)

    r = core_utils.to_str(r_oct)

    # Clean memory
    core_utils.clear_octet(x_oct)
    core_utils.clear_octet(r_oct)

    return r, core_utils.to_str(c_oct)

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

    x_oct, x_val = core_utils.make_octet(None, x)
    r_oct, r_val = core_utils.make_octet(None, r)
    c_oct, c_val = core_utils.make_octet(None, c)
    _ = x_val, r_val, c_val # Suppress warning

    ec = _libamcl_mpc.COMMITMENTS_NM_decommit(x_oct, r_oct, c_oct)

    return ec
