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

This module use cffi to access the c functions in the amcl_core library.

"""

import cffi
import platform

_ffi = cffi.FFI()
_ffi.cdef("""

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

""")

if (platform.system() == 'Windows'):
    _libamcl_core = _ffi.dlopen("libamcl_core.dll")
elif (platform.system() == 'Darwin'):
    _libamcl_core = _ffi.dlopen("libamcl_core.dylib")
else:
    _libamcl_core = _ffi.dlopen("libamcl_core.so")


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
        oct_ptr.len = length
    return oct_ptr, val


def clear_octet(octet):
    """ Clear an octet

    Empty the octet and zero out the underlying memory

    Args::

        octet : octet to clear

    Returns::

    Raises::
    """
    _libamcl_core.OCT_clear(octet)


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
    _libamcl_core.RAND_seed(rng, seed_len, seed_val)

    return rng


def kill_csprng(rng):
    """Kill a random number generator

    Deletes all internal state

    Args::

        rng: Pointer to cryptographically secure pseudo-random number generator instance

    Returns::

    Raises:

    """
    _libamcl_core.RAND_clean(rng)

    return 0
