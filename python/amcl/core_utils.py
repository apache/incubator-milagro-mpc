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
// Necessary typedefs for milagro-crypto-c
typedef signed int sign32;

#define NLEN_256_56 5
#define NLEN_512_60 9
#define NLEN_1024_58 18

typedef long unsigned int BIG_256_56[NLEN_256_56];
typedef long unsigned int BIG_512_60[NLEN_512_60];
typedef long unsigned int BIG_1024_58[NLEN_1024_58];

#define HFLEN_2048 1
#define FFLEN_2048 2
#define HFLEN_4096 4
#define FFLEN_4096 8

typedef struct
{
    BIG_256_56 g;
    sign32 XES;
} FP_SECP256K1;

typedef struct
{
    FP_SECP256K1 x;
    FP_SECP256K1 y;
    FP_SECP256K1 z;
} ECP_SECP256K1;

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
extern void generateRandom(csprng* RNG, octet* randomValue);

typedef struct
{
    BIG_1024_58 p[HFLEN_2048];
    BIG_1024_58 q[HFLEN_2048];
    BIG_1024_58 invpq[HFLEN_2048];
    BIG_1024_58 n[FFLEN_2048];
} MODULUS_priv;

void MODULUS_fromOctets(MODULUS_priv *m, octet *P, octet *Q);
void MODULUS_kill(MODULUS_priv *m);
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
        val = _ffi.new(f"char [{len(value)}]", value)
        oct_ptr.val = val
        oct_ptr.max = len(value)
        oct_ptr.len = len(value)
    else:
        val = _ffi.new("char []", length)
        oct_ptr.val = val
        oct_ptr.max = length
        oct_ptr.len = 0
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


def make_empty_octets(n, length):
    """ Generate an n-array of empty octets of the specified length

    Generate an array of empty octets, or fill them with the values.

    If values is specified it MUST be a list of n strings

    Args::
        n      : Length of the octets array
        length : Length of the octets to create

    Returns::
        oct_ptr : pointer to the octet array
        vals    : list with the data associated to the octets to prevent garbage collection
   """
    oct_ptr = _ffi.new(f"octet [{n}]")

    vals = []

    for i in range(n):
        val = _ffi.new("char []", length)

        oct_ptr[i].val = val
        oct_ptr[i].max = length
        oct_ptr[i].len = 0

        vals.append(val)

    return oct_ptr, vals


def make_octets(values):
    """ Generate an n-array of octets from the given values

    Generate an array of empty octets, or fill them with the values.

    Args::
        values : Values to fill the octets

    Return::
        oct_ptr : pointer to the octet array
        vals    : list with the data associated to the octets to prevent garbage collection
   """
    oct_ptr = _ffi.new(f"octet [{len(values)}]")

    vals = []

    for i, v in enumerate(values):
        length = len(v)

        val = _ffi.new(f"char [{length}]", v)

        oct_ptr[i].val = val
        oct_ptr[i].max = length
        oct_ptr[i].len = length

        vals.append(val)

    return oct_ptr, vals


def clear_octets(octets, n):
    """ Clear an octet array

    Empty the octets in the array and zero out the underlying memory

    Args::

        octets : array of octets to clear
    """
    for i in range(n):
        _libamcl_core.OCT_clear(_ffi.addressof(octets, i))


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

def generate_random(rng, length):
    """Generate a random string

    Generate a random string

    Args::

        rng: Pointer to cryptographically secure pseudo-random number generator instance
        length: length of random byte array

    Returns::

        random_value: Random value

    Raises:

    """
    random_value1, random_value1_val = make_octet(length)
    _ = random_value1_val # Suppress warning

    # Set length of random value to tell the generateRandom
    # how long the random octet needs to be
    random_value1.len = length

    _libamcl_core.generateRandom(rng, random_value1)

    random_value = to_str(random_value1)

    # clear memory
    _libamcl_core.OCT_clear(random_value1)

    return random_value
