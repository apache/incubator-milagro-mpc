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
from . import core_utils

_ffi = core_utils._ffi
_ffi.cdef("""
#define HDLOG_n_iters 128

typedef BIG_1024_58 HDLOG_iter_values[HDLOG_n_iters][FFLEN_2048];

typedef struct
{
    MODULUS_priv mod;
    BIG_1024_58 pq[FFLEN_2048];
    BIG_1024_58 alpha[FFLEN_2048];
    BIG_1024_58 ialpha[FFLEN_2048];
    BIG_1024_58 b0[FFLEN_2048];
    BIG_1024_58 b1[FFLEN_2048];
} BIT_COMMITMENT_priv;

typedef struct
{
    BIG_1024_58 N[FFLEN_2048];
    BIG_1024_58 b0[FFLEN_2048];
    BIG_1024_58 b1[FFLEN_2048];
} BIT_COMMITMENT_pub;

typedef struct
{
    HDLOG_iter_values rho;
    HDLOG_iter_values irho;
    HDLOG_iter_values t;
    HDLOG_iter_values it;
} BIT_COMMITMENT_setup_proof;

extern void BIT_COMMITMENT_setup(csprng *RNG, BIT_COMMITMENT_priv *m, octet *P, octet *Q, octet *B0, octet *ALPHA);
extern void BIT_COMMITMENT_priv_fromOctets(BIT_COMMITMENT_priv *m, octet *P, octet *Q, octet *B0, octet * ALPHA);
extern void BIT_COMMITMENT_priv_toOctets(octet *P, octet *Q, octet *B0, octet * ALPHA, BIT_COMMITMENT_priv *m);
extern void BIT_COMMITMENT_priv_kill(BIT_COMMITMENT_priv *m);
extern void BIT_COMMITMENT_priv_to_pub(BIT_COMMITMENT_pub *pub, BIT_COMMITMENT_priv *priv);
extern void BIT_COMMITMENT_pub_fromOctets(BIT_COMMITMENT_pub *m, octet *N, octet *B0, octet *B1);
extern void BIT_COMMITMENT_pub_toOctets(octet *N, octet *B0, octet *B1, BIT_COMMITMENT_pub *m);
extern void BIT_COMMITMENT_setup_prove(csprng *RNG, BIT_COMMITMENT_priv *m, BIT_COMMITMENT_setup_proof *p, octet *id, octet *ad);
extern int BIT_COMMITMENT_setup_verify(BIT_COMMITMENT_pub *m, BIT_COMMITMENT_setup_proof *p, octet *id, octet *ad);
extern int BIT_COMMITMENT_setup_proof_fromOctets(BIT_COMMITMENT_setup_proof *p, octet *RHO, octet *IRHO, octet *T, octet *IT);
extern void BIT_COMMITMENT_setup_proof_toOctets(octet *RHO, octet *IRHO, octet *T, octet *IT, BIT_COMMITMENT_setup_proof *p);
""")

if (platform.system() == 'Windows'):
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.dll")
elif (platform.system() == 'Darwin'):
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.dylib")
else:
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.so")

# Constants
FS_2048 = 256      # Size of an FF_2048 in bytes
HFS_2048 = 128     # Half-size of an FF_2048 in bytes

HDLOG_iv_size = 128 * FS_2048 # 128 iterations are necessary for the HDLOG

OK             = 0
FAIL           = 121
INVALID_PROOF  = 122
INVALID_FORMAT = 123


def priv_from_octets(p, q, b0, alpha):
    """Read a Bit Commitment Private Modulus from byte arrays

    Args::

        p:     First factor of the modulus
        q:     Second factor of the modulus
        b0:    Generator of the subgroup
        alpha: Exponent for the second generator

    Returns::

        priv:  Private modulus for the Bit Commitment

    Raises::
    """
    priv = _ffi.new('BIT_COMMITMENT_priv*')

    p, p_val         = core_utils.make_octet(None, p)
    q, q_val         = core_utils.make_octet(None, q)
    b0, b0_val       = core_utils.make_octet(None, b0)
    alpha, alpha_val = core_utils.make_octet(None, alpha)
    _ = p_val, q_val, b0_val, alpha_val

    _libamcl_mpc.BIT_COMMITMENT_priv_fromOctets(priv, p, q, b0, alpha)

    # Clear memory
    core_utils.clear_octet(p)
    core_utils.clear_octet(q)
    core_utils.clear_octet(alpha)

    return priv


def priv_to_octets(priv):
    """Write a Bit Commitment Private Modulus into byte arrays

    Args::

        priv:  Private modulus for the Bit Commitment

    Returns::

        p:     First factor of the modulus
        q:     Second factor of the modulus
        b0:    Generator of the subgroup
        alpha: Exponent for the second generator

    Raises::
    """
    p, p_val         = core_utils.make_octet(HFS_2048)
    q, q_val         = core_utils.make_octet(HFS_2048)
    b0, b0_val       = core_utils.make_octet(FS_2048)
    alpha, alpha_val = core_utils.make_octet(FS_2048)
    _ = p_val, q_val, b0_val, alpha_val

    _libamcl_mpc.BIT_COMMITMENT_priv_toOctets(p, q, b0, alpha, priv)

    p_bytes     = core_utils.to_str(p)
    q_bytes     = core_utils.to_str(q)
    b0_bytes    = core_utils.to_str(b0)
    alpha_bytes = core_utils.to_str(alpha)

    # Clear memory
    core_utils.clear_octet(p)
    core_utils.clear_octet(q)
    core_utils.clear_octet(alpha)

    return p_bytes, q_bytes, b0_bytes, alpha_bytes


def priv_to_pub(priv):
    """Exports the public portion of a Bit Commitment Private Modulus

    Args::

        priv:  Private modulus for the Bit Commitment

    Returns::

        pub:   Public modulus for the Bit Commitment

    Raises::
    """
    pub = _ffi.new('BIT_COMMITMENT_pub*')

    _libamcl_mpc.BIT_COMMITMENT_priv_to_pub(pub, priv)

    return pub


def pub_from_octets(n, b0, b1):
    """Read a Bit Commitment Public Modulus from byte arrays

    Args::

        n:     Public Modulus
        b0:    First generator of the subgroup
        b1:    Second generator of the subgroup

    Returns::

        pub:  Public modulus for the Bit Commitment

    Raises::
    """
    pub = _ffi.new('BIT_COMMITMENT_pub*')

    n, n_val   = core_utils.make_octet(None, n)
    b0, b0_val = core_utils.make_octet(None, b0)
    b1, b1_val = core_utils.make_octet(None, b1)
    _ = n_val, b0_val, b1_val

    _libamcl_mpc.BIT_COMMITMENT_pub_fromOctets(pub, n, b0, b1)

    return pub


def pub_to_octets(pub):
    """Write a Bit Commitment Public Modulus into byte arrays

    Args::

        pub:  Public modulus for the Bit Commitment

    Returns::

        n:     Public Modulus
        b0:    First generator of the subgroup
        b1:    Second generator of the subgroup

    Raises::
    """

    n, n_val   = core_utils.make_octet(FS_2048)
    b0, b0_val = core_utils.make_octet(FS_2048)
    b1, b1_val = core_utils.make_octet(FS_2048)
    _ = n_val, b0_val, b1_val

    _libamcl_mpc.BIT_COMMITMENT_pub_toOctets(n, b0, b1, pub)

    n_bytes  = core_utils.to_str(n)
    b0_bytes = core_utils.to_str(b0)
    b1_bytes = core_utils.to_str(b1)

    return n_bytes, b0_bytes, b1_bytes


def setup_proof_from_octets(rho, irho, t, it):
    """Read a ZKP of well formedness of a BC Setup from byte arrays

    Args::

        rho:   Commitment for the first generator ZKP
        irho:  Commitment for the second generator ZKP
        t:     Proof for the first generator ZKP
        it:    Proof for the second generator ZKP

    Returns::

        proof: Imported proof system
        rc:    OK or an error code

    Raises::
    """
    rho, rho_val   = core_utils.make_octet(None, rho)
    irho, irho_val = core_utils.make_octet(None, irho)
    t, t_val       = core_utils.make_octet(None, t)
    it, it_val     = core_utils.make_octet(None, it)
    _ = rho_val, irho_val, t_val, it_val

    proof = _ffi.new('BIT_COMMITMENT_setup_proof*')

    rc = _libamcl_mpc.BIT_COMMITMENT_setup_proof_fromOctets(proof, rho, irho, t, it)
    if rc != OK:
        return _ffi.NULL, INVALID_FORMAT

    return proof, OK


def setup_proof_to_octets(proof):
    """Write a Bit Commitment Public Modulus into byte arrays

    Args::

        proof: Proof system to export

    Returns::

        rho:   Commitment for the first generator ZKP
        irho:  Commitment for the second generator ZKP
        t:     Proof for the first generator ZKP
        it:    Proof for the second generator ZKP

    Raises::

    """
    rho, rho_val   = core_utils.make_octet(HDLOG_iv_size)
    irho, irho_val = core_utils.make_octet(HDLOG_iv_size)
    t, t_val       = core_utils.make_octet(HDLOG_iv_size)
    it, it_val     = core_utils.make_octet(HDLOG_iv_size)
    _ = rho_val, irho_val, t_val, it_val


    _libamcl_mpc.BIT_COMMITMENT_setup_proof_toOctets(rho, irho, t, it, proof)

    rho_bytes  = core_utils.to_str(rho)
    irho_bytes = core_utils.to_str(irho)
    t_bytes    = core_utils.to_str(t)
    it_bytes   = core_utils.to_str(it)

    return rho_bytes, irho_bytes, t_bytes, it_bytes


def setup(rng, p=None, q=None, b0=None, alpha=None):
    """Generate a Setup for the Bit Commitment

    Args::

        rng :  Pointer to cryptographically secure pseudo-random generator instance
        p:     First factor of the modulus
        q:     Second factor of the modulus
        b0:    Generator of the subgroup
        alpha: DLOG exponent for the second generator - Optional

    Returns::

        priv:  Private modulus for the Bit Commitment Setup

    Raises::
    """
    priv = _ffi.new('BIT_COMMITMENT_priv*')

    if p is None:
        p = _ffi.NULL
    else:
        p, p_val = core_utils.make_octet(None, p)
        _ = p_val

    if q is None:
        q = _ffi.NULL
    else:
        q, q_val = core_utils.make_octet(None, q)
        _ = q_val

    if b0 is None:
        b0 = _ffi.NULL
    else:
        b0, b0_val = core_utils.make_octet(None, b0)
        _ = b0_val

    if alpha is None:
        alpha = _ffi.NULL
    else:
        alpha, alpha_val = core_utils.make_octet(None, alpha)
        _ = alpha_val

    _libamcl_mpc.BIT_COMMITMENT_setup(rng, priv, p, q, b0, alpha)

    # Clear memory
    if p != _ffi.NULL:
        core_utils.clear_octet(p)

    if q != _ffi.NULL:
        core_utils.clear_octet(q)

    if alpha != _ffi.NULL:
        core_utils.clear_octet(alpha)

    return priv


def setup_prove(rng, priv, id, ad=None):
    """Generate a proof of well formedness of the Private Modulus priv

    Args::

        rng:  Pointer to cryptographically secure pseudo-random generator instance
        priv: Private Bit Commitment Setup modulus
        id:   Unique identifier of the prover
        ad:   Additional data to bind in the proof

    Returns::

        proof: Proof of well formedness of priv

    Raises::
    """
    proof = _ffi.new('BIT_COMMITMENT_setup_proof*')

    if ad is None:
        ad = _ffi.NULL
    else:
        ad, ad_val = core_utils.make_octet(None, ad)
        _ = ad_val # Suppress warning

    id, id_val = core_utils.make_octet(None, id)
    _ = id_val

    _libamcl_mpc.BIT_COMMITMENT_setup_prove(rng, priv, proof, id, ad)

    return proof


def setup_verify(pub, proof, id, ad=None):
    """Generate a proof of well formedness of the Private Modulus priv

    Args::

        pub:   Private Bit Commitment Setup modulus
        proof: Proof of well formedness of pub
        id:    Unique identifier of the prover
        ad:    Additional data to bind in the proof

    Returns::

        rc:    OK or an error code

    Raises::
    """
    if ad is None:
        ad = _ffi.NULL
    else:
        ad, ad_val = core_utils.make_octet(None, ad)
        _ = ad_val # Suppress warning

    id, id_val = core_utils.make_octet(None, id)
    _ = id_val

    rc = _libamcl_mpc.BIT_COMMITMENT_setup_verify(pub, proof, id, ad)

    return rc

