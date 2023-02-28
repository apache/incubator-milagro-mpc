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
typedef struct {
    BIG_256_56 a;
    BIG_256_56 b;
} GG20_ZKP_rv;

typedef struct {
    BIG_256_56 t;
    BIG_256_56 u;
} GG20_ZKP_proof;

typedef struct {
    ECP_SECP256K1 ALPHA;
    ECP_SECP256K1 BETA;
} GG20_ZKP_phase6_commitment;

void GG20_ZKP_proof_fromOctets(GG20_ZKP_proof *p, octet *T, octet *U);
void GG20_ZKP_proof_toOctets(octet *T, octet *U, GG20_ZKP_proof *p);
int GG20_ZKP_phase6_commitment_fromOctets(GG20_ZKP_phase6_commitment *c, octet *ALPHA, octet *BETA);
void GG20_ZKP_phase6_commitment_toOctets(octet *ALPHA, octet *BETA, GG20_ZKP_phase6_commitment *c);

void GG20_ZKP_rv_kill(GG20_ZKP_rv *r);

void GG20_ZKP_phase3_commit(csprng *RNG, GG20_ZKP_rv *r, octet *C);
void GG20_ZKP_phase3_challenge(const octet *V, const octet *C, const octet* ID, const octet *AD, octet *E);
void GG20_ZKP_phase3_prove(GG20_ZKP_rv *r, const octet *E, const octet *S, const octet *L, GG20_ZKP_proof *p);
int GG20_ZKP_phase3_verify(octet *V, octet *C, const octet *E, GG20_ZKP_proof *p);

int GG20_ZKP_phase6_commit(csprng *RNG, octet *R, GG20_ZKP_rv *r, GG20_ZKP_phase6_commitment *c);
void GG20_ZKP_phase6_challenge(const octet *R, const octet *T, const octet *S, GG20_ZKP_phase6_commitment *c, const octet *ID, const octet *AD, octet *E);
void GG20_ZKP_phase6_prove(GG20_ZKP_rv *r, const octet *E, const octet *S, const octet *L, GG20_ZKP_proof *p);
int GG20_ZKP_phase6_verify(octet *R, octet *T, octet *S, GG20_ZKP_phase6_commitment *c, const octet *E, GG20_ZKP_proof *p);

""")

if (platform.system() == 'Windows'):
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.dll")
elif (platform.system() == 'Darwin'):
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.dylib")
else:
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.so")

# Constants
EGS = 32      # Size of a Z/qZ element in bytes
EFS = 32      # Size of a Fp element in bytes
PTS = EFS + 1 # Size of a ECP in compressed form

OK          = 0
FAIL        = 141
INVALID_ECP = 142


# Octet functions


def proof_from_octets(t, u):
    """ Import a proof from its components octets

    Args::
        t : t component of the proof
        u : u component of the proof

    Returns::
        p : pointer to the proof

    """
    p = _ffi.new('GG20_ZKP_proof*')

    t_oct, t_val = core_utils.make_octet(None, t)
    u_oct, u_val = core_utils.make_octet(None, u)
    _ = t_val, u_val  # Suppress warnings

    _libamcl_mpc.GG20_ZKP_proof_fromOctets(p, t_oct, u_oct)

    return p


def proof_to_octets(p):
    """ Export the proof to octets

    Args::
        p : pointer to the proof

    Returns::
        t : t component of the proof
        u : u component of the proof

    """
    t_oct, t_val = core_utils.make_octet(EGS)
    u_oct, u_val = core_utils.make_octet(EGS)
    _ = t_val, u_val  # Suppress warnings

    _libamcl_mpc.GG20_ZKP_proof_toOctets(t_oct, u_oct, p)

    t = core_utils.to_str(t_oct)
    u = core_utils.to_str(u_oct)

    return t, u


def phase6_commitment_from_octets(alpha, beta):
    """ Import a Phase 6 commitment from its components octets

    Args::
        alpha : commitment for the additional DLOG
        beta  : commitment for the double DLOG

    Returns::
        c  : pointer to the commitment. NULL if rc is not OK
        rc : OK or an error code

    """
    c = _ffi.new('GG20_ZKP_phase6_commitment*')

    alpha_oct, alpha_val = core_utils.make_octet(None, alpha)
    beta_oct,  beta_val  = core_utils.make_octet(None, beta)
    _ = alpha_val, beta_val  # Suppress warnings

    rc = _libamcl_mpc.GG20_ZKP_phase6_commitment_fromOctets(c, alpha_oct, beta_oct)
    if rc != OK:
        c = _ffi.NULL

    return c, rc


def phase6_commitment_to_octets(c):
    """ Export a Phase 6 commitment to octets

    Args::
        c : pointer to the commitment

    Returns::
        t : t component of the proof
        u : u component of the proof

    """
    alpha_oct, alpha_val = core_utils.make_octet(PTS)
    beta_oct,  beta_val  = core_utils.make_octet(PTS)
    _ = alpha_val, beta_val  # Suppress warnings

    _libamcl_mpc.GG20_ZKP_phase6_commitment_toOctets(alpha_oct, beta_oct, c)

    alpha = core_utils.to_str(alpha_oct)
    beta  = core_utils.to_str(beta_oct)

    return alpha, beta


# Cleanup functions


def rv_kill(rv):
    """ Clean memory for the commitment random values

    Args::
        rv : the random values to clean
    """

    _libamcl_mpc.GG20_ZKP_rv_kill(rv)


# GG20 ZKP Phase 3


def phase3_commit(rng, rv=None):
    ''' Generate a commitment for the GG20 Phase 3 ZKP

    Compute random values and commitment. If r is given as input, use
    the given values instead of generating random ones.

    Args::
        rng : Pointer to csprng
        rv  : Pointer to deterministic values for commitment. Optional

    Returns::
        r : Pointer to random values used in commitments
        C : commitment
    '''

    if rv is None:
        rv = _ffi.new('GG20_ZKP_rv*')
    else:
        rng = _ffi.NULL

    c_oct, _ = core_utils.make_octet(PTS)

    _libamcl_mpc.GG20_ZKP_phase3_commit(rng, rv, c_oct)

    return rv, core_utils.to_str(c_oct)


def phase3_challenge(V, C, ID, AD=None):
    """ Bind public parameters and commitment in challenge

    Args::
        V  : Public ECP of the double DLOG
        C  : Generated Commitment
        ID : Unique user identifier
        AD : Additional data to bind in the challenge. Optional

    Returns::
        E  : Pseudorandom challenge
    """

    if AD is None:
        ad_oct = _ffi.NULL
    else:
        ad_oct, ad_val = core_utils.make_octet(None, AD)
        _ = ad_val  # Suppress warning

    v_oct,  v_val  = core_utils.make_octet(None, V)
    c_oct,  c_val  = core_utils.make_octet(None, C)
    id_oct, id_val = core_utils.make_octet(None, ID)
    e_oct,  e_val  = core_utils.make_octet(EGS)
    _ = v_val, c_val, id_val, e_val  # Suppress warning

    _libamcl_mpc.GG20_ZKP_phase3_challenge(v_oct, c_oct, id_oct, ad_oct, e_oct)

    return core_utils.to_str(e_oct)


def phase3_prove(r, e, s, l):
    """ Generate proof from commitment random values and ZKP secret input

    Args::
        r : Pointer to commitment random values from commitment
        e : pseudorandom challenge
        s : secret exponent of the double DLOG for G
        l : secret exponent of the double DLOG for H

    Returns::
        p : Pointer to generated proof
    """

    e_oct, e_val = core_utils.make_octet(None, e)
    s_oct, s_val = core_utils.make_octet(None, s)
    l_oct, l_val = core_utils.make_octet(None, l)
    _ = e_val, s_val, l_val  # Suppress warning

    p = _ffi.new('GG20_ZKP_proof*')

    _libamcl_mpc.GG20_ZKP_phase3_prove(r, e_oct, s_oct, l_oct, p)

    return p


def phase3_verify(V, C, e, p):
    ''' Verify a GG20 ZKP

    Args::
        V : Public ECP of the DLOG
        C : Received Commitment
        e : Pesudo random challenge
        p : Pointer to Received Proof

    Returns::
        ok : OK or an error code
    '''

    v_oct, v_val = core_utils.make_octet(None, V)
    c_oct, c_val = core_utils.make_octet(None, C)
    e_oct, e_val = core_utils.make_octet(None, e)
    _ = v_val, c_val, e_val   # Suppress warnings

    rc = _libamcl_mpc.GG20_ZKP_phase3_verify(v_oct, c_oct, e_oct, p)

    return rc


# GG20 ZKP Phase 6


def phase6_commit(rng, R, rv=None):
    ''' Generate a commitment for the GG20 Phase 6 ZKP

    Compute random values and commitment. If rv is given as input, use
    the given values instead of generating random ones.

    Args::
        rng : Pointer to csprng
        R   : Base of the additional DLOG
        rv  : Pointer to deterministic values for commitment. Optional

    Returns::
        rv    : Pointer to random values used in commitments
        c     : Pointer to the commitment
        rc    : OK or an error code
    '''

    if rv is None:
        rv = _ffi.new('GG20_ZKP_rv*')
    else:
        rng = _ffi.NULL

    c = _ffi.new('GG20_ZKP_phase6_commitment*')
    r_oct, _ = core_utils.make_octet(None, R)

    rc = _libamcl_mpc.GG20_ZKP_phase6_commit(rng, r_oct, rv, c)

    if rc != OK:
        rv = _ffi.NULL
        c = _ffi.NULL

    return rv, c, rc


def phase6_challenge(R, T, S, c, ID, AD=None):
    """ Bind public parameters and commitment in challenge.

    Args::
        R  : Base ECP of the additional DLOG
        T  : Double DLOG public ECP
        S  : Additional DLOG public ECP
        c  : Pointer to generated Commitment
        ID : Unique user identifier
        AD : Additional data to bind in the challenge. Optional

    Returns::
        E : Pesudorandom challenge
    """

    if AD is None:
        ad_oct = _ffi.NULL
    else:
        ad_oct, ad_val = core_utils.make_octet(None, AD)
        _ = ad_val  # Suppress warning

    r_oct,  r_val  = core_utils.make_octet(None, R)
    t_oct,  t_val  = core_utils.make_octet(None, T)
    s_oct,  s_val  = core_utils.make_octet(None, S)
    id_oct, id_val = core_utils.make_octet(None, ID)
    e_oct,  e_val  = core_utils.make_octet(EGS)
    _ = r_val, t_val, s_val, id_val, e_val  # Suppress warning

    _libamcl_mpc.GG20_ZKP_phase6_challenge(r_oct, t_oct, s_oct, c, id_oct, ad_oct, e_oct)

    return core_utils.to_str(e_oct)


def phase6_prove(r, e, s, l):
    """ Generate proof from commitment random values and ZKP secret input

    Args::
        r : Pointer to commitment random values from commitment
        e : pseudorandom challenge
        s : secret exponent of the double DLOG for G
        l : secret exponent of the double DLOG for H

    Returns::
        p : Pointer to generated proof
    """

    e_oct, e_val = core_utils.make_octet(None, e)
    s_oct, s_val = core_utils.make_octet(None, s)
    l_oct, l_val = core_utils.make_octet(None, l)
    _ = e_val, s_val, l_val  # Suppress warning

    p = _ffi.new('GG20_ZKP_proof*')

    _libamcl_mpc.GG20_ZKP_phase6_prove(r, e_oct, s_oct, l_oct, p)

    return p


def phase6_verify(R, T, S, c, e, p):
    ''' Verify a GG20 ZKP

    Args::
        R : Base ECP of the additional DLOG
        T : Double DLOG public ECP
        S : Additional DLOG public ECP
        c : Pointer to received Commitment
        e : Pesudo random challenge
        p : Pointer to Received Proof

    Returns::
        ok : OK or an error code
    '''

    r_oct, r_val  = core_utils.make_octet(None, R)
    t_oct, t_val  = core_utils.make_octet(None, T)
    s_oct, s_val  = core_utils.make_octet(None, S)
    e_oct, e_val = core_utils.make_octet(None, e)
    _ = r_val, t_val, s_val, e_val   # Suppress warnings

    rc = _libamcl_mpc.GG20_ZKP_phase6_verify(r_oct, t_oct, s_oct, c, e_oct, p)

    return rc
