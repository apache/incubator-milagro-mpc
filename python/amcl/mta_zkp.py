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
from . import bit_commitments

_ffi = bit_commitments._ffi
_ffi.cdef("""

typedef BIT_COMMITMENT_rv MTA_RP_rv;
typedef BIT_COMMITMENT_commitment MTA_RP_commitment;
typedef BIT_COMMITMENT_proof MTA_RP_proof;

void MTA_RP_commit(csprng *RNG, PAILLIER_private_key *key, BIT_COMMITMENT_pub *mod,  octet *M, MTA_RP_rv *rv, MTA_RP_commitment *c);
void MTA_RP_challenge(PAILLIER_public_key *key, BIT_COMMITMENT_pub *mod, const octet *CT, MTA_RP_commitment *c, const octet *ID, const octet *AD, octet *E);
void MTA_RP_prove(PAILLIER_private_key *key, octet *M, octet *R, MTA_RP_rv *rv, octet *E, MTA_RP_proof *p);
int MTA_RP_verify(PAILLIER_public_key *key, BIT_COMMITMENT_priv *mod, octet *CT, MTA_RP_commitment *c, octet *E, MTA_RP_proof *p);
void MTA_RP_commitment_toOctets(octet *Z, octet *U, octet *W, MTA_RP_commitment *c);
void MTA_RP_commitment_fromOctets(MTA_RP_commitment *c, octet *Z, octet *U, octet *W);
void MTA_RP_proof_toOctets(octet *S, octet *S1, octet *S2, MTA_RP_proof *p);
void MTA_RP_proof_fromOctets(MTA_RP_proof *p, octet *S, octet *S1, octet *S2);
void MTA_RP_rv_kill(MTA_RP_rv *rv);

typedef BIT_COMMITMENT_muladd_rv MTA_ZK_rv;
typedef BIT_COMMITMENT_muladd_commitment MTA_ZK_commitment;
typedef BIT_COMMITMENT_muladd_proof MTA_ZK_proof;

void MTA_ZK_commit(csprng *RNG, PAILLIER_public_key *key, BIT_COMMITMENT_pub *mod,  octet *X, octet *Y, octet *C1, MTA_ZK_rv *rv, MTA_ZK_commitment *c);
void MTA_ZK_challenge(PAILLIER_public_key *key, BIT_COMMITMENT_pub *mod, const octet *C1, const octet *C2, MTA_ZK_commitment *c, const octet *ID, const octet *AD, octet *E);
void MTA_ZK_prove(PAILLIER_public_key *key, octet *X, octet *Y, octet *R, MTA_ZK_rv *rv, octet *E, MTA_ZK_proof *p);
int MTA_ZK_verify(PAILLIER_private_key *key, BIT_COMMITMENT_priv *mod, octet *C1, octet *C2, MTA_ZK_commitment *c, octet *E, MTA_ZK_proof *p);
void MTA_ZK_commitment_toOctets(octet *Z, octet *Z1, octet *T, octet *V, octet *W, MTA_ZK_commitment *c);
void MTA_ZK_commitment_fromOctets(MTA_ZK_commitment *c, octet *Z, octet *Z1, octet *T, octet *V, octet *W);
void MTA_ZK_proof_toOctets(octet *S, octet *S1, octet *S2, octet *T1, octet *T2, MTA_ZK_proof *p);
void MTA_ZK_proof_fromOctets(MTA_ZK_proof *p, octet *S, octet *S1, octet *S2, octet *T1, octet *T2);
void MTA_ZK_rv_kill(MTA_ZK_rv *rv);

typedef BIT_COMMITMENT_muladd_rv MTA_ZKWC_rv;
typedef struct
{
    BIT_COMMITMENT_muladd_commitment mc;  /**< Commitment for the base Receiver ZKP */
    ECP_SECP256K1 U;                      /**< Commitment for the DLOG knowledge proof */
} MTA_ZKWC_commitment;

typedef BIT_COMMITMENT_muladd_proof MTA_ZKWC_proof;

void MTA_ZKWC_commit(csprng *RNG, PAILLIER_public_key *key, BIT_COMMITMENT_pub *mod,  octet *X, octet *Y, octet *C1, MTA_ZKWC_rv *rv, MTA_ZKWC_commitment *c);
void MTA_ZKWC_challenge(PAILLIER_public_key *key, BIT_COMMITMENT_pub *mod, const octet *C1, const octet *C2, const octet *X, MTA_ZKWC_commitment *c, const octet *ID, const octet *AD, octet *E);
void MTA_ZKWC_prove(PAILLIER_public_key *key, octet *X, octet *Y, octet *R, MTA_ZKWC_rv *rv, octet *E, MTA_ZKWC_proof *p);
int MTA_ZKWC_verify(PAILLIER_private_key *key, BIT_COMMITMENT_priv *mod, octet *C1, octet *C2, octet *X, MTA_ZKWC_commitment *c, octet *E, MTA_ZKWC_proof *p);
void MTA_ZKWC_commitment_toOctets(octet *U, octet *Z, octet *Z1, octet *T, octet *V, octet *W, MTA_ZKWC_commitment *c);
int MTA_ZKWC_commitment_fromOctets(MTA_ZKWC_commitment *c, octet *U, octet *Z, octet *Z1, octet *T, octet *V, octet *W);
void MTA_ZKWC_proof_toOctets(octet *S, octet *S1, octet *S2, octet *T1, octet *T2, MTA_ZKWC_proof *p);
void MTA_ZKWC_proof_fromOctets(MTA_ZKWC_proof *p, octet *S, octet *S1, octet *S2, octet *T1, octet *T2);
void MTA_ZKWC_rv_kill(MTA_ZKWC_rv *rv);

#ifdef __cplusplus
}
#endif

#endif

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

OK          = 0    # Proof successfully verified
FAIL        = 61   # Invalid proof
INVALID_ECP = 62   # Invalid ECP

def rp_commit(key, mod, m, c, alpha=None, beta=None, gamma=None, rho=None):
    """ Generate a Range Proof commitment for the message M

    Args::
        key : Paillier Key used to ecnrypt M
        mod : Public bit commitment modulus
        m
    """