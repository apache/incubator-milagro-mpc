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
#define EFS_SECP256K1 32

typedef signed int sign32;
typedef long unsigned int BIG_256_56[5];

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

typedef struct
{
    BIG_512_60 n[8];
    BIG_512_60 g[8];
    BIG_512_60 n2[8];
} PAILLIER_public_key;

typedef struct
{
    BIG_1024_58 p[1];
    BIG_1024_58 q[1];
    BIG_1024_58 lp[1];
    BIG_1024_58 lq[1];
    BIG_1024_58 invp[2];
    BIG_1024_58 invq[2];
    BIG_1024_58 p2[2];
    BIG_1024_58 q2[2];
    BIG_1024_58 mp[1];
    BIG_1024_58 mq[1];
} PAILLIER_private_key;

extern void PAILLIER_KEY_PAIR(csprng *RNG, octet *P, octet* Q, PAILLIER_public_key *PUB, PAILLIER_private_key *PRIV);
extern void PAILLIER_PRIVATE_KEY_KILL(PAILLIER_private_key *PRIV);
extern void PAILLIER_PK_toOctet(octet *PK, PAILLIER_public_key *PUB);
extern void PAILLIER_PK_fromOctet(PAILLIER_public_key *PUB, octet *PK);

extern int ECP_SECP256K1_PUBLIC_KEY_VALIDATE(octet *W);

extern void MPC_ECDSA_KEY_PAIR_GENERATE(csprng *RNG, octet *S, octet *W);
extern int MPC_ECDSA_VERIFY(const octet *HM,octet *PK, octet *R,octet *S);
extern void MPC_MTA_CLIENT1(csprng *RNG, PAILLIER_public_key* PUB, octet* A, octet* CA, octet* R);
extern void MPC_MTA_CLIENT2(PAILLIER_private_key *PRIV, octet* CB, octet *ALPHA);
extern void MPC_MTA_SERVER(csprng *RNG, PAILLIER_public_key *PUB, octet *B, octet *CA, octet *Z, octet *R, octet *CB, octet *BETA);
extern void MPC_SUM_MTA(octet *A, octet *B, octet *ALPHA, octet *BETA, octet *SUM);
extern void MPC_K_GENERATE(csprng *RNG, octet *K);
extern void MPC_INVKGAMMA(const octet *KGAMMA1, const octet *KGAMMA2, octet *INVKGAMMA);
extern int MPC_R(const octet *INVKGAMMA, octet *GAMMAPT1, octet *GAMMAPT2, octet *R, octet *RP);
extern void MPC_HASH(int sha, octet *M, octet *HM);
extern int MPC_S(const octet *HM, const octet *R, const octet *K, const octet *SIGMA, octet *S);
extern void MPC_SUM_S(const octet *S1, const octet *S2, octet *S);
extern int MPC_SUM_PK(octet *PK1, octet *PK2, octet *PK);
extern void MPC_DUMP_PAILLIER_SK(PAILLIER_private_key *PRIV, octet *P, octet *Q);
""")

if (platform.system() == 'Windows'):
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.dll")
    _libamcl_paillier = _ffi.dlopen("libamcl_paillier.dll")
    _libamcl_curve_secp256k1 = _ffi.dlopen("libamcl_curve_SECP256K1.dll")
elif (platform.system() == 'Darwin'):
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.dylib")
    _libamcl_paillier = _ffi.dlopen("libamcl_paillier.dylib")
    _libamcl_curve_secp256k1 = _ffi.dlopen("libamcl_curve_SECP256K1.dylib")
else:
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.so")
    _libamcl_paillier = _ffi.dlopen("libamcl_paillier.so")
    _libamcl_curve_secp256k1 = _ffi.dlopen("libamcl_curve_SECP256K1.so")

# Constants
FS_2048 = 256      # Size of an FF_2048 in bytes
HFS_2048 = 128     # Half-suze of an FF_2048 in bytes
FS_4096 = 512      # Size of an FF_4096 in bytes
EGS_SECP256K1 = 32 # Size of an element of Z/qZ in bytes
EFS_SECP256K1 = 32 # Size of an Fp element in bytes
SHA256 = 32        # Size of a sha256 digest in bytes

curve_order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


def paillier_key_pair(rng, p=None, q=None):
    """Generate Paillier key pair

    Generate Paillier key pair

    Args::

        rng: Pointer to cryptographically secure pseudo-random number generator instance
        p: p prime number. Externally generated
        q: q prime number. Externally generated

    Returns::

        paillier_pk: Paillier public key
        paillier_sk: Paillier secret key

    Raises:

    """
    if p:
        p1, p1_val = core_utils.make_octet(None, p)
        q1, q1_val = core_utils.make_octet(None, q)
        _ = p1_val, q1_val
        rng = _ffi.NULL
    else:
        p1 = _ffi.NULL
        q1 = _ffi.NULL

    paillier_pk = _ffi.new('PAILLIER_public_key*')
    paillier_sk = _ffi.new('PAILLIER_private_key*')

    _libamcl_paillier.PAILLIER_KEY_PAIR(rng, p1, q1, paillier_pk, paillier_sk)

    if p1 is not _ffi.NULL:
        core_utils.clear_octet(p1)

    if q1 is not _ffi.NULL:
        core_utils.clear_octet(q1)

    return paillier_pk, paillier_sk


def paillier_private_key_kill(paillier_sk):
    """Kill a Paillier secret key

    Deletes all internal state

    Args::

        paillier_sk: Pointer to Paillier secret key

    Returns::



    Raises:

    """
    _libamcl_paillier.PAILLIER_PRIVATE_KEY_KILL(paillier_sk)

    return 0


def paillier_pk_to_octet(paillier_pk):
    """Write Paillier public key to byte array

    Write Paillier public key to byte array

    Args::

        paillier_pk: Pointer to Paillier public key

    Returns::

        n: Paillier Modulus - n = pq

    Raises:

    """
    n1, n1_val = core_utils.make_octet(FS_4096)
    _ = n1_val

    _libamcl_paillier.PAILLIER_PK_toOctet(n1, paillier_pk)

    n2 = core_utils.to_str(n1)

    return n2


def paillier_pk_from_octet(n):
    """Read Paillier public key from byte array

    Read Paillier public key from byte array

    Args::

        n: Paillier Modulus - n = pq

    Returns::

        paillier_pk: Pointer to Paillier public key

    Raises:

    """
    paillier_pk = _ffi.new('PAILLIER_public_key*')

    n1, n1_val = core_utils.make_octet(None, n)
    _ = n1_val

    _libamcl_paillier.PAILLIER_PK_fromOctet(paillier_pk, n1)

    return paillier_pk


def mpc_ecdsa_key_pair_generate(rng, ecdsa_sk=None):
    """Generate ECDSA key pair

    Generate ECDSA key pair

    Args::

        rng: Pointer to cryptographically secure pseudo-random number generator instance
        ecdsa_sk: secret key input

    Returns::

        ecdsa_sk: ECDSA secret key
        ecdsa_pk: ECDSA public key

    Raises:

    """
    if ecdsa_sk:
        ecdsa_sk1, ecdsa_sk1_val = core_utils.make_octet(None, ecdsa_sk)
        rng = _ffi.NULL
    else:
        ecdsa_sk1, ecdsa_sk1_val = core_utils.make_octet(EGS_SECP256K1)

    ecdsa_pk1, ecdsa_pk1_val = core_utils.make_octet(2 * EFS_SECP256K1 + 1)
    _ = ecdsa_pk1_val, ecdsa_sk1_val # Suppress warnings

    _libamcl_mpc.MPC_ECDSA_KEY_PAIR_GENERATE(rng, ecdsa_sk1, ecdsa_pk1)

    ecdsa_sk2 = core_utils.to_str(ecdsa_sk1)
    ecdsa_pk2 = core_utils.to_str(ecdsa_pk1)

    core_utils.clear_octet(ecdsa_sk1)

    return ecdsa_pk2, ecdsa_sk2


def ecp_secp256k1_public_key_validate(ecdsa_pk):
    """Validate an ECDSA public key

    Validate an ECDSA public key

    Args::

        ecdsa_pk: ECDSA public key

    Returns::

        rc: Zero for success or else an error code

    Raises:

    """
    ecdsa_pk1, ecdsa_pk1_val = core_utils.make_octet(None, ecdsa_pk)
    _ = ecdsa_pk1_val

    rc = _libamcl_curve_secp256k1.ECP_SECP256K1_PUBLIC_KEY_VALIDATE(ecdsa_pk1)

    return rc


def mpc_mta_client1(rng, paillier_pk, a, r=None):
    """Client MTA first pass

    Client MTA first pass

    Args::

        rng: Pointer to cryptographically secure pseudo-random number generator instance
        paillier_pk: Pointer to Paillier public keys
        a: Multiplicative share of secret
        r: R value for testing.

    Returns::

        ca: Ciphertext of additive share of secret
        r: R value for testing.

    Raises:

    """
    if r:
        r1, r1_val = core_utils.make_octet(None, r)
        _ = r1_val
        rng = _ffi.NULL
    else:
        r1 = _ffi.NULL

    a1, a1_val = core_utils.make_octet(None, a)
    ca1, ca1_val = core_utils.make_octet(FS_4096)
    _ = a1_val, ca1_val

    _libamcl_mpc.MPC_MTA_CLIENT1(rng, paillier_pk, a1, ca1, r1)

    ca2 = core_utils.to_str(ca1)

    # Clear memory
    core_utils.clear_octet(a1)

    if r1 is not _ffi.NULL:
        core_utils.clear_octet(r1)

    return ca2


def mpc_mta_client2(paillier_sk, cb):
    """Client MtA second pass

    Client MTA first pass

    Args::

        paillier_sk: Pointer to Paillier secret key
        cb: Ciphertext to decrypt

    Returns::

        alpha: Additive share of secret

    Raises:

    """
    cb1, cb1_val = core_utils.make_octet(None, cb)
    alpha1, alpha1_val = core_utils.make_octet(EGS_SECP256K1)
    _ = cb1_val, alpha1_val # Suppress warnings

    _libamcl_mpc.MPC_MTA_CLIENT2(paillier_sk, cb1, alpha1)

    alpha2 = core_utils.to_str(alpha1)
    core_utils.clear_octet(alpha1)

    return alpha2


def mpc_mta_server(rng, paillier_pk, b, ca, z=None, r=None):
    """Server MtA

    Server MtA

    Args::

        rng: Pointer to cryptographically secure pseudo-random number generator instance
        paillier_pk: Pointer to Paillier public key
        b: Multiplicative share of secret
        ca: Ciphertext of client's additive share of secret
        z: Negative of beta value used for testing
        r: r value for testing.

    Returns::

        cb: Ciphertext
        beta: Additive share of secret

    Raises:

    """
    if r:
        r1, r1_val = core_utils.make_octet(None, r)
        z1, z1_val = core_utils.make_octet(None, z)
        _ = r1_val, z1_val
        rng = _ffi.NULL
    else:
        r1 = _ffi.NULL
        z1 = _ffi.NULL

    b1, b1_val = core_utils.make_octet(None, b)
    ca1, ca1_val = core_utils.make_octet(None, ca)
    beta1, beta1_val = core_utils.make_octet(EGS_SECP256K1)
    cb1, cb1_val = core_utils.make_octet(FS_4096)
    _ = b1_val, ca1_val, beta1_val, cb1_val

    _libamcl_mpc.MPC_MTA_SERVER(rng, paillier_pk, b1, ca1, z1, r1, cb1, beta1)

    beta2 = core_utils.to_str(beta1)
    cb2 = core_utils.to_str(cb1)

    # Clear memory
    core_utils.clear_octet(b1)
    core_utils.clear_octet(beta1)

    if r1 is not _ffi.NULL:
        core_utils.clear_octet(r1)

    if z1 is not _ffi.NULL:
        core_utils.clear_octet(z1)

    return cb2, beta2


def mpc_sum_mta(a, b, alpha, beta):
    """Sum of secret shares

    Sum of secret shares

    Args::

        a1: A1 Value
        b1: B1 Value
        alpha: Additive share of A1.B2
        beta: Additive share of A2.B1

    Returns::

        sum: The sum of all values

    Raises:

    """
    a1, a1_val = core_utils.make_octet(None, a)
    b1, b1_val = core_utils.make_octet(None, b)
    alpha1, alpha1_val = core_utils.make_octet(None, alpha)
    beta1, beta1_val = core_utils.make_octet(None, beta)

    sum1, sum1_val = core_utils.make_octet(EGS_SECP256K1)
    _ = a1_val, b1_val, alpha1_val, beta1_val, sum1_val # Suppress warnings

    _libamcl_mpc.MPC_SUM_MTA(a1, b1, alpha1, beta1, sum1)

    sum2 = core_utils.to_str(sum1)

    core_utils.clear_octet(a1)
    core_utils.clear_octet(b1)

    return sum2


def mpc_k_generate(rng):
    """ Generate random k mod curve order

    Args::

        rng: pointer to a cryptographically secure prng

    Returns::

        k: a random value modulo the curve order

    Raises:

    """
    k, k_val = core_utils.make_octet(EGS_SECP256K1)
    _ = k_val

    _libamcl_mpc.MPC_K_GENERATE(rng, k)

    k_str = core_utils.to_str(k)
    core_utils.clear_octet(k)

    return k_str


def mpc_invkgamma(kgamma1, kgamma2):
    """Calculate the inverse of the sum of kgamma values

    Calculate the inverse of the sum of kgamma values

    Args::

        kgamma1: Actor 1 additive share
        kgamma2: Actor 2 additive share

    Returns::

        invkgamma: Inverse of the sum of the additive shares

    Raises:

    """
    kgamma11, kgamma11_val = core_utils.make_octet(None, kgamma1)
    kgamma21, kgamma21_val = core_utils.make_octet(None, kgamma2)

    invkgamma1, invkgamma1_val = core_utils.make_octet(EGS_SECP256K1)
    _ = kgamma11_val, kgamma21_val, invkgamma1_val # Suppress warnings

    _libamcl_mpc.MPC_INVKGAMMA(kgamma11, kgamma21, invkgamma1)

    invkgamma2 = core_utils.to_str(invkgamma1)

    return invkgamma2


def mpc_r(invkgamma, gammapt1, gammapt2):
    """R component

    Generate the ECDSA signature R component

    Args::

        invkgamma: Inverse of k times gamma
        gammapt1: Actor 1 gamma point
        gammapt2: Actor 2 gamma point

    Returns::

        rc: Zero for success or else an error code
        r : R component of the signature
        rp: ECP associated to R component of signature
    Raises:

    """
    invkgamma1, invkgamma1_val = core_utils.make_octet(None, invkgamma)
    gammapt11, gammapt11_val = core_utils.make_octet(None, gammapt1)
    gammapt21, gammapt21_val = core_utils.make_octet(None, gammapt2)

    r1, r1_val = core_utils.make_octet(EGS_SECP256K1)
    rp, rp_val = core_utils.make_octet(EFS_SECP256K1 + 1)
    _ = invkgamma1_val, gammapt11_val, gammapt21_val, r1_val, rp_val

    rc = _libamcl_mpc.MPC_R(invkgamma1, gammapt11, gammapt21, r1, rp)

    r2 = core_utils.to_str(r1)
    rp_str = core_utils.to_str(rp)

    return rc, r2, rp_str


def mpc_hash(message):
    """Hash the message value

    Hash the message value using sha256

    Args::

        message: Message to be hashed

    Returns::

        hm: hash of message

    Raises:

    """
    message1, message1_val = core_utils.make_octet(None, message)
    hm1, hm1_val = core_utils.make_octet(SHA256)
    _ = message1_val, hm1_val

    _libamcl_mpc.MPC_HASH(SHA256, message1, hm1)

    hm2 = core_utils.to_str(hm1)

    return hm2


def mpc_s(hm, r, k, sigma):
    """S component

    Generate the ECDSA signature S component

    Args::

        hm: Hash of the message to be signed
        r: r component of signature
        k: nonce value
        sigma: Additive share of k.w

    Returns::

        s: s signature component output
        rc: Zero for success or else an error code

    Raises:

    """
    hm1, hm1_val = core_utils.make_octet(None, hm)
    r1, r1_val = core_utils.make_octet(None, r)
    k1, k1_val = core_utils.make_octet(None, k)
    sigma1, sigma1_val = core_utils.make_octet(None, sigma)

    s1, s1_val = core_utils.make_octet(EGS_SECP256K1)
    _ = hm1_val, r1_val, k1_val, sigma1_val, s1_val

    rc = _libamcl_mpc.MPC_S(hm1, r1, k1, sigma1, s1)

    s2 = core_utils.to_str(s1)

    core_utils.clear_octet(k1)

    return rc, s2


def mpc_ecdsa_verify(hm, pk, r, s):
    """ECDSA Verify signature

    Verify the ECDSA signature (R,S) on a message

    Args::

        hm: Hash of the message to be verify
        pk: ecdsa public key
        r: r component of signature
        s: s component of signature

    Returns::

        rc: Zero for success or else an error code

    Raises:

    """
    hm1, hm1_val = core_utils.make_octet(None, hm)
    pk1, pk1_val = core_utils.make_octet(None, pk)
    r1, r1_val = core_utils.make_octet(None, r)
    s1, s1_val = core_utils.make_octet(None, s)
    _ = hm1_val, pk1_val, r1_val, s1_val

    rc = _libamcl_mpc.MPC_ECDSA_VERIFY(hm1, pk1, r1, s1)

    return rc


def mpc_sum_s(s1, s2):
    """Sum of ECDSA s components

    Calculate the sum of the s components of the ECDSA signature

    Args::

        s1: Actor 1 ECDSA s component
        s2: Actor 2 ECDSA s component

    Returns::

        s: The sum of all ECDSA s shares

    Raises:

    """
    s11, s11_val = core_utils.make_octet(None, s1)
    s21, s21_val = core_utils.make_octet(None, s2)

    s1, s1_val = core_utils.make_octet(EGS_SECP256K1)
    _ = s11_val, s21_val, s1_val

    _libamcl_mpc.MPC_SUM_S(s11, s21, s1)

    s2 = core_utils.to_str(s1)

    return s2


def mpc_sum_pk(pk1, pk2):
    """Sum of ECDSA public key shares

    Calculate the sum of the ECDSA public key shares

    Args::

        pk1: Actor 1 ECDSA public key share
        pk2: Actor 2 ECDSA public key share

    Returns::

        pk: The sum of all ECDSA pk shares
        rc: Zero for success or else an error code

    Raises:

    """
    pk11, pk11_val = core_utils.make_octet(None, pk1)
    pk21, pk21_val = core_utils.make_octet(None, pk2)

    pk1, pk1_val = core_utils.make_octet(EFS_SECP256K1 + 1)
    _ = pk11_val, pk21_val, pk1_val

    rc = _libamcl_mpc.MPC_SUM_PK(pk11, pk21, pk1)

    pk2 = core_utils.to_str(pk1)

    return rc, pk2


def mpc_dump_paillier_sk(paillier_sk):
    """Write Paillier public key to byte array

    Write Paillier public key to byte array

    Args::

        paillier_sk: Pointer to Paillier secret key

    Returns::

        p:           Secret prime number
        q:           Secret prime number

    Raises:

    """
    p, p_val = core_utils.make_octet(HFS_2048)
    q, q_val = core_utils.make_octet(HFS_2048)
    _ = p_val, q_val

    _libamcl_mpc.MPC_DUMP_PAILLIER_SK(paillier_sk, p, q)

    p2 = core_utils.to_str(p)
    q2 = core_utils.to_str(q)

    # Clear memory
    core_utils.clear_octet(p)
    core_utils.clear_octet(q)

    return p2, q2
