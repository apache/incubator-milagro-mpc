/*
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
*/

/**
 * @file bit_commitment.h
 * @brief ZKP for Polynomial Relations based on the Bit Commitment
 *
 */

#ifndef BIT_COMMITMENT_H
#define BIT_COMMITMENT_H

#include "amcl/amcl.h"
#include "amcl/paillier.h"
#include "amcl/bit_commitment_setup.h"
#include "amcl/ecp_SECP256K1.h"
#include "amcl/ecdh_SECP256K1.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* ZKP of knowledge and range of Paillier Ciphertext */

/** \brief Secret random values for the ZKP */
typedef struct
{
    BIG_1024_58 alpha[FFLEN_2048];               /**< Random value in \f$ [0, \ldots, q^3]          \f$ */
    BIG_1024_58 beta[FFLEN_2048];                /**< Random value in \f$ [0, \ldots, N] \f$ */
    BIG_1024_58 gamma[FFLEN_2048 + HFLEN_2048];  /**< Random value in \f$ [0, \ldots, \tilde{N}q^3] \f$ */
    BIG_1024_58 rho[FFLEN_2048 + HFLEN_2048];    /**< Random value in \f$ [0, \ldots, \tilde{N}q]   \f$ */
} BIT_COMMITMENT_rv;

/** \brief Public commitment for the ZKP */
typedef struct
{
    BIG_1024_58 z[FFLEN_2048];  /**< Commitment to h1, h2, x using rho */
    BIG_512_60  u[FFLEN_4096];  /**< Commitment for Paillier consistency using beta */
    BIG_1024_58 w[FFLEN_2048];  /**< Commitment to h1, h2, alpha using gamma */
} BIT_COMMITMENT_commitment;

/** \brief Proof for the ZKP */
typedef struct
{
    BIG_512_60  s[FFLEN_4096];                /**< Proof of knowledge of the Paillier r value */
    BIG_1024_58 s1[FFLEN_2048];               /**< Proof of knowledge of x. It must be less than q^3 */
    BIG_1024_58 s2[FFLEN_2048 + HFLEN_2048];  /**< Auxiliary proof of knowledge for x */
} BIT_COMMITMENT_proof;

/** \brief Commitment Generation
 *
 *  Generate a commitment for the ZKP
 *
 *  <ol>
 *  <li> \f$ \alpha \in_R [0, \ldots, q^3]\f$
 *  <li> \f$ \beta  \in_R [0, \ldots, N]\f$
 *  <li> \f$ \gamma \in_R [0, \ldots, q^{3}\tilde{N}]\f$
 *  <li> \f$ \rho   \in_R [0, \ldots, q\tilde{N}]\f$
 *  <li> \f$ z = h_1^{x}h_2^{\rho}        \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ u = h_1^{\alpha}h_2^{\gamma} \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ w = g^{\alpha}\beta^{N} \text{ }\mathrm{mod}\text{ }N^2 \f$
 *  </ol>
 *
 *  @param RNG         csprng for random generation
 *  @param key         Paillier key used to encrypt X
 *  @param m           Public BC modulus of the verifier
 *  @param X           Message to prove knowledge and range
 *  @param rv          Random values associated to the commitment. If RNG is NULL this is read
 *  @param c           Destination commitment
 */
extern void BIT_COMMITMENT_commit(csprng *RNG, PAILLIER_private_key *key, BIT_COMMITMENT_pub *m, octet *X, BIT_COMMITMENT_rv *rv, BIT_COMMITMENT_commitment *c);

/** \brief Proof generation
 *
 *  Generate a proof for the ZKP
 *
 *  <ol>
 *  <li> \f$ s  = \beta r^e \text{ }\mathrm{mod}\text{ }N \f$
 *  <li> \f$ s_1 = ex + \alpha \f$
 *  <li> \f$ s_2 = e\rho + \gamma \f$
 *  </ol>
 *
 *  @param key         Private Paillier key of the prover
 *  @param X           Message to prove knowledge and range
 *  @param R           Random value used in the Paillier encryption of X
 *  @param rv          Random values associated to the commitment
 *  @param E           (pseudo)random challenge
 *  @param p           Destination proof
 */
extern void BIT_COMMITMENT_prove(PAILLIER_private_key *key, octet *X, octet *R, BIT_COMMITMENT_rv *rv, octet *E, BIT_COMMITMENT_proof *p);

/** \brief Verify a Proof
 *
 *  <ol>
 *  <li> \f$ s1 \stackrel{?}{\leq} q^3 \f$
 *  <li> \f$ w \stackrel{?}{=} h_1^{s_1}h_2^{s_2}z^{-e} \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ u \stackrel{?}{=} g^{s_1}s^{N}c^{-e} \text{ }\mathrm{mod}\text{ }N^2 \f$
 *  </ol>
 *
 *  @param key         Public Paillier key of the prover
 *  @param m           Private BC modulus of the verifier
 *  @param CT          Encrypted Message to prove knowledge and range
 *  @param c           Received commitment
 *  @param E           Generated challenge
 *  @param p           Received proof
 *  @return            BIT_COMMITMENT_OK if the proof is valid, BIT_COMMITMENT_FAIL otherwise
 */
extern int BIT_COMMITMENT_verify(PAILLIER_public_key *key, BIT_COMMITMENT_priv *m, octet *CT, BIT_COMMITMENT_commitment *c, octet *E, BIT_COMMITMENT_proof *p);

/** \brief Dump the commitment to octets
 *
 *  @param Z           Destination Octet for the z component of the commitment. FS_2048 long
 *  @param U           Destination Octet for the u component of the commitment. FS_4096 long
 *  @param W           Destination Octet for the w component of the commitment. FS_2048 long
 *  @param c           Commitment to export
 */
extern void BIT_COMMITMENT_commitment_toOctets(octet *Z, octet *U, octet *W, BIT_COMMITMENT_commitment *c);

/** \brief Read the commitments from octets
 *
 *  @param c           Destination commitment
 *  @param Z           Octet with the z component of the proof
 *  @param U           Octet with the u component of the proof
 *  @param W           Octet with the w component of the proof
 */
extern void BIT_COMMITMENT_commitment_fromOctets(BIT_COMMITMENT_commitment *c, octet *Z, octet *U, octet *W);

/** \brief Dump the proof to octets
 *
 *  @param S           Destination Octet for the s component of the proof. FS_2048 long
 *  @param S1          Destination Octet for the s1 component of the proof. HFS_2048 long
 *  @param S2          Destination Octet for the s2 component of the proof. FS_2048 + HFS_2048 long
 *  @param p           Proof to export
 */
extern void BIT_COMMITMENT_proof_toOctets(octet *S, octet *S1, octet *S2, BIT_COMMITMENT_proof *p);

/** \brief Read the proof from octets
 *
 *  @param p           Destination proof
 *  @param S           Octet with the s component of the proof
 *  @param S1          Octet with the s1 component of the proof
 *  @param S2          Octet with the s2 component of the proof
 */
extern void BIT_COMMITMENT_proof_fromOctets(BIT_COMMITMENT_proof *p, octet *S, octet *S1, octet *S2);

/** \brief Clean the memory containing the random values
 *
 *   @param rv         Random values to clean
 */
extern void BIT_COMMITMENT_rv_kill(BIT_COMMITMENT_rv *rv);


/* ZKP of Knowledge and range of Paillier homomorphic mul/add */

/** \brief Secret random values for the muladd ZKP */
typedef struct
{
    BIG_1024_58 alpha[FFLEN_2048];              /**< Random value in \f$ [0, \ldots, q^3]          \f$ */
    BIG_1024_58 beta[FFLEN_2048];               /**< Random value in \f$ [0, \ldots, N]            \f$ */
    BIG_1024_58 gamma[FFLEN_2048];              /**< Random value in \f$ [0, \ldots, N]            \f$ */
    BIG_1024_58 rho[FFLEN_2048 + HFLEN_2048];   /**< Random value in \f$ [0, \ldots, \tilde{N}q]   \f$ */
    BIG_1024_58 rho1[FFLEN_2048 + HFLEN_2048];  /**< Random value in \f$ [0, \ldots, \tilde{N}q^3] \f$ */
    BIG_1024_58 sigma[FFLEN_2048 + HFLEN_2048]; /**< Random value in \f$ [0, \ldots, \tilde{N}q]   \f$ */
    BIG_1024_58 tau[FFLEN_2048 + HFLEN_2048];   /**< Random value in \f$ [0, \ldots, \tilde{N}q]   \f$ */
} BIT_COMMITMENT_muladd_rv;

/** \brief Public commitment for the muladd ZKP */
typedef struct
{
    BIG_1024_58 z[FFLEN_2048];      /**< Commitment to h1, h2, x using rho */
    BIG_1024_58 z1[FFLEN_2048];     /**< Auxiliary Commitment to h1, h2, binding alpha and rho1 */
    BIG_1024_58 t[FFLEN_2048];      /**< Commitment to h1, h2, y using sigma */
    BIG_1024_58 v[2 * FFLEN_2048];  /**< Commitment to paillier PK and c1 using alpha and gamma */
    BIG_1024_58 w[FFLEN_2048];      /**< Auxiliary Commitment to h1, h2, binding gamma and tau */
} BIT_COMMITMENT_muladd_commitment;

/** \brief Proof for the muladd ZKP */
typedef struct
{
    BIG_1024_58 s[FFLEN_2048];                /**< Proof of knowledge of the Paillier r value */
    BIG_1024_58 s1[FFLEN_2048];               /**< Proof of knowledge of x. It must be less than q^3 */
    BIG_1024_58 s2[FFLEN_2048 + HFLEN_2048];  /**< Auxiliary proof of knowledge for x */
    BIG_1024_58 t1[FFLEN_2048];               /**< Proof of knowledge of y */
    BIG_1024_58 t2[FFLEN_2048 + HFLEN_2048];  /**< Auxiliary proof of knowledge for y */
} BIT_COMMITMENT_muladd_proof;

/** \brief Commitment Generation
 *
 *  Generate a commitment for the ZKP
 *
 *  <ol>
 *  <li> \f$ \alpha \in_R [0, \ldots, q^3]\f$
 *  <li> \f$ \beta  \in_R [0, \ldots, N]\f$
 *  <li> \f$ \gamma \in_R [0, \ldots, N]\f$
 *  <li> \f$ \rho   \in_R [0, \ldots, q\tilde{N}]\f$
 *  <li> \f$ \rho_1 \in_R [0, \ldots, q^{3}\tilde{N}]\f$
 *  <li> \f$ \sigma \in_R [0, \ldots, q\tilde{N}]\f$
 *  <li> \f$ \tau   \in_R [0, \ldots, q\tilde{N}]\f$
 *  <li> \f$ z  = h_1^{x}h_2^{\rho}              \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ z_1 = h_1^{\alpha}h_2^{\rho_1}       \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ t  = h_1^{y}h_2^{\sigma}            \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ w  = h_1^{\gamma}h_2^{\tau}         \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ v  = c1^{\alpha}g^{\gamma}\beta^{N} \text{ }\mathrm{mod}\text{ }N^2 \f$
 *  </ol>
 *
 *  @param RNG         csprng for random generation
 *  @param key         Paillier key used to encrypt C1
 *  @param m           Public BC modulus of the verifier
 *  @param X           Homomorphically multiplied PT
 *  @param Y           Homomorphically added PT
 *  @param C1          Base Paillier Ciphertext
 *  @param rv          Random values associated to the commitment. If RNG is NULL this is read
 *  @param c           Destination commitment
 */
extern void BIT_COMMITMENT_muladd_commit(csprng *RNG, PAILLIER_public_key *key, BIT_COMMITMENT_pub *m, octet *X, octet *Y, octet *C1, BIT_COMMITMENT_muladd_rv *rv, BIT_COMMITMENT_muladd_commitment *c);

/** \brief Proof generation
 *
 *  Generate a proof for the ZKP
 *
 *  <ol>
 *  <li> \f$ s  = \beta r^e \text{ }\mathrm{mod}\text{ }N \f$
 *  <li> \f$ s_1 = ex + \alpha \f$
 *  <li> \f$ s_2 = e\rho + \rho_1 \f$
 *  <li> \f$ t_1 = ey + \gamma \f$
 *  <li> \f$ t_2 = e\sigma + \tau \f$
 *  </ol>
 *
 *  @param key         Public Paillier key used for the homomorphic operations
 *  @param X           Homomorphically multiplied PT
 *  @param Y           Homomorphically added PT
 *  @param R           Random value used in the Paillier addition
 *  @param rv          Random values associated to the commitment
 *  @param E           Generated challenge
 *  @param p           Destination proof
 */
extern void BIT_COMMITMENT_muladd_prove(PAILLIER_public_key *key, octet *X, octet *Y, octet *R, BIT_COMMITMENT_muladd_rv *rv, octet *E, BIT_COMMITMENT_muladd_proof *p);

/** \brief Verify a proof
 *
 *  <ol>
 *  <li> \f$ s_1 \stackrel{?}{\leq} q^3 \f$
 *  <li> \f$ z_1 \stackrel{?}{=} h_1^{s_1}h_2^{s_2}z^{-e}    \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ w  \stackrel{?}{=} h_1^{t_1}h_2^{t_2}t^{-e}    \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ v  \stackrel{?}{=} c1^{s_1}s^{N}g^{t_1}c2^{-e} \text{ }\mathrm{mod}\text{ }N^2 \f$
 *  </ol>
 *
 *  @param key         Private Paillier Key used for the homomorphic operations
 *  @param m         Private BC modulus of the verifier
 *  @param C1          Base Paillier Ciphertext
 *  @param C2          New Paillier Ciphertext to prove knowledge and range
 *  @param c           Received commitment
 *  @param E           Generated challenge
 *  @param p           Received proof
 *  @return            BIT_COMMITMENT_OK if the proof is valid, BIT_COMMITMENT_FAIL otherwise
 */
extern int BIT_COMMITMENT_muladd_verify(PAILLIER_private_key *key, BIT_COMMITMENT_priv *m, octet *C1, octet *C2, BIT_COMMITMENT_muladd_commitment *c, octet *E, BIT_COMMITMENT_muladd_proof *p);

/** \brief Dump the commitment to octets
 *
 *  @param Z           Destination Octet for the z component of the commitment. FS_2048 long
 *  @param Z1          Destination Octet for the z1 component of the commitment. FS_2048 long
 *  @param T           Destination Octet for the t component of the commitment. FS_2048 long
 *  @param V           Destination Octet for the v component of the commitment. FS_4096 long
 *  @param W           Destination Octet for the w component of the commitment. FS_2048 long
 *  @param c           Commitment to export
 */
extern void BIT_COMMITMENT_muladd_commitment_toOctets(octet *Z, octet *Z1, octet *T, octet *V, octet *W, BIT_COMMITMENT_muladd_commitment *c);

/** \brief Read the commitments from octets
 *
 *  @param c           Destination commitment
 *  @param Z           Destination Octet for the z component of the commitment. FS_2048 long
 *  @param Z1          Destination Octet for the z1 component of the commitment. FS_2048 long
 *  @param T           Destination Octet for the t component of the commitment. FS_2048 long
 *  @param V           Destination Octet for the v component of the commitment. FS_4096 long
 *  @param W           Destination Octet for the w component of the commitment. FS_2048 long
 */
extern void BIT_COMMITMENT_muladd_commitment_fromOctets(BIT_COMMITMENT_muladd_commitment *c, octet *Z, octet *Z1, octet *T, octet *V, octet *W);

/** \brief Dump the proof to octets
 *
 *  @param S           Destination Octet for the s component of the proof. FS_2048 long
 *  @param S1          Destination Octet for the s1 component of the proof. HFS_2048 long
 *  @param S2          Destination Octet for the s2 component of the proof. FS_2048 + HFS_2048 long
 *  @param T1          Destination Octet for the t1 component of the proof. FS_2048 long
 *  @param T2          Destination Octet for the t2 component of the proof. FS_2048 + HFS_2048 long
 *  @param p           Proof to export
 */
extern void BIT_COMMITMENT_muladd_proof_toOctets(octet *S, octet *S1, octet *S2, octet *T1, octet *T2, BIT_COMMITMENT_muladd_proof *p);

/** \brief Read the proof from octets
 *
 *  @param p           Destination proof
 *  @param S           Octet with the s component of the proof
 *  @param S1          Octet with the s1 component of the proof
 *  @param S2          Octet with the s2 component of the proof
 *  @param T1          Octet with the t1 component of the proof
 *  @param T2          Octet with the t2 component of the proof
 */
extern void BIT_COMMITMENT_muladd_proof_fromOctets(BIT_COMMITMENT_muladd_proof *p, octet *S, octet *S1, octet *S2, octet *T1, octet *T2);

/** \brief Clean the memory containing the random values
 *
 *   @param rv         Random values to clean
 */
extern void BIT_COMMITMENT_muladd_rv_kill(BIT_COMMITMENT_muladd_rv *rv);


/* Additional ZKP of knowledge of DLOG for Paillier Plaintext */

/** \brief Compute additional commitment for DLOG ZKP
 *
 *  <ol>
 *  <li> \f$ G = \alpha.G \f$
 *  </ol>
 *
 *   @param G           ECP, base of the DLOG. On output \f$ \alpha.G \f$
 *   @param alpha       alpha value from the base ZKP random values
 */
extern void BIT_COMMITMENT_ECP_commit(ECP_SECP256K1 *G, BIG_1024_58 *alpha);

/** \brief Verify additional ZKP of knowledge of DLOG
 *
 *  <ol>
 *  <li> \f$ U \stackrel{?}{=} s_1.G - e.X \f$
 *  </ol>
 *
 *   @param G           ECP, base of the DLOG
 *   @param X           ECP, public DLOG
 *   @param U           ECP, commitment for the proof
 *   @param E           Generated challenge
 *   @param s1          s1 value from the base ZKP
 *   @return            BIT_COMMITMENT_OK or an error code
 */
extern int BIT_COMMITMENT_ECP_verify(ECP_SECP256K1 *G, ECP_SECP256K1 *X, ECP_SECP256K1 *U, octet *E, BIG_1024_58 *s1);


/* Helpers to hash parameters and commitments for pseudorandom challenges */

/** \brief Feed the ZKP base parameters into a sha instance
 *
 *   @param sha        Destination sha instance
 *   @param key        Paillier Public Key used for encryption
 *   @param m          Bit Commitment modulus used for the ZKP
 */
extern void BIT_COMMITMENT_hash_params(hash256 *sha, PAILLIER_public_key *key, BIT_COMMITMENT_pub *m);

/** \brief Feed the plaintext ZKP commitment into a sha instance
 *
 *   @param sha        Destination sha instance
 *   @param c          Commitment for the ZKP
 */
extern void BIT_COMMITMENT_hash_commitment(hash256 *sha, BIT_COMMITMENT_commitment *c);

/** \brief Feed the muladd ZKP commitment into a sha instance
 *
 *   @param sha        Destination sha instance
 *   @param c          Commitment for the ZKP
 */
extern void BIT_COMMITMENT_hash_muladd_commitment(hash256 *sha, BIT_COMMITMENT_muladd_commitment *c);

#ifdef __cplusplus
}
#endif

#endif
