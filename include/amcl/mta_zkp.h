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
 * @file mta_zkp.h
 * @brief MTA ZKP declarations
 *
 */

#ifndef MTA_ZKP_H
#define MTA_ZKP_H

#include "amcl/amcl.h"
#include "amcl/mta.h"
#include "amcl/bit_commitment.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Range Proof API - This is a Bit Commitment base ZKP */

/** \brief Secret random values for RP ZKP */
typedef BIT_COMMITMENT_rv MTA_RP_rv;

/** \brief Public commitment for the RP ZKP */
typedef BIT_COMMITMENT_commitment MTA_RP_commitment;

/** \brief Proof for the RP ZKP */
typedef BIT_COMMITMENT_proof MTA_RP_proof;

/** \brief Commitment Generation
 *
 *  Generate a commitment for the message M
 *
 *  <ol>
 *  <li> \f$ \alpha \in_R [0, \ldots, q^3]\f$
 *  <li> \f$ \beta  \in_R [0, \ldots, N]\f$
 *  <li> \f$ \gamma \in_R [0, \ldots, q^{3}\tilde{N}]\f$
 *  <li> \f$ \rho   \in_R [0, \ldots, q\tilde{N}]\f$
 *  <li> \f$ z = h_1^{m}h_2^{\rho}        \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ u = h_1^{\alpha}h_2^{\gamma} \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ w = g^{\alpha}\beta^{N} \text{ }\mathrm{mod}\text{ }N^2 \f$
 *  </ol>
 *
 *  @param RNG         csprng for random generation
 *  @param key         Paillier key used to encrypt M
 *  @param mod         Public BC modulus of the verifier
 *  @param M           Message to prove knowledge and range
 *  @param rv          Random values associated to the commitment. If RNG is NULL this is read
 *  @param c           Destination commitment
 */
extern void MTA_RP_commit(csprng *RNG, PAILLIER_private_key *key, BIT_COMMITMENT_pub *mod,  octet *M, MTA_RP_rv *rv, MTA_RP_commitment *c);

/** \brief Deterministic RP Challenge generation
 *
 *  Generate a challenge binding together public parameters and commitment
 *
 *  <ol>
 *  <li> \f$ e = H( g | \tilde{N} | h_1 | h_2 | CT | z | u | w | ID | AD ) \f$
 *  </ol>
 *
 *  @param key         Public Paillier key of the prover
 *  @param mod         Public BC modulus of the verifier
 *  @param CT          Encrypted Message to prove knowledge and range
 *  @param c           Commitment of the prover
 *  @param ID          Unique prover identifier
 *  @param AD          Additional data to bind in the proof. Optional
 *  @param E           Destination challenge
 */
extern void MTA_RP_challenge(PAILLIER_public_key *key, BIT_COMMITMENT_pub *mod, const octet *CT, MTA_RP_commitment *c, const octet *ID, const octet *AD, octet *E);

/** \brief RP Proof generation
 *
 *  Generate a proof of knowledge of m and of its range
 *
 *  <ol>
 *  <li> \f$ s  = \beta r^e \text{ }\mathrm{mod}\text{ }N \f$
 *  <li> \f$ s_1 = em + \alpha \f$
 *  <li> \f$ s_2 = e\rho + \gamma \f$
 *  </ol>
 *
 *  @param key         Private Paillier key of the prover
 *  @param rv          Random values associated to the commitment
 *  @param M           Message to prove knowledge and range
 *  @param R           Random value used in the Paillier encryption of M
 *  @param E           Generated challenge
 *  @param p           Destination proof
 */
extern void MTA_RP_prove(PAILLIER_private_key *key, octet *M, octet *R, MTA_RP_rv *rv, octet *E, MTA_RP_proof *p);

/** \brief Verify a RP Proof
 *
 *  Verify the proof of knowledge of m associated to CT and of its range
 *
 *  <ol>
 *  <li> \f$ s1 \stackrel{?}{\leq} q^3 \f$
 *  <li> \f$ w \stackrel{?}{=} h_1^{s_1}h_2^{s_2}z^{-e} \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ u \stackrel{?}{=} g^{s_1}s^{N}c^{-e} \text{ }\mathrm{mod}\text{ }N^2 \f$
 *  </ol>
 *
 *  @param key         Public Paillier key of the prover
 *  @param mod         Private BC modulus of the verifier
 *  @param CT          Encrypted Message to prove knowledge and range
 *  @param c           Received commitment
 *  @param E           Generated challenge
 *  @param p           Received proof
 *  @return            MTA_OK if the proof is valid, MTA_FAIL otherwise
 */
extern int MTA_RP_verify(PAILLIER_public_key *key, BIT_COMMITMENT_priv *mod, octet *CT, MTA_RP_commitment *c, octet *E, MTA_RP_proof *p);

/** \brief Dump the commitment to octets
 *
 *  @param Z           Destination Octet for the z component of the commitment. FS_2048 long
 *  @param U           Destination Octet for the u component of the commitment. FS_4096 long
 *  @param W           Destination Octet for the w component of the commitment. FS_2048 long
 *  @param c           Commitment to export
 */
extern void MTA_RP_commitment_toOctets(octet *Z, octet *U, octet *W, MTA_RP_commitment *c);

/** \brief Read the commitments from octets
 *
 *  @param c           Destination commitment
 *  @param Z           Octet with the z component of the proof
 *  @param U           Octet with the u component of the proof
 *  @param W           Octet with the w component of the proof
 */
extern void MTA_RP_commitment_fromOctets(MTA_RP_commitment *c, octet *Z, octet *U, octet *W);

/** \brief Dump the proof to octets
 *
 *  @param S           Destination Octet for the s component of the proof. FS_2048 long
 *  @param S1          Destination Octet for the s1 component of the proof. HFS_2048 long
 *  @param S2          Destination Octet for the s2 component of the proof. FS_2048 + HFS_2048 long
 *  @param p           Proof to export
 */
extern void MTA_RP_proof_toOctets(octet *S, octet *S1, octet *S2, MTA_RP_proof *p);

/** \brief Read the proof from octets
 *
 *  @param p           Destination proof
 *  @param S           Octet with the s component of the proof
 *  @param S1          Octet with the s1 component of the proof
 *  @param S2          Octet with the s2 component of the proof
 */
extern void MTA_RP_proof_fromOctets(MTA_RP_proof *p, octet *S, octet *S1, octet *S2);

/** \brief Clean the memory containing the random values
 *
 *   @param rv         Random values to clean
 */
extern void MTA_RP_rv_kill(MTA_RP_rv *rv);


/* Receiver Zero Knowledge Proof - This is a Bit Commitment muladd ZKP */

/** \brief Secret random values for the receiver ZKP */
typedef BIT_COMMITMENT_muladd_rv MTA_ZK_rv;

/** \brief Public commitment for the Receiver ZKP */
typedef BIT_COMMITMENT_muladd_commitment MTA_ZK_commitment;

/** \brief Proof for the RP ZKP */
typedef BIT_COMMITMENT_muladd_proof MTA_ZK_proof;

/** \brief Commitment Generation for Receiver ZKP
 *
 *  Generate a commitment for the values x, y and c1
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
 *  @param mod         Public BC modulus of the verifier
 *  @param X           Message to prove knowledge and range
 *  @param Y           Message to prove knowledge
 *  @param C1          Base Paillier Ciphertext
 *  @param rv          Random values associated to the commitment. If RNG is NULL this is read
 *  @param c           Destination commitment
 */
extern void MTA_ZK_commit(csprng *RNG, PAILLIER_public_key *key, BIT_COMMITMENT_pub *mod,  octet *X, octet *Y, octet *C1, MTA_ZK_rv *rv, MTA_ZK_commitment *c);

/** \brief Deterministic Challenge generations for Receiver ZKP
 *
 *  Generate a challenge binding together public parameters and commitment
 *
 *  <ol>
 *  <li> \f$ e = H( g | \tilde{N} | h_1 | h_2 | c_1 | c_2 | z | z1 | t | v | w ) \f$
 *  </ol>
 *
 *  @param key         Public Paillier key of the prover
 *  @param mod         Public BC modulus of the verifier
 *  @param C1          Base Paillier Ciphertext
 *  @param C2          New Paillier Ciphertext to prove knowledge and range
 *  @param c           Commitment of the prover
 *  @param ID          Unique prover identifier
 *  @param AD          Additional data to bind in the proof. Optional
 *  @param E           Destination challenge
 */
extern void MTA_ZK_challenge(PAILLIER_public_key *key, BIT_COMMITMENT_pub *mod, const octet *C1, const octet *C2, MTA_ZK_commitment *c, const octet *ID, const octet *AD, octet *E);

/** \brief Proof generation for Receiver ZKP
 *
 *  Generate a proof of knowledge of x, y and a range proof for x
 *
 *  <ol>
 *  <li> \f$ s  = \beta r^e \text{ }\mathrm{mod}\text{ }N \f$
 *  <li> \f$ s_1 = ex + \alpha \f$
 *  <li> \f$ s_2 = e\rho + \rho_1 \f$
 *  <li> \f$ t_1 = ey + \gamma \f$
 *  <li> \f$ t_2 = e\sigma + \tau \f$
 *  </ol>
 *
 *  @param key         Private Paillier key of the prover
 *  @param X           Message to prove knowledge and range
 *  @param Y           Message to prove knowledge
 *  @param R           Random value used in the Paillier addition
 *  @param rv          Random values associated to the commitment
 *  @param E           Generated challenge
 *  @param p           Destination proof
 */
extern void MTA_ZK_prove(PAILLIER_public_key *key, octet *X, octet *Y, octet *R, MTA_ZK_rv *rv, octet *E, MTA_ZK_proof *p);

/** \brief Verify a Proof for Receiver ZKP
 *
 *  Verify the proof of knowledge of x, y associated to c1, c2 and of x range
 *
 *  <ol>
 *  <li> \f$ s_1 \stackrel{?}{\leq} q^3 \f$
 *  <li> \f$ z_1 \stackrel{?}{=} h_1^{s_1}h_2^{s_2}z^{-e}    \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ w  \stackrel{?}{=} h_1^{t_1}h_2^{t_2}t^{-e}    \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ v  \stackrel{?}{=} c1^{s_1}s^{N}g^{t_1}c2^{-e} \text{ }\mathrm{mod}\text{ }N^2 \f$
 *  </ol>
 *
 *  @param key         Public Paillier key of the prover
 *  @param mod         Private BC modulus of the verifier
 *  @param C1          Base Paillier Ciphertext
 *  @param C2          New Paillier Ciphertext to prove knowledge and range
 *  @param E           Generated challenge
 *  @param c           Received commitment
 *  @param p           Received proof
 *  @return            MTA_OK if the proof is valid, MTA_FAIL otherwise
 */
extern int MTA_ZK_verify(PAILLIER_private_key *key, BIT_COMMITMENT_priv *mod, octet *C1, octet *C2, MTA_ZK_commitment *c, octet *E, MTA_ZK_proof *p);

/** \brief Dump the commitment to octets
 *
 *  @param Z           Destination Octet for the z component of the commitment. FS_2048 long
 *  @param Z1          Destination Octet for the z1 component of the commitment. FS_2048 long
 *  @param T           Destination Octet for the t component of the commitment. FS_2048 long
 *  @param V           Destination Octet for the v component of the commitment. FS_4096 long
 *  @param W           Destination Octet for the w component of the commitment. FS_2048 long
 *  @param c           Commitment to export
 */
extern void MTA_ZK_commitment_toOctets(octet *Z, octet *Z1, octet *T, octet *V, octet *W, MTA_ZK_commitment *c);

/** \brief Read the commitments from octets
 *
 *  @param c           Destination commitment
 *  @param Z           Destination Octet for the z component of the commitment. FS_2048 long
 *  @param Z1          Destination Octet for the z1 component of the commitment. FS_2048 long
 *  @param T           Destination Octet for the t component of the commitment. FS_2048 long
 *  @param V           Destination Octet for the v component of the commitment. FS_4096 long
 *  @param W           Destination Octet for the w component of the commitment. FS_2048 long
 */
extern void MTA_ZK_commitment_fromOctets(MTA_ZK_commitment *c, octet *Z, octet *Z1, octet *T, octet *V, octet *W);

/** \brief Dump the proof to octets
 *
 *  @param S           Destination Octet for the s component of the proof. FS_2048 long
 *  @param S1          Destination Octet for the s1 component of the proof. HFS_2048 long
 *  @param S2          Destination Octet for the s2 component of the proof. FS_2048 + HFS_2048 long
 *  @param T1          Destination Octet for the t1 component of the proof. FS_2048 long
 *  @param T2          Destination Octet for the t2 component of the proof. FS_2048 + HFS_2048 long
 *  @param p           Proof to export
 */
extern void MTA_ZK_proof_toOctets(octet *S, octet *S1, octet *S2, octet *T1, octet *T2, MTA_ZK_proof *p);

/** \brief Read the proof from octets
 *
 *  @param p           Destination proof
 *  @param S           Octet with the s component of the proof
 *  @param S1          Octet with the s1 component of the proof
 *  @param S2          Octet with the s2 component of the proof
 *  @param T1          Octet with the t1 component of the proof
 *  @param T2          Octet with the t2 component of the proof
 */
extern void MTA_ZK_proof_fromOctets(MTA_ZK_proof *p, octet *S, octet *S1, octet *S2, octet *T1, octet *T2);

/** \brief Clean the memory containing the random values
 *
 *   @param rv         Random values to clean
 */
extern void MTA_ZK_rv_kill(MTA_ZK_rv *rv);


/* Receiver Zero Knowledge Proof with Check - This is a Bit Commitment mulad ZKP with DLOG check */

/** \brief Random random values for the receiver ZKP with check */
typedef BIT_COMMITMENT_muladd_rv MTA_ZKWC_rv;

/** \brief Public commitment for the Receiver ZKP with check */
typedef struct
{
    BIT_COMMITMENT_muladd_commitment mc;  /**< Commitment for the base Receiver ZKP */
    ECP_SECP256K1 U;                      /**< Commitment for the DLOG knowledge proof */
} MTA_ZKWC_commitment;

/** \brief Range Proof for the Receiver ZKP with check */
typedef BIT_COMMITMENT_muladd_proof MTA_ZKWC_proof;

/** \brief Commitment Generation for Receiver ZKP with check
 *
 *  Generate a commitment for the values x, y and c1
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
 *  <li> \f$ U  = \alpha.G \f$
 *  </ol>
 *
 *  @param RNG         csprng for random generation
 *  @param key         Paillier key used to encrypt C1
 *  @param mod         Public BC modulus of the verifier
 *  @param X           Message to prove knowledge and range
 *  @param Y           Message to prove knowledge
 *  @param C1          Base Paillier Ciphertext
 *  @param rv          Random values associated to the commitment. If RNG is NULL this is read
 *  @param c           Destination commitment
 */
extern void MTA_ZKWC_commit(csprng *RNG, PAILLIER_public_key *key, BIT_COMMITMENT_pub *mod,  octet *X, octet *Y, octet *C1, MTA_ZKWC_rv *rv, MTA_ZKWC_commitment *c);

/** \brief Deterministic Challenge generations for Receiver ZKP with check
 *
 *  Generate a challenge binding together public parameters and commitment
 *
 *  <ol>
 *  <li> \f$ e = H( g | \tilde{N} | h_1 | h_2 | q | c_1 | c_2 | U | z | z1 | t | v | w ) \f$
 *  </ol>
 *
 *  @param key         Public Paillier key of the prover
 *  @param mod         Public BC modulus of the verifier
 *  @param C1          Base Paillier Ciphertext
 *  @param C2          New Paillier Ciphertext to prove knowledge and range
 *  @param X           Public exponent of the associated DLOG to prove knowledge
 *  @param c           Commitment of the prover
 *  @param ID          Unique prover identifier
 *  @param AD          Additional data to bind in the proof. Optional
 *  @param E           Destination challenge
 */
extern void MTA_ZKWC_challenge(PAILLIER_public_key *key, BIT_COMMITMENT_pub *mod, const octet *C1, const octet *C2, const octet *X, MTA_ZKWC_commitment *c, const octet *ID, const octet *AD, octet *E);

/** \brief Proof generation for Receiver ZKP with check
 *
 *  Generate a proof of knowledge of x, y and a range proof for x.
 *  These values are the same as for the ZKP without check. The
 *  knowledge of the DLOG can be verified using the value U in the
 *  commitment
 *
 *  <ol>
 *  <li> \f$ s  = \beta r^e \text{ }\mathrm{mod}\text{ }N \f$
 *  <li> \f$ s_1 = ex + \alpha \f$
 *  <li> \f$ s_2 = e\rho + \rho_1 \f$
 *  <li> \f$ t_1 = ey + \gamma \f$
 *  <li> \f$ t_2 = e\sigma + \tau \f$
 *  </ol>
 *
 *  @param key         Private Paillier key of the prover
 *  @param X           Message to prove knowledge and range
 *  @param Y           Message to prove knowledge
 *  @param R           Random value used in the Paillier addition
 *  @param rv          Random values associated to the commitment
 *  @param E           Generated challenge
 *  @param p           Destination proof
 */
extern void MTA_ZKWC_prove(PAILLIER_public_key *key, octet *X, octet *Y, octet *R, MTA_ZKWC_rv *rv, octet *E, MTA_ZKWC_proof *p);

/** \brief Verify a Proof for Receiver ZKP with check
 *
 *  Verify the proof of knowledge of x, y associated to c1, c2 and of x range.
 *  Additionally verify the knowledge of X = x.G
 *
 *  <ol>
 *  <li> \f$ s_1 \stackrel{?}{\leq} q^3 \f$
 *  <li> \f$ z_1 \stackrel{?}{=} h_1^{s_1}h_2^{s_2}z^{-e}   \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ w  \stackrel{?}{=} h_1^{t_1}h_2^{t_2}t^{-e}    \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ v  \stackrel{?}{=} c1^{s_1}s^{N}g^{t_1}c2^{-e} \text{ }\mathrm{mod}\text{ }N^2 \f$
 *  <li> \f$ U  \stackrel{?}{=} s_1.G - e.X \f$
 *  </ol>
 *
 *  @param key         Public Paillier key of the prover
 *  @param mod         Private BC modulus of the verifier
 *  @param C1          Base Paillier Ciphertext
 *  @param C2          New Paillier Ciphertext to prove knowledge and range
 *  @param X           Public ECP of the DLOG x.G
 *  @param c           Received commitment
 *  @param E           Generated challenge
 *  @param p           Received proof
 *  @return            MTA_OK if the proof is valid, MTA_FAIL otherwise
 */
extern int MTA_ZKWC_verify(PAILLIER_private_key *key, BIT_COMMITMENT_priv *mod, octet *C1, octet *C2, octet *X, MTA_ZKWC_commitment *c, octet *E, MTA_ZKWC_proof *p);

/** \brief Dump the commitment to octets
 *
 *  @param U           Octet with the commitment for the DLOG ZKP. EGS_SECP256K1 + 1 long
 *  @param Z           Destination Octet for the z component of the commitment. FS_2048 long
 *  @param Z1          Destination Octet for the z1 component of the commitment. FS_2048 long
 *  @param T           Destination Octet for the t component of the commitment. FS_2048 long
 *  @param V           Destination Octet for the v component of the commitment. FS_4096 long
 *  @param W           Destination Octet for the w component of the commitment. FS_2048 long
 *  @param c           Commitment to export
 */
extern void MTA_ZKWC_commitment_toOctets(octet *U, octet *Z, octet *Z1, octet *T, octet *V, octet *W, MTA_ZKWC_commitment *c);

/** \brief Read the commitments from octets
 *
 *  @param c           Destination commitment
 *  @param U           Octet with the commitment for the DLOG ZKP
 *  @param Z           Octet with the z component of the commitment
 *  @param Z1          Octet with the z1 component of the commitment
 *  @param T           Octet with the t component of the commitment
 *  @param V           Octet with the v component of the commitment
 *  @param W           Octet with the w component of the commitment
 *  @return            MTA_INVALID_ECP if U is not a valid ECP, MTA_OK otherwise
 */
extern int MTA_ZKWC_commitment_fromOctets(MTA_ZKWC_commitment *c, octet *U, octet *Z, octet *Z1, octet *T, octet *V, octet *W);

/** \brief Dump the proof to octets
 *
 *  @param S           Destination Octet for the s component of the proof. FS_2048 long
 *  @param S1          Destination Octet for the s1 component of the proof. HFS_2048 long
 *  @param S2          Destination Octet for the s2 component of the proof. FS_2048 + HFS_2048 long
 *  @param T1          Destination Octet for the t1 component of the proof. FS_2048 long
 *  @param T2          Destination Octet for the t2 component of the proof. FS_2048 + HFS_2048 long
 *  @param p           Proof to export
 */
extern void MTA_ZKWC_proof_toOctets(octet *S, octet *S1, octet *S2, octet *T1, octet *T2, MTA_ZKWC_proof *p);

/** \brief Read the proof from octets
 *
 *  @param p           Destination proof
 *  @param S           Octet with the s component of the proof
 *  @param S1          Octet with the s1 component of the proof
 *  @param S2          Octet with the s2 component of the proof
 *  @param T1          Octet with the t1 component of the proof
 *  @param T2          Octet with the t2 component of the proof
 */
extern void MTA_ZKWC_proof_fromOctets(MTA_ZKWC_proof *p, octet *S, octet *S1, octet *S2, octet *T1, octet *T2);

/** \brief Clean the memory containing the random values
 *
 *   @param rv         Random values to clean
 */
extern void MTA_ZKWC_rv_kill(MTA_ZKWC_rv *rv);

#ifdef __cplusplus
}
#endif

#endif
