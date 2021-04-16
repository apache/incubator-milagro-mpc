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
 * @file ggn.h
 * @brief Gennaro, Goldfeder, Narayanan ZKP of consistency of a Paillier Ciphertext
 *
 */

#ifndef GGN_H
#define GGN_H

#include "amcl/amcl.h"
#include "amcl/paillier.h"
#include "amcl/bit_commitment.h"
#include "amcl/ecp_SECP256K1.h"
#include "amcl/ecdh_SECP256K1.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define GGN_OK             0    /**< Proof successfully verified */
#define GGN_INVALID_ECP    131  /**< Invalid ECP octet */

/** \brief Secret random values for the GGN commitment */
typedef BIT_COMMITMENT_rv GGN_rv;

/** \brief Public commitment for the GGN Proof */
typedef struct
{
    BIT_COMMITMENT_commitment c; /**< Commitment for the base ZKP */
    ECP_SECP256K1 u1;            /**< Commitment for the DLOG knowledge proof */
} GGN_commitment;

/** \brief GGN Proof */
typedef BIT_COMMITMENT_proof GGN_proof;

/** \brief GGN Commitment Generation
 *
 *  Generate a commitment for the message M
 *
 *  <ol>
 *  <li> \f$ \alpha \in_R [0, \ldots, q^3]\f$
 *  <li> \f$ \beta  \in_R [0, \ldots, N]\f$
 *  <li> \f$ \gamma \in_R [0, \ldots, q^{3}\tilde{N}]\f$
 *  <li> \f$ \rho   \in_R [0, \ldots, q\tilde{N}]\f$
 *  <li> \f$ z = h_1^{m}h_2^{\rho} \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ u1 = \alpha.R \f$
 *  <li> \f$ u2 = g^{\alpha}\beta^{N} \text{ }\mathrm{mod}\text{ }N^2 \f$
 *  <li> \f$ u3 = h_1^{\alpha}h_2^{\gamma} \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  </ol>
 *
 *  @param RNG         csprng for random generation
 *  @param key         Paillier key used to encrypt M
 *  @param mod         Public BC modulus of the verifier
 *  @param R           Public ECp, base of the DLOG
 *  @param M           Message to prove knowledge and consistency
 *  @param c           Destination commitment
 *  @param rv          Random values associated to the commitment. If RNG is NULL this is read
 *  @return            GGN_OK or GGN_INVALID_ECP if the octet R is not a valid ECp
 */
extern int GGN_commit(csprng *RNG, PAILLIER_private_key *key, BIT_COMMITMENT_pub *mod, octet *R, octet *M, GGN_rv *rv, GGN_commitment *c);

/** \brief Deterministic Challenge generations for the GGN ZKP
 *
 *  Generate a challenge binding together public parameters and commitment
 *
 *  <ol>
 *  <li> \f$ e = H( N | \tilde{N} | h_1 | h_2 | R | \tilde{R} | C | z | u1 | u2 | u3 | ID | AD ) \f$
 *  </ol>
 *
 *  @param key         Public Paillier key of the prover
 *  @param m           Public BC modulus of the verifier
 *  @param R           Public ECp, base of the DLOG
 *  @param Rt          Public ECp, DLOG
 *  @param CT           Paillier Ciphertext to prove knowledge and range
 *  @param c           Commitment of the prover
 *  @param ID          Unique prover identifier
 *  @param AD          Additional data to bind in the proof. Optional
 *  @param E           Destination challenge
 */
extern void GGN_challenge(PAILLIER_public_key *key, BIT_COMMITMENT_pub *m, const octet *R, const octet *Rt, const octet *CT, GGN_commitment *c, const octet *ID, const octet *AD, octet *E);

/** \brief Proof generation for Receiver ZKP with check
 *
 *  Generate a proof of knowledge of x, y and a range proof for x.
 *  These values are the same as for the ZKP without check. The
 *  knowledge of the DLOG can be verified using the value U in the
 *  commitment
 *
 *  <ol>
 *  <li> \f$ s_1 = ex + \alpha \f$
 *  <li> \f$ s_2 = \beta r^e \text{ }\mathrm{mod}\text{ }N \f$
 *  <li> \f$ s_3 = e\rho + \gamma \f$
 *  </ol>
 *
 *  @param key         Private Paillier key of the prover
 *  @param K           Message to prove knowledge and range
 *  @param R           Random value used in the Paillier encryption
 *  @param rv          Random values associated to the commitment
 *  @param E           Generated challenge
 *  @param p           Destination proof
 */
extern void GGN_prove(PAILLIER_private_key *key, octet *K, octet *R, GGN_rv *rv, octet *E, GGN_proof *p);

/** \brief Verify a Proof for Receiver ZKP with check
 *
 *  Verify the proof of knowledge and range of x associated to C.
 *  Additionally verify the knowledge of \f$ \tilda{R} = x.G \f{R} \f$
 *
 *  <ol>
 *  <li> \f$ s_1 \stackrel{?}{\leq} q^3 \f$
 *  <li> \f$ u_1 \stackrel{?}{=} s_1.R - e.\tilda{R} \f$
 *  <li> \f$ u_2 \stackrel{?}{=} g^{s_1}s_2^{N}C^{-e} \text{ }\mathrm{mod}\text{ }N^2 \f$
 *  <li> \f$ u_3 \stackrel{?}{=} h_1^{s_1}h_2^{s_3}z^{-e} \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  </ol>
 *
 *  @param key         Public Paillier key of the prover
 *  @param m           Private BC modulus of the verifier
 *  @param R           Public ECp, base of the DLOG
 *  @param Rt          Public ECp, DLOG
 *  @param CT          Paillier Ciphertext to prove knowledge and range
 *  @param c           Commitment of the prover
 *  @param E           Generated challenge
 *  @param p           Received proof
 *  @return            GGN_OK if the proof is valid or an error code
 */
extern int GGN_verify(PAILLIER_public_key *key, BIT_COMMITMENT_priv *m, octet *R, octet *Rt, octet *CT, GGN_commitment *c, octet *E, GGN_proof *p);

/** \brief Dump the commitment to octets
 *
 *  @param Z           Destination Octet for the z component of the commitment. FS_4096 long
 *  @param U1          Destination Octet for the u1 component of the commitment. EGS_SECP256K1 + 1 long
 *  @param U2          Destination Octet for the u2 component of the commitment. FS_2048 long
 *  @param U3          Destination Octet for the u3 component of the commitment. FS_2048 long
 *  @param c           Commitment to export
 */
extern void GGN_commitment_toOctets(octet *Z, octet *U1, octet *U2, octet *U3, GGN_commitment *c);

/** \brief Read the commitments from octets
 *
 *  @param c           Destination Commitment
 *  @param Z           Octet with the z component of the commitment
 *  @param U1          Octet with the u1 component of the commitment
 *  @param U2          Octet with the u2 component of the commitment
 *  @param U3          Octet with the u3 component of the commitment
 */
extern int GGN_commitment_fromOctets(GGN_commitment *c, octet *Z, octet *U1, octet *U2, octet *U3);

/** \brief Dump the proof to octets
 *
 *  @param S1          Destination Octet for the s1 component of the proof. HFS_2048 long
 *  @param S2          Destination Octet for the s2 component of the proof. FS_2048 long
 *  @param S3          Destination Octet for the s3 component of the proof. FS_2048 + HFS_2048 long
 *  @param p           Proof to export
 */
extern void GGN_proof_toOctets(octet *S1, octet *S2, octet *S3, GGN_proof *p);

/** \brief Read the proof from octets
 *
 *  @param p           Destination Proof
 *  @param S1          Octet with the s1 component of the proof
 *  @param S2          Octet with the s2 component of the proof
 *  @param S3          Octet with the s3 component of the proof
 */
extern void GGN_proof_fromOctets(GGN_proof *p, octet *S1, octet *S2, octet *S3);

/** \brief Clean the memory containing the random values
 *
 *   @param rv         Random values to clean
 */
extern void GGN_rv_kill(GGN_rv *rv);

#ifdef __cplusplus
}
#endif

#endif