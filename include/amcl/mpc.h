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
 * @file mpc.h
 * @brief MPC declarations
 *
 */

#ifndef MPC_H
#define MPC_H

#include <amcl/amcl.h>
#include <amcl/paillier.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MPC_OK          0    /**< Execution Successful */
#define MPC_FAIL        71   /**< Failure */
#define MPC_INVALID_ECP 72   /**< Input is not a valid point on the curve */

/** \brief ECDSA Sign message
 *
 *  Generate the ECDSA signature on message, M, with outputs (R,S)
 *
 *  <ol>
 *  <li> Choose a random non-zero value \f$ k \in  F_q \f$ where \f$q\f$ is the curve order
 *  <li> \f$ r_x, r_y = k^{-1}G \f$ where G is the group generator
 *  <li> \f$ r = rx \text{ }\mathrm{mod}\text{ }q \f$
 *  <li> \f$ z = hash(message) \f$
 *  <li> \f$ s = k.(z + r.sk) \text{ }\mathrm{mod}\text{ }q \f$ where \f$ sk \f$ is the ECDSA secret key
 *  </ol>
 *
 *  @param sha is the hash type
 *  @param K Ephemeral key.
 *  @param SK the input private signing key
 *  @param M the input message to be signed
 *  @param R component of the signature
 *  @param S component of the signature
 */
int MPC_ECDSA_SIGN(int sha, const octet *K, const octet *SK, octet *M, octet *R, octet *S);

/** \brief ECDSA Verify signature
 *
 *  Verify the ECDSA signature (R,S) on a message
 *
 *  @param  HM               Hash of the message
 *  @param  PK               ECDSA public key
 *  @param  R                R component of signature
 *  @param  S                S component of signature
 *  @return                  Returns 0 or else error code
 */
int MPC_ECDSA_VERIFY(const octet *HM,octet *PK, octet *R,octet *S);

/** \brief Calculate the inverse of the sum of kgamma values
 *
 *  Calculate the inverse of the sum of kgamma values
 *
 *  <ol>
 *  <li> \f$ invkgamma = (kgamma1 + kgamma2)^{-1} \text{ }\mathrm{mod}\text{ }q \f$
 *  </ol>
 *
 *  @param KGAMMA1            Actor 1 additive share
 *  @param KGAMMA2            Actor 2 additive share
 *  @param INVKGAMMA          Inverse of the sum of the additive shares
 */
void MPC_INVKGAMMA(const octet *KGAMMA1, const octet *KGAMMA2, octet *INVKGAMMA);

/** \brief R component
 *
 *  Generate the ECDSA signature R component. It also outputs the ECP
 *  associate to the R component if specified
 *
 *  <ol>
 *  <li> \f$ r_x, r_y = k^{-1}G \f$ where G is the group generator
 *  <li> \f$ r = rx \text{ }\mathrm{mod}\text{ }q \f$
 *  </ol>
 *
 *  @param  INVKGAMMA         Inverse of k times gamma
 *  @param  GAMMAPT1          Actor 1 gamma point
 *  @param  GAMMAPT2          Actor 2 gamma point
 *  @param  R                 R component of the signature
 *  @param  RP                ECP associated to the R component of the signature. Optional
 *  @return                   Returns 0 or else error code
 */
int MPC_R(const octet *INVKGAMMA, octet *GAMMAPT1, octet *GAMMAPT2, octet *R, octet *RP);

/** \brief Hash the message value
 *
 *  Hash the message value
 *
 *  @param  sha               Hash type
 *  @param  M                 Message to be hashed
 *  @param  HM                Hash value
 *  @return                   Returns 0 or else error code
 */
void MPC_HASH(int sha, octet *M, octet *HM);

/** \brief S component
 *
 *  Generate the ECDSA signature S component
 *
 *  <ol>
 *  <li> \f$ s = k * (h(m) + sk * r) \text{ }\mathrm{mod}\text{ }q \f$ where h() means hash
 *  <li> \f$ s = (k * h(m)) + (k * sk * r) \text{ }\mathrm{mod}\text{ }q \f$
 *  <li> \f$ s = (k * h(m)) + sigma * r) \text{ }\mathrm{mod}\text{ }q \f$
 *  </ol>
 *
 *  @param  HM                Hash of the message to be signed
 *  @param  R                 R component input
 *  @param  K                 Nonce value
 *  @param  SIGMA             Additive share of k.w
 *  @param  S                 S component output
 *  @return                   Returns 0 or else error code
 */
int MPC_S(const octet *HM, const octet *R, const octet *K, const octet *SIGMA, octet *S);

/** \brief Sum of ECDSA s components
 *
 *  Calculate the sum of the s components of the ECDSA signature
 *
 *  <ol>
 *  <li> \f$ s = s1 + s2 \text{ }\mathrm{mod}\text{ }q \f$
 *  </ol>
 *
 *  @param  S1                Actor 1 ECDSA s component
 *  @param  S2                Actor 2 ECDSA s component
 *  @param  S                 S component sum
 */
void MPC_SUM_S(const octet *S1, const octet *S2, octet *S);

/** \brief Sum of ECDSA public key shares
 *
 *  Calculate the sum of the ECDSA public key shares
 *
 *  <ol>
 *  <li> \f$ pk = pk1 + pk2 \text{ }\mathrm{mod}\text{ }q \f$
 *  </ol>
 *
 *  @param  PK1               Actor 1 ECDSA public key share
 *  @param  PK2               Actor 2 ECDSA public key share
 *  @param  PK                ECDSA public key
 *  @return                   Returns 0 or else error code
 */
int MPC_SUM_PK(octet *PK1, octet *PK2, octet *PK);

/* MPC Phase 5 API */

/** \brief Generate Commitment for the MPC Phase 5
 *
 *  Calculate player Commitment (A, V) for MPC Phase 5
 *
 *  <ol>
 *  <li> \f$ \phi \in_R [0, \ldots, q] \f$
 *  <li> \f$ \rho \in_R [0, \ldots, q] \f$
 *  <li> \f$ V = \phi.G + s.R \f$
 *  <li> \f$ A = \rho.G \f$
 *  </ol>
 *
 *  @param RNG                csprng for random values generation
 *  @param R                  Reconciled R for the signature
 *  @param S                  Player signature share
 *  @param PHI                Random value for the commitment. If RNG is null this is read
 *  @param RHO                Random value for the commitment. If RNG is null this is read
 *  @param V                  First component of the player commitment. An ECP in compressed form
 *  @param A                  Second component of the player commitment. An ECP in compressed form
 *  @return                   Returns MPC_OK or an error code
 */
extern int MPC_PHASE5_commit(csprng *RNG, octet *R, const octet *S, octet *PHI, octet *RHO, octet *V, octet *A);

/** \brief Generate Proof for the MPC Phase 5
 *
 *  Calculate player Proof (U, T) for MPC Phase 5
 *
 *  <ol>
 *  <li> \f$ m = H(M) \f$
 *  <li> \f$ A = A1 + A2 \f$
 *  <li> \f$ V = V1 + V2 \f$
 *  <li> \f$ U = \rho.(V - m.G - r.PK) \f$
 *  <li> \f$ T = \phi.A \f$
 *  </ol>
 *
 *  @param PHI                Random value used in the commitment
 *  @param RHO                Random value used in the commitment
 *  @param V                  Array with the commitments V from both players. ECPs in compressed form
 *  @param A                  Array with the commitments A from both players. ECPs in compressed form
 *  @param PK                 Shared public key for MPC
 *  @param HM                 Hash of the message being signed
 *  @param RX                 x component of the reconciled R for the signature
 *  @param U                  First component of the player proof. An ECP in compressed form
 *  @param T                  Second component of the player proof. An ECP in compressed form
 *  @return                   Returns MPC_OK or an error code
 */
extern int MPC_PHASE5_prove(const octet *PHI, const octet *RHO, octet *V[2], octet *A[2], octet *PK, const octet *HM, const octet *RX, octet *U, octet *T);

/** \brief Verify Proof for the MPC Phase 5
 *
 *  Combine player Proofs and verify the consistency of the signature shares
 *  This does NOT prove that the signature is valid. It only verifies that
 *  all players know the secret quantities used to generate their shares.
 *
 *  <ol>
 *  <li> \f$ U = U1 + U2 \f$
 *  <li> \f$ T = T1 + T2 \f$
 *  <li> \f$ U \stackrel{?}{=} T \f$
 *  </ol>
 *
 *  @param U                  Array with the proofs U from both players. ECPs in compressed form
 *  @param T                  Array with the proofs T from both players. ECPs in compressed form
 *  @return                   Returns MPC_OK or an error code
 */
extern int MPC_PHASE5_verify(octet *U[2], octet *T[2]);

/*! \brief Write Paillier keys to octets
 *
 *  @param   PRIV             Paillier secret key
 *  @param   P                Secret prime number
 *  @param   Q                Secret prime number
 */
void MPC_DUMP_PAILLIER_SK(PAILLIER_private_key *PRIV, octet *P, octet *Q);


#ifdef __cplusplus
}
#endif

#endif
