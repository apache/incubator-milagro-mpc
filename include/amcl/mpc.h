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

/**	@brief Generate an ECC public/private key pair
 *
 *  Generat an ECC public/private key pair W = s.G, where
 *  G is a fixed public generator
 *
 *  @param RNG is a pointer to a cryptographically secure random number generator
 *  @param S the private key, an output internally randomly generated if R!=NULL, otherwise must be provided as an input
 *  @param W the output public key, which is s.G, where G is a fixed generator
 */
extern void MPC_ECDSA_KEY_PAIR_GENERATE(csprng *RNG, octet* S, octet *W);

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
extern int MPC_ECDSA_SIGN(int sha, const octet *K, const octet *SK, octet *M, octet *R, octet *S);

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
extern int MPC_ECDSA_VERIFY(const octet *HM,octet *PK, octet *R,octet *S);

/** \brief Generate a random K for and ECDSA signature
 *
 *  Generate a random K modulo the curve order
 *
 *  @param RNG               Pointer to a cryptographically secure PRNG
 *  @param K                 Destination octet for the randomly generated value
 */
extern void MPC_K_GENERATE(csprng *RNG, octet *K);

/** \brief Calculate the inverse of the sum of kgamma values
 *
 *  Calculate the inverse of the sum of kgamma values
 *
 *  <ol>
 *  <li> \f$ invkgamma = (kgamma_1 + ... + kgamma_n)^{-1} \text{ }\mathrm{mod}\text{ }q \f$
 *  </ol>
 *
 *  @param KGAMMA             Actors additive shares
 *  @param INVKGAMMA          Inverse of the sum of the additive shares
 *  @param n                  Number of actors
 */
extern void MPC_INVKGAMMA(const octet *KGAMMA, octet *INVKGAMMA, int n);

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
 *  @param  GAMMAPT           Actors gamma points
 *  @param  R                 R component of the signature
 *  @param  RP                ECP associated to the R component of the signature. Optional
 *  @param  n                 Number of actors
 *  @return                   Returns 0 or else error code
 */
extern int MPC_R(const octet *INVKGAMMA, octet *GAMMAPT, octet *R, octet *RP, int n);

/** \brief Hash the message value
 *
 *  Hash the message value
 *
 *  @param  sha               Hash type
 *  @param  M                 Message to be hashed
 *  @param  HM                Hash value
 *  @return                   Returns 0 or else error code
 */
extern void MPC_HASH(int sha, octet *M, octet *HM);

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
extern int MPC_S(const octet *HM, const octet *R, const octet *K, const octet *SIGMA, octet *S);

/** \brief Combine BIGs in the EC group
 *
 *  Calculate the sum of the given BIGs mod the curve order
 *
 *  <ol>
 *  <li> \f$ out = s_1 + ... + s_n \text{ }\mathrm{mod}\text{ }q \f$
 *  </ol>
 *
 *  @param  OUT               Output BIG, sum od the shares
 *  @param  SHARES            Actors shares to combine
 *  @param  n                 Number of actors
 */
extern void MPC_SUM_BIGS(octet *OUT, const octet *SHARES, int n);

/** \brief Combine ECPs
 *
 *  Calculate the sum of the given ECPs
 *
 *  <ol>
 *  <li> \f$ ecp = ecp_1 + ... + ecp_n \f$
 *  </ol>
 *
 *  @param  OUT               Output ECP, sum of the shares
 *  @param  SHARES            Actor 1 ECDSA public key share
 *  @param  n                 Number of actors
 *  @return                   Returns 0 or else error code
 */
extern int MPC_SUM_ECPS(octet *OUT, octet *SHARES, int n);

/* MPC Phase 3 API */

/** \brief Compute commitment to sigma, l for Phase 3
 *
 *  <ol>
 *  <li> \f$ T = sigma.G + l.H \f$
 *  </ol>
 *
 *  @param RNG               Pointer to a cryptographically secure PRNG
 *  @param SIGMA             Value to commit
 *  @param L                 Random value for the commitment. If RNG is NULL this is read.
 *  @param T                 Output commitment
 */
extern void MPC_PHASE3_T(csprng *RNG, octet *SIGMA, octet *L, octet *T);

/* MPC Phase 5-6 API */

/** \brief Compute check for R, x
 *
 *  <ol>
 *  <li> \f$ RT = x.R \f$
 *  </ol>
 *
 *  @param R                 Base of the DLOG for the check
 *  @param X                 Exponent for the DLGG
 *  @param RT                Check for R, X
 *  @return                  MPC_OK or an error code
 */
extern int MPC_ECP_GENERATE_CHECK(octet *R, octet *X, octet *RT);

/** \brief Verify checks in RT using ground truth R
 *
 *  <ol>
 *  <li> \f$ G =? RT_1 + ... + RT_n \f$
 *  </ol>
 *
 *  @param RT                Checks for R
 *  @param G                 Ground truth for the checks. If NULL the curve generator is used
 *  @param n                 Number of players
 *  @return                  MPC_OK or an error code
 */
extern int MPC_ECP_VERIFY(octet *RT, octet *G, int n);

/*! \brief Write Paillier keys to octets
 *
 *  @param   PRIV             Paillier secret key
 *  @param   P                Secret prime number
 *  @param   Q                Secret prime number
 */
extern void MPC_DUMP_PAILLIER_SK(PAILLIER_private_key *PRIV, octet *P, octet *Q);


#ifdef __cplusplus
}
#endif

#endif
