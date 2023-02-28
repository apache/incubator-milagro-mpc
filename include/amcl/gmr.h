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
 * @file gmr.h
 * @brief Gennaro, Micciancio, Rabin ZKP for the Square Free language
 *
 */

#ifndef GMR_H
#define GMR_H

#include "amcl/amcl.h"
#include "amcl/modulus.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define GMR_OK   0            /**< Proof successfully verified */
#define GMR_FAIL 111          /**< Invalid proof */
#define GMR_INVALID_PROOF 112 /**< Invalid proof bounds */

#define GMR_PROOF_ITERS 10                        /**< Iterations necessary for the Proof, n */
#define GMR_PROOF_SIZE  GMR_PROOF_ITERS * FS_2048 /**< Length of the Proof in bytes */

/*! \brief Holds the values for each iteration of the protocol */
typedef BIG_1024_58 GMR_proof[GMR_PROOF_ITERS][FFLEN_2048];

/*! \brief Generate the GMR Proofs
 *
 *  Generate the proofs \f$ Y_i \f$ for the pseudorandom challenges
 *  computed from N, ID, AD
 *
 *  <ol>
 *  <li> For each \f$ i = 0, \ldots, n-1 \f$
 *  <li> \f$ X_i = H(N, ID, AD, I2OSP(i), I2OSP(k)) \f$
 *  <li>
 *  <li> \f$ M = N^(-1) mod \phi(N) \f$
 *  <li> \f$ Y_i = X_i^M mod N \f$
 *  </ol>
 *
 *  @param  m           Private Modulus to prove Square Freeness
 *  @param  ID          Prover unique identifier
 *  @param  AD          Additional data to bind in the proof. Optional
 *  @param  Y           Destination GMR proof
 */
extern void GMR_prove(MODULUS_priv *m, const octet *ID, const octet *AD, GMR_proof Y);

/*! \brief Verify the GMR Proofs
 *
 *  Verify the proofs \f$ Y_i \f$ against the pseudorandom challenges
 *  computed from N, ID, AD
 *
 *  <ol>
 *  <li> For each \f$ i = 0, \ldots, n-1 \f$
 *  <li> \f$ X_i = H(N, ID, AD, I2OSP(i), I2OSP(k)) \f$
 *  <li>
 *  <li> \f$ X_i = Y_i^N mod N \f$
 *  </ol>
 *
 *  @param  N           Public RSA Modulus
 *  @param  Y           GMR Proof
 *  @param  ID          Prover unique identifier
 *  @param  AD          Additional data to bind in the proof. Optional
 *  @return             GMR_OK if the proof is valid or aNn error code
 */
extern int GMR_verify(octet *N, GMR_proof Y, const octet *ID, const octet *AD);

/*! \brief Encode a GMR Proof into an octet
 *
 * @param O      Destination Octet
 * @param p      Source proof
 */
extern void GMR_proof_toOctet(octet *O, GMR_proof p);

/*! \brief Decode an octet into a GMR Proof
 *
 * @param p      Destination proof. Must be at least GMR_PROOF_SIZE bytes long
 * @param O      Source Octet
 * @return       GMR_OK if the octet is valid or an error code
 */
extern int GMR_proof_fromOctet(GMR_proof p, octet *O);


#ifdef __cplusplus
}
#endif

#endif

