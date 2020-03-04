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
 * @file schnorr.h
 * @brief Schnorr's proofs declarations
 *
 */

#ifndef SCHNORR_H
#define SCHNORR_H

#include "amcl/amcl.h"
#include "amcl/big_256_56.h"
#include "amcl/ecp_SECP256K1.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Field size is assumed to be greater than or equal to group size */

#define SGS_SECP256K1 MODBYTES_256_56  /**< Schnorr Group Size */
#define SFS_SECP256K1 MODBYTES_256_56  /**< Schnorr Field Size */

#define SCHNORR_OK          0   /**< Valid proof */
#define SCHNORR_FAIL	      51  /**< Invalid proof */
#define SCHNORR_INVALID_ECP 52  /**< Not a valid point on the curve */

/*! \brief Generate random challenge for any Schnorr Proof
 *
 * Generate a random challenge that can be used to make any
 * of the following Schnorr Proofs interactive. This can be used
 * to be interoperable with other implementations.
 */
extern void SCHNORR_random_challenge(csprng *RNG, octet *E);

/* Classic Schnorr's proofs API */

/*! \brief Generate a commitment for the proof
 *
 * @param RNG   CSPRNG to use for commitment
 * @param R     Secret value used for the commitment. If RNG is NULL this is read
 * @param C     Public commitment value. An ECP
 */
extern void SCHNORR_commit(csprng *RNG, octet *R, octet *C);

/*! \brief Generate the challenge for the proof
 *
 * Compute the challenge for the proof as described in RFC8235#section-3.3
 *
 * @param V     Public ECP of the DLOG. V = x.G. Compressed form
 * @param C     Public commitment value. Compressed form
 * @param E     Challenge generated
 */
extern void SCHNORR_challenge(const octet *V, const octet *C, octet *E);

/*! \brief Generate the proof for the given commitment and challenge
 *
 * @param R     Secret value used for the commitment
 * @param E     Challenge received from the verifier
 * @param X     Secret exponent of the DLOG. V = x.G
 * @param P     Proof of knowldege of the DLOG
 */
extern void SCHNORR_prove(const octet *R, const octet *E, const octet *X, octet *P);

/*! \brief Verify the proof of knowledge for the DLOG
 *
 * @param V     Public ECP of the DLOG. V = x.G
 * @param C     Commitment value received from the prover
 * @param E     Challenge for the Schnorr Proof
 * @param P     Proof received from the prover
 * @return      SCHNORR_OK if the prove is valid or an error code
 */
extern int SCHNORR_verify(octet *V, octet *C, const octet *E, const octet *P);

/* Double Schnorr's proofs API */

// The double Schnorr Proof allows to prove knwoldedge of
// s,l s.t. V = s.R + l.G for some R ECP

/*! \brief Generate a commitment for the proof
 *
 * @param RNG   CSPRNG to use for commitment
 * @param R     Public ECP base of the DLOG. Compressed form
 * @param A     Secret value used for the commitment. If RNG is NULL this is read
 * @param B     Secret value used for the commitment. If RNG is NULL this is read
 * @param C     Public commitment value. An ECP in compressed form
 * @return      SCHNORR_INVALID_ECP if R is not a valid ECP, SCHNORR_OK otherwise
 */
extern int SCHNORR_D_commit(csprng *RNG, octet *R, octet *A, octet *B, octet *C);

/*! \brief Generate the challenge for the proof
 *
 * Compute the challenge for the proof. RFC8235#section-3.3 can not be applied
 * here, but we try to follow closely by treating R like a secondary generator.
 * Returns H(G, R, C, V)
 *
 * @param V     Public ECP result of the DLOG. V = s.R + l.G. Compressed form
 * @param R     Public ECP base of the DLOG. Compressed form
 * @param C     Public commitment value. Compressed form
 * @param E     Challenge generated
 */
extern void SCHNORR_D_challenge(const octet *R, const octet *V, const octet *C, octet *E);

/*! \brief Generate the proof for the given commitment and challenge
 *
 * @param A     Secret value used for the commitment
 * @param B     Secret value used for the commitment
 * @param E     Challenge received from the verifier
 * @param S     Secret exponent of the DLOG. V = s.R + l.G
 * @param L     Secret exponent of the DLOG. V = s.R + l.G
 * @param T     First component of the proof of knowldege of the DLOG
 * @param U     Second component of the proof of knowldege of the DLOG
 */
extern void SCHNORR_D_prove(const octet *A, const octet *B, const octet *E, const octet *S, const octet *L, octet *T, octet *U);

/*! \brief Verify the proof of knowledge for the DLOG
 *
 * @param R     Public ECP base of the DLOG. Compressed form
 * @param V     Public ECP of the DLOG. V = s.R + l.G. Compressed form
 * @param C     Commitment value received from the prover
 * @param E     Challenge for the Schnorr Proof
 * @param T     First component of the proof received
 * @param U     Second component of the proof received
 * @return      SCHNORR_OK if the prove is valid or an error code
 */
extern int SCHNORR_D_verify(octet *R, octet *V, octet *C, const octet *E, const octet *T, const octet *U);

#ifdef __cplusplus
}
#endif

#endif
