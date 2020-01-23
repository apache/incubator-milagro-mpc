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
#define SCHNORR_FAIL	    51  /**< Invalid proof */
#define SCHNORR_INVALID_ECP 52  /**< Not a valid point on the curve */

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
extern void SCHNORR_challenge(octet *V, octet *C, octet *E);

/*! \brief Generate the proof for the given commitment and challenge
 *
 * @param R     Secret value used for the commitment
 * @param E     Challenge received from the verifier
 * @param X     Secret exponent of the DLOG. V = x.G
 * @param P     Proof of knowldege of the DLOG
 */
extern void SCHNORR_prove(octet *R, octet *E, octet *X, octet *P);

/*! \brief Verify the proof of knowledge for the DLOG
 *
 * @param V     Public ECP of the DLOG. V = x.G
 * @param C     Commitment value received from the prover
 * @param E     Challenge for the Schnorr Proof
 * @param P     Proof received from the prover
 * @return      SCHNORR_OK if the prove is valid or an error code
 */
extern int SCHNORR_verify(octet *V, octet *C, octet *E, octet *P);

#ifdef __cplusplus
}
#endif

#endif
