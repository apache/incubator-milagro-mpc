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
 * @file mta.h
 * @brief MTA declarations
 *
 */

#ifndef MTA_H
#define MTA_H

#include "amcl/amcl.h"
#include "amcl/paillier.h"
#include "amcl/ecp_SECP256K1.h"
#include "amcl/ecdh_SECP256K1.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MTA_OK 0             /**< Proof successfully verified */
#define MTA_FAIL 61          /**< Invalid proof */
#define MTA_INVALID_ECP 62   /**< Invalid ECP */

/* MTA protocol API */

/*! \brief Client MTA first pass
 *
 *  Encrypt multiplicative share, \f$ a \f$, of secret \f$ s = a.b \f$
 *
 *  @param  RNG              Pointer to a cryptographically secure random number generator
 *  @param  PUB              Paillier Public key
 *  @param  A                Multiplicative share of secret
 *  @param  CA               Ciphertext
 *  @param  R                R value for testing. If RNG is NULL then this value is read.
 */
void MTA_CLIENT1(csprng *RNG, PAILLIER_public_key* PUB, octet* A, octet* CA, octet* R);

/*! \brief Client MtA second pass
 *
 *  Calculate additive share, \f$ \alpha \f$, of secret \f$ s = a.b \f$
 *
 *  <ol>
 *  <li> Choose a random non-zero value \f$ z \in  F_q \f$ where \f$q\f$ is the curve order
 *  <li> \f$ \alpha = D_A(cb) = D_A(E_A(ab + z)) = ab + z \text{ }\mathrm{mod}\text{ }q \f$
 *  </ol>
 *
 *  @param   PRIV             Paillier Private key
 *  @param   CB               Ciphertext
 *  @param   ALPHA            Additive share of secret
 */
void MTA_CLIENT2(PAILLIER_private_key *PRIV, octet* CB, octet *ALPHA);

/*! \brief Server MtA
 *
 *  Calculate additive share, \f$ \beta \f$, of secret \f$ s = a.b \f$ and
 *  ciphertext allowing client to calculate their additive share.
 *
 *  <ol>
 *  <li> Choose a random non-zero value \f$ z \in  F_q \f$ where \f$q\f$ is the curve order
 *  <li> \f$ \beta = -z\text{ }\mathrm{mod}\text{ }q \f$
 *  <li> \f$ cb = ca \otimes{} b \oplus{} z = E_A(ab + z) \f$
 *  </ol>
 *
 *  @param   RNG              Pointer to a cryptographically secure random number generator
 *  @param   PUB              Paillier Public key
 *  @param   B                Multiplicative share of secret
 *  @param   CA               Ciphertext of client's additive share of secret
 *  @param   Z                Plaintext z value (see above)
 *  @param   R                R value for testing. If RNG is NULL then this value is read.
 *  @param   CB               Ciphertext
 *  @param   BETA             Additive share of secret (see above)
 */
void MTA_SERVER(csprng *RNG, PAILLIER_public_key *PUB, octet *B, octet *CA, octet *Z, octet *R, octet *CB, octet *BETA);

/** \brief Set the value for an accumulator from octets
 *
 * Set the accumulator to V1 * V2
 *
 * @param accum               Accumulator to be set
 * @param V1                  First factor for the value to set
 * @param V2                  Second Factor for the value to set
 */
void MTA_ACCUMULATOR_SET(BIG_256_56 accum, octet *V1, octet *V2);

/** \brief Add a value to an accumulator
 *
 * The octet value V is added to the accumulator and
 * reduced modulo the curve order
 *
 * @param accum               Accumulator. This must have a valid value
 * @param V                   Octet value to add
 */
void MTA_ACCUMULATOR_ADD(BIG_256_56 accum, octet *V);

#ifdef __cplusplus
}
#endif

#endif
