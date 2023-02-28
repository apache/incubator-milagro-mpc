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
 * @file shamir.h
 * @brief Shamir Secret Shering and Verifiable Secret Sharing declarations
 *
 */

#ifndef SHAMIR_H
#define SHAMIR_H

#include "amcl/amcl.h"
#include "amcl/big_256_56.h"
#include "amcl/ecp_SECP256K1.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define VSS_OK             0   /**< Shares verification succeded */
#define VSS_INVALID_SHARES 161 /**< Shares verification failed   */
#define VSS_INVALID_CHECKS 162 /**< Checks are not valid ECp     */

#define SGS_SECP256K1 MODBYTES_256_56  /**< Shamir Group Size */
#define SFS_SECP256K1 MODBYTES_256_56  /**< Shamir Field Size */

/** \brief Shamir Secret Shares */
typedef struct
{
    octet *X;  /**< Public component X of the share */
    octet *Y;  /**< Secret component Y = f(X) of the share */
} SSS_shares;

/**	@brief Use Shamir's secret sharing to distribute a secret modulo the SECP256K1 curve order
 *
 * @param  k      Threshold
 * @param  n      Number of shares
 * @param  RNG    Pointer to a cryptographically secure random number generator
 * @param  shares n Secret Shares (x, y) to be distributed
 * @param  S      Secret to share. It is generated if empty
 */
void SSS_make_shares(int k, int n, csprng *RNG, SSS_shares *shares, octet* S);

/**	@brief Use Shamir's secret sharing to recover secret modulo the SECP256K1 curve order
 *
 * @param  k      Threshold
 * @param  shares k Secret Shares (x, y) collected for secret recovery
 * @param  S      Recovered Secret
 */
void SSS_recover_secret(int k, SSS_shares *shares, octet* S);

/** @brief Convert a Shamir Secet share to an additive share for a (k, k) secret sharing
 *
 * @param k      Threshold
 * @param X_j    X component of the share to convert
 * @param Y_j    Y component of the share to convert
 * @param X      X components of the shares of the other participants
 * @param S      Additive share for the equivalent (k, k) additive sharing.
 */
void SSS_shamir_to_additive(int k, octet *X_j, octet *Y_j, octet *X, octet *S);

/**	@brief Use the Verifiable Secret Sharing to distribute a secret modulo the SECP256K1 curve order
 *
 * @param  k      Threshold
 * @param  n      Number of shares
 * @param  RNG    Pointer to a cryptographically secure random number generator
 * @param  shares n Secret Shares (x, y) to be distributed
 * @param  C      checks for the generated shares
 * @param  S      Secret to share. It is generated if empty
 */
void VSS_make_shares(int k, int n, csprng *RNG, SSS_shares *shares, octet *C, octet *S);

/** @brief Verify a VSS Share using the checks C
 *
 * @param k      Threshold
 * @param X_j    X component of the share to check
 * @param Y_j    Y component of the share to check
 * @param C      Checks for the shares
 * @return       VSS_OK or an error code
 */
int VSS_verify_shares(int k, octet *X_j, octet * Y_j, octet *C);

#ifdef __cplusplus
}
#endif

#endif
