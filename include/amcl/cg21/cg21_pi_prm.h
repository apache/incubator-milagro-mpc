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
 * This code implements Pedersen parameter generation as described in https://link.springer.com/chapter/10.1007/BFb0052225
 * Note: there are two ways to generate 'b0' ('s' in cg21) based on the above paper. We implement the way which 'b0' is
 * always a generator of G_{pq} for security reasons.
 */


#include <amcl/amcl.h>
#include <amcl/big_512_60.h>
#include <amcl/ff_4096.h>
#include <amcl/paillier.h>
#include "cg21_utilities.h"
#include "amcl/shamir.h"
#include "amcl/modulus.h"

typedef struct
{
    HDLOG_iter_values rho;          /**< BIT_Commitment for the h1 DLOG ZKP */
    HDLOG_iter_values irho;         /**< BIT_Commitment for the h0 DLOG ZKP */
    HDLOG_iter_values t;            /**< Proofs for the h1 DLOG ZKP */
    HDLOG_iter_values it;           /**< Proofs for the h1 DLOG ZKP */
} CG21_PIPRM_PROOF;

typedef struct
{
    octet *rho;
    octet *irho;
    octet *t;
    octet *it;
} CG21_PIPRM_PROOF_OCT;

/**	@brief Generate ZKP for Ring-Pedersen Parameters
*
*  @param RNG       is a pointer to a cryptographically secure random number generator
*  @param priv      Ring-Pedersen private parameters
*  @param ssid      system-wide session-ID, refers to the same notation as in CG21
*  @param proofOct  ZKP in octet form
*/
extern int CG21_PI_PRM_PROVE(csprng *RNG, PEDERSEN_PRIV *priv, const CG21_SSID *ssid,
                             CG21_PIPRM_PROOF_OCT *proofOct);

/**	@brief Verify ZKP for Ring-Pedersen Parameters
*
*  @param pub       Ring-Pedersen public parameters
*  @param ssid      system-wide session-ID, refers to the same notation as in CG21
*  @param proofOct  ZKP in octet form
*  @param n         number of the players
*/
extern int CG21_PI_PRM_VERIFY(PEDERSEN_PUB *pub, const CG21_SSID *ssid, CG21_PIPRM_PROOF_OCT *proofOct, int n);