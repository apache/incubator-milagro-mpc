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
 * @file hidden_dlog.h
 * @brief Declarations for ZKPoK of a DLOG in a hidden order group
 *
 */

#ifndef HDLOG
#define HDLOG

#include "amcl/shamir.h"
#include "amcl/cg21/cg21_utilities.h"


#ifdef __cplusplus
extern "C"
{
#endif

#define HDLOG_OK                0        /**< Success */
#define HDLOG_FAIL              3130801  /**< Invalid Proof */
#define HDLOG_INVALID_VALUES    3130802  /**< Invalid encoding for the iterations values */
#define HDLOG_PROOF_ITERS       128                         /**< Iterations necessary for the Proof */
#define HDLOG_CHALLENGE_SIZE HDLOG_PROOF_ITERS / 8    /**< Length of the challenge necessary for the chosen Proof iterations */
#define HDLOG_VALUES_SIZE HDLOG_PROOF_ITERS * FS_2048 /**< Length of the values encoding */

typedef struct
{
    octet *sid;             // session ID
    octet *rid;             // xor of partial rids,                filled in KeyGen
    octet *rho;             // xor of partial rhos,                filled in Aux.
    octet *X_set_packed;   // packed set of partial ECDSA PKs,     filled in KeyGen
    octet *j_set_packed;   // players' IDs,                        filled in KeyGen
    octet *q;               // curve order,                        filled in KeyGen
    octet *g;               // curve generator,                    filled in KeyGen
    octet *N_set_packed;   // packed set of Ped. and Pail. PKs,    filled in Aux.
    octet *s_set_packed;   // packed set of Pedersen s params,     filled in Aux.
    octet *t_set_packed;   // packed set of Pedersen t params,     filled in Aux.

} HDLOG_SSID;        // system-wide unique session ID

/*! \brief Holds the values for each iteration of the protocol */
typedef BIG_1024_58 HDLOG_iter_values[HDLOG_PROOF_ITERS][FFLEN_2048];

/*! \brief Generate a commitment for the ZKPs
 *
 * @param RNG   CSPRNG
 * @param m     Private modulus (necessary to speed up computations)
 * @param ord   Order of B0
 * @param B0    Base of the DLOG
 * @param R     Random value used in the commitment. If RNG is NULL this is read
 * @param RHO   Commitment of the ZKP
 */
extern void  HDLOG_commit(csprng *RNG, MODULUS_priv *m, BIG_1024_58 *ord, BIG_1024_58 *B0, HDLOG_iter_values R, HDLOG_iter_values RHO);

/*! \brief Generate a challenge
 *
 * @param N     Public Modulus
 * @param B0    Base of the DLOG
 * @param B1    Public Value of the DLOG
 * @param RHO   Commitment of the ZKP
 * @param ID    Prover unique identifier
 * @param AD    Additional data to bind in the proof - Optional
 * @param E     Generated challenge for the ZKP
 */
extern void HDLOG_challenge(BIG_1024_58 *N, BIG_1024_58 *B0, BIG_1024_58 *B1, HDLOG_iter_values RHO, const octet *ID, const octet *AD, octet *E);

/*! \brief Generate a challenge
 *
 * @param N     Public Modulus
 * @param B0    Base of the DLOG
 * @param B1    Public Value of the DLOG
 * @param RHO   Commitment of the ZKP
 * @param ssid  System-wide session ID
 * @param E     Generated challenge for the ZKP
 * @param n     Number of the octets packed in a package
 */
extern int HDLOG_challenge_CG21(BIG_1024_58 *N, BIG_1024_58 *B0, BIG_1024_58 *B1, HDLOG_iter_values RHO, const HDLOG_SSID *ssid, octet *E, int n);

/*! \brief Prove knowledge of the DLOG
 *
 * @param ord   Order of B0
 * @param alpha Exponent of the DLOG
 * @param R     Random value used in the commitment
 * @param E     Challenge of the ZKP
 * @param T     Proof of the ZKP
 */
extern void HDLOG_prove(BIG_1024_58 *ord, BIG_1024_58 *alpha, HDLOG_iter_values R, octet *E, HDLOG_iter_values T);

/*! \brief Verify the ZKP that the modulus is well formed
 *
 * @param N     Public Modulus
 * @param B0    Base of the DLOG
 * @param B1    Public Value of the DLOG
 * @param RHO   Commitment of the ZKP
 * @param E     Challenge of the ZKP
 * @param T     Proof of the ZKP
 *
 * @return      Returns HDLOG_OK if the proof is valid or an error code
 */
extern int HDLOG_verify(BIG_1024_58 *N, BIG_1024_58 *B0, BIG_1024_58 *B1, HDLOG_iter_values RHO, const octet *E, HDLOG_iter_values T);

/*! \brief Encode v into an octet
 *
 * @param O      Destination Octet
 * @param v      Source value
 */
extern void HDLOG_iter_values_toOctet(octet *O, HDLOG_iter_values v);

/*! \brief Decode an octet into a
 *
 * @param v      Destination values
 * @param O      Source Octet
 *
 * @return       HDLOG_OK if the octet is valid or an error code
 */
extern int HDLOG_iter_values_fromOctet(HDLOG_iter_values v, octet *O);

/*! \brief Clean the values from v
 *
 * @param v      The values to clean
 */
extern void HDLOG_iter_values_kill(HDLOG_iter_values v);

#ifdef __cplusplus
}
#endif

#endif
