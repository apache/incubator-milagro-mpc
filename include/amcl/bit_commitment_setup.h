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
 * @file bit_commitment_setup.h
 * @brief Commitment schemes declarations
 *
 */

#ifndef BIT_COMMITMENT_SETUP_H
#define BIT_COMMITMENT_SETUP_H

#include "amcl/amcl.h"
#include "amcl/modulus.h"
#include "amcl/hidden_dlog.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define BIT_COMMITMENT_OK   0              /**< Success */
#define BIT_COMMITMENT_FAIL 121            /**< Invalid Commitment */
#define BIT_COMMITMENT_INVALID_PROOF 122   /**< The Proof of well formednes is invalid */
#define BIT_COMMITMENT_INVALID_FORMAT 123  /**< An octet value has an invalid format */


/* Bit Commitment Setup API */

/*! \brief Private values and modulus for Bit Commitment */
typedef struct
{
    MODULUS_priv mod;               /**< Modulus N=PQ, P=2p+1, Q=2q+1 */
    BIG_1024_58 pq[FFLEN_2048];     /**< Precomputed product of p and q */
    BIG_1024_58 alpha[FFLEN_2048];  /**< Secret exponent of the DLOG b1 = b0^alpha*/
    BIG_1024_58 ialpha[FFLEN_2048]; /**< Inverse of alpha mod pq. Secret exponent of the DLOG b0 = b1^ialpha */
    BIG_1024_58 b0[FFLEN_2048];     /**< Generator of G_pq as subgroup of Z/PQZ */
    BIG_1024_58 b1[FFLEN_2048];     /**< Generator of G_pq as subgroup of Z/PQZ */
} BIT_COMMITMENT_priv;

/*! \brief Public values and modulus for Bit Commitment */
typedef struct
{
    BIG_1024_58 N[FFLEN_2048];      /**< Modulus */
    BIG_1024_58 b0[FFLEN_2048];     /**< Generator of G_pq as subgroup of Z/PQZ */
    BIG_1024_58 b1[FFLEN_2048];     /**< Generator of G_pq as subgroup of Z/PQZ */
} BIT_COMMITMENT_pub;

/*! \brief Set up an RSA modulus and the necessary values for the BC.
 *
 * Generates an RSA modulus PQ using Safe Primes P = 2p+1 and Q=2q+1
 * It then computes a generator b0 of G_pq as subgroup of Z/PQZ and
 * an exponent alpha coprime with phi(pq) and uses it to compute a
 * second generator b1 = b0^alpha of G_pq
 *
 * RNG is only used to generate the values not explicitly specified.
 * This allows using safe primes P and Q generated externally while
 * still randomly generating B0 and ALPHA. In turn, this allows the
 * user to generate P and Q with ad hoc libraries for the generation of
 * primes instead of the (slow) safe prime generation utility included
 * here.
 *
 * @param RNG   CSPRNG to generate P, Q, B0 and ALPHA
 * @param m     Private modulus to populate
 * @param P     Safe prime 2p+1. Generated if NULL
 * @param Q     Safe prime 2q+1. Generated if NULL
 * @param B0    Generator of G_pq as subgroup of Z/PQZ. Generated if NULL
 * @param ALPHA DLOG exponent for B1 = B0^ALPHA. Generated if NULL
 */
extern void BIT_COMMITMENT_setup(csprng *RNG, BIT_COMMITMENT_priv *m, octet *P, octet *Q, octet *B0, octet *ALPHA);

/*! \brief Import a modulus from octets
 *
 * @param m     The destination modulus
 * @param P     The first factor of the modulus
 * @param Q     The second factor of the modulus
 * @param B0    Generator of the subgroup for the Bit Commitment
 * @param ALPHA Secret exponent use to compute the second generator
 */
extern void BIT_COMMITMENT_priv_fromOctets(BIT_COMMITMENT_priv *m, octet *P, octet *Q, octet *B0, octet * ALPHA);

/*! \brief Export a modulus to octets
 *
 * @param P     The first factor of the modulus
 * @param Q     The second factor of the modulus
 * @param B0    Generator of the subgroup for the Bit Commitment
 * @param ALPHA Secret exponent use to compute the second generator
 * @param m     The source modulus
 */
extern void BIT_COMMITMENT_priv_toOctets(octet *P, octet *Q, octet *B0, octet * ALPHA, BIT_COMMITMENT_priv *m);

/*! \brief Clean secret values from the modulus
 *
 * @param m     The modulus to clean
 */
extern void BIT_COMMITMENT_priv_kill(BIT_COMMITMENT_priv *m);

/*! \brief Export the public part of the modulus
 *
 * @param pub   The destination public modulus
 * @param priv  The source private modulus
 */
extern void BIT_COMMITMENT_priv_to_pub(BIT_COMMITMENT_pub *pub, BIT_COMMITMENT_priv *priv);

/*! \brief Import a modulus from octets
 *
 * @param m     The destination modulus
 * @param N     The public modulus
 * @param B0    First generator of the subgroup for the Bit Commitment
 * @param B1    Second generator of the subgroup for the Bit Commitment
 */
extern void BIT_COMMITMENT_pub_fromOctets(BIT_COMMITMENT_pub *m, octet *N, octet *B0, octet *B1);

/*! \brief Export a modulus to octets
 *
 * @param N     The public modulus
 * @param B0    First generator of the subgroup for the Bit Commitment
 * @param B1    Second generator of the subgroup for the Bit Commitment
 * @param m     The source modulus
 */
extern void BIT_COMMITMENT_pub_toOctets(octet *N, octet *B0, octet *B1, BIT_COMMITMENT_pub *m);


/* Bit Commitment Setup ZKP of well formedness API */

/*! \brief Proof of well-fromedness of the Bit Setup parameters */
typedef struct
{
    HDLOG_iter_values rho;          /**< BIT_Commitment for the h1 DLOG ZKP */
    HDLOG_iter_values irho;         /**< BIT_Commitment for the h0 DLOG ZKP */
    HDLOG_iter_values t;            /**< Proofs for the h1 DLOG ZKP */
    HDLOG_iter_values it;           /**< Proofs for the h1 DLOG ZKP */
} BIT_COMMITMENT_setup_proof;

/*! \brief Prove the well formedness of a Bit Commitment setup
 *
 * @param RNG   Cryptographically secure PRNG
 * @param m     Bit Commitment modulus
 * @param p     Destination proof of well formedness. If RNG is NULL, then rho and irho are used as r and ir in the commitment
 * @param ID    Prover unique identifier
 * @param AD    Additional data to bind in the proof - Optional
 */
extern void BIT_COMMITMENT_setup_prove(csprng *RNG, BIT_COMMITMENT_priv *m, BIT_COMMITMENT_setup_proof *p, octet *ID, octet *AD);

/*! \brief Verify the well formedness of a Bit Commitment setup
 *
 * @param m     Bit Commitment modulus
 * @param p     Proof of well formedness
 * @param ID    Prover unique identifier
 * @param AD    Additional data to bind in the proof - Optional
 *
 * @return      BIT_COMMITMENT_OK if the proof is valid or an error code
 */
extern int BIT_COMMITMENT_setup_verify(BIT_COMMITMENT_pub *m, BIT_COMMITMENT_setup_proof *p, octet *ID, octet *AD);

/*! \brief Import a proof of well formedness from octets
 *
 * @param p     The destination proof
 * @param RHO   Commitment for the ZKPoK of DLOG of B1
 * @param IRHO  Commitment for the ZKPoK of DLOG of B0
 * @param T     Proof for the ZKPoK of DLOG of B1
 * @param IT    Proof for the ZKPoK of DLOG of B0
 *
 * @return      BIT_COMMITMENT_OK or an error code
 */
extern int BIT_COMMITMENT_setup_proof_fromOctets(BIT_COMMITMENT_setup_proof *p, octet *RHO, octet *IRHO, octet *T, octet *IT);

/*! \brief Export a modulus to octets
 *
 * @param RHO   Commitment for the ZKPoK of DLOG of B1
 * @param IRHO  Commitment for the ZKPoK of DLOG of B0
 * @param T     Proof for the ZKPoK of DLOG of B1
 * @param IT    Proof for the ZKPoK of DLOG of B0
 * @param p     The source proof
 */
extern void BIT_COMMITMENT_setup_proof_toOctets(octet *RHO, octet *IRHO, octet *T, octet *IT, BIT_COMMITMENT_setup_proof *p);

#ifdef __cplusplus
}
#endif

#endif
