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
 * @file commitments.h
 * @brief Commitment schemes declarations
 *
 */

#ifndef COMMITMENTS_H
#define COMMITMENTS_H

#include "amcl/amcl.h"
#include "amcl/ff_2048.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define COMMITMENTS_OK   0   /** < Success */
#define COMMITMENTS_FAIL 81  /** < Invalid Commitment */

/* NM Commitment Scheme API */

/*! \brief Generate a commitment for the value X
 *
 * @param RNG   CSPRNG to use for commitment
 * @param X     Value to commit to
 * @param R     Decommitment value. If RNG is null then this value is read and must be 256 bit long
 * @param C     Commitment value
 */
extern void COMMITMENTS_NM_commit(csprng *RNG, const octet *X, octet *R, octet *C);

/*! \brief Decommit the value X
 *
 * @param X     Committed value
 * @param R     Decommitment value. Must be 256 bit long
 * @param C     Commitment value
 * @return      Returns 1 for a valid decommitment, 0 otherwise
 */
extern int COMMITMENTS_NM_decommit(const octet* X, const octet* R, octet* C);

/* Bit Commitment Setup API */

#ifndef FS_2048
#define FS_2048 MODBYTES_1024_58 * FFLEN_2048  /**< 2048 field size in bytes */
#endif
#ifndef HFS_2048
#define HFS_2048 MODBYTES_1024_58 * HFLEN_2048 /**< Half 2048 field size in bytes */
#endif

/*! \brief RSA modulus for Bit Commitment */
typedef struct
{
    BIG_1024_58 P[HFLEN_2048];      /**< Safe prime P = 2p+1 */
    BIG_1024_58 Q[HFLEN_2048];      /**< Safe prime Q = 2q+1 */
    BIG_1024_58 pq[FFLEN_2048];     /**< Precomputed product of p and q */
    BIG_1024_58 N[FFLEN_2048];      /**< Public part of the modulus */
    BIG_1024_58 alpha[FFLEN_2048];  /**< Secret exponent of the DLOG b1 = b0^alpha*/
    BIG_1024_58 ialpha[FFLEN_2048]; /**< Inverse of alpha mod pq. Secret exponent of the DLOG b0 = b1^ialpha */
    BIG_1024_58 b0[FFLEN_2048];     /**< Generator of G_pq as subgroup of Z/PQZ */
    BIG_1024_58 b1[FFLEN_2048];     /**< Generator of G_pq as subgroup of Z/PQZ */
} COMMITMENTS_BC_priv_modulus;

/*! \brief Public RSA modulus for Bit Commitment */
typedef struct
{
    BIG_1024_58 N[FFLEN_2048];      /**< Modulus */
    BIG_1024_58 b0[FFLEN_2048];     /**< Generator of G_pq as subgroup of Z/PQZ */
    BIG_1024_58 b1[FFLEN_2048];     /**< Generator of G_pq as subgroup of Z/PQZ */
} COMMITMENTS_BC_pub_modulus;

/*! \brief Set up an RSA modulus and the necessary values.
 *
 * RNG is only used to generate the values not explicitely specified.
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
extern void COMMITMENTS_BC_setup(csprng *RNG, COMMITMENTS_BC_priv_modulus *m, octet *P, octet *Q, octet *B0, octet *ALPHA);

/*! \brief Clean secret values from the modulus
 *
 * @param m     The modulus to clean
 */
extern void COMMITMENTS_BC_kill_priv_modulus(COMMITMENTS_BC_priv_modulus *m);

/*! \brief Export the public part of the modulus
 *
 * @param pub   The destination public modulus
 * @param priv  The source private modulus
 */
extern void COMMITMENTS_BC_export_public_modulus(COMMITMENTS_BC_pub_modulus *pub, COMMITMENTS_BC_priv_modulus *priv);

#ifdef __cplusplus
}
#endif

#endif
