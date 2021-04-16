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
 * @file gg20_zkp.h
 * @brief Gennaro 2020 - Schnorr-like proofs declarations
 *
 */

#ifndef GG20_ZKP_H
#define GG20_ZKP_H

#include "amcl/amcl.h"
#include "amcl/big_256_56.h"
#include "amcl/ecp_SECP256K1.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Field size is assumed to be greater than or equal to group size */

#define GGS_SECP256K1 MODBYTES_256_56  /**< ECP Group Size */
#define GFS_SECP256K1 MODBYTES_256_56  /**< ECP Field Size */

#define GG20_ZKP_OK           0    /**< Valid proof */
#define GG20_ZKP_FAIL	        141  /**< Invalid proof */
#define GG20_ZKP_INVALID_ECP  142  /**< Not a valid point on the curve */

/* Structs for the GG20 ZKPs */

/*! \brief Random values for both Phase 3 and Phase 6 ZKP commitment */
typedef struct
{
    BIG_256_56 a;      /**< Randomness for the G commitment */
    BIG_256_56 b;      /**< Randomness for the H commitment */
} GG20_ZKP_rv;

/*! \brief Proof for both Phase 3 and Phase 6 */
typedef struct
{
    BIG_256_56 t;      /**< Proof for the s component */
    BIG_256_56 u;      /**< Proof for the l component */
} GG20_ZKP_proof;

/*! \brief Commitment for the Phase 6 ZKP */
typedef struct
{
    ECP_SECP256K1 ALPHA;      /**< Commitment for the additional DLOG proof */
    ECP_SECP256K1 BETA;       /**< Commitment for the base double DLOG proof*/
} GG20_ZKP_phase6_commitment;

/* ROM for SECP256K1 alternative generator */

/*! \brief Read the alternative generator for the proof from ROM
 *
 * Alternative generator of unknown DLOG w.r.t. the standard generator
 * for SECP256K1.
 *
 * @param G      Destination ECP
 */
extern void GG20_ZKP_generator_2(ECP_SECP256K1 *G);

/* Octet functions */

/*! \brief Import a Proof values from octets
 *
 * @param p      Destination Proof
 * @param T      Octet with the t value of the proof. GGS_SECP256K1 long
 * @param U      Octet with the u value of the proof. GGS_SECP256K1 long
 */
extern void GG20_ZKP_proof_fromOctets(GG20_ZKP_proof *p, octet *T, octet *U);

/*! \brief Exprot a Proof to octets
 *
 * @param T      Destination octet for the t value of the proof. GGS_SECP256K1 long
 * @param U      Destination octet for the u value of the proof. GGS_SECP256K1 long
 * @param p      Proof to export
 */
extern void GG20_ZKP_proof_toOctets(octet *T, octet *U, GG20_ZKP_proof *p);

/*! \brief Import a Phase 6 Commitment from octets
 *
 * @param c      Destination Commitment
 * @param ALPHA  Octet with the alpha value of the commtiment. 1 + GFS_SECP256K1 long
 * @param BETA   Octet with the beta value of the commtiment. 1 + GFS_SECP256K1 long
 * @return       GG20_ZKP_OK if ALPHA and BETA are valid ECPs, GG20_ZKP_INVALID_ECP otherwise
 */
extern int GG20_ZKP_phase6_commitment_fromOctets(GG20_ZKP_phase6_commitment *c, octet *ALPHA, octet *BETA);

/*! \brief Export a Phase 6 Commitment to octets
 *
 * @param ALPHA  Destination octet for the alpha value of the commtiment. 1 + GFS_SECP256K1 long
 * @param BETA   Destination octet for the beta value of the commtiment. 1 + GFS_SECP256K1 long
 * @param c      Destination Commitment
 */
extern void GG20_ZKP_phase6_commitment_toOctets(octet *ALPHA, octet *BETA, GG20_ZKP_phase6_commitment *c);

/* Cleanup functions */

/*! \brief Clean the random values for a GG20 ZKP
 *
 * @param r     Random values to clean
 */
extern void GG20_ZKP_rv_kill(GG20_ZKP_rv *r);

/* Phase 3 ZKP API */

/*! \brief Generate a commitment for the proof
 *
 * @param RNG   CSPRNG to use for commitment
 * @param r     Secret values used for the commitment. If RNG is NULL this is read
 * @param C     Public commitment value. An ECP in compressed form
 */
extern void GG20_ZKP_phase3_commit(csprng *RNG, GG20_ZKP_rv *r, octet *C);

/*! \brief Generate the challenge for the proof
 *
 * Compute the challenge for the proof.
 * The challenge is inspired by RFC8235#section-3.3, with the needed tweak to
 * also bind the secondary generator H
 * Returns H(G, H, C, V, ID[, AD])
 *
 * @param V     Public ECP result of the DLOG. V = s.G + l.H. Compressed form
 * @param C     Public commitment value. Compressed form
 * @param ID    Prover unique identifier
 * @param AD    Additional data to bind in the challenge - Optional
 * @param E     Challenge generated
 */
extern void GG20_ZKP_phase3_challenge(const octet *V, const octet *C, const octet* ID, const octet *AD, octet *E);

/*! \brief Generate the proof for the given commitment and challenge
 *
 * @param r     Random values used in the commitment
 * @param E     Pseudorandom challenge
 * @param S     Secret exponent of the double DLOG. V = s.G + l.H
 * @param L     Secret exponent of the double DLOG. V = s.G + l.H
 * @param p     Proof for the ZKP
 */
extern void GG20_ZKP_phase3_prove(GG20_ZKP_rv *r, const octet *E, const octet *S, const octet *L, GG20_ZKP_proof *p);

/*! \brief Verify the proof of knowledge for the DLOG
 *
 * @param V     Public ECP of the DLOG. V = s.G + l.H. Compressed form
 * @param C     Commitment value received from the prover
 * @param E     Pseudorandom challenge
 * @param p     Proof for the ZKP
 * @return      GG20_ZKP_OK if the prove is valid or an error code
 */
extern int GG20_ZKP_phase3_verify(octet *V, octet *C, const octet *E, GG20_ZKP_proof *p);

/* Phase 6 ZKP API */

/*! \brief Generate a commitment for the proof
 *
 * @param RNG   CSPRNG to use for commitment
 * @param R     DLOG Base for additional consistency Proof
 * @param r     Random values for the commitment. If RNG is NULL this is read
 * @param c     Public commitment value
 * @return      GG20_ZKP_INVALID_ECP if R is not a valid ECP, GG20_ZKP_OK otherwise
 */
extern int GG20_ZKP_phase6_commit(csprng *RNG, octet *R, GG20_ZKP_rv *r, GG20_ZKP_phase6_commitment *c);

/*! \brief Generate the challenge for the proof
 *
 * Compute the challenge for the proof.
 * The challenge is inspired by RFC8235#section-3.3, with the needed tweak to
 * also bind the secondary generator H and the base point R, as well as the
 * additional commitment value BETA.
 *
 * Returns H(G, H, R, ALPHA, BETA, T, S, ID[, AD])
 *
 * @param R     Base of the additional DLOG S = s.R. Compressed form
 * @param T     Public ECP result of the additional DLOG S = s.R. Compressed form
 * @param S     Public ECP result of the DLOG V = s.G + l.H. Compressed form
 * @param c     Public commitment values
 * @param ID    Prover unique identifier
 * @param AD    Additional data to bind in the challenge - Optional
 * @param E     Challenge generated
 */
void GG20_ZKP_phase6_challenge(const octet *R, const octet *T, const octet *S, GG20_ZKP_phase6_commitment *c, const octet *ID, const octet *AD, octet *E);

/*! \brief Generate the proof for the given commitment and challenge
 *
 * @param r     Random values used in the commitment
 * @param E     Pseudorandom challenge
 * @param S     Secret exponent of the double DLOG. T = s.G + l.H
 * @param L     Secret exponent of the double DLOG. T = s.G + l.H
 * @param p     Proof for the ZKP
 */
extern void GG20_ZKP_phase6_prove(GG20_ZKP_rv *r, const octet *E, const octet *S, const octet *L, GG20_ZKP_proof *p);

/*! \brief Verify the proof of knowledge for the DLOG
 *
 * @param R     Base of the additional DLOG S = s.R. Compressed form
 * @param T     Public ECP result of the DLOG T = s.G + l.H. Compressed form
 * @param S     Public ECP result of the additional DLOG S = s.R. Compressed form
 * @param c     Received Phase6 commitment
 * @param E     Pseudorandom challenge
 * @param p     Received Phase6 proof
 * @return      GG20_ZKP_OK if the prove is valid or an error code
 */
int GG20_ZKP_phase6_verify(octet *R, octet *T, octet *S, GG20_ZKP_phase6_commitment *c, const octet *E, GG20_ZKP_proof *p);

#ifdef __cplusplus
}
#endif

#endif
