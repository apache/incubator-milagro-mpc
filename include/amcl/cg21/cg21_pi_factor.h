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



#include <amcl/amcl.h>
#include <amcl/big_512_60.h>
#include <amcl/ff_4096.h>
#include <amcl/paillier.h>
#include "cg21_utilities.h"
#include "amcl/shamir.h"
#include "amcl/modulus.h"

#define CG21_PI_FACTOR_INVALID_RANGE 3130201
#define CG21_PI_FACTOR_INVALID_PROOF 3130202
#define CG21_PI_FACTOR_MAX_N_LENGTH  (256 * 8)               /**<  Minimum bit-length of N*/




typedef struct
{
    octet *alpha;   // Random value in [0, ..., 2^{\ell+\epsilon}.(N)^{1/2}] (FFLEN_2048)
    octet *beta;    // Random value in [0, ..., 2^{\ell+\epslion}.(N)^{1/2}] (FFLEN_2048)
    octet *mu;      // Random value in [0, ..., 2^{\ell}.N] (FFLEN_2048 + HFLEN_2048)
    octet *nu;      // Random value in [0, ..., 2^{\ell}.N] (FFLEN_2048 + HFLEN_2048)
    octet *r;       // Random value in [0, ..., 2^{\ell+\epsilon}.N^2] (2*FFLEN_2048 + HFLEN_2048)
    octet *x;       // Random value in [0, ..., 2^{\ell+\epsilon}.N] (FFLEN_2048 + HFLEN_2048)
    octet *y;       // Random value in [0, ..., 2^{\ell+\epsilon}.N] (FFLEN_2048 + HFLEN_2048)
} CG21_PiFACTOR_SECRETS;

typedef struct
{
    octet *P;
    octet *Q;
    octet *A;
    octet *B;
    octet *T;
    octet *sigma;   // Random value in [0, ..., 2^{\ell}.N^2] (2*FFLEN_2048 + HFLEN_2048)

} CG21_PiFACTOR_COMMIT;

typedef struct
{
    octet *z1;
    octet *z2;
    octet *w1;
    octet *w2;
    octet *v;

} CG21_PiFACTOR_PROOF;


/**	@brief Sample randoms and generate commitments
*
*  1: choose randoms
*  2: commit to sampled randoms
*
*  Note: All the randoms are sampled from positive range. Sampling from both negative and positive ranges
*  improves the efficiency and not security.
*
*  @param RNG           a pointer to a cryptographically secure random number generator
*  @param r1priv        sampled randoms to be stored locally
*  @param r1pub         commitment to be broadcast
*  @param pub_com       Pedersen public parameters
*  @param p1            safe prime
*  @param q1            safe prime
*  @param e             challenge for sigma protocol
*  @param ssid          system-wide session-ID, refers to the same notation as in CG21
*  @param n             number of elements in packed octets of ssid
*/
extern void CG21_PI_FACTOR_COMMIT(csprng *RNG, CG21_PiFACTOR_SECRETS *r1priv, CG21_PiFACTOR_COMMIT *r1pub,
                                  PEDERSEN_PUB *pub_com, octet *p1, octet *q1, octet *e, const CG21_SSID *ssid, int n);

/**	@brief Generate proof that N's primes are larger than ~2q-bit
*
*  @param r1priv        sampled randoms to be stored locally
*  @param r1pub         commitment for sampled randoms
*  @param proof         generated range proof for the primes
*  @param p1            safe prime
*  @param q1            safe prime
*  @param e             challenge for sigma protocol
*/
extern void CG21_PI_FACTOR_PROVE(const CG21_PiFACTOR_SECRETS *r1priv, const CG21_PiFACTOR_COMMIT *r1pub, CG21_PiFACTOR_PROOF *proof,
                                 octet *p1, octet *q1, octet *e);

/**	@brief Sample randoms, generate commitments and proof that N's primes are larger than ~2q-bit
*
*  @param RNG           a pointer to a cryptographically secure random number generator
*  @param ssid          system-wide session-ID, refers to the same notation as in CG21
*  @param pub_com       Pedersen public parameters
*  @param commit         commitment to be broadcast
*  @param proof         generated range proof for the primes
*  @param p1            safe prime
*  @param q1            safe prime
*  @param pack_size     number of elements in packed octets of ssid
 *
*/
extern void CG21_PI_FACTOR_COMMIT_PROVE(csprng *RNG, const CG21_SSID *ssid, PEDERSEN_PUB *pub_com, CG21_PiFACTOR_COMMIT *commit,
                                        CG21_PiFACTOR_PROOF *proof, octet *p1, octet *q1, int pack_size);

/**	@brief Verify generated proofs for the lengths of N's primes
*
*  @param r1pub         commitment for sampled randoms
*  @param proof         generated range proof for the primes
*  @param N_oct         RSA N modulus
*  @param priv_com      Pedersen private parameters
*  @param ssid          system-wide session-ID, refers to the same notation as in CG21
*  @param n             number of elements in packed octets of ssid
*/
extern int CG21_PI_FACTOR_VERIFY(const CG21_PiFACTOR_COMMIT *r1pub, const CG21_PiFACTOR_PROOF *proof, octet *N_oct,
                                 PEDERSEN_PRIV *priv_com, const CG21_SSID *ssid, int n);