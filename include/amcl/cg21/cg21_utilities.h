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

#ifndef CG21_RP_COMMON_H
#define CG21_RP_COMMON_H

#define CG21_OK                             0           /**< Execution Successful */
#define CG21_UTILITIES_WRONG_PACKED_SIZE    3130301
#define CG21_PAILLIER_PROVE_FAIL            3130302     /**< Invalid proof */
#define CG21_PAILLIER_PROOF_INVALID         3130303     /**< Invalid proof bounds */
#define CG21_PAILLIER_N_IS_EVEN             3130304     /**< Paillier PK shouldn't be an even number */
#define CG21_PAILLIER_INVALID_N_LENGTH      3130305     /**< Paillier PK is smaller than 2^{8\kappa} */
#define CG21_INVALID_ECP                    3130306
#define CG21_PI_PRM_INVALID_PROOF           3130307     /**< The Proof of well formednes is invalid */
#define CG21_PI_PRM_INVALID_FORMAT          3130308     /**< An octet value has an invalid format */

#define CG21_PAILLIER_PROOF_SIZE  CG21_PAILLIER_PROOF_ITERS * FS_2048 /**< Length of components of the Proof in bytes */
#define CG21_PAILLIER_PROOF_ITERS           80                        /**< Iterations necessary for the Proof of Paillier N */

#include "amcl/amcl.h"
#include "amcl/modulus.h"
#include "amcl/hidden_dlog.h"
#include "amcl/ecp_SECP256K1.h"
#include "amcl/ecdh_SECP256K1.h"
#include "amcl/hash_utils.h"
#include "amcl/paillier.h"
#include "amcl/shamir.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*! \brief Private Ring Pedersen Parameters */
typedef struct
{
    MODULUS_priv mod;               /**< Modulus N=PQ, P=2p+1, Q=2q+1 */
    BIG_1024_58 pq[FFLEN_2048];     /**< Precomputed product of p and q */
    BIG_1024_58 alpha[FFLEN_2048];  /**< Secret exponent of the DLOG b1 */
    BIG_1024_58 ialpha[FFLEN_2048]; /**< Inverse of alpha mod pq. */
    BIG_1024_58 b0[FFLEN_2048];     /**< Generator  of Z/PQZ */
    BIG_1024_58 b1[FFLEN_2048];     /**< Generator  of Z/PQZ */
} PEDERSEN_PRIV;

/*! \brief Public Ring Pedersen Parameters */
typedef struct
{
    BIG_1024_58 N[FFLEN_2048];      /**< Modulus */
    BIG_1024_58 b0[FFLEN_2048];     /**< Generator of Z/PQZ */
    BIG_1024_58 b1[FFLEN_2048];     /**< Generator of Z/PQZ */
} PEDERSEN_PUB;

typedef struct
{
    octet *uid;             // session ID
    octet *rid;             // xor of partial rids,                filled in KeyGen
    octet *rho;             // xor of partial rhos,                filled in Aux.
    octet *X_set_packed;   // packed set of partial ECDSA PKs,     filled in KeyGen
    octet *j_set_packed;   // players' IDs,                        filled in KeyGen
    int   *n1;               // number of octets in key re-sharing packages
    octet *q;               // curve order,                        filled in KeyGen
    octet *g;               // curve generator,                    filled in KeyGen
    octet *N_set_packed;   // packed set of Ped. and Pail. PKs,    filled in Aux.
    octet *s_set_packed;   // packed set of Pedersen s params,     filled in Aux.
    octet *t_set_packed;   // packed set of Pedersen t params,     filled in Aux.
    octet *j_set_packed2;  // packed set of Pedersen t params,    filled in Aux.
    int   *n2;                // number of octets in key Aux. packages
} CG21_SSID;        // system-wide unique session ID

typedef struct
{
    PAILLIER_private_key paillier_sk;
    PAILLIER_public_key paillier_pk;

} CG21_PAILLIER_KEYS;

typedef struct
{
    PEDERSEN_PRIV pedersenPriv;
    PEDERSEN_PUB pedersenPub;

} CG21_PEDERSEN_KEYS;

/*
 * Find random element of order p in Z/PZ
 * Assuming P = 2p + 1 is a safe prime, i.e. phi(P) = 2p
 */
void BC_find_generator(csprng *RNG, BIG_1024_58* x, BIG_1024_58 *P, int n);

/*
 * Generate a safe prime P, such that P = 2 * p + 1
 * n is the size of P in BIGs
 */
extern void safe_prime_gen (csprng *RNG, BIG_1024_58 *p, BIG_1024_58 *P, int n);

/** \brief Pack Pedersen private parameters into one octet
 *
 *   @param priv    input:  Pedersen private parameters
 *   @param oct     output: packed octet
 */
extern void CG21_PedersenPriv_to_octet(PEDERSEN_PRIV *priv, octet *oct);

/** \brief Pack Pedersen public parameters into one octet
 *
 *   @param pub    input:  Pedersen public parameters
 *   @param oct    output: packed octet
 */
extern void CG21_PedersenPub_to_octet(PEDERSEN_PUB *pub, octet *oct);

/** \brief Recover Pedersen private parameters from octet
 *
 *   @param priv    output: Pedersen private parameters
 *   @param oct     input:  packed octet
 */
extern int CG21_PedersenPriv_from_octet(PEDERSEN_PRIV *priv, octet *oct);

/** \brief Recover Pedersen public parameters from octet
 *
 *   @param pub    output: Pedersen public parameters
 *   @param oct     input:  packed octet
 */
extern int CG21_PedersenPub_from_octet(PEDERSEN_PUB *pub, octet *oct);

/** \brief Pack Paillier private parameters into one octet
 *
 *   @param priv    input:  Paillier private parameters
 *   @param oct     output: packed octet
 */
extern void CG21_PaillierPriv_to_octet(PAILLIER_private_key *priv, octet *oct);

/** \brief Pack Paillier public parameters into one octet
 *
 *   @param pub    input:  Paillier public parameters
 *   @param oct     output: packed octet
 */
extern void CG21_PaillierPub_to_octet(PAILLIER_public_key *pub, octet *oct);

/** \brief Recover Paillier private parameters from octet
 *
 *   @param priv    output: Paillier private parameters
 *   @param oct     input:  packed octet
 */
extern int CG21_PaillierKeys_from_octet(CG21_PAILLIER_KEYS *priv, octet *oct);

/** \brief Recover Paillier public parameters from octet
 *
 *   @param pub     output: Paillier public parameters
 *   @param oct     input:  packed octet
 */
extern int CG21_PaillierPub_from_octet(PAILLIER_public_key *pub, octet *oct);

/** \brief Feed the ZKP base parameters into a sha instance
 *
 *   @param sha        Destination sha instance
 *   @param pub_key    Paillier Public Key used for encryption
 *   @param pub_com    Bit Commitment modulus used for the ZKP
 */
extern void CG21_hash_pubKey_pubCom(hash256 *sha, PAILLIER_public_key *pub_key, PEDERSEN_PUB *pub_com);


/** \brief Feed the ZKP base parameters into a sha instance
 *
 *   @param sha        Destination sha instance
 *   @param pub_keya   Paillier Public Key used for encryption
 *   @param pub_keyb   Paillier Public Key used for encryption
 *   @param pub_com    Bit Commitment modulus used for the ZKP
 */
extern void CG21_hash_pubKey2x_pubCom(hash256 *sha, PAILLIER_public_key *pub_keya, PAILLIER_public_key *pub_keyb, PEDERSEN_PUB *pub_com);


/*! \brief Set up an RSA modulus and the necessary values for the BC.
 *
 * Generates an RSA modulus PQ using Safe Primes P = 2p+1 and Q=2q+1
 * It then computes a generator b0 of G_pq as subgroup of Z/PQZ and
 * an exponent alpha coprime with phi(pq) and uses it to compute a
 * second generator b1 = b0^alpha of G_pq
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
 */
extern void ring_Pedersen_setup(csprng *RNG, PEDERSEN_PRIV *m, octet *P, octet *Q);

/*! \brief Export the public part of the modulus
 *
 * @param pub   The destination public modulus
 * @param priv  The source private modulus
 */
extern void Pedersen_get_public_param(PEDERSEN_PUB *pub, PEDERSEN_PRIV *priv);

/*! \brief Clean up Pedersen private parameters
 *
 * @param priv  Pedersen private parameters
 */
extern void CG21_Pedersen_Private_Kill( PEDERSEN_PRIV *priv);


/*! \brief Asymmetric mul
 *
 * Efficiently compute product by breaking up y in k chunks of length xlen
 * and computing the product separately. r must be different from x and y and
 * it must have length at least rlen = xlen + ylen
 * Assuming xlen * k = ylen for some integer k
 *
 * @param r     FF instance, on exit = x*y
 * @param x     FF instance
 * @param xlen  size of x in BIGs
 * @param y     FF instance
 * @param ylen  size of y in BIGs
 */
extern void CG21_FF_2048_amul(BIG_1024_58 *r, BIG_1024_58 *x, int xlen, BIG_1024_58 *y, int ylen);

/*! \brief Asymmetric mod
 *
 * Starting from the top of x, select the top 2 * plen BIGs and reduce
 * them mod p, reducing the length of x by a plen until x is completely
 * reduced.
 * Assuming plen * k = xlen for some integer k
 *
 * @param r     FF instance, on exit = x mod p
 * @param x     FF instance
 * @param xlen  size of x in BIGs
 * @param p     FF instance
 * @param plen  size of p in BIGs
 */
extern void CG21_FF_2048_amod(BIG_1024_58 *r, BIG_1024_58 *x, int xlen, BIG_1024_58 *p, int plen);

/*! \brief computes s^z1 * t^z3 * S^(-e) mod p
 *
 *
 * @param proof         on exit = s^z1 * t^z3 * S^(-e) mod p
 * @param st            Pedersen private parameters
 * @param z1            a component of proof
 * @param z3            a component of proof
 * @param S             a component of commitment
 * @param e             generated challenge
 * @param p             modulus
 * @param reduce_s1     if 1, then reduce z1
 */
extern void CG21_Pedersen_verify(BIG_1024_58 *proof, PEDERSEN_PRIV *st, BIG_1024_58 *z1,
                                 BIG_1024_58 *z3, BIG_1024_58 *S, BIG_1024_58 *e, BIG_1024_58 *p, bool reduce_s1);

/**	@brief Initialize an array of octets
*
*
*  @param mem       octet: val
*  @param OCTETS    output
*  @param max       octet: max
*  @param n         length of array
*/
extern void init_octets(char* mem, octet *OCTETS, int max, int n);

/**	@brief Convert concatenated values into an array
*   e.g. 0001000200040005 into (0001,0002,0004,0005)
*
*  @param temp      concatenated values
*  @param arr       output array
*  @param n         number of the values
*/
extern void hex_to_array(const char *temp, int *arr, int n);

/**	@brief Convert a packed set of octet and their indices into unpacked form and sort the indices
*
*  1: Unpack set_packed into X
*  2: Unpack j_packed and generate indices that reflect the sorted j_packed
*
*  @param X             array of octets as a result of unpacking set_packed
*  @param set_packed    set of octets packed into one octet
*  @param j_packed      corresponding id of each individual octet in set_packed
*  @param n             number of octet packed in set_packed and j_packed
*  @param size          size of each individual octet
*  @param indices       sorted indices, e.g. (0003000100050002) -> (1,3,0,2)
*/
extern int CG21_unpack_and_sort(octet *X, octet *set_packed, const octet *j_packed, int n, int size, int *indices);

/**	@brief Unpack an octet into array of octets and hash them
*
*  @param sha           instance of hash256
*  @param X_packed      packed set of octets
*  @param j_packed      packed set of indices for X_packed
*  @param n             number of octets in X_packed
*  @param m             size of octets in X_packed
*/
extern int CG21_hash_set_X(hash256 *sha, octet *X_packed, octet *j_packed, int n, int m);

/**	@brief Unpack a set of octets and their indices and check whether they are equal
*
*  @param set_packed1   first packed set of octets
*  @param j_packed1     indices for first packed set
*  @param set_packed2   second packed set of octets
*  @param j_packed2     indices for second packed set
*  @param n             number of octets in the packed sets
*  @param size          size of each individual octet
*/
extern int CG21_set_comp(octet *set_packed1, octet *j_packed1, octet *set_packed2, octet *j_packed2, int n, int size);

/**	@brief Get curve group generator
*
*  @param g       curve group generator
*/
extern void CG21_get_G(octet *g);

/**	@brief Get curve order in octet form
*
*  @param q       curve order
*/
extern void CG21_get_q(octet *q);

/**	@brief Add two curve points
*
*  1: convert first point from octet to ECP
*  2: convert second point from octet to ECP
*  3: add two points and convert the result to octet
*
*  @param O       first octet and result of addition on exit
*  @param P       second octet
*/
extern int CG21_ADD_TWO_PK(octet *O, const octet *P);

/**	@brief Pack VSS checks into one octet
*
*
*  @param checks    VSS checks
*  @param t         number of VSS checks
*  @param out       output
*/
extern void CG21_pack_vss_checks(const octet *checks, int t, octet *out);

/**	@brief Unpack a set of octets in packed form
*
*
*  @param checks    packed octets
*  @param t         number of octets
*  @param out       array of octets on exit
*  @param size      size of each individual octet
*/
extern int CG21_unpack(octet *checks, int t, octet *out, int size);

/**	@brief Unpack checks from a packed set of packed VSS checks
*
*  1: unpack packed set of packed VSS checks
*  2: unpack each packed VSS checks
*
*  @param checks    packed of packed set of VSS checks
*  @param t1        size of set
*  @param t2        number of VSS checks
*  @param out       array of checks, where |array|= t1*t2
*/
extern int CG21_double_unpack(octet *checks, int t1, int t2, octet *out);

/**	@brief Sort hex number in char form
*   e.g. (0003000100050002) -> (1,3,0,2)
*
*  @param temp      concatenated hex values
*  @param indices   indices that reflect sorted number
*  @param n         number of hex values
*/
extern void sort_indices(const char *temp, int *indices, int n);

/*! \brief Get CURVE_Order_SECP256K1 in BIG_1024_58 instead of BIG_256_58
 *
 * @param q   on exit = CURVE_Order_SECP256K1
 */
extern void CG21_GET_CURVE_ORDER(BIG_1024_58 *q);

/**	@brief Multiplies an ECP instance P by a BIG, side-channel resistant
 *
 *  ECP_SECP256K1_mul in crypto-c accepts e in form of BIG_256_56
 * Uses Montgomery ladder for Montgomery curves
 *
 *
 * @param P     ECP instance, on exit =e*P
 * @param e     BIG number multiplier
 */
void ECP_mul_1024(ECP_SECP256K1 *P,BIG_1024_58 e[HFLEN_2048]);

/* convert array of ints in T into array octets */
extern void CG21_lagrange_index_to_octet(int t, const int *T, int myID, octet *out);

extern void CG21_lagrange_calc_coeff(int k, const octet *X_j, const octet *X, BIG_256_56 *out);

/*  computes g^{\sigma_i} as described in GG20, p.:11 */
extern int CG21_CALC_XI(int t, const octet *i, const octet *checks, ECP_SECP256K1 *V);

/**	@brief  Calculate jacobi Symbol (a/p) - not constant time
 *
	@param a BIG number
	@param p BIG number
	@return Jacobi symbol, -1,0 or 1
 */
extern int FF_4096_jacobi(BIG_512_60 a[HFLEN_4096], BIG_512_60 p[HFLEN_4096]);

/**	@brief Tonelli–Shanks algorithm to check sqrt exist
*
*  @param a         non-zero value to check it has a sqrt
*  @param p         a prime
*  @return          true if sqrt exis; otherwise, false
*/
extern bool CG21_check_sqrt_exist(BIG_1024_58 a[FFLEN_2048], BIG_1024_58 p[HFLEN_2048]);

/* Set r=sqrt(a) mod p */
extern void CG21_sqrt(BIG_1024_58 r[FFLEN_2048], BIG_1024_58 a[FFLEN_2048], BIG_1024_58 p[HFLEN_2048]);


/**	@brief Unpack an octet into array of octets and hash them
*
*  @param sha       instance of hash256
*  @param ssid      packed set of octets
*/
extern int CG21_hash_SSID(CG21_SSID *ssid, hash256 *sha);

/**	@brief takes an integer number as input and return its bit-length
*
*  @param number    input integer
*/
extern int CG21_calculateBitLength(int number);

#ifdef __cplusplus
}
#endif

#endif