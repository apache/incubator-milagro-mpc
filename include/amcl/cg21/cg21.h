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
#include "amcl/shamir.h"
#include "cg21_utilities.h"
#include "amcl/modulus.h"
#include <amcl/big_256_56.h>
#include <amcl/ecp_SECP256K1.h>
#include <amcl/ecdh_SECP256K1.h>
#include <amcl/paillier.h>
#include "amcl/hash_utils.h"
#include "amcl/schnorr.h"
#include "cg21_pi_mod.h"
#include "cg21_pi_prm.h"
#include "cg21_pi_factor.h"


#define CG21_KEY_ERROR                       3130101
#define CG21_V_IS_NOT_VERIFIED               3130102
#define CG21_A_DOES_NOT_MATCH                3130103
#define CG21_SCHNORR_VERIFY_FAILED           3130104
#define CG21_Xs_ARE_NOT_EQUAL                3130106
#define CG21_WRONG_SHARE_IS_GIVEN            3130107
#define CG21_WRONG_PACKED_X_SIZE             3130108
#define CG21_UNKNOWN_SSID                    3130109
#define CG21_AUX_V_IS_NOT_VALID              3130110
#define CG21_ID_IS_INVALID                   3130111
#define CG21_RESHARE_V_IS_NOT_VALID          3130112
#define CG21_RESHARE_CHECKS_NOT_VALID        3130113
#define CG21_RESHARE_PARTIAL_PK_NOT_VALID    3130114
#define CG21_PRESIGN_PARTIAL_PK_NOT_VALID    3130115
#define CG21_PRESIGN_DELTA_NOT_VALID         3130116
#define CG21_PRESIGN_FAILED                  3130117
#define CG21_SIGN_r_IS_ZERO                  3130118
#define CG21_SIGN_SIGMA_IS_ZERO              3130119
#define CG21_SIGN_SIGNATURE_IS_INVALID       3130120
#define CG21_RESHARE_t1_IS_SMALL             3130121


#define CG21_MINIMUM_N_LENGTH  (256 * 8 - 1)               /**<  Minimum bit-length of N*/

typedef struct
{
    int *i;

} CG21_PLAYER;

typedef struct
{
    octet *A;
    octet *psi;

} CG21_PI_SCH_PROOF;

typedef struct
{
    octet *q; // curve order
    octet *g; // curve group generator
    octet *P; // players' IDs packed into one octet, 000100020003...
    octet *uid;// unique session ID

} CG21_KEYGEN_SID;


typedef struct
{
    int i;
    int t;
    int n;
    octet *x;           // ECDSA secret key
    octet *tau;         // for xi
    octet *tau2;        // for x'i
    SSS_shares shares;  // Shares for VSS

} CG21_KEYGEN_ROUND1_STORE_PRIV; //not going to be broadcast

typedef struct
{
    int i;
    CG21_KEYGEN_SID sid;
    octet *rid;
    octet *X;           // ECDSA public key
    octet *A;           // for xi
    octet *A2;          // for x'i
    octet *u;           // randomness for the computation of V
    octet *packed_checks;

} CG21_KEYGEN_ROUND1_STORE_PUB; // will be broadcast in Round 2

typedef struct
{
    int i;
    octet *V;

} CG21_KEYGEN_ROUND1_output;

typedef struct
{
    int *j;
    octet *V;
    SSS_shares shares; // Shares for VSS
    octet *checks;     // Checks for VSS

} CG21_KEYGEN_ROUND2;


typedef struct
{
    int t;
    int n;
    octet *xor_rid;
    octet *packed_share_Y;      // pack y component of received shared points VSS
    octet *packed_all_checks;   // pack all the packed checks into one octet
    SSS_shares xi;

} CG21_KEYGEN_ROUND3_STORE;

typedef struct
{
    int i;
    CG21_KEYGEN_SID sid;
    CG21_PI_SCH_PROOF ui_proof;
    CG21_PI_SCH_PROOF xi_proof;

} CG21_KEYGEN_ROUND3_OUTPUT;

typedef struct
{
    octet *X;
    octet *X_set_packed;
    octet *j_set_packed;
    octet *pk_ss_sum_pack;
    int pack_size;

} CG21_KEYGEN_OUTPUT;

typedef struct
{
    int i;
    octet *V;

} CG21_AUX_ROUND1_OUT;

typedef struct
{
    int i;
    int t;
    octet *rho;
    octet *u;
    octet *PedPub;
    octet *PaiPub;
    CG21_PIPRM_PROOF_OCT pedersenProof;

} CG21_AUX_ROUND1_STORE_PUB;

typedef struct
{
    int i;
    octet *Paillier_PRIV;
    octet *PEDERSEN_PRIV;

} CG21_AUX_ROUND1_STORE_PRIV;

typedef struct
{
    int *j;
    octet *V;
    CG21_SSID ssid;

} CG21_AUX_ROUND2;

typedef struct
{
    octet *rho;
    int i;
    int t;
    CG21_PIMOD_PROOF_OCT paillierProof;
    CG21_PiFACTOR_PROOF factorProof;
    CG21_PiFACTOR_COMMIT factorCommits;
} CG21_AUX_ROUND3;

typedef struct
{
    octet *j;     // packed j values
    octet *N;   // packed N values
    octet *s;   // packed s values
    octet *t;   // packed t values

} CG21_AUX_OUTPUT;

typedef struct
{
    octet *Xi;      // Public Key associated with the additive share
    octet *checks;  // VSS Checks
    octet *rho;     // Partial rho (rho_i)
    octet *A;
    octet *u;
    int *i;

} CG21_RESHARE_ROUND1_STORE_PUB_T1;

typedef struct
{
    octet *rho;     // Partial rho (rho_i)
    octet *A;
    octet *u;
    int *i;

} CG21_RESHARE_ROUND1_STORE_PUB_N2;

typedef struct
{
    octet *a;   // Secret additive share
    SSS_shares shares; // VSS Shares
    octet *r;

} CG21_RESHARE_ROUND1_STORE_SECRET_T1;

typedef struct
{
    octet *r;

} CG21_RESHARE_ROUND1_STORE_SECRET_N2;

typedef struct
{
    SSS_shares shares; // sum of the received shares in ROUND3
    octet *rho;
    octet *pack_all_checks; // packed of the packed vss received from all parties in T1

} CG21_RESHARE_ROUND4_STORE;

typedef struct
{
    octet *X;   // x-coord in clear
    octet *C;   // y-coord in encrypted form
    int *i;
    int *j;

} CG21_RESHARE_ROUND3_OUTPUT;

typedef struct
{
    CG21_PI_SCH_PROOF proof;
    int *i;

} CG21_RESHARE_ROUND4_OUTPUT;

typedef struct
{
    int t;
    int n;
    int myID;
    octet *rho;
    octet *rid;
    CG21_KEYGEN_OUTPUT pk;
    SSS_shares shares;

} CG21_RESHARE_OUTPUT;

typedef struct
{
    octet *V;
    int *i;

} CG21_RESHARE_ROUND1_OUT;

typedef struct
{
    int t1;
    int n1;
    int t2;
    int n2;
    int *T1;
    int *T2;
    int *N2;

} CG21_RESHARE_SETTING;

typedef struct
{
    octet *k;
    octet *gamma;
    octet *rho;
    octet *nu;
    octet *a; // additive share
    int i;

} CG21_PRESIGN_ROUND1_STORE;

typedef struct
{
    octet *psi;
    octet *G;
    octet *K;
    int i;

} CG21_PRESIGN_ROUND1_OUTPUT;

typedef struct
{
    octet *Gamma;
    octet *D;
    octet *D_hat;
    octet *F;
    octet *F_hat;
    octet *psi;
    octet *psi_hat;
    octet *psi_prime;
    int i; // my id
    int j; // his id

} CG21_PRESIGN_ROUND2_OUTPUT;

typedef struct
{
    octet *r;
    octet *r_hat;
    octet *s;
    octet *s_hat;
    octet *Gamma;
    octet *beta;
    octet *beta_hat;
    octet *neg_beta;
    octet *neg_beta_hat;
    int i; // my id
    int j; // his id

} CG21_PRESIGN_ROUND2_STORE;

typedef struct
{
    octet *delta;
    octet *Delta;
    octet *psi_douplePrime; // psi''
    int i; // my id

} CG21_PRESIGN_ROUND3_OUTPUT;

typedef struct
{
    octet *Gamma;
    octet *Delta;
    int i; // my id

} CG21_PRESIGN_ROUND3_STORE_1;

typedef struct
{
    octet *delta; // same delta in CG21_PRESIGN_ROUND3_OUTPUT
    octet *chi;
    int i; // my id

} CG21_PRESIGN_ROUND3_STORE_2;

typedef struct
{
    int PRESIGN_SUCCESS;    // 0: success , 1: failure
    int i;                  // my id

} CG21_PRESIGN_ROUND4_OUTPUT;

typedef struct
{
    octet *Delta;   // \prod Delta_j
    octet *delta;   // \sum delta_j
    int i;          // my id

} CG21_PRESIGN_ROUND4_STORE_1;

typedef struct
{
    octet *R;
    octet *chi;     // same as in round3_store
    octet *k;       // same as in round1_store
    int i;          // my id

} CG21_PRESIGN_ROUND4_STORE_2;

typedef struct
{
    octet *r;           // r component of the signature
    octet *sigma;       // s component of the signature
    int i;              // my id

} CG21_SIGN_ROUND1_STORE;

typedef struct
{
    octet *sigma;       // s component of the signature
    int i;              // my id

} CG21_SIGN_ROUND1_OUTPUT;

typedef struct
{
    octet *r;           // r component of the signature
    octet *sigma;       // sum of sigmas computed in the previous round
    int i;              // my id

} CG21_SIGN_ROUND2_OUTPUT;



#define iLEN 32

/**	@brief Compute SID
*
*  @param sid      the structure that holds elements of SID
*  @param P        ID of the players packed into one octet
*/
extern void CG21_KEY_GENERATE_GET_SID(CG21_KEYGEN_SID *sid, octet *P);

/**	@brief Choose partial ECDSA secret key and perform VSS
*
*  1: Samples a random x_i (partial secret key) and computes X_i=x_i*G (corresponding partial PK)
*  2: Chooses a random rid_i and computes (A_i, tau) and (A_i2, tau2)
*  3: Perform (t,n) Feldman-VSS of the value x_i to get shares and checks
*  4: Sample random u_i, computes V_i = H(sid, i, rid_i, X_i, A_i, u_i)
*  5: Broadcasts (sid, i, V_i)
*
*  @param RNG       is a pointer to a cryptographically secure random number generator
*  @param priv      the structure that holds data to be stored in the database
*  @param pub       the structure that holds data to be stored and broadcast in Round 2
*  @param output    the structure that holds data for the output
*  @param sid       session ID
*  @param myID      the ID of the player
*  @param n         threshold setting
*  @param t         threshold setting
*  @param P         packed ID of the players, "000100020003..."
*/
extern int CG21_KEY_GENERATE_ROUND1(csprng *RNG, CG21_KEYGEN_ROUND1_STORE_PRIV *priv,
                                    CG21_KEYGEN_ROUND1_STORE_PUB *pub,
                                    CG21_KEYGEN_ROUND1_output *output,
                                    CG21_KEYGEN_SID *sid,
                                    int myID, int n, int t, octet *P);

/**	@brief Validate V and VSS checks for the given partial shares
*
*  1: Validate the received V from Round 1
*  2: Check the partial PK received from Round1 is equal to the free term in the exponent in VSS checks
*  3: Check that given shared secrets have same x-coord
*  4: Validate the given share using VSS checks
*
*  @param r1_out        received data from the broadcasting channel in Round 1
*  @param r2_out        received data from the broadcasting channel in Round 2
*  @param myPriv        the structure that holds data computed in Round 1
*  @param r2_share      received VSS share from the other players
*  @param sid           session ID
*  @param r3            the structure that holds data to be stored in the database in Round 3
*/
extern int CG21_KEY_GENERATE_ROUND3_1(const CG21_KEYGEN_ROUND1_output *r1_out,
                                      CG21_KEYGEN_ROUND1_STORE_PUB *r2_out,
                                      const CG21_KEYGEN_ROUND1_STORE_PRIV *myPriv,
                                      const SSS_shares *r2_share,
                                      const CG21_KEYGEN_SID *sid,
                                      CG21_KEYGEN_ROUND3_STORE *r3);

/**	@brief Compute rid = \xor rid_i
*
*
*  @param pub       received data from the broadcasting channel in Round 2
*  @param r3        the structure that holds data to be stored in the database in Round 3
*  @param myrid     if true pub is generated by the player's itself, otherwise, it's received in Round 2
*/
extern int CG21_KEY_GENERATE_ROUND3_2_1(const CG21_KEYGEN_ROUND1_STORE_PUB *pub,
                                         CG21_KEYGEN_ROUND3_STORE *r3,
                                         bool myrid);

/**	@brief Compute Schnorr proof for partial secret key
*
*
*  @param myPriv    the structure that holds private data computed in Round 1
*  @param pub       the structure that holds public data computed in Round 1
*  @param r3        the structure that holds data to be stored in the database in Round 3
*  @param sid       session ID
*  @param r3Out     the structure that holds data to be broadcast in Round 3
*/
extern int CG21_KEY_GENERATE_ROUND3_2_2(const CG21_KEYGEN_ROUND1_STORE_PRIV *myPriv,
                                         const CG21_KEYGEN_ROUND1_STORE_PUB *pub,
                                         const CG21_KEYGEN_ROUND3_STORE *r3,
                                         const CG21_KEYGEN_SID *sid,
                                         CG21_KEYGEN_ROUND3_OUTPUT *r3Out);

/**	@brief Compute Schnorr proof for sum-of-the-shares
*
*  1: Compute sum-of-the-shares
*  2: Generate challenge e
*  3: Compute Schnorr proof for the knowledge of sum-of-the-shares using challenge e
*
*  @param myPriv    the structure that holds private data computed in Round 1
*  @param pub       the structure that holds public data computed in Round 1
*  @param r3        the structure that holds data to be stored in the database in Round 3
*  @param sid       session ID
*  @param r3Out     the structure that holds data to be broadcast in Round 3
*/
extern int CG21_KEY_GENERATE_ROUND3_2_3(const CG21_KEYGEN_ROUND1_STORE_PRIV *myPriv,
                                         const CG21_KEYGEN_ROUND1_STORE_PUB *pub,
                                         CG21_KEYGEN_ROUND3_STORE *r3,
                                         const CG21_KEYGEN_SID *sid,
                                         CG21_KEYGEN_ROUND3_OUTPUT *r3Out);
/**	@brief Verify Schnorr proof for partial secret key
*
*
*  @param r3Out     the structure that holds data to be broadcast in Round 3
*  @param r3        the structure that holds public data computed in Round 1
*  @param sid       session ID
*  @param r3Store   the structure that holds data to be stored in the database in Round 3
*/
extern int CG21_KEY_GENERATE_OUTPUT_1_1(const CG21_KEYGEN_ROUND3_OUTPUT *r3Out,
                                        const CG21_KEYGEN_ROUND1_STORE_PUB *r3,
                                        const CG21_KEYGEN_SID *sid,
                                        const CG21_KEYGEN_ROUND3_STORE *r3Store);

/**	@brief Verify Schnorr proof for sum-of-the-shares
*
*  1: Unpack all the VSS checks
*  2: Calculate g^{x_j}, where x_j is the sum-of-the-shares of the party j
*  3: Use calculated g^{x_j} verify Schnorr proof for sum-of-the-shares
*
*  @param output    the structure that holds the final output of the KeyGen
*  @param r3Out     the structure that holds data to be broadcast in Round 3
*  @param r3Store   the structure that holds data to be stored in the database in Round 3
*  @param myPriv    the structure that holds private data computed in Round 1
*  @param sid       session ID
*  @param r1Pub     the structure that holds public data computed in Round 1
*/
extern int CG21_KEY_GENERATE_OUTPUT_1_2(CG21_KEYGEN_OUTPUT *output,
                                        const CG21_KEYGEN_ROUND3_OUTPUT *r3Out,
                                        CG21_KEYGEN_ROUND3_STORE *r3Store,
                                        CG21_KEYGEN_ROUND1_STORE_PRIV *myPriv,
                                        const CG21_KEYGEN_SID *sid,
                                        const CG21_KEYGEN_ROUND1_STORE_PUB *r1Pub);

/**	@brief Pack partial PKs and the corresponding player's IDs
*
*
*  @param output        includes partial PKs and the corresponding IDs in packed form
*  @param X             partial PK
*  @param i             ID of the owner of given partial PK
*  @param first_entry   if true initialize output
*/
void CG21_PACK_PARTIAL_PK(CG21_KEYGEN_OUTPUT *output, octet *X, int i, bool first_entry);

/**	@brief Form set of partial PKs X = (X1, ... , Xn)
*
*
*  @param output        the structure that holds the final output of the KeyGen
*  @param r1Pub         the structure that holds public data computed in Round 1
*  @param first_entry   if true, then initialize X
*/
extern int CG21_KEY_GENERATE_OUTPUT_2(CG21_KEYGEN_OUTPUT *output,
                                       CG21_KEYGEN_ROUND1_STORE_PUB *r1Pub,
                                       bool first_entry);

/**	@brief Add all the partial PK_i to form main ECDSA PK
*
*  @param out   the structure that holds the final output of the KeyGen
*  @param n     number of players in the threshold setting
*/
extern int CG21_KEY_GENERATE_OUTPUT_3(CG21_KEYGEN_OUTPUT *out, int n);

/**	@brief Generate V as described in KeyGen:Round1
*
*  @param store     the structure that holds public data computed in Round 1
*  @param sid       the structure for session ID
*  @param V         output of the function
*/
extern void CG21_KEYGEN_ROUND1_GEN_V(const CG21_KEYGEN_ROUND1_STORE_PUB *store, const CG21_KEYGEN_SID *sid, octet *V);

/*  ------------- PHASE 2: Auxiliary Info ----------------  */

/**	@brief FORM SSID including rid, sid, partial ECDSA PKs, and players' IDs
*
*
*  @param ssid          system-wide session-ID, refers to the same notation as in CG21
*  @param rid           a random to be used in ZKP
*  @param X_packed      packed partial ECDSA PKs
*  @param j_packed      packed players' IDs
*  @param t             number of octets in each package
*/
extern void CG21_AUX_FORM_SSID(CG21_SSID *ssid, octet *rid, octet *X_packed, octet *j_packed, const int n);

/**	@brief Generate V according to CG21: KeyGen
*
*
*  @param RNG               is a pointer to a cryptographically secure random number generator
*  @param rnd1StorePub      the structure that hold public data computed in Round 1 to be broadcast in Round 3
*  @param rnd1StorePriv     the structure that hold private data computed in Round 1 to be stored locally
*  @param rnd1Out           the structure that hold output data
*  @param paillier          Paillier keys
*  @param ssid              system-wide session-ID, refers to the same notation as in CG21
*  @param pedersen          Pedersen keys
*  @param id                Player ID
*  @param n                 number of the players
*/
extern int CG21_AUX_ROUND1_GEN_V(csprng *RNG, CG21_AUX_ROUND1_STORE_PUB *rnd1StorePub,
                                 CG21_AUX_ROUND1_STORE_PRIV *rnd1StorePriv,
                                 CG21_AUX_ROUND1_OUT *rnd1Out,
                                 CG21_PAILLIER_KEYS *paillier,
                                 const CG21_SSID *ssid,
                                 CG21_PEDERSEN_KEYS *pedersen,
                                 int id, int n);

/**	@brief Validate data in given SSID
*
*
*  @param his_ssid      system-wide session-ID, refers to the same notation as in CG21
*  @param my_rid        generated in CG21: KeyGen
*  @param my_rho        generated in CG21: Key Re-Sharing
*  @param my_ssid
*  @param n             number of the players
*  @param rho           if true, validates rho in the given SSID
*/
extern int CG21_AUX_ROUND3_CHECK_SSID(CG21_SSID *his_ssid, octet *my_rid, octet *my_rho,
                                      CG21_SSID *my_ssid, int n, bool rho);

/**	@brief Validates V and N received from Round2
*
*  1: Generate V' from given data received from Round2 and compare it against given V from Round1
*  2: Check whether N >= 2^{8\kappa-1}
*
*  @param ssid          system-wide session-ID, refers to the same notation as in CG21
*  @param round1Pub     structure that hold the data that are output of the round1
*  @param round1Out     structure that hold output data
*/
extern int CG21_AUX_ROUND3_CHECK_V_N(CG21_SSID *ssid, CG21_AUX_ROUND1_STORE_PUB round1Pub,
                                     const CG21_AUX_ROUND1_OUT *round1Out);

/**	@brief XOR partial rho values
*
*  @param rn1SP     data stored at round1 to be broadcast in the next round
*  @param rnd3      output of the AUX. round3
*  @param myrho     if true, initialize xor_rho
*/
extern void CG21_AUX_ROUND3_XOR_RHO(const CG21_AUX_ROUND1_STORE_PUB *rn1SP, CG21_AUX_ROUND3 *rnd3, bool myrho);

/**	@brief Generate proof for correctness Pedersen parameters
*
*  @param RNG               pointer to a cryptographically secure random number generator
*  @param rnd1Priv          hold Paillier and Pedersen private parameters in packed form
*  @param ssid              system-wide session-ID, refers to the same notation as in CG21
*  @param rnd1StorePub      public data to be stored at round1 and broadcast at round2
*/
extern int CG21_PI_PRM_PROVE_HELPER(csprng *RNG, CG21_AUX_ROUND1_STORE_PRIV *rnd1Priv, const CG21_SSID *ssid,
                                    CG21_AUX_ROUND1_STORE_PUB *rnd1StorePub);

/**	@brief Generate proof for correctness of Paillier
*
*  @param RNG               pointer to a cryptographically secure random number generator
*  @param rnd1Priv          hold Paillier and Pedersen private parameters in packed form
*  @param ssid              system-wide session-ID, refers to the same notation as in CG21
*  @param rnd3              output of round3
*/
extern int CG21_PI_MOD_PROVE_HELPER(csprng *RNG, CG21_AUX_ROUND1_STORE_PRIV *rnd1Priv, const CG21_SSID *ssid,
                                        CG21_AUX_ROUND3 *rnd3);

/**	@brief Generate proof for correctness of Paillier
*
*  @param rnd1Pub           hold Paillier and Pedersen public parameters in packed form
*  @param ssid              system-wide session-ID, refers to the same notation as in CG21
*  @param rnd3              output of round3
*/
extern int CG21_PI_MOD_VERIFY_HELPER(CG21_AUX_ROUND1_STORE_PUB *rnd1Pub, const CG21_SSID *ssid,
                                        CG21_AUX_ROUND3 *rnd3);

/**	@brief Generate proof for correctness of Pedersen parameters
*
*  @param rnd1Pub           hold Paillier and Pedersen public parameters in packed form
*  @param ssid              system-wide session-ID, refers to the same notation as in CG21
*/
extern int CG21_PI_PRM_VERIFY_HELPER(CG21_AUX_ROUND1_STORE_PUB *rnd1Pub, const CG21_SSID *ssid);

/**	@brief Generate proof for correctness of Paillier and Pedersen parameters
*
*  @param RNG               pointer to a cryptographically secure random number generator
*  @param ssid              system-wide session-ID, refers to the same notation as in CG21
*  @param rnd1Pub           hold Paillier and Pedersen public parameters in packed form
*  @param rnd4pub           hold Pi-factor proof to be broadcast
*  @param rnd1Priv          hold Paillier and Pedersen private parameters in packed form
*/
int CG21_PI_FACTOR_PROVE_HELPER(csprng *RNG, const CG21_SSID *ssid, CG21_AUX_ROUND1_STORE_PUB *rnd1Pub,
                                CG21_AUX_ROUND3 *rnd4pub, CG21_AUX_ROUND1_STORE_PRIV *rnd1Priv);


/**	@brief Generate proof for correctness of Paillier and Pedersen parameters
*
*  @param ssid              system-wide session-ID, refers to the same notation as in CG21
*  @param rnd4pub           hold Pi-factor proof to be broadcast
*  @param rnd1Pub           hold Paillier and Pedersen public parameters in packed form
*  @param rnd1Priv          hold Paillier and Pedersen private parameters in packed form
*/
int CG21_PI_FACTOR_VERIFY_HELPER(const CG21_SSID *ssid, CG21_AUX_ROUND3 *rnd4pub, CG21_AUX_ROUND1_STORE_PUB *rnd1Pub,
                                 CG21_AUX_ROUND1_STORE_PRIV *rnd1Priv);

/**	@brief Pack players' Pedersen parameters and IDs
*   Note: Paillier and Pedersen share the same N
*
*  @param output            output
*  @param rnd1Pub           public data stored in round1
*  @param first_entry       if true: initialize output
*/
extern void CG21_AUX_PACK_OUTPUT(CG21_AUX_OUTPUT *output, CG21_AUX_ROUND1_STORE_PUB rnd1Pub, bool first_entry);

/*  ------------- PHASE 2: KEY REFRESH ----------------  */

/**	@brief Received threshold setting data for key re-sharing and form a structure
*
*  @param out           final structure that holds threshold setting
*  @param t1            t component before key re-sharing
*  @param n1            n component before key re-sharing
*  @param t2            t component after key re-sharing
*  @param n2            n component after key re-sharing
*  @param old_t_IDs     IDs of t1 players
*  @param new_n_IDs     IDs of n2 players
*/
extern void CG21_KEY_RESHARE_GET_RESHARE_SETTING(CG21_RESHARE_SETTING *out, int t1, int n1, int t2, int n2,
                                                 int *old_t_IDs, int *new_n_IDs);

/**	@brief t1 players that are in T1 perform the following operations:
*
*  1: convert their sum-of-the-shares to additive shares
*  2: apply VSS on their additive shares and pack the checks
*  3: sample random numbers
*  4: compute V
*  5: broadcast (ssid, i, V)
*
*  @param RNG           pointer to a cryptographically secure random number generator
*  @param ssid          system-wide session-ID, refers to the same notation as in CG21
*  @param ID            ID of the player
*  @param setting       holds (t1,n1), (t2,n2), and (T2, N2)
*  @param myShare       SSS point
*  @param storeSecret   secret data to be stored and used in the next round
*  @param storePub      public data stored to be used or broadcast in the next round
*  @param pubOut        output to be broadcast in this round
*/
extern int CG21_KEY_RESHARE_ROUND1_T1(csprng *RNG, const CG21_SSID *ssid, int ID, CG21_RESHARE_SETTING setting,
                                      const SSS_shares *myShare, CG21_RESHARE_ROUND1_STORE_SECRET_T1 *storeSecret,
                                      CG21_RESHARE_ROUND1_STORE_PUB_T1 *storePub, CG21_RESHARE_ROUND1_OUT *pubOut);

/**	@brief the set of players in N2-T1 perform the following operations:
*
*  1: sample random numbers
*  2: compute V
*  3: broadcast (ssid, i, V)
*
*  @param RNG           pointer to a cryptographically secure random number generator
*  @param ssid          system-wide session-ID, refers to the same notation as in CG21
*  @param ID            ID of the player
*  @param setting       holds (t1,n1), (t2,n2), and (T2, N2)
*  @param storeSecret   secret data to be stored and used in the next round
*  @param storePub      public data stored to be used or broadcast in the next round
*  @param pubOut        output to be broadcast in this round
*/
extern int CG21_KEY_RESHARE_ROUND1_N2(csprng *RNG, const CG21_SSID *ssid, int ID, CG21_RESHARE_SETTING setting,
                                      CG21_RESHARE_ROUND1_STORE_SECRET_N2 *storeSecret, CG21_RESHARE_ROUND1_STORE_PUB_N2 *storePub,
                                      CG21_RESHARE_ROUND1_OUT *pubOut);

/**	@brief compute V' based on data received in round2 and compare it against V received in round1
*
*
*  @param ssid          system-wide session-ID, refers to the same notation as in CG21
*  @param setting       holds (t1,n1), (t2,n2), and (T2, N2)
*  @param ReceiveR3     public data received in round2 from the other players
*  @param ReceiveR2     output of the round1 received from the other players
*/
extern int CG21_KEY_RESHARE_ROUND3_CHECK_V_T1(const CG21_SSID *ssid,
                                              CG21_RESHARE_SETTING setting,
                                              const CG21_RESHARE_ROUND1_STORE_PUB_T1 *ReceiveR3,
                                              CG21_RESHARE_ROUND1_OUT *ReceiveR2);

/**	@brief compute V' based on data received in round2 and compare it against V received in round1
*
*
*  @param ssid          system-wide session-ID, refers to the same notation as in CG21
*  @param setting       holds (t1,n1), (t2,n2), and (T2, N2)
*  @param ReceiveR3     public data received in round2 from the other players
*  @param ReceiveR2     output of the round1 received from the other players
*/
extern int CG21_KEY_RESHARE_ROUND3_CHECK_V_N2(const CG21_SSID *ssid,
                                              CG21_RESHARE_SETTING setting,
                                              const CG21_RESHARE_ROUND1_STORE_PUB_N2 *ReceiveR3,
                                              CG21_RESHARE_ROUND1_OUT *ReceiveR2);

/**	@brief each user in N2 that receives a message from T1:
*
* 1: unpack the checks from the other player
* 2: check the first check matches the received X component of the share point
* 3: checked X component of the received point to match the receivers' ID
* 4: validate the VSS checks
* 5: validate received partial PK based on VSS checks from keygen
* 6: check sum of the partial PKs matches the PK from keygen
*
*  @param setting               holds (t1,n1), (t2,n2), and (T2, N2)
*  @param ReceiveR3             given inputs from the other players in round3
*  @param myR3_T1               shared output with the other players in round2
*  @param SS_R3                 given ecdsa SSS point from the other players in round3
*  @param myX                   X component of SSS point
*  @param PK                    ecdsa final PK generated in KeyGen
*  @param X                     variable to temporary sum the partial PKs
*  @param pack_pk_sum_shares    sum-of-the-shares packed in one octet in KeyGen
*  @param r3Store               parameters to be stored in db at the end of round3
*  @param Xstatus               0: first call, 1:neither first call, nor last call,
*                               2:last call, 3:first and last call (t=2)
*/
extern int CG21_KEY_RESHARE_CHECK_VSS_T1(CG21_RESHARE_SETTING setting, CG21_RESHARE_ROUND1_STORE_PUB_T1 *ReceiveR3,
                                         const CG21_RESHARE_ROUND1_STORE_PUB_T1 *myR3_T1, const SSS_shares *SS_R3,
                                         octet *myX, octet *PK, octet *X, octet *pack_pk_sum_shares,
                                         CG21_RESHARE_ROUND4_STORE *r3Store, int Xstatus);

/**	@brief Encrypt ECDSA shares using receivers' Paillier PKs
*
*
*  @param RNG           pointer to a cryptographically secure random number generator
*  @param pk            Paillier PK
*  @param hisID         ID of the receiver
*  @param storeSecret   secret data to be stored and used in the next round
*  @param storePub      shared output with the other players in round2
*  @param output        output of the function
*/
extern void CG21_KEY_RESHARE_ENCRYPT_SHARES(csprng *RNG, PAILLIER_public_key *pk, int hisID,
                                            CG21_RESHARE_ROUND1_STORE_SECRET_T1 *storeSecret,
                                            CG21_RESHARE_ROUND1_STORE_PUB_T1 storePub,
                                            CG21_RESHARE_ROUND3_OUTPUT *output);

/**	@brief Encrypt ECDSA shares using receivers' Paillier PKs
*
*
*  @param sk            Paillier private key
*  @param r3output      output of the round3
*  @param share         decryption result
*/
extern void CG21_KEY_RESHARE_DECRYPT_SHARES(PAILLIER_private_key *sk,
                                            CG21_RESHARE_ROUND3_OUTPUT *r3output,
                                            SSS_shares *share);


/**	@brief each user in N2 that receives a message from N2-T1:
*
* 1: unpack the checks from the other player
* 2: check the first check matches the received X component of the share point
* 3: checked X component of the received point to match the receivers' ID
* 4: validate the VSS checks
* 5: validate received partial PK based on VSS checks from keygen
* 6: check sum of the partial PKs matches the PK from keygen
*
*  @param setting               holds (t1,n1), (t2,n2), and (T2, N2)
*  @param ReceiveR3             given inputs from the other players in round3
*  @param SS_R3                 given ecdsa SSS point from the other players in round3
*  @param myX                   X component of SSS point
*  @param PK                    ecdsa final PK generated in KeyGen
*  @param X                     variable to temporary sum the partial PKs
*  @param pack_pk_sum_shares    sum-of-the-shares packed in one octet in KeyGen
*  @param r3Store               parameters to be stored in db at the end of round3
*  @param Xstatus               0: first call, 1:neither first call, nor last call,
*                               2:last call, 3:first and last call (t=2)
*/
extern int CG21_KEY_RESHARE_CHECK_VSS_N2(CG21_RESHARE_SETTING setting, CG21_RESHARE_ROUND1_STORE_PUB_T1 *ReceiveR3,
                                         const SSS_shares *SS_R3, const octet *myX, const octet *PK, octet *X, octet *pack_pk_sum_shares,
                                         CG21_RESHARE_ROUND4_STORE *r3Store, int Xstatus);

/**	@brief Sum the received SSS shares
*
*
*  @param share     given SSS share
*  @param r3Store   structure to store the sum-of-the-shares
*  @param first     true: initialize variable for sum-of-the-shares in r3Store
*/
extern void CG21_KEY_RESHARE_SUM_SHARES(const SSS_shares *share, CG21_RESHARE_ROUND4_STORE *r3Store, bool first);

/**	@brief Compute proof of knowledge for sum-of-the-shares
*
*  1: compute sum-of-the-shares*G
*  2: compute challenge
*  3: compute ZK proof
*
*  @param output        output of the round3
*  @param secretT1      secrets stored in round1
*  @param pubT1         public parameters stored in round1
*  @param r3Store       parameters to be stored at the end of round3
*  @param ssid          system-wide session-ID, refers to the same notation as in CG21
*  @param rho           xor-ed rho value used in sigma protocols for challenge generation
*  @param myID
*  @param n             number of players in KeyGen, n1
*/
extern int CG21_KEY_RESHARE_PROVE_T1(CG21_RESHARE_ROUND4_OUTPUT *output, const CG21_RESHARE_ROUND1_STORE_SECRET_T1 *secretT1,
                                     const CG21_RESHARE_ROUND1_STORE_PUB_T1 *pubT1, CG21_RESHARE_ROUND4_STORE *r3Store, CG21_SSID *ssid,
                                     octet *rho, int myID, int n);

/**	@brief Compute proof of knowledge for sum-of-the-shares
*
*  1: compute sum-of-the-shares*G
*  2: compute challenge
*  3: compute ZK proof
*
*  @param output        output of the round3
*  @param secretT1      secrets stored in round1
*  @param pubT1         public parameters stored in round1
*  @param r3Store       parameters to be stored at the end of round3
*  @param ssid          system-wide session-ID, refers to the same notation as in CG21
*  @param rho           xor-ed rho value used in sigma protocols for challenge generation
*  @param myID
*  @param n             number of players in KeyGen, n1
*/
extern int CG21_KEY_RESHARE_PROVE_N2(CG21_RESHARE_ROUND4_OUTPUT *output, const CG21_RESHARE_ROUND1_STORE_SECRET_N2 *secretN2,
                                     const CG21_RESHARE_ROUND1_STORE_PUB_N2 *pubN2, CG21_RESHARE_ROUND4_STORE *r3Store, CG21_SSID *ssid,
                                     octet *rho, int myID, int n);

/**	@brief Verify the zero knowledge proof on sum-of-the-shares of users in
*
*  1: computes sum-of-shares*G of the other players based on VSS checks
*  2: verify the proof
*
*  @param input         proof from the other players generated in round3
*  @param pubT1         data received from other parties in round3
*  @param setting       holds (t1,n1), (t2,n2), and (T2, N2)
*  @param r3Store       data that is generated and stored in round3
*  @param ssid          system-wide session-ID, refers to the same notation as in CG21
*  @param hisID
 *
*/
extern int CG21_KEY_RESHARE_VERIFY_T1(const CG21_RESHARE_ROUND4_OUTPUT *input, const CG21_RESHARE_ROUND1_STORE_PUB_T1 *pubT1,
                                      CG21_RESHARE_SETTING setting, CG21_RESHARE_ROUND4_STORE *r3Store,
                                      CG21_SSID *ssid, int hisID);

/**	@brief Verify the zero knowledge proof on sum-of-the-shares
*
*  1: computes sum-of-shares*G of the other players based on VSS checks
*  2: verify the proof
*
*  @param input         proof from the other players generated in round3
*  @param pubN2         data received from other parties in round3
*  @param setting       holds (t1,n1), (t2,n2), and (T2, N2)
*  @param r3Store       data that is generated and stored in round3
*  @param ssid          system-wide session-ID, refers to the same notation as in CG21
*  @param hisID
 *
*/
extern int CG21_KEY_RESHARE_VERIFY_N2(const CG21_RESHARE_ROUND4_OUTPUT *input, const CG21_RESHARE_ROUND1_STORE_PUB_N2 *pubN2,
                                      CG21_RESHARE_SETTING setting, CG21_RESHARE_ROUND4_STORE *r3Store,
                                      CG21_SSID *ssid, int hisID);

/**	@brief Form the output of key re-sharing protocol
*
*  @param output        output structure of key re-sharing
*  @param r3Store       data that is generated and stored in round3
*  @param r3Receive     data received from parties in T in round3
*  @param PK            new ECDSA PK
*  @param setting       holds (t1,n1), (t2,n2), and (T2, N2)
*  @param rid           a random to be used in ZKPs
*  @param j             id of the player
*  @param first         if it's the first call of this function -> true
*/
extern void CG21_KEY_RESHARE_OUTPUT(CG21_RESHARE_OUTPUT *output, const CG21_RESHARE_ROUND4_STORE *r3Store,
                                    const CG21_RESHARE_ROUND1_STORE_PUB_T1 *r3Receive, octet *PK,
                                    CG21_RESHARE_SETTING setting, octet *rid, int j, bool first);

/*  ------------- PHASE 3: PRE-SIGN ----------------  */

/**	@brief Validate partial ECDSA PKs against full PK
*
*  @param reshareOutput       final outout of key re-sharing protocol
*/
extern int CG21_VALIDATE_PARTIAL_PKS(CG21_RESHARE_OUTPUT *reshareOutput);

/**	@brief From SSID
*
*
*  @param ssid                  system-wide session-ID, refers to the same notation as in CG21
*  @param reshareOutput         output of key re-sharing protocol
*  @param n1                    number of octets in key re-sharing packages
*  @param n2                    number of octets in Aux. packages
*  @param auxOutput             output of Aux. information protocol
*/
extern void CG21_PRESIGN_GET_SSID(CG21_SSID *ssid, const CG21_RESHARE_OUTPUT *reshareOutput,
                                  int n1, int n2, const CG21_AUX_OUTPUT *auxOutput);

/**	@brief Compute the operations in Round 1 as follows:
*
*  1: choosing randoms k, gamma, rho, nu
*  2: compute G and K
*  3: convert sum-of-the-shares to additive shares
*
*  @param RNG               pointer to a cryptographically secure random number generator
*  @param reshareOutput     data stored in the db at the end of key resharing protocol
*  @param setting           holds (t1,n1), (t2,n2), and (T2, N2)
*  @param output            data to be broadcast in round 1
*  @param store             data to be stored in db in round 1
*  @param keys              Paillier public key
*/
extern int CG21_PRESIGN_ROUND1(csprng *RNG, const CG21_RESHARE_OUTPUT *reshareOutput,
                                CG21_RESHARE_SETTING *setting, CG21_PRESIGN_ROUND1_OUTPUT *output,
                                CG21_PRESIGN_ROUND1_STORE *store, PAILLIER_public_key *keys);

/**	@brief Operations in CG21:Round2 as follows:
*
*  1: compute Gamma = gamma*G
*  2: choosing randoms beta and beta_hat
*  3: choosing randoms r, r_hat, s, s_hat
*  4: compute F=Enc(Beta, r) and F_hat=Enc(Beta_hat, r_hat)
*  5: compute D=Enc(K.gamma + H) and D_hat=Enc(K.a + H_hat)
*
*  @param RNG           pointer to a cryptographically secure random number generator
*  @param r2output      data to be broadcast in round 2
*  @param r2store       data to be stored in db in round 2
*  @param r1output      output of round 1
*  @param r1store       data that are stored in round 1
*  @param hisPK         Paillier PK
*  @param myPK          Paillier PK
*/
extern int CG21_PRESIGN_ROUND2(csprng *RNG, CG21_PRESIGN_ROUND2_OUTPUT *r2output, CG21_PRESIGN_ROUND2_STORE *r2store,
                               const CG21_PRESIGN_ROUND1_OUTPUT *r1output, const CG21_PRESIGN_ROUND1_STORE *r1store,
                               PAILLIER_public_key *hisPK, PAILLIER_public_key *myPK);

/**	@brief Compute Gamma and Delta in CG21:Round3 as follows:
*
*  1: compute Gamma = \prod Gamma_j
*  2: compute Delta = Gamma^{k}
*
*  @param r2hisOutput   data that are broadcast in round 2
*  @param r3Store       public data to be stored in db in round 3
*  @param r2Store       data stored in db in round 2
*  @param r1Store       data stored in db in round 1
*  @param status        whether it is the first call or the last call of this function
*/
extern int CG21_PRESIGN_ROUND3_2_1(const CG21_PRESIGN_ROUND2_OUTPUT *r2hisOutput, CG21_PRESIGN_ROUND3_STORE_1 *r3Store,
                                   const CG21_PRESIGN_ROUND2_STORE *r2Store, const CG21_PRESIGN_ROUND1_STORE *r1Store, int status);

/**	@brief Operations in CG21:Round3 as follows:
*
*  1: compute alpha = Decryption(D)
*  2: compute alpha_hat = Decryption(D_hat)
*  3: compute delta = gamma*k + \sum{alpha + beta}
*  4: compute chi = a*k + \sum{alpha_hat + beta_hat}
*
*  @param r2hisOutput   data that are broadcast in round 2
*  @param r3Output      data to be broadcast in round 3
*  @param r3Store1      public data to be stored in db in round 3
*  @param r3Store2      private data to be stored in db in round 3
*  @param r1Store       data stored in db in round 1
*  @param myKeys        Paillier private key
*  @param r2Store       data stored in db in round 2
*  @param status        whether it is the first call or the last call of this function
*/
extern int CG21_PRESIGN_ROUND3_2_2(const CG21_PRESIGN_ROUND2_OUTPUT *r2hisOutput,
                                   CG21_PRESIGN_ROUND3_OUTPUT *r3Output,
                                   const CG21_PRESIGN_ROUND3_STORE_1 *r3Store1,
                                   CG21_PRESIGN_ROUND3_STORE_2 *r3Store2,
                                   const CG21_PRESIGN_ROUND1_STORE *r1Store,
                                   PAILLIER_private_key *myKeys,
                                   const CG21_PRESIGN_ROUND2_STORE *r2Store,
                                   int status);

/**	@brief Operations in CG21:round4 (output) as follows:
*
*  1: compute delta=\sum delta_i
*  2: compute Delta=\prod Delta_j
*  3: check g^\delta == \prod \Delta_j
*
*  @param r3hisOutput       data received from other players in round 3
*  @param r3myOutput        data that are generated and broadcast in round 3
*  @param r4Store           data to be stored in db in round 4
*  @param status            whether it is the first call or the last call of this function
*/
extern int CG21_PRESIGN_OUTPUT_2_1(const CG21_PRESIGN_ROUND3_OUTPUT *r3hisOutput,
                                   const CG21_PRESIGN_ROUND3_OUTPUT *r3myOutput,
                                   CG21_PRESIGN_ROUND4_STORE_1 *r4Store,
                                   int status);

/**	@brief Compute R = Gamma ^ {delta^{-1}} in CG21:round4 (output)
*
*  @param r1Store       data stored in db in round 1
*  @param r3Store1      data stored in db in round 3
*  @param r3Store2      data stored in db in round 3
*  @param r4Store1      data stored in db in round 4 step 1
*  @param r4Store2      data to be stored in db once round 4 ends
*  @param r4Output      publish SUCCESS if no problem is discovered
*/
extern int CG21_PRESIGN_OUTPUT_2_2(const CG21_PRESIGN_ROUND1_STORE *r1Store,
                                   const CG21_PRESIGN_ROUND3_STORE_1 *r3Store1,
                                   const CG21_PRESIGN_ROUND3_STORE_2 *r3Store2,
                                   const CG21_PRESIGN_ROUND4_STORE_1 *r4Store1,
                                   CG21_PRESIGN_ROUND4_STORE_2 *r4Store2,
                                   CG21_PRESIGN_ROUND4_OUTPUT *r4Output);


/*  ------------- PHASE 4: SIGN ----------------  */

/**	@brief Compute sigma_i = k_i*m + r*\chi_i mod q
*
*  @param msg       message to be signed
*  @param pre       generated data in presign
*  @param store     data to be stored in db in round 1
*  @param out       data to be broadcast once round 1 ends
*/
extern int CG21_SIGN_ROUND1(octet *msg,
                            const CG21_PRESIGN_ROUND4_STORE_2 *pre,
                            CG21_SIGN_ROUND1_STORE *store,
                            CG21_SIGN_ROUND1_OUTPUT *out);

/**	@brief Compute sigma = \sum sigma_j
*
*  @param mystore       data stored in db in round 1
*  @param hisout        data generated by another player in round 1
*  @param out           data generated as output of round 2
*  @param status        whether it is the first call or the last call of this function
*/
extern int CG21_SIGN_ROUND2(const CG21_SIGN_ROUND1_STORE *mystore,
                            const CG21_SIGN_ROUND1_OUTPUT *hisout,
                            CG21_SIGN_ROUND2_OUTPUT *out,
                            int status);

/**	@brief Validate a generated signature for message msg using PK
*
*  @param msg       messaged that is signed
*  @param out       (r, sigma): components of a signature
*  @param PK        ECDSA PK
*/
extern int CG21_SIGN_VALIDATE(const octet *msg,
                              CG21_SIGN_ROUND2_OUTPUT *out,
                              octet *PK);

