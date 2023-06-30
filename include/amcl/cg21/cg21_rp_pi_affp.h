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


#ifndef CG21_RP_PI_AFFP_H
#define CG21_RP_PI_AFFP_H

#include "amcl/amcl.h"
#include "amcl/paillier.h"
#include "amcl/ecp_SECP256K1.h"
#include "amcl/ecdh_SECP256K1.h"
#include "cg21_utilities.h"


#ifdef __cplusplus
extern "C"
{
#endif

#define PiAffp_OK               0                        /**< Proof successfully verified */
#define PiAffp_INVALID_PROOF_P1 3130501           /**< The Proof form is invalid */
#define PiAffp_INVALID_PROOF_P2 3130502           /**< The Proof form is invalid */
#define PiAffp_INVALID_PROOF_P3 3130503           /**< The Proof form is invalid */
#define PiAffp_INVALID_PROOF_P4 3130504           /**< The Proof form is invalid */
#define PiAffp_INVALID_PROOF_P5 3130505           /**< The Proof form is invalid */
#define PiAffp_INVALID_RANGE    3130506           /**< The Proof form is invalid */
#define PiAffp_RNG_IS_NULL      3130507           /**< The Proof form is invalid */


typedef struct
{
    BIG_1024_58 alpha[HFLEN_2048];
    BIG_1024_58 beta[FFLEN_2048];
    BIG_1024_58 r[FFLEN_2048];
    BIG_1024_58 rx[2*FFLEN_2048];
    BIG_1024_58 ry[2*FFLEN_2048];
    BIG_1024_58 gamma[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 m[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 delta[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 mu[FFLEN_2048 + HFLEN_2048];
} PiAffp_SECRETS;

typedef struct
{
    BIG_1024_58 A[2 * FFLEN_2048];  /**< Commitment to h1, h2, x using rho */
    BIG_1024_58 Bx[2 * FFLEN_2048];  /**< Commitment for Paillier consistency using beta */
    BIG_1024_58 By[2 * FFLEN_2048];  /**< Commitment to h1, h2, alpha using gamma */
    BIG_1024_58 E[FFLEN_2048];
    BIG_1024_58 S[FFLEN_2048];
    BIG_1024_58 F[FFLEN_2048];
    BIG_1024_58 T[FFLEN_2048];

} PiAffp_COMMITS;

typedef struct
{
    BIG_1024_58 z1[FFLEN_2048];
    BIG_1024_58 z2[FFLEN_2048];
    BIG_1024_58 z3[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 z4[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 w[FFLEN_2048];
    BIG_1024_58 wx[FFLEN_2048];
    BIG_1024_58 wy[FFLEN_2048];
} PiAffp_PROOFS;

typedef struct
{
    octet A;
    octet Bx;
    octet By;
    octet E;
    octet S;
    octet F;
    octet T;

} PiAffp_COMMITS_OCT;

typedef struct
{
    octet z1;
    octet z2;
    octet z3;
    octet z4;
    octet w;
    octet wx;
    octet wy;
} PiAffp_PROOFS_OCT;

/** \brief Commitment Generation
 *
 *  Generate a commitment for the ZKP
 *
 *  Note: All the randoms are sampled from positive range. Sampling from both negative and positive ranges
 *  improves the efficiency and not security.
 *
 *  <ol>
 *  <li> \f$ \alpha \in_R [0, \ldots, q^3]\f$
 *  <li> \f$ \beta \in_R [0, \ldots, q^7]\f$
 *  <li> \f$ r \in_R [0, \ldots, N0]\f$
 *  <li> \f$ rx \in_R [0, \ldots, N1]\f$
 *  <li> \f$ ry \in_R [0, \ldots, N1]\f$
 *  <li> \f$ \gamma \in_R [0, \ldots, q^{3}\tilde{N}]\f$
 *  <li> \f$ \delta \in_R [0, \ldots, q^{3}\tilde{N}]\f$
 *  <li> \f$ \mu \in_R [0, \ldots, q\tilde{N}]\f$
 *  <li> \f$ \m \in_R [0, \ldots, q\tilde{N}]\f$
 *  <li> \f$ A = C^{\alpha}(1+N0)^{\beta}r^{N0} \text{ }\mathrm{pub_com}\text{ }N0^2 \f$
 *  <li> \f$ Bx = (1+N1)^{\alpha}rx^{N1} \text{ }\mathrm{pub_com}\text{ }N1^2 \f$
 *  <li> \f$ By = (1+N1)^{\beta}ry^{N1} \text{ }\mathrm{pub_com}\text{ }N1^2 \f$
 *  <li> \f$ S = s^{x}t^{m} \text{ }\mathrm{pub_com}\text{ }\tilde{N} \f$
 *  <li> \f$ E = s^{\alpha}t^{\gamma} \text{ }\mathrm{pub_com}\text{ }\tilde{N} \f$
 *  <li> \f$ F = s^{\beta}t^{\delta} \text{ }\mathrm{pub_com}\text{ }\tilde{N} \f$
 *  <li> \f$ T = s^{y}t^{\mu} \text{ }\mathrm{pub_com}\text{ }\tilde{N} \f$
 *  </ol>
 *
 *  @param RNG              csprng for random generation
 *  @param paillier_priv    Provers's Paillier private key
 *  @param paillier_pub     Verifier's Paillier public key
 *  @param pedersen_pub     Verifier's Ring Pederesen public parameters (Nt,s,t)
 *  @param x                Message to prove its ranges
 *  @param y                Message to prove its ranges
 *  @param secrets          Prover's secret randoms
 *  @param commit           Prover's commitments to his secret randoms
 *  @param commitsOct       Prover's commitments in Octet form
 *  @param C                Ciphertext given to the prover from the verifier
 */
extern int PiAffp_Sample_and_Commit(csprng *RNG, PAILLIER_private_key *paillier_priv, PAILLIER_public_key *paillier_pub,
                                     PEDERSEN_PUB *pedersen_pub, octet *x, octet *y, PiAffp_SECRETS *secrets,
                                     PiAffp_COMMITS *commit, PiAffp_COMMITS_OCT *commitsOct, octet *C);

/** \brief Dump the commitment to octets
 *
 *  @param commitsOct  Destination Octet for the commitment
 *  @param commit      Commitment to export
 */
extern void PiAffp_Commitment_toOctets_enc(PiAffp_COMMITS_OCT *commitsOct, PiAffp_COMMITS *commit);

/** \brief Read the commitments from octets
 *
 *  @param commits     Destination commitment
 *  @param commitsOct  Octet components of the proof
 */
extern void PiAffp_commits_fromOctets(PiAffp_COMMITS *commits, PiAffp_COMMITS_OCT *commitsOct);

/** \brief Deterministic RP Challenge generation
 *
 *  Generate a challenge binding together public parameters and commitment
 *
 *  <ol>
 *  <li> \f$ e = H( verifier_paillier_pub | prover_paillier_pub | verifier_pub | X | Y | C | D | commits | ID | AD | q ) \f$
 *  </ol>
 *
 *  @param puba        Verifier Paillier public key
 *  @param pubb        Prover Paillier public key
 *  @param mod         Verifier's ring Pedersen public parameters
 *  @param X           Encryption of x
 *  @param Y           Encryption of y
 *  @param C           Ciphertext generated by verifier
 *  @param D           Ciphertext generated by prover
 *  @param ssid        System-wide session-ID, refers to the same notation as in CG21
 *  @param E           Destination challenge
 */
extern void PiAffp_Challenge_gen(PAILLIER_public_key *puba, PAILLIER_public_key *pubb, PEDERSEN_PUB *mod,
                                 const octet *X, const octet *Y, const octet *C, const octet *D,
                                 PiAffp_COMMITS *affp, CG21_SSID *ssid, octet *E);

/** \brief Proof generation
 *
 *  Generate a proof for the ZKP
 *
 *  <ol>
 *  <li> \f$ z1 = \alpha + ex \f$
 *  <li> \f$ z2  = \beta + ey \f$
 *  <li> \f$ z3 = \gamma + em \f$
 *  <li> \f$ z4 = \delta + e\mu \f$
 *  <li> \f$ w = r \rho^{e} \text{ }\mathrm{mod}\text{ }N0 \f$
 *  <li> \f$ wx = r \rho_{x}^{e} \text{ }\mathrm{mod}\text{ }N1 \f$
 *  <li> \f$ wy = r \rho_{y}^{e} \text{ }\mathrm{mod}\text{ }N1 \f$
 *  </ol>
 *
 *  @param prover_paillier_pub   Paillier public keys
 *  @param verifier_paillier_pub Paillier public keys
 *  @param secrets               Random values associated to the commitment
 *  @param x                     Message to prove its range
 *  @param y                     Message to prove its range
 *  @param rho                   Random value used in D
 *  @param rho_x                 Random value used in the Paillier encryption of x
 *  @param rho_y                 Random value used in the Paillier encryption of y
 *  @param E                     Deterministic generated challenge
 *  @param proofs                Destination proofs
 *  @param proofsOct             Destination proofs in Octet
 */
extern void PiAffp_Prove(PAILLIER_public_key *prover_paillier_pub, PAILLIER_public_key *verifier_paillier_pub,
                         PiAffp_SECRETS *secrets, octet *x, octet *y, octet *rho, octet *rho_x,
                         octet *rho_y, octet *E, PiAffp_PROOFS *proofs, PiAffp_PROOFS_OCT *proofsOct);

/** \brief Dump the proofs to octets
 *
 *  @param proofsOct    Destination Octet for component of the proofs
 *  @param proofs       Proof to export
 */
extern void PiAffp_proof_toOctets(PiAffp_PROOFS_OCT *proofsOct, PiAffp_PROOFS *proofs);

/** \brief Read the proof from octets
 *
 *  @param proofs      Destination proof
 *  @param proofsOct   Octet with the proofs
 */
extern void PiAffp_proofs_fromOctets(PiAffp_PROOFS *proofs, PiAffp_PROOFS_OCT *proofsOct);

/** \brief Clean the memory containing the random values
 *
 *   @param secrets    Clean random values (alpha,beta,r,rx,ry,gamma,m,delta,mu)
 */
extern void PiAffp_Kill_secrets(PiAffp_SECRETS *secrets);

/** \brief Verify a Proof
 *  <ol>
 *  <li> \f$ z1 \stackrel{?}{\leq} q^3 \f$
 *  <li> \f$ z2 \stackrel{?}{\leq} q^7 \f$
 *  <li> \f$ A \stackrel{?}{=} C^{z1}(1+N0)^{z2}w^{N0} \text{ }\mathrm{mod}\text{ }N0^2 \f$
 *  <li> \f$ (1+N1)^{z1}w_{x}^{N1} \stackrel{?}{=} Bx X^{-e} \text{ }\mathrm{mod}\text{ }N1^2 \f$
 *  <li> \f$ (1+N1)^{z2}w_{y}^{N1} \stackrel{?}{=} By Y^{-e} \text{ }\mathrm{mod}\text{ }N1^2 \f$
 *  <li> \f$ E \stackrel{?}{=} s^{z1}t^{z3}S^{-e} \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ F \stackrel{?}{=} s^{z2}t^{z4}T^{-e} \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  </ol>
 *
 *  @param verifier_paillier_priv   Private Paillier key of the verifier
 *  @param prover_paillier_pub      Public Paillier key of the prover
 *  @param pedersen_priv            Verifier ring Pedersen private parameters
 *  @param X                        Encryption of x
 *  @param Y                        Encryption of y
 *  @param C                        Ciphertext generated by verifier
 *  @param D                        Ciphertext generated by prover
 *  @param commits                  Commitment of the prover
 *  @param E                        Generated challenge
 *  @param proofs                   Generated proofs by prover
 *  @return                         PiAffp_COM_OK if the proofs are valid, PiAffp_COM_FAIL otherwise
 */
extern int PiAffp_Verify(PAILLIER_private_key *verifier_paillier_priv, PAILLIER_public_key *prover_paillier_pub,
                         PEDERSEN_PRIV *pedersen_priv, octet *C, octet *D, octet *X, octet *Y, PiAffp_COMMITS *commits,
                         octet *E, PiAffp_PROOFS *proofs);
#ifdef __cplusplus
}
#endif

#endif