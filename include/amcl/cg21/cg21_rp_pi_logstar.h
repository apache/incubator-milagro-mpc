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


#ifndef CG21_RP_PI_LOGSTAR_H
#define CG21_RP_PI_LOGSTAR_H

#include "amcl/amcl.h"
#include "amcl/paillier.h"
#include "amcl/ecp_SECP256K1.h"
#include "amcl/ecdh_SECP256K1.h"
#include "cg21_utilities.h"


#ifdef __cplusplus
extern "C"
{
#endif

#define PiLogstar_OK                    0               /**< Proof successfully verified */
#define PiLogstar_RNG_IS_NULL           3130701         /**< RNG instance is NULL */
#define PiLogstar_PAILLIER_SK_IS_NULL   3130702         /**< Paillier sk is NULL  */
#define PiLogstar_COM_PUB_IS_NULL       3130703         /**< Pedersen pub-params is NULL */
#define PiLogstar_INPUT_IS_NULL         3130704         /**< The input is NULL */
#define PiLogstar_INVALID_PROOF_P1      3130705         /**< The Proof form is invalid */
#define PiLogstar_INVALID_PROOF_P2      3130706         /**< The Proof form is invalid */
#define PiLogstar_INVALID_PROOF_P3      3130707         /**< The Proof form is invalid */
#define PiLogstar_INVALID_RANGE         3130708         /**< The Proof form is invalid */
#define Pilogstar_Y_FAIL                3130709
#define Pilogstar_Y_OK                  3130710

typedef struct
{
    /**< Proof of knowledge of x. It must be less than q^3 */
    BIG_1024_58 z1[FFLEN_2048];

    /**< Proof of knowledge of the Paillier r value */
    BIG_512_60  z2[FFLEN_4096];

    /**< Auxiliary proof of knowledge for x */
    BIG_1024_58 z3[FFLEN_2048 + HFLEN_2048];
} PiLogstar_PROOFS;

typedef struct
{
    /**< Commitment to x and mu */
    BIG_1024_58 S[FFLEN_2048];

    /**< Commitment for Paillier consistency using alpha */
    BIG_512_60  A[FFLEN_4096];

    /**< Commitment to alpha and gamma */
    BIG_1024_58 D[FFLEN_2048];
    ECP_SECP256K1  Y;
} PiLogstar_COMMITS;

typedef struct
{
    // Random value in [0, ..., q^3]
    BIG_1024_58 alpha[HFLEN_2048];

    //Random value in [0, ..., N]
    BIG_1024_58 r[FFLEN_2048];

    //Random value in [0, ..., \tilde{N}q^3]
    BIG_1024_58 gamma[FFLEN_2048 + HFLEN_2048];

    // Random value in [0, ..., \tilde{N}q]
    BIG_1024_58 mu[FFLEN_2048 + HFLEN_2048];
} PiLogstar_SECRETS;

typedef struct
{
    octet *S;
    octet *A;
    octet *D;
    octet *Y;
}  PiLogstar_COMMITS_OCT;

typedef struct
{
    octet *z1;
    octet *z2;
    octet *z3;
}  PiLogstar_PROOFS_OCT;

/** \brief Deterministic RP Challenge generation
 *
 *  Generate a challenge binding together public parameters and commitment
 *
 *  <ol>
 *  <li> \f$ e = H( N0 | \tilde{N} | s | t | K | S | A | C | ID | AD | q ) \f$
 *  </ol>
 *
 *  @param N0         Paillier modulus
 *  @param Nt         Ring Pedersen modulus
 *  @param C          Encrypted Message to PiLogstar_Prove knowledge and range
 *  @param commits    Commitment of the prover
 *  @param ssid       system-wide session-ID, refers to the same notation as in CG21
 *  @param X          xG, where G is a group generator
 *  @param E          Destination challenge
 */
extern void PiLogstar_Challenge_gen(PAILLIER_public_key *pub_key, PEDERSEN_PUB *pub_com,
                                    const octet *C, PiLogstar_COMMITS *commits, CG21_SSID *ssid,
                                    const octet *X, octet *E);

/** \brief Commitment Generation
 *
 *  Generate a commitment for the ZKP
 *
 *  Note: All the randoms are sampled from positive range. Sampling from both negative and positive ranges
 *  improves the efficiency and not security.
 *
 *  <ol>
 *  <li> \f$ \alpha \in_R [0, \ldots, q^3]\f$
 *  <li> \f$ r \in_R [0, \ldots, N0]\f$
 *  <li> \f$ \gamma \in_R [0, \ldots, q^{3}\tilde{N}]\f$
 *  <li> \f$ \mu \in_R [0, \ldots, q\tilde{N}]\f$
 *  <li> \f$ Y = \alpha \cdot G \f$
 *  <li> \f$ S = s^{x}t^{\mu} \text{ }\mathrm{pub_com}\text{ }\tilde{N} \f$
 *  <li> \f$ D = s^{\alpha}t^{\gamma} \text{ }\mathrm{pub}\text{ }\tilde{N}\f$
 *  <li> \f$ A = (1+N0)^{\alpha}r^{N0} \text{ }\mathrm{pub_com}\text{ }N0^2\f$
 *  </ol>
 *
 *  @param RNG            csprng for random generation
 *  @param priv_key       Paillier priv_key used to encrypt X
 *  @param pub_com        Public BC modulus of the verifier
 *  @param x              Value to prove its range
 *  @param g              A curve point
 *  @param secrets        Random values (alpha, mu, r, gamma)
 *  @param commits        Destination commitment (S, A, D, Y)
 *  @param commitsOct     Destination commitments in Octet form
 */
extern int PiLogstar_Sample_and_commit(csprng *RNG, PAILLIER_private_key *priv_key, PEDERSEN_PUB *pub_com,
                                       octet *x, octet *g, PiLogstar_SECRETS *secrets,
                                       PiLogstar_COMMITS *commits, PiLogstar_COMMITS_OCT *commitsOct);

/** \brief Verify a Proof
 *
 *  <ol>
 *  <li> \f$ z1 \stackrel{?}{\leq} q^3 \f$
 *  <li> \f$ g^{z1} \stackrel{?}= Y \cdot X^{e} \f$
 *  <li> \f$ D \stackrel{?}{=} s^{z1}t^{z3}S^{-e} \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ A \stackrel{?}{=} (1+N0)^{z1}z2^{N}C_oct^{-e} \text{ }\mathrm{mod}\text{ }N^2 \f$
 *  </ol>
 *
 *  @param pub_key            Public Paillier key of the prover
 *  @param priv_com           Private BC modulus of the verifier
 *  @param C_oct              Encrypted value
 *  @param g                  A curve point
 *  @param commits            Received commitment
 *  @param e                  Generated challenge
 *  @param proofs             Received proofs
 *  @return                   PiLogstar_COM_OK if the proofs is valid
 */
extern int PiLogstar_Verify(PAILLIER_public_key *pub_key, PEDERSEN_PRIV *priv_com, octet *C_oct, octet *g,
                        PiLogstar_COMMITS *commits, octet *X, octet *e_oct, PiLogstar_PROOFS *proofs);

/** \brief Dump the proofs to octets
 *
 *  @param proofs      Destination Octet for component of the proofs
 *  @param proofs      Proof to export
 */
extern void PiLogstar_proof_toOctets(PiLogstar_PROOFS_OCT *proofsOct, PiLogstar_PROOFS *proofs);

/** \brief Clean the memory containing the random values
 *
 *   @param secrets    Clean random values (alpha, mu, r, gamma)
 */
extern void PiLogstar_clean_secrets(PiLogstar_SECRETS *secrets);

/** \brief Read the proof from octets
 *
 *  @param proofs      Destination proof
 *  @param proofsOct   Octet with the proofs
 */
extern void PiLogstar_proofs_fromOctets(PiLogstar_PROOFS *proofs, const PiLogstar_PROOFS_OCT *proofsOct);

/** \brief Read the commitments from octets
 *
 *  @param commits     Destination commitment
 *  @param commitsOct  Octet components of the proof
 *  @return            Piaffg_OK if the ECP Octet BX is valid,
 */
extern int PiLogstar_commits_fromOctets(PiLogstar_COMMITS *commits, const PiLogstar_COMMITS_OCT *commitsOct);

/** \brief Dump the commitment to octets
 *
 *  @param PiLogstar_COMMITS_OCT  Destination Octet for the (S,A,C)
 *  @param commit             Commitment to export
 */
extern void PiLogstar_Commitment_toOctets_logstar(PiLogstar_COMMITS_OCT *commitsOct, PiLogstar_COMMITS *commit);

/** \brief Proof generation
 *
 *  Generate a proof for the ZKP
 *
 *  <ol>
 *  <li> \f$ z1 = \alpha + ek \f$
 *  <li> \f$ z2  = r \rho^e \text{ }\mathrm{mod}\text{ }N0 \f$
 *  <li> \f$ z3 = \gamma + e\mu \f$
 *  </ol>
 *
 *  @param priv_key    Private Paillier key of the prover
 *  @param k_oct       Message to PiLogstar_Prove knowledge and range
 *  @param rho_oct     Random value used in the Paillier encryption of k
 *  @param secrets     Random values associated to the commitment
 *  @param e_oct       (pseudo)random challenge
 *  @param proofs      Destination proof
 *  @param proofsOct   Destination proof in Octet form
 */
extern void PiLogstar_Prove(PAILLIER_private_key *priv_key, octet *k_oct, octet *rho_oct,
                        PiLogstar_SECRETS *secrets, octet *e_oct, PiLogstar_PROOFS *proofs, PiLogstar_PROOFS_OCT *proofsOct);


#ifdef __cplusplus
}
#endif

#endif