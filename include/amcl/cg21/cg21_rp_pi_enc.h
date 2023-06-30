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


#ifndef CG21_RP_PI_ENC_H
#define CG21_RP_PI_ENC_H

#include "amcl/amcl.h"
#include "amcl/paillier.h"
#include "amcl/ecp_SECP256K1.h"
#include "amcl/ecdh_SECP256K1.h"
#include "cg21_utilities.h"


#ifdef __cplusplus
extern "C"
{
#endif

#define PiEnc_OK                    0                   /**< Proof successfully verified */
#define PiEnc_RNG_IS_NULL           3130601             /**< RNG instance is NULL */
#define PiEnc_PAILLIER_SK_IS_NULL   3130602             /**< Paillier sk is NULL  */
#define PiEnc_COM_PUB_IS_NULL       3130603             /**< Pedersen pub-params are not provided */
#define PiEnc_INPUT_IS_NULL         3130604             /**< The input is NULL */
#define PiEnc_INVALID_PROOF_P1      3130605             /**< The Proof form is invalid */
#define PiEnc_INVALID_PROOF_P2      3130606             /**< The Proof form is invalid */
#define PiEnc_INVALID_RANGE         3130607             /**< The Proof form is invalid */

typedef struct
{
    BIG_1024_58 z1[FFLEN_2048];               /**< Proof of knowledge of x */
    BIG_512_60  z2[FFLEN_4096];           /**< ZKP of the Paillier r value */
    BIG_1024_58 z3[FFLEN_2048 + HFLEN_2048];  /**< ZKP of x */
} PiEnc_PROOFS;

typedef struct
{
    /**< Commitment to h1, h2, x using rho */
    BIG_1024_58 S[FFLEN_2048];

    /**< Commitment for Paillier consistency using beta */
    BIG_512_60  A[FFLEN_4096];

    /**< Commitment to h1, h2, alpha using gamma */
    BIG_1024_58 C[FFLEN_2048];

} PiEnc_COMMITS;

typedef struct
{
    /**< Random value in \f$ [0, \ldots, q^3]          \f$ */
    BIG_1024_58 alpha[FFLEN_2048];

    /**< Random value in \f$ [0, \ldots, N] \f$ */
    BIG_1024_58 r[FFLEN_2048];

    /**< Random value in \f$ [0, \ldots, \tilde{N}q^3] \f$ */
    BIG_1024_58 gamma[FFLEN_2048 + HFLEN_2048];

    /**< Random value in \f$ [0, \ldots, \tilde{N}q]   \f$ */
    BIG_1024_58 mu[FFLEN_2048 + HFLEN_2048];
} PiEnc_SECRETS;

typedef struct
{
    octet *S;
    octet *A;
    octet *C;
}  PiEnc_COMMITS_OCT;

typedef struct
{
    octet *z1;
    octet *z2;
    octet *z3;
}  PiEnc_PROOFS_OCT;

/** \brief Deterministic RP Challenge generation
 *
 *  Generate a challenge binding together public parameters and commitment
 *
 *  <ol>
 *  <li> \f$ e = H( N0 | \tilde{N} | s | t | K | S | A | C | ID | AD | q ) \f$
 *  </ol>
 *
 *  @param N0         Public Paillier key of the prover
 *  @param Nt         Public BC modulus of the verifier
 *  @param K          Encrypted Message to PiEnc_Prove knowledge and range
 *  @param secrets    Commitment of the prover
 *  @param ssid       system-wide session-ID, refers to the same notation as in CG21
 *  @param E          Destination challenge
 */
extern void PiEnc_Challenge_gen(PAILLIER_public_key *pub_key, PEDERSEN_PUB *pub_com, const octet *K,
                                PiEnc_COMMITS *secrets, CG21_SSID *ssid, octet *E);

/** \brief Commitment Generation
 *
 *  Generate a commitment for the ZKP
 *  Note: All the randoms are sampled from positive range. Sampling from both negative and positive ranges
 *  improves the efficiency and not security.
 *
 *  <ol>
 *  <li> \f$ \alpha \in_R [0, \ldots, q^3]\f$
 *  <li> \f$ r \in_R [0, \ldots, N0]\f$
 *  <li> \f$ \gamma \in_R [0, \ldots, q^{3}\tilde{N}]\f$
 *  <li> \f$ \mu \in_R [0, \ldots, q\tilde{N}]\f$
 *  <li> \f$ S = s^{k}t^{\mu}    \text{ }\mathrm{pub_com}\text{ }\tilde{N}\f$
 *  <li> \f$ C = s^{\alpha}t^{\gamma} \text{ }\mathrm{pub}\text{ }\tilde{N}\f$
 *  <li> \f$ A = (1+N0)^{\alpha}r^{N0} \text{ }\mathrm{pub}\text{ }N0^2 \f$
 *  </ol>
 *
 *  @param RNG            csprng for random generation
 *  @param priv_key       Paillier priv_key used to encrypt X
 *  @param pub_com        Public BC modulus of the verifier
 *  @param k              Value to prove its range
 *  @param secrets        Random values (alpha, mu, r, gamma)
 *  @param commits        Destination commitment (S, A, C)
 *  @param commitsOct     Destination commitments in Octet form
 */
extern int PiEnc_Sample_randoms_and_commit(csprng *RNG, PAILLIER_private_key *priv_key, PEDERSEN_PUB *pub_com, octet *k,
                                           PiEnc_SECRETS *secrets, PiEnc_COMMITS *commits, PiEnc_COMMITS_OCT *commitsOct);

/** \brief Verify a Proof
 *
 *  <ol>
 *  <li> \f$ z1 \stackrel{?}{\leq} q^3 \f$
 *  <li> \f$ C \stackrel{?}{=} s^{z1}t^{z3}S^{-e}
 *  \text{ }\mathrm{mod}\text{ }\tilde{N} \f$
 *  <li> \f$ A \stackrel{?}{=} (1+N0)^{z1}z2^{N}K_oct^{-e}
 *  \text{ }\mathrm{mod}\text{ }N^2 \f$
 *  </ol>
 *
 *  @param pub_key            Public Paillier key of the prover
 *  @param priv_com           Private BC modulus of the verifier
 *  @param K_oct              Encrypted value
 *  @param commits            Received commitment
 *  @param e                  Generated challenge
 *  @param proofs             Received proofs
 *  @return                   PiEnc_COM_OK if the proofs is valid
 */
extern int PiEnc_Verify(PAILLIER_public_key *pub_key, PEDERSEN_PRIV *priv_com, octet *K_oct,
                        PiEnc_COMMITS *commits, octet *e_oct, PiEnc_PROOFS *proofs);

/** \brief Dump the proofs to octets
 *
 *  @param proofs      Destination Octet for component of the proofs
 *  @param proofs      Proof to export
 */
extern void PiEnc_proof_toOctets(PiEnc_PROOFS_OCT *proofsOct, PiEnc_PROOFS *proofs);

/** \brief Clean the memory containing the random values
 *
 *   @param secrets    Clean random values (alpha, mu, r, gamma)
 */
extern void PiEnc_Kill_secrets(PiEnc_SECRETS *secrets);

/** \brief Read the proof from octets
 *
 *  @param proofs      Destination proof
 *  @param proofsOct   Octet with the proofs
 */
extern void PiEnc_proofs_fromOctets(PiEnc_PROOFS *proofs, const PiEnc_PROOFS_OCT *proofsOct);

/** \brief Read the commitments from octets
 *
 *  @param commits     Destination commitment
 *  @param commitsOct  Octet components of the proof
 */
extern void PiEnc_commits_fromOctets(PiEnc_COMMITS *commits, const PiEnc_COMMITS_OCT *commitsOct);

/** \brief Dump the commitment to octets
 *
 *  @param PiEnc_COMMITS_OCT  Destination Octet for the (S,A,C) component
 *  @param commit             Commitment to export
 */
extern void PiEnc_Commitment_toOctets_enc(PiEnc_COMMITS_OCT *commitsOct, PiEnc_COMMITS *commit);

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
 *  @param k_oct       Message to PiEnc_Prove knowledge and range
 *  @param rho_oct     Random value used in the Paillier encryption of k
 *  @param secrets     Random values associated to the commitment
 *  @param e_oct       (pseudo)random challenge
 *  @param proofs      Destination proof
 *  @param proofsOct   Destination proof in Octet form
 */
extern void PiEnc_Prove(PAILLIER_private_key *priv_key, octet *k_oct, octet *rho_oct,
                        PiEnc_SECRETS *secrets, octet *e_oct, PiEnc_PROOFS *proofs, PiEnc_PROOFS_OCT *proofsOct);


#ifdef __cplusplus
}
#endif

#endif