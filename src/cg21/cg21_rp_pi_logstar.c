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

#include "amcl/cg21/cg21_rp_pi_logstar.h"
#include "amcl/hash_utils.h"


int PiLogstar_Sample_and_commit(csprng *RNG, PAILLIER_private_key *priv_key, PEDERSEN_PUB *pub_com,
                                octet *x, octet *g, PiLogstar_SECRETS *secrets, PiLogstar_COMMITS *commits,
                                PiLogstar_COMMITS_OCT *commitsOct)
{
    /*
     * ---------STEP 1: choosing randoms -----------
     * alpha:       random from [0, q^3]
     * mu_mod:      |q| + |\hat{N}| bits
     * r:           random from Z_{N_0}
     * gamma_mod:   |q^3| + |\hat{N}| bits
     *
     * ---------STEP 2: commitment --------------
     * S = s^x * t^mu mod \hat{N}
     * A = (1 + N0)^alpha * r^N0 mod N0^2
     * D = s^alpha * t^gamma mod \hat{N}
     * Y = alpha*G
     */


    // ------------ CHECKING INPUTS -------------
    if (RNG == NULL){
        return PiLogstar_RNG_IS_NULL;
    }
    if (priv_key == NULL){
        return PiLogstar_PAILLIER_SK_IS_NULL;
    }
    if (pub_com == NULL){
        return PiLogstar_COM_PUB_IS_NULL;
    }
    if (x == NULL){
        return PiLogstar_INPUT_IS_NULL;
    }
    if (g == NULL){
        return PiLogstar_INPUT_IS_NULL;
    }

    // ------------ VARIABLE DEFINITION ----------
    ECP_SECP256K1 G;

    BIG_1024_58 q[HFLEN_2048];          // q
    BIG_1024_58 q2[FFLEN_2048];         // q^2
    BIG_1024_58 q3[FFLEN_2048];         // q^3

    BIG_1024_58 n[FFLEN_2048];
    BIG_1024_58 invp2q2[FFLEN_2048];
    BIG_1024_58 n2[2 * FFLEN_2048];     // n^2
    BIG_1024_58 ws3[FFLEN_2048];
    BIG_1024_58 gamma_mod[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 mu_mod[2 * FFLEN_2048];
    BIG_1024_58 dws2[2 * FFLEN_2048];
    BIG_1024_58 t[2 * FFLEN_2048];

    char oct[2 * FS_2048];
    octet OCT = {0, sizeof(oct), oct};


    // Curve order
    CG21_GET_CURVE_ORDER(q);

    FF_2048_mul(n, priv_key->p, priv_key->q, HFLEN_2048);
    FF_2048_sqr(n2, n, FFLEN_2048);
    FF_2048_norm(n2, 2 * FFLEN_2048);
    FF_2048_invmodp(invp2q2, priv_key->p2, priv_key->q2, FFLEN_2048);

    FF_2048_sqr(q2, q, HFLEN_2048);
    FF_2048_mul(q3, q, q2, HFLEN_2048);

    // ------------ RANDOM GENERATION ----------
    // Generate alpha in [0, .., q^3]
    FF_2048_zero(secrets->alpha, HFLEN_2048);
    FF_2048_random(secrets->alpha, RNG, HFLEN_2048);        // alpha: a 1024-bit number
    FF_2048_mod(secrets->alpha, q3, HFLEN_2048);            // random of size |q^3| bits needs to be reduced mod q^3

    // Generate r in [0, .., N]
    FF_2048_randomnum(secrets->r, n, RNG, FFLEN_2048);   // |N| bit sized r needs to be reduced mod N

    // Generate mu_mod in [0, .., Nt * q^3]
    CG21_FF_2048_amul(gamma_mod, q3, HFLEN_2048, pub_com->N, FFLEN_2048);   //Nt*q^3
    FF_2048_norm(gamma_mod,FFLEN_2048 + HFLEN_2048);
    FF_2048_random(secrets->gamma, RNG, FFLEN_2048 + HFLEN_2048);           //gamma_mod: a (1024+2048)-bit number
    FF_2048_mod(secrets->gamma, gamma_mod, FFLEN_2048 + HFLEN_2048);            //gamma_mod: in [0, .., 3*256+2048]

    // Generate mu_mod in [0, .., Nt * q]
    CG21_FF_2048_amul(mu_mod, q, HFLEN_2048, pub_com->N, FFLEN_2048);
    FF_2048_norm(mu_mod,FFLEN_2048 + HFLEN_2048);
    FF_2048_random(secrets->mu, RNG, FFLEN_2048 + HFLEN_2048);         //mu_mod: a (1024+2048)-bit number
    FF_2048_mod(secrets->mu, mu_mod, FFLEN_2048 + HFLEN_2048);             //mu_mod: in [0, .., 256+2048]

    // ------------ READING INPUTS ----------
    OCT_copy(&OCT, x);                      // x is 32 bytes long
    OCT_pad(&OCT, HFS_2048);                // pad to ensure that all 1024 bits are initialized
    FF_2048_zero(t, 2 * FFLEN_2048);        // Set t to zero
    FF_2048_fromOctet(t, &OCT, HFLEN_2048);

    // ------------ COMMITMENT ----------
    // Compute S and C
    FF_2048_ct_pow_2(commits->S, pub_com->b0, t, pub_com->b1, secrets->mu, pub_com->N, FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    FF_2048_copy(t, secrets->alpha, HFLEN_2048);

    // recall: b0 is s and b1 is t from the eprint fig.25
    FF_2048_ct_pow_2(commits->D, pub_com->b0, t, pub_com->b1, secrets->gamma, pub_com->N,
                     FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    // Compute A using CRT and Paillier PK trick
    // Compute 1 + n * alpha
    // Defer the increment after the modular reduction so it can
    // be performed without conversion to FF_4096
    FF_2048_zero(dws2, 2 * FFLEN_2048);
    CG21_FF_2048_amul(dws2, secrets->alpha, HFLEN_2048, n, FFLEN_2048);

    // Compute pub_com P^2
    FF_2048_zero(ws3, FFLEN_2048);
    FF_2048_dmod(ws3, dws2, priv_key->p2, FFLEN_2048);
    FF_2048_inc(ws3, 1, FFLEN_2048);
    FF_2048_norm(ws3, FFLEN_2048);

    FF_2048_ct_pow(q2, secrets->r, n, priv_key->p2, FFLEN_2048, FFLEN_2048);

    FF_2048_mul(t, q2, ws3, FFLEN_2048);
    FF_2048_dmod(q2, t, priv_key->p2, FFLEN_2048);

    // Compute pub_com Q^2
    FF_2048_zero(ws3, FFLEN_2048);
    FF_2048_dmod(ws3, dws2, priv_key->q2, FFLEN_2048);
    FF_2048_inc(ws3, 1, FFLEN_2048);
    FF_2048_norm(ws3, FFLEN_2048);

    FF_2048_ct_pow(q3, secrets->r, n, priv_key->q2, FFLEN_2048, FFLEN_2048);

    FF_2048_mul(t, q3, ws3, FFLEN_2048);
    FF_2048_dmod(q3, t, priv_key->q2, FFLEN_2048);

    // Combine results
    FF_2048_crt(t, q2, q3, priv_key->p2, invp2q2, n2, FFLEN_2048);

    // Convert A to FF_4096 since it is only used as such
    FF_2048_toOctet(&OCT, t, 2 * FFLEN_2048);
    FF_4096_fromOctet(commits->A, &OCT, FFLEN_4096);

    // Compute Y
    int rc = ECP_SECP256K1_fromOctet(&G, g);
    if (rc != 1)
    {
        return Pilogstar_Y_FAIL;
    }
    ECP_mul_1024(&G, secrets->alpha);
    ECP_SECP256K1_copy(&commits->Y,&G);

    // the commitment to octets for transmission
    PiLogstar_Commitment_toOctets_logstar(commitsOct, commits);

    // ------------ CLEAN MEMORY ----------
    OCT_clear(&OCT);
    FF_2048_zero(dws2, 2 * FFLEN_2048);
    FF_2048_zero(ws3, FFLEN_2048);
    FF_2048_zero(q2, FFLEN_2048);
    FF_2048_zero(q3, FFLEN_2048);
    FF_2048_zero(t, 2 * FFLEN_2048);
    FF_2048_zero(invp2q2, FFLEN_2048);

    return PiLogstar_OK;
}

void PiLogstar_hash_commits(hash256 *sha, PiLogstar_COMMITS *com)
{
    char oct[2 * FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    OCT_clear(&OCT);

    FF_2048_toOctet(&OCT, com->S, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_4096_toOctet(&OCT, com->A, FFLEN_4096);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_2048_toOctet(&OCT, com->D, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);

    ECP_SECP256K1_toOctet(&OCT, &com->Y , true);
    HASH_UTILS_hash_oct(sha, &OCT);

    OCT_clear(&OCT);
}


void PiLogstar_Challenge_gen(PAILLIER_public_key *pub_key, PEDERSEN_PUB *pub_com,
                         const octet *C, PiLogstar_COMMITS *commits, CG21_SSID *ssid, const octet *X, octet *E)
{
    // ------------ VARIABLE DEFINITION ----------
    hash256 sha;
    BIG_256_56 q;
    BIG_256_56 t;

    HASH256_init(&sha);

    // ------------ CHALLENGE GENERATION ----------
    /* Bind to public parameters (N0,Nt,s,t) */
    CG21_hash_pubKey_pubCom(&sha, pub_key, pub_com);

    /* Bind to proof input */
    HASH_UTILS_hash_oct(&sha, C);
    HASH_UTILS_hash_oct(&sha, X);

    /* Bind to proof commitment (S,A,Y,D) */
    PiLogstar_hash_commits(&sha, commits);

    /* Bind to SSID */
    int rc = CG21_hash_SSID(ssid, &sha);
    if (rc != CG21_OK){
        exit(rc);
    }

    // ------------ OUTPUT ----------
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    HASH_UTILS_rejection_sample_mod_BIG(&sha, q, t); // interpret sha output as an int mod q

    BIG_256_56_toBytes(E->val, t);
    E->len = EGS_SECP256K1;
}

void PiLogstar_proof_toOctets(PiLogstar_PROOFS_OCT *proofsOct, PiLogstar_PROOFS *proofs)
{
    FF_2048_toOctet(proofsOct->z1, proofs->z1, HFLEN_2048);
    FF_4096_toOctet(proofsOct->z2, proofs->z2, HFLEN_4096);
    FF_2048_toOctet(proofsOct->z3, proofs->z3, FFLEN_2048 + HFLEN_2048);
}

void PiLogstar_clean_secrets(PiLogstar_SECRETS *secrets)
{
    FF_2048_zero(secrets->alpha, HFLEN_2048);
    FF_2048_zero(secrets->r, FFLEN_2048);
    FF_2048_zero(secrets->gamma, FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(secrets->mu, FFLEN_2048 + HFLEN_2048);
}

void PiLogstar_proofs_fromOctets(PiLogstar_PROOFS *proofs, const PiLogstar_PROOFS_OCT *proofsOct)
{
    FF_2048_zero(proofs->z1, FFLEN_2048);
    FF_4096_zero(proofs->z2, FFLEN_4096);
    FF_2048_zero(proofs->z3, FFLEN_2048 + HFLEN_2048);

    FF_2048_fromOctet(proofs->z1, proofsOct->z1, HFLEN_2048);
    FF_4096_fromOctet(proofs->z2, proofsOct->z2, HFLEN_4096);
    FF_2048_fromOctet(proofs->z3, proofsOct->z3, FFLEN_2048 + HFLEN_2048);
}

int PiLogstar_commits_fromOctets(PiLogstar_COMMITS *commits, const PiLogstar_COMMITS_OCT *commitsOct)
{
    int rc;

    rc = ECP_SECP256K1_fromOctet(&commits->Y, commitsOct->Y);
    if (rc != 1)
    {
        return Pilogstar_Y_FAIL;
    }
    FF_2048_fromOctet(commits->S, commitsOct->S, FFLEN_2048);
    FF_4096_fromOctet(commits->A, commitsOct->A, FFLEN_4096);
    FF_2048_fromOctet(commits->D, commitsOct->D, FFLEN_2048);
    return Pilogstar_Y_OK;
}

void PiLogstar_Commitment_toOctets_logstar(PiLogstar_COMMITS_OCT *commitsOct, PiLogstar_COMMITS *commit)
{
    FF_2048_toOctet(commitsOct->S, commit->S, FFLEN_2048);
    FF_4096_toOctet(commitsOct->A, commit->A, FFLEN_4096);
    FF_2048_toOctet(commitsOct->D, commit->D, FFLEN_2048);
    ECP_SECP256K1_toOctet(commitsOct->Y, &commit->Y, true);
}


void PiLogstar_Prove(PAILLIER_private_key *priv_key, octet *k_oct, octet *rho_oct,
                 PiLogstar_SECRETS *secrets, octet *e_oct, PiLogstar_PROOFS *proofs,
                 PiLogstar_PROOFS_OCT *proofsOct)
{
    // ------------ VARIABLE DEFINITION ----------
    BIG_1024_58 ws1[FFLEN_2048];
    BIG_1024_58 ws2[FFLEN_2048];
    BIG_1024_58 hws[HFLEN_2048];
    BIG_1024_58 t[2 * FFLEN_2048];
    BIG_1024_58 e[HFLEN_2048];
    BIG_1024_58 k[HFLEN_2048];
    BIG_1024_58 sp[HFLEN_2048];
    BIG_1024_58 sq[HFLEN_2048];

    char oct[2*FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    // ------------ READ INPUTS ----------
    OCT_copy(&OCT, k_oct);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(k, &OCT, HFLEN_2048);

    OCT_clear(&OCT);
    OCT_copy(&OCT, rho_oct);
    FF_2048_fromOctet(t, &OCT, 2 * FFLEN_2048);

    OCT_copy(&OCT, e_oct);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(e, &OCT, HFLEN_2048);

    // ------------ GENERATE PiLogstar_PROOFS ----------
    // Compute z2 = r * rho^e mod N using CRT
    CG21_FF_2048_amod(hws, t, 2 * FFLEN_2048, priv_key->p, HFLEN_2048);
    FF_2048_dmod(sp, secrets->r, priv_key->p, HFLEN_2048);
    FF_2048_nt_pow(hws, hws, e, priv_key->p, HFLEN_2048, HFLEN_2048);
    FF_2048_mul(ws1, sp, hws,  HFLEN_2048);
    FF_2048_dmod(sp, ws1, priv_key->p, HFLEN_2048);

    CG21_FF_2048_amod(hws, t, 2 * FFLEN_2048, priv_key->q, HFLEN_2048);
    FF_2048_dmod(sq, secrets->r, priv_key->q, HFLEN_2048);
    FF_2048_nt_pow(hws, hws, e, priv_key->q, HFLEN_2048, HFLEN_2048);
    FF_2048_mul(ws1, sq, hws,  HFLEN_2048);
    FF_2048_dmod(sq, ws1, priv_key->q, HFLEN_2048);

    FF_2048_mul(ws2, priv_key->p, priv_key->q, HFLEN_2048);
    FF_2048_crt(ws1, sp, sq, priv_key->p, priv_key->invpq, ws2, HFLEN_2048);

    // Convert z2 to FF_4096 since it is only used as such
    FF_2048_toOctet(&OCT, ws1, FFLEN_2048);
    OCT_pad(&OCT, FS_4096);
    FF_4096_fromOctet(proofs->z2, &OCT, FFLEN_4096);

    // Compute z1 = e*k + alpha
    FF_2048_mul(ws1, e, k, HFLEN_2048);  // k at this point is x from the paper
    FF_2048_zero(proofs->z1, FFLEN_2048);
    FF_2048_copy(proofs->z1, secrets->alpha, HFLEN_2048);
    FF_2048_add(proofs->z1, proofs->z1, ws1, FFLEN_2048);
    FF_2048_norm(proofs->z1, FFLEN_2048);

    // Compute z3 = e*mu + gamma
    FF_2048_zero(t, 2*FFLEN_2048);
    CG21_FF_2048_amul(t, e, HFLEN_2048, secrets->mu, FFLEN_2048 + HFLEN_2048);
    FF_2048_copy(proofs->z3, secrets->gamma, FFLEN_2048 + HFLEN_2048);
    FF_2048_add(proofs->z3, proofs->z3, t, FFLEN_2048 + HFLEN_2048);
    FF_2048_norm(proofs->z3, FFLEN_2048 + HFLEN_2048);

    // proof to octets for transmission
    PiLogstar_proof_toOctets(proofsOct, proofs);

    // ------------ CLEAR MEMORY ----------
    OCT_clear(&OCT);
    FF_2048_zero(t, 2 * FFLEN_2048);
    FF_2048_zero(ws1, FFLEN_2048);
    FF_2048_zero(ws2, FFLEN_2048);
    FF_2048_zero(hws, HFLEN_2048);
    FF_2048_zero(sp, HFLEN_2048);
    FF_2048_zero(sq, HFLEN_2048);
    FF_2048_zero(k, HFLEN_2048);
}

int PiLogstar_Verify(PAILLIER_public_key *pub_key, PEDERSEN_PRIV *priv_com, octet *C_oct, octet *g,
                 PiLogstar_COMMITS *commits, octet *X, octet *e_oct, PiLogstar_PROOFS *proofs)
{
    int fail;
    int equal;
    ECP_SECP256K1 G;
    ECP_SECP256K1 P;
    ECP_SECP256K1 Q;


    // ------------ VARIABLE DEFINITION ----------
    BIG_1024_58 ws[FFLEN_2048];
    BIG_1024_58 hws1[HFLEN_2048];
    BIG_1024_58 hws2[HFLEN_2048];
    BIG_1024_58 wp_proof[HFLEN_2048];
    BIG_1024_58 wq_proof[HFLEN_2048];
    BIG_1024_58 e[HFLEN_2048];
    BIG_512_60 e_4096[HFLEN_4096];
    BIG_512_60 s1[HFLEN_4096];
    BIG_512_60 ws1_4096[FFLEN_4096];
    BIG_512_60 ws2_4096[FFLEN_4096];
    BIG_512_60 dws_4096[2 * FFLEN_4096];

    char oct[FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    // ------------ READ INPUTS ----------
    OCT_copy(&OCT, e_oct);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(e, &OCT, HFLEN_2048);
    OCT_pad(&OCT, HFS_4096);
    FF_4096_fromOctet(e_4096, &OCT, HFLEN_4096);
    OCT_clear(&OCT);

    // Read q and compute q^3
    CG21_GET_CURVE_ORDER(hws1);                         // hws1 is now q
    FF_2048_sqr(ws, hws1, HFLEN_2048);             // ws is q^2
    FF_2048_mul(ws, ws, hws1, HFLEN_2048);      // ws is now q^3


    // ------------ CHECK 'z1' IS IN [0, ..., q^3] ------------
    if (FF_2048_comp(proofs->z1, ws, FFLEN_2048) > 0)
    {
        return PiLogstar_INVALID_RANGE;
    }

    // ------------ VALIDATES THE PROOF - PART1 ----------
    // s^z1 * t^z3 =? D * S^e
    // Split computation of proofs for C using CRT.
    CG21_Pedersen_verify(wp_proof, priv_com, proofs->z1, proofs->z3, commits->S, e, priv_com->mod.p,false);
    CG21_Pedersen_verify(wq_proof, priv_com, proofs->z1, proofs->z3, commits->S, e, priv_com->mod.q, false);

    // Reduce C mod P and Q for comparison
    FF_2048_dmod(hws1, commits->D, priv_com->mod.p, HFLEN_2048);
    FF_2048_dmod(hws2, commits->D, priv_com->mod.q, HFLEN_2048);

    // Compare the results modulo P and Q
    // since C == C' mod PQ <==> C == C' mod P & C == C' mod Q
    fail = (FF_2048_comp(hws1, wp_proof, HFLEN_2048) != 0) || (FF_2048_comp(hws2, wq_proof, HFLEN_2048) != 0);

    // ------------ CLEAN MEMORY ----------
    FF_2048_zero(hws1, HFLEN_2048);
    FF_2048_zero(hws2, HFLEN_2048);
    FF_2048_zero(wp_proof, HFLEN_2048);
    FF_2048_zero(wq_proof, HFLEN_2048);

    if(fail)
    {
        return PiLogstar_INVALID_PROOF_P1;
    }

    // ------------ VALIDATES THE PROOF - PART2 ----------
    //(1+N)^z1 * z2^N * C_oct^(-e) mod N^2 =? A
    FF_2048_toOctet(&OCT, proofs->z1, HFLEN_2048);
    OCT_pad(&OCT, HFS_4096);
    FF_4096_fromOctet(s1, &OCT, HFLEN_4096);

    FF_4096_fromOctet(ws1_4096, C_oct, FFLEN_4096);
    FF_4096_invmodp(ws1_4096, ws1_4096, pub_key->n2, FFLEN_4096);

    // u_proof = (1+N)^z1 * z2^N * C_oct^(-e) mod N^2 ,  (u_proof = ws2_4096 * ws1_4096)
    FF_4096_mul(ws2_4096, pub_key->n, s1, HFLEN_4096);
    FF_4096_inc(ws2_4096, 1, FFLEN_4096);
    FF_4096_norm(ws2_4096, FFLEN_4096);
    FF_4096_nt_pow_2(ws1_4096, proofs->z2, pub_key->n, ws1_4096, e_4096, pub_key->n2, FFLEN_4096, HFLEN_4096);
    FF_4096_mul(dws_4096, ws1_4096, ws2_4096, FFLEN_4096);
    FF_4096_dmod(ws1_4096, dws_4096, pub_key->n2, FFLEN_4096);

    // ------------ CLEAN MEMORY ----------
    OCT_clear(&OCT);
    FF_4096_zero(dws_4096, 2 * FFLEN_4096);
    FF_4096_zero(ws2_4096, FFLEN_4096);
    FF_4096_zero(s1, HFLEN_4096);

    // ------------ OUTPUT ----------
    if(FF_4096_comp(ws1_4096, commits->A, FFLEN_4096) != 0)
    {
        FF_4096_zero(ws1_4096, FFLEN_4096);
        return PiLogstar_INVALID_PROOF_P2;
    }

    // ------------ VALIDATES THE PROOF - PART4 ----------
    // z1*G =? Y + e*X

    int rc = ECP_SECP256K1_fromOctet(&G, g);
    if (rc != 1)
    {
        return Pilogstar_Y_FAIL;
    }
    ECP_mul_1024(&G, proofs->z1);

    ECP_SECP256K1_copy(&P,&commits->Y);       // P <- Y
    ECP_SECP256K1_fromOctet(&Q, X);         // Q <- X
    ECP_mul_1024(&Q, e);                      // Q <- e * X

    ECP_SECP256K1_add(&P, &Q);                  // P <- Y + e * X

    equal = ECP_SECP256K1_equals(&P, &G);

    // ------------ CLEAN MEMORY ----------
    ECP_SECP256K1_inf(&G);
    ECP_SECP256K1_inf(&P);
    ECP_SECP256K1_inf(&Q);
    FF_4096_zero(ws1_4096, FFLEN_4096);

    if (equal!=1)
    {
        return PiLogstar_INVALID_PROOF_P3;
    }

    // Note that 'z1' is already checked to be in the range of [0, ..., q^3]

    return PiLogstar_OK;
}