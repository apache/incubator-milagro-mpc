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

#include "amcl/cg21/cg21_rp_pi_affp.h"
#include "amcl/hash_utils.h"

int PiAffp_Sample_and_Commit(csprng *RNG, PAILLIER_private_key *paillier_priv, PAILLIER_public_key *paillier_pub,
                              PEDERSEN_PUB *pedersen_pub, octet *x, octet *y, PiAffp_SECRETS *secrets,
                              PiAffp_COMMITS *commit, PiAffp_COMMITS_OCT *commitsOct, octet *C){

    // ------------ VARIABLE DEFINITION ----------
    BIG_1024_58 n_b[FFLEN_2048];
    BIG_1024_58 n2_b[2 * FFLEN_2048];

    BIG_1024_58 q[HFLEN_2048];          //q:256 bits
    BIG_1024_58 q2[FFLEN_2048];         //q^2
    BIG_1024_58 q3[FFLEN_2048];         //q^3
    BIG_1024_58 q5[FFLEN_2048];         //q^5
    BIG_1024_58 q7[FFLEN_2048];         //q^7

    BIG_512_60 r[FFLEN_4096];
    BIG_1024_58 gamma_mod[2 * FFLEN_2048];
    BIG_1024_58 delta_mod[2 * FFLEN_2048];
    BIG_1024_58 m_mod[2 * FFLEN_2048];
    BIG_1024_58 mu_mod[2 * FFLEN_2048];

    BIG_1024_58 x_[2 * FFLEN_2048];
    BIG_1024_58 y_[2 * FFLEN_2048];

    BIG_512_60 ws1[FFLEN_4096];
    BIG_512_60 ws2[FFLEN_4096];
    BIG_512_60 dws[2 * FFLEN_4096];
    BIG_512_60 alpha[HFLEN_4096];
    BIG_512_60 r_[FFLEN_4096];
    BIG_512_60 beta[FFLEN_4096];
    BIG_1024_58 tws[FFLEN_2048 + HFLEN_2048];

    char oct1[2 * FS_2048];
    octet OCT = {0, sizeof(oct1), oct1};

    char oct4[2*FS_2048];
    octet rx_oct = {0, sizeof(oct4), oct4};

    char oct5[2*FS_2048];
    octet ry_oct = {0, sizeof(oct5), oct5};

    char oct2[2 * FS_2048];
    octet alpha_oct = {0, sizeof(oct2), oct2};

    char oct6[2 * FS_2048];
    octet beta_oct = {0, sizeof(oct6), oct6};

    char oct3[2*FS_2048];
    octet CT_oct = {0, sizeof(oct3), oct3};

    PAILLIER_public_key PUB;

    // Curve order
    CG21_GET_CURVE_ORDER(q);

    // Calculate N and N^2 parameters based on p and q
    FF_2048_mul(n_b, paillier_priv->p, paillier_priv->q, HFLEN_2048);

    FF_2048_sqr(n2_b, n_b, FFLEN_2048);
    FF_2048_norm(n2_b, 2 * FFLEN_2048);

    if (RNG == NULL)
    {
        return PiAffp_RNG_IS_NULL;
    }
    FF_2048_sqr(q2, q, HFLEN_2048);
    FF_2048_mul(q3, q, q2, HFLEN_2048);
    FF_2048_mul(q5, q3, q2, FFLEN_2048);
    FF_2048_mul(q7, q5, q2, FFLEN_2048);

    // ------------ RANDOM GENERATION ----------
    // Generate alpha in [0, .., q^3]
    FF_2048_zero(secrets->alpha, HFLEN_2048);
    FF_2048_random(secrets->alpha, RNG, HFLEN_2048);        //alpha: 1024-bit random number
    FF_2048_mod(secrets->alpha, q3, HFLEN_2048);            //alpha: 1024-bit reduced to (3*256)-bit number

    // Generate beta in [0, .., q^7]
    FF_2048_zero(secrets->beta, FFLEN_2048);
    FF_2048_random(secrets->beta, RNG, FFLEN_2048);          //beta: 2048-bit random number
    FF_2048_mod(secrets->beta, q7, FFLEN_2048);              //beta: 2048-bit reduced to (7*256)-bit number

    // Generate r in [0, .., N]
    FF_4096_randomnum(r, paillier_pub->n, RNG, HFLEN_4096);   // r: 2048-bit random number
    FF_4096_toOctet(&OCT, r, HFLEN_4096);
    FF_2048_fromOctet(secrets->r, &OCT, FFLEN_2048);

    // Generate rx and ry in [0, .., N]
    FF_2048_randomnum(secrets->rx, n_b, RNG, FFLEN_2048);   // rx: 2048-bit random number
    FF_2048_randomnum(secrets->ry, n_b, RNG, FFLEN_2048);   // ry: 2048-bit random number

    // Generate gamma in [0, .., Nt * q^3]
    CG21_FF_2048_amul(gamma_mod, q3, HFLEN_2048, pedersen_pub->N, FFLEN_2048);   //Nt*q^3
    FF_2048_random(secrets->gamma, RNG, FFLEN_2048 + HFLEN_2048);           //gamma: (1024+2048)-bit random number
    FF_2048_mod(secrets->gamma, gamma_mod, FFLEN_2048 + HFLEN_2048);        //gamma: (3*256+2048)-bit number

    // Generate delta in [0, .., Nt * q^3]
    CG21_FF_2048_amul(delta_mod, q3, HFLEN_2048, pedersen_pub->N, FFLEN_2048);   //Nt*q^3
    FF_2048_random(secrets->delta, RNG, FFLEN_2048 + HFLEN_2048);           //delta: (1024+2048)-bit random number

    //delta: (1024+2048)-bit reduced to (3*256+2048)-bit number
    FF_2048_mod(secrets->delta, delta_mod, FFLEN_2048 + HFLEN_2048);

    // Generate m in [0, .., Nt * q]
    CG21_FF_2048_amul(m_mod, q, HFLEN_2048, pedersen_pub->N, FFLEN_2048);
    FF_2048_random(secrets->m, RNG, FFLEN_2048 + HFLEN_2048);            //m: (1024+2048)-bit random number

    //m: (1024+2048)-bit reduced to (256+2048)-bit number
    FF_2048_mod(secrets->m, m_mod, FFLEN_2048 + HFLEN_2048);

    // Generate mu in [0, .., Nt * q]
    CG21_FF_2048_amul(mu_mod, q, HFLEN_2048, pedersen_pub->N, FFLEN_2048);
    FF_2048_random(secrets->mu, RNG, FFLEN_2048 + HFLEN_2048);  //mu: (1024+2048)-bit random number
    FF_2048_mod(secrets->mu, mu_mod, FFLEN_2048 + HFLEN_2048);  //mu: (1024+2048)-bit reduced to (256+2048)-bit number


    // ------------ READING INPUTS ----------
    OCT_copy(&OCT, x);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_zero(x_, FFLEN_2048 + HFLEN_2048);
    FF_2048_fromOctet(x_, &OCT, HFLEN_2048);

    OCT_copy(&OCT, y);
    OCT_pad(&OCT, HFS_4096);
    FF_2048_zero(y_, HFLEN_4096);
    FF_2048_fromOctet(y_, &OCT, FFLEN_2048);

    // ------------ COMMITMENT ----------
    // Compute E: b0^alpha * b1^gamma mod hat{N}
    FF_2048_zero(tws, FFLEN_2048 + HFLEN_2048);
    FF_2048_copy(tws, secrets->alpha, HFLEN_2048);

    // b0 is s and b1 is t from paper's fig.26
    FF_2048_ct_pow_2(commit->E, pedersen_pub->b0, tws, pedersen_pub->b1, secrets->gamma,
                     pedersen_pub->N, FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    // Compute S: b0^x * b1^m mod hat{N}
    FF_2048_ct_pow_2(commit->S, pedersen_pub->b0, x_, pedersen_pub->b1, secrets->m,
                     pedersen_pub->N, FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    // Compute F: b0^beta * b1^delta mod hat{N}
    FF_2048_zero(tws, FFLEN_2048 + HFLEN_2048);
    FF_2048_copy(tws, secrets->beta, FFLEN_2048);
    FF_2048_ct_pow_2(commit->F, pedersen_pub->b0, tws, pedersen_pub->b1, secrets->delta,
                     pedersen_pub->N, FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    // Compute T: b0^y * b1^mu mod hat{N}
    FF_2048_ct_pow_2(commit->T, pedersen_pub->b0, y_, pedersen_pub->b1, secrets->mu,
                     pedersen_pub->N, FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    // Compute A = C^alpha * g^beta * r^N mod n2
    FF_4096_fromOctet(ws2, C, FFLEN_4096);

    FF_2048_toOctet(&alpha_oct, secrets->alpha, HFLEN_2048);
    OCT_pad(&alpha_oct, HFS_4096);
    FF_4096_fromOctet(alpha, &alpha_oct, HFLEN_4096);

    FF_2048_toOctet(&beta_oct, secrets->beta, FFLEN_2048);
    OCT_pad(&beta_oct, HFS_4096);
    FF_4096_fromOctet(beta, &beta_oct, HFLEN_4096);

    FF_2048_toOctet(&OCT, secrets->r, FFLEN_2048);
    OCT_pad(&OCT, FS_4096);
    FF_4096_fromOctet(r_, &OCT, FFLEN_4096);

    // (N0 * beta + 1)
    FF_4096_zero(ws1, FFLEN_4096);
    FF_4096_mul(ws1, paillier_pub->n, beta, HFLEN_4096);
    FF_4096_inc(ws1, 1, FFLEN_4096);
    FF_4096_norm(ws1, FFLEN_4096);

    // C^alpha * r^N0 mod n2
    FF_4096_ct_pow_2(ws2, ws2, alpha, r_, paillier_pub->n, paillier_pub->n2, FFLEN_4096, HFLEN_4096);

    // (N0 * beta + 1) * C^alpha * r^N0 mod N0^2
    FF_4096_zero(dws, 2 * FFLEN_4096);
    FF_4096_mul(dws, ws1, ws2, FFLEN_4096);
    FF_4096_dmod(ws1, dws, paillier_pub->n2, FFLEN_4096);

    FF_4096_toOctet(&OCT, ws1, FFLEN_4096);
    FF_2048_fromOctet(commit->A, &OCT, 2 * FFLEN_2048);

    // Form PAILLIER_public_key using prover's PK
    FF_2048_toOctet(&OCT, n_b, FFLEN_2048);
    OCT_pad(&OCT, HFS_2048);
    FF_4096_zero(PUB.n, FFLEN_4096);
    FF_4096_fromOctet(PUB.n, &OCT, HFLEN_4096);
    FF_4096_sqr(PUB.n2, PUB.n, HFLEN_4096);
    FF_4096_norm(PUB.n2, FFLEN_4096);

    // Computes Bx and By
    FF_2048_toOctet(&rx_oct, secrets->rx, FFLEN_2048);
    FF_2048_toOctet(&ry_oct, secrets->ry, FFLEN_2048);

    OCT_pad(&rx_oct, FS_4096);
    OCT_pad(&ry_oct, FS_4096);

    PAILLIER_ENCRYPT(NULL, &PUB, &alpha_oct, &CT_oct,&rx_oct); // Bx = Enc(alpha; rx)
    FF_2048_fromOctet(commit->Bx, &CT_oct, 2 * FFLEN_2048);

    PAILLIER_ENCRYPT(NULL, &PUB, &beta_oct, &CT_oct,&ry_oct);  // By = Enc(beta; ry)
    FF_2048_fromOctet(commit->By, &CT_oct, 2 * FFLEN_2048);

    PiAffp_Commitment_toOctets_enc(commitsOct, commit);

    // ------------ CLEAN MEMORY ----------
    OCT_clear(&OCT);
    OCT_clear(&rx_oct);
    OCT_clear(&ry_oct);
    OCT_clear(&alpha_oct);
    OCT_clear(&beta_oct);
    OCT_clear(&CT_oct);
    FF_2048_zero(x_, FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(y_, HFLEN_4096);
    FF_2048_zero(tws, FFLEN_2048 + HFLEN_2048);
    FF_4096_zero(r, FFLEN_4096);
    FF_4096_zero(ws1, FFLEN_4096);
    FF_4096_zero(ws2, FFLEN_4096);
    FF_4096_zero(dws, 2*FFLEN_4096);

    return PiAffp_OK;
}

void PiAffp_Commitment_toOctets_enc(PiAffp_COMMITS_OCT *commitsOct, PiAffp_COMMITS *commit){

    FF_2048_toOctet(&commitsOct->A, commit->A, 2 * FFLEN_2048);
    FF_2048_toOctet(&commitsOct->Bx,commit->Bx, 2 * FFLEN_2048);
    FF_2048_toOctet(&commitsOct->By,commit->By, 2 * FFLEN_2048);

    FF_2048_toOctet(&commitsOct->E, commit->E, FFLEN_2048);
    FF_2048_toOctet(&commitsOct->S, commit->S, FFLEN_2048);
    FF_2048_toOctet(&commitsOct->F, commit->F, FFLEN_2048);
    FF_2048_toOctet(&commitsOct->T, commit->T, FFLEN_2048);
}

void PiAffp_proof_toOctets(PiAffp_PROOFS_OCT *proofsOct, PiAffp_PROOFS *proofs){
    FF_2048_toOctet(&proofsOct->z1, proofs->z1, FFLEN_2048);
    FF_2048_toOctet(&proofsOct->z2,proofs->z2, FFLEN_2048);
    FF_2048_toOctet(&proofsOct->z3,proofs->z3, FFLEN_2048+HFLEN_2048);
    FF_2048_toOctet(&proofsOct->z4, proofs->z4, FFLEN_2048+HFLEN_2048);

    FF_2048_toOctet(&proofsOct->w, proofs->w, FFLEN_2048);
    FF_2048_toOctet(&proofsOct->wx, proofs->wx, FFLEN_2048);
    FF_2048_toOctet(&proofsOct->wy, proofs->wy, FFLEN_2048);
}

void PiAffp_proofs_fromOctets(PiAffp_PROOFS *proofs, PiAffp_PROOFS_OCT *proofsOct){
    FF_2048_fromOctet(proofs->z1, &proofsOct->z1, FFLEN_2048);
    FF_2048_fromOctet(proofs->z2, &proofsOct->z2, FFLEN_2048);
    FF_2048_fromOctet(proofs->z3, &proofsOct->z3, FFLEN_2048+HFLEN_2048);
    FF_2048_fromOctet(proofs->z4, &proofsOct->z4, FFLEN_2048+HFLEN_2048);

    FF_2048_fromOctet(proofs->w, &proofsOct->w, FFLEN_2048);
    FF_2048_fromOctet(proofs->wx, &proofsOct->wx, FFLEN_2048);
    FF_2048_fromOctet(proofs->wy, &proofsOct->wy, FFLEN_2048);
}

void PiAffp_commits_fromOctets(PiAffp_COMMITS *commits, PiAffp_COMMITS_OCT *commitsOct)
{
    FF_2048_fromOctet(commits->A, &commitsOct->A, 2 * FFLEN_2048);
    FF_2048_fromOctet(commits->Bx, &commitsOct->Bx, 2 * FFLEN_2048);
    FF_2048_fromOctet(commits->By, &commitsOct->By, 2 * FFLEN_2048);

    FF_2048_fromOctet(commits->E, &commitsOct->E, FFLEN_2048);
    FF_2048_fromOctet(commits->S, &commitsOct->S, FFLEN_2048);
    FF_2048_fromOctet(commits->F, &commitsOct->F, FFLEN_2048);
    FF_2048_fromOctet(commits->T, &commitsOct->T, FFLEN_2048);
}


/** \brief Hash the commitments in the Pi-Affp
 *
 *  @param sha      hash output
 *  @param com      Pi-Affp commitments
 */
void PiAffp_hash_commits(hash256 *sha, PiAffp_COMMITS *com)
{
    char oct[FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    char oct2[2 * FS_2048];
    octet OCT2 = {0, sizeof(oct2), oct2};

    FF_2048_toOctet(&OCT2, com->A, 2 * FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT2);

    FF_2048_toOctet(&OCT2, com->Bx, 2 * FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT2);

    FF_2048_toOctet(&OCT2, com->By, 2 * FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT2);

    FF_2048_toOctet(&OCT, com->E, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_2048_toOctet(&OCT, com->S, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_2048_toOctet(&OCT, com->F, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_2048_toOctet(&OCT, com->T, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);
}

// non-interactive challenge generation based on the Fiat-Shamir heuristic
void PiAffp_Challenge_gen(PAILLIER_public_key *puba, PAILLIER_public_key *pubb, PEDERSEN_PUB *mod,
                           const octet *X, const octet *Y, const octet *C, const octet *D,
                          PiAffp_COMMITS *affp, CG21_SSID *ssid, octet *E)
{
    hash256 sha;
    BIG_256_56 q;
    BIG_256_56 t;

    HASH256_init(&sha);

    // Process Paillier keys (Prover and Verifier) and Ring Pedersen parameters
    CG21_hash_pubKey2x_pubCom(&sha, puba, pubb, mod);

    /* Bind to proof input */
    HASH_UTILS_hash_oct(&sha, C);
    HASH_UTILS_hash_oct(&sha, D);
    HASH_UTILS_hash_oct(&sha, X);
    HASH_UTILS_hash_oct(&sha, Y);

    /* Bind to proof commitment */
    PiAffp_hash_commits(&sha, affp);

    /* Bind to SSID */
    int rc = CG21_hash_SSID(ssid, &sha);
    if (rc != CG21_OK){
        exit(rc);
    }

    /* Output */
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    HASH_UTILS_rejection_sample_mod_BIG(&sha, q, t);

    BIG_256_56_toBytes(E->val, t);
    E->len = EGS_SECP256K1;

}

void PiAffp_Prove(PAILLIER_public_key *prover_paillier_pub, PAILLIER_public_key *verifier_paillier_pub, PiAffp_SECRETS *secrets,
                  octet *x, octet *y, octet *rho, octet *rho_x, octet *rho_y,
                  octet *E, PiAffp_PROOFS *proofs, PiAffp_PROOFS_OCT *proofsOct)
{
    // ------------ VARIABLE DEFINITION ----------
    BIG_1024_58 hws[HFLEN_2048];
    BIG_1024_58 ws[FFLEN_2048];
    BIG_1024_58 dws[2*FFLEN_2048];

    BIG_1024_58 n[FFLEN_2048];
    BIG_1024_58 e[HFLEN_2048];
    BIG_1024_58 e_[FFLEN_2048];

    char oct[2*FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    char oct3[FS_2048];
    octet OCT3 = {0, sizeof(oct3), oct3};

    char oct2[FS_2048];
    octet OCT2 = {0, sizeof(oct2), oct2};

    // ------------ READ INPUTS ----------
    OCT_copy(&OCT, E);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(e, &OCT, HFLEN_2048);

    // Compute w = r * rho^e mod N0
    OCT_copy(&OCT, rho);
    FF_2048_zero(dws, 2*FFLEN_2048);
    FF_2048_fromOctet(dws, &OCT, FFLEN_2048);   // dws <- rho

    FF_4096_toOctet(&OCT, verifier_paillier_pub->n, HFLEN_4096);
    FF_2048_fromOctet(n, &OCT, FFLEN_2048);

    // ------------ GENERATE PiAffp_PROOFS ----------
    FF_2048_copy(ws, dws, FFLEN_2048);
    FF_2048_ct_pow(ws, ws, e, n, FFLEN_2048, HFLEN_2048);

    FF_2048_zero(dws, 2*FFLEN_2048);
    FF_2048_mul(dws, secrets->r, ws, FFLEN_2048);
    FF_2048_dmod(proofs->w, dws, n, FFLEN_2048);

    // Compute wx = rx * rho_x^e mod N0
    OCT_copy(&OCT2, rho_x);
    FF_2048_fromOctet(ws, &OCT2, FFLEN_2048);   // ws <- rho_x

    FF_4096_toOctet(&OCT, prover_paillier_pub->n, HFLEN_4096);
    FF_2048_fromOctet(n, &OCT, FFLEN_2048);

    FF_2048_mod(ws, n, FFLEN_2048);
    FF_2048_ct_pow(ws, ws, e, n, FFLEN_2048, HFLEN_2048);   // ws <- rho_x^e

    FF_2048_zero(dws, 2*FFLEN_2048);
    FF_2048_mul(dws, secrets->rx, ws, FFLEN_2048);
    FF_2048_dmod(proofs->wx, dws, n, FFLEN_2048);

    // Compute wy = ry * rho_y^e mod N0
    OCT_copy(&OCT2, rho_y);
    FF_2048_fromOctet(ws, &OCT2, FFLEN_2048);   // ws <- rho_y

    FF_4096_toOctet(&OCT, prover_paillier_pub->n, HFLEN_4096);
    FF_2048_fromOctet(n, &OCT, FFLEN_2048);

    FF_2048_mod(ws, n, FFLEN_2048);
    FF_2048_ct_pow(ws, ws, e, n, FFLEN_2048, HFLEN_2048);

    FF_2048_mul(dws, secrets->ry, ws, FFLEN_2048);
    FF_2048_dmod(proofs->wy, dws, n, FFLEN_2048);

    // Compute z1 = alpha + ex
    OCT_copy(&OCT, x);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(hws, &OCT, HFLEN_2048);   // hws <- x

    FF_2048_zero(proofs->z1, FFLEN_2048);
    FF_2048_mul(ws, e, hws, HFLEN_2048);
    FF_2048_add(proofs->z1, secrets->alpha, ws, HFLEN_2048);
    FF_2048_norm(proofs->z1, HFLEN_2048);

    // Compute z2 = beta + ey
    OCT_copy(&OCT, y);
    OCT_pad(&OCT, HFS_4096);
    FF_2048_fromOctet(ws, &OCT, FFLEN_2048);    // ws <- y

    OCT_copy(&OCT3, E);
    OCT_pad(&OCT3, HFS_4096);
    FF_2048_fromOctet(e_, &OCT3, FFLEN_2048);

    FF_2048_zero(dws, 2*FFLEN_2048);
    FF_2048_mul(dws, ws, e_, FFLEN_2048);   // dws <- e * m

    FF_2048_zero(proofs->z2, FFLEN_2048);
    FF_2048_add(proofs->z2, secrets->beta, dws, FFLEN_2048);
    FF_2048_norm(proofs->z2, FFLEN_2048);

    //Compute z3 = gamma + e*m
    FF_2048_zero(dws, 2*FFLEN_2048);
    CG21_FF_2048_amul(dws, e, HFLEN_2048, secrets->m, FFLEN_2048 + HFLEN_2048);
    FF_2048_copy(proofs->z3, secrets->gamma, FFLEN_2048 + HFLEN_2048);
    FF_2048_add(proofs->z3, proofs->z3, dws, FFLEN_2048 + HFLEN_2048);
    FF_2048_norm(proofs->z3, FFLEN_2048 + HFLEN_2048);

    //Compute z4 = delta + e*mu
    FF_2048_zero(dws, 2*FFLEN_2048);
    CG21_FF_2048_amul(dws, e, HFLEN_2048, secrets->mu, FFLEN_2048 + HFLEN_2048);
    FF_2048_copy(proofs->z4, secrets->delta, FFLEN_2048 + HFLEN_2048);
    FF_2048_add(proofs->z4, proofs->z4, dws, FFLEN_2048 + HFLEN_2048);
    FF_2048_norm(proofs->z4, FFLEN_2048 + HFLEN_2048);

    PiAffp_proof_toOctets(proofsOct, proofs);

    // ------------ CLEAN MEMORY ----------
    OCT_clear(&OCT);
    OCT_clear(&OCT2);
    OCT_clear(&OCT3);
    FF_2048_zero(dws, 2*FFLEN_2048);
    FF_2048_zero(ws, FFLEN_2048);
    FF_2048_zero(hws, HFLEN_2048);
}

void PiAffp_Kill_secrets(PiAffp_SECRETS *secrets){

    FF_2048_zero(secrets->alpha, HFLEN_2048);
    FF_2048_zero(secrets->beta, FFLEN_2048);
    FF_2048_zero(secrets->r, FFLEN_2048);
    FF_2048_zero(secrets->rx, 2 * FFLEN_2048);
    FF_2048_zero(secrets->ry, 2 * FFLEN_2048);
    FF_2048_zero(secrets->gamma, FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(secrets->m, FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(secrets->delta, FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(secrets->mu, FFLEN_2048 + HFLEN_2048);

}

int PiAffp_Verify(PAILLIER_private_key *verifier_paillier_priv, PAILLIER_public_key *prover_paillier_pub,
                  PEDERSEN_PRIV *pedersen_priv, octet *C, octet *D, octet *X, octet *Y,
                  PiAffp_COMMITS *commits, octet *E, PiAffp_PROOFS *proofs){

    // ------------ VARIABLE DEFINITION ---------
    int fail;

    BIG_1024_58 e[FFLEN_2048];
    BIG_1024_58 n[FFLEN_2048];

    BIG_1024_58 p_proof[FFLEN_2048];
    BIG_1024_58 q_proof[FFLEN_2048];
    BIG_1024_58 p_gt[FFLEN_2048];
    BIG_1024_58 q_gt[FFLEN_2048];
    BIG_1024_58 ws1[FFLEN_2048];
    BIG_1024_58 ws2[FFLEN_2048];
    BIG_1024_58 ws3[FFLEN_2048];

    BIG_1024_58 CC[2 * FFLEN_2048];
    BIG_1024_58 DD[2 * FFLEN_2048];
    BIG_1024_58 dws[2 * FFLEN_2048];

    BIG_512_60 ws4[FFLEN_4096];
    BIG_512_60 ws5[HFLEN_4096];
    BIG_512_60 ws6[FFLEN_4096];
    BIG_512_60 dws2[2 * FFLEN_4096];

    BIG_1024_58 q[HFLEN_2048];          //256 bits
    BIG_1024_58 q2[FFLEN_2048];         //q^2
    BIG_1024_58 q3[FFLEN_2048];         //q^3
    BIG_1024_58 q5[FFLEN_2048];         //q^5
    BIG_1024_58 q7[FFLEN_2048];         //q^7

    char oct1[2 * FS_2048];
    octet OCT1 = {0, sizeof(oct1), oct1};

    char oct2[2 * FS_2048];
    octet OCT2 = {0, sizeof(oct2), oct2};

    char oct3[2 * FS_2048];
    octet OCT3 = {0, sizeof(oct3), oct3};

    // Curve order
    CG21_GET_CURVE_ORDER(q);

    FF_2048_sqr(q2, q, HFLEN_2048);             // q^2
    FF_2048_mul(q3, q, q2, HFLEN_2048);      // q^3
    FF_2048_mul(q5, q3, q2, FFLEN_2048);     // q^5
    FF_2048_mul(q7, q5, q2, FFLEN_2048);     // q^7

    // ------------ CHECK 'z1' IS IN [0, ..., q^3] and 'z2' IS IN [0, ..., q^7]------------
    if (FF_2048_comp(proofs->z1, q3, FFLEN_2048) > 0 || FF_2048_comp(proofs->z2, q7, FFLEN_2048) > 0)
    {
        return PiAffp_INVALID_RANGE;
    }

    // load a 256-bit challenge octet e into 2048-bit big e
    OCT_copy(&OCT1, E);
    OCT_pad(&OCT1, FS_2048);
    FF_2048_fromOctet(e, &OCT1, FFLEN_2048);

    // ------------ VALIDATES THE PROOF - PART1 ----------
    // Split check s^z1 * t^z3 * S^(-e) == E mod PQ using CRT
    CG21_Pedersen_verify(p_proof, pedersen_priv, proofs->z1, proofs->z3, commits->S, e, pedersen_priv->mod.p, false);
    CG21_Pedersen_verify(q_proof, pedersen_priv, proofs->z1, proofs->z3, commits->S, e, pedersen_priv->mod.q, false);

    FF_2048_dmod(p_gt, commits->E, pedersen_priv->mod.p, HFLEN_2048);
    FF_2048_dmod(q_gt, commits->E, pedersen_priv->mod.q, HFLEN_2048);

    fail = (FF_2048_comp(p_gt, p_proof, HFLEN_2048) != 0) || (FF_2048_comp(q_gt, q_proof, HFLEN_2048) != 0);

    if (fail)
    {
        // Clean memory
        FF_2048_zero(p_gt, HFLEN_2048);
        FF_2048_zero(q_gt, HFLEN_2048);
        FF_2048_zero(p_proof, HFLEN_2048);
        FF_2048_zero(q_proof, HFLEN_2048);

        return PiAffp_INVALID_PROOF_P1;
    }

    // ------------ VALIDATES THE PROOF - PART2 ----------
    // Split check s^z2 * t^z4 * T^(-e) == F mod PQ using CRT
    CG21_Pedersen_verify(p_proof, pedersen_priv, proofs->z2, proofs->z4, commits->T, e, pedersen_priv->mod.p, 1);
    CG21_Pedersen_verify(q_proof, pedersen_priv, proofs->z2, proofs->z4, commits->T, e, pedersen_priv->mod.q, 1);

    FF_2048_dmod(p_gt, commits->F, pedersen_priv->mod.p, HFLEN_2048);
    FF_2048_dmod(q_gt, commits->F, pedersen_priv->mod.q, HFLEN_2048);
    fail = (FF_2048_comp(p_gt, p_proof, HFLEN_2048) != 0) || (FF_2048_comp(q_gt, q_proof, HFLEN_2048) != 0);

    if (fail)
    {
        // ------------ CLEAR MEMORY ----------
        FF_2048_zero(p_gt, HFLEN_2048);
        FF_2048_zero(q_gt, HFLEN_2048);
        FF_2048_zero(p_proof, HFLEN_2048);
        FF_2048_zero(q_proof, HFLEN_2048);

        return PiAffp_INVALID_PROOF_P2;
    }

    // ------------ VALIDATES THE PROOF - PART3 ----------
    // Split check C^z1 * w^N0 * g^z2 * D^(-e) == A mod N0^2 using CRT

    FF_2048_mul(n, verifier_paillier_priv->p, verifier_paillier_priv->q, HFLEN_2048);     // n = p * q

    FF_2048_fromOctet(CC, C, 2 * FFLEN_2048);
    FF_2048_fromOctet(DD, D, 2 * FFLEN_2048);

    // CRT: check modulo p^2
    FF_2048_copy(ws3, verifier_paillier_priv->p2, FFLEN_2048); // ws3 := p^2
    FF_2048_zero(ws1, FFLEN_2048);
    FF_2048_copy(ws1, verifier_paillier_priv->p, HFLEN_2048);  // ws1 := p
    FF_2048_sub(ws3, ws3, ws1, FFLEN_2048);                  // ws3 := p^2 - p

    //https://math.stackexchange.com/a/3099042
    FF_2048_sub(ws3, ws3, e, FFLEN_2048);                    // ws3 := p^2 - p - e
    FF_2048_norm(ws3, FFLEN_2048);

    FF_2048_dmod(ws1, CC, verifier_paillier_priv->p2, FFLEN_2048);  // ws1 = C mod p^2
    FF_2048_dmod(ws2, DD, verifier_paillier_priv->p2, FFLEN_2048);  // ws2 = D mod p^2

    // p_proof := C^z1 * w^N0 * D^-e modulo p^2 = (C mod p^2)^e * w^N0 * (D mod p^2)^{p^2 - p - e} mod p^2
    FF_2048_ct_pow_3(p_proof, ws1, proofs->z1, proofs->w, n, ws2, ws3,
                     verifier_paillier_priv->p2, FFLEN_2048, FFLEN_2048);

    FF_2048_mul(dws, n, proofs->z2, FFLEN_2048);                        // dws := n * z2
    FF_2048_dmod(ws1, dws, verifier_paillier_priv->p2, FFLEN_2048);     // ws1 := (n * z2) mod p^2
    FF_2048_inc(ws1, 1, FFLEN_2048);                                      // ws1 := (n * z2) mod p^2 + 1
    FF_2048_norm(ws1, FFLEN_2048);

    // dws := ((n * z2) mod p^2 + 1) * p_proof
    FF_2048_mul(dws, p_proof, ws1, FFLEN_2048);
    FF_2048_dmod(p_proof, dws, verifier_paillier_priv->p2, FFLEN_2048); // dws := dws mod p^2

    // CRT: check modulo q^2
    FF_2048_copy(ws3, verifier_paillier_priv->q2, FFLEN_2048);
    FF_2048_zero(ws1, FFLEN_2048);
    FF_2048_copy(ws1, verifier_paillier_priv->q, HFLEN_2048);
    FF_2048_sub(ws3, ws3, ws1, FFLEN_2048);
    FF_2048_sub(ws3, ws3, e, FFLEN_2048);
    FF_2048_norm(ws3, FFLEN_2048);

    FF_2048_dmod(ws1, CC, verifier_paillier_priv->q2, FFLEN_2048);
    FF_2048_dmod(ws2, DD, verifier_paillier_priv->q2, FFLEN_2048);

    // // C^z1 * w^N0 * D^-e modulo q^2
    FF_2048_ct_pow_3(q_proof, ws1, proofs->z1, proofs->w, n, ws2, ws3,
                     verifier_paillier_priv->q2, FFLEN_2048, FFLEN_2048);

    FF_2048_zero(dws, 2 * FFLEN_2048);
    FF_2048_mul(dws, n, proofs->z2, FFLEN_2048);
    FF_2048_dmod(ws1, dws, verifier_paillier_priv->q2, FFLEN_2048);
    FF_2048_inc(ws1, 1, FFLEN_2048);

    FF_2048_zero(dws, 2 * FFLEN_2048);
    FF_2048_mul(dws, q_proof, ws1, FFLEN_2048);
    FF_2048_dmod(q_proof, dws, verifier_paillier_priv->q2, FFLEN_2048);

    FF_2048_dmod(p_gt, commits->A, verifier_paillier_priv->p2, FFLEN_2048);     // p_gt := A mod p^2
    FF_2048_dmod(q_gt, commits->A, verifier_paillier_priv->q2, FFLEN_2048);     // q_gt := A mod q^2

    fail = (FF_2048_comp(p_gt, p_proof, FFLEN_2048) != 0) ||
           (FF_2048_comp(q_gt, q_proof, FFLEN_2048) != 0);

    if (fail)
    {
        // ------------ CLEAR MEMORY ----------
        FF_2048_zero(p_gt, FFLEN_2048);
        FF_2048_zero(q_gt, FFLEN_2048);
        FF_2048_zero(p_proof, FFLEN_2048);
        FF_2048_zero(q_proof, FFLEN_2048);
        FF_2048_zero(ws1, FFLEN_2048);
        FF_2048_zero(ws2, FFLEN_2048);
        FF_2048_zero(ws3, FFLEN_2048);
        FF_2048_zero(dws, 2 * FFLEN_2048);

        return PiAffp_INVALID_PROOF_P3;
    }

    // ------------ VALIDATES THE PROOF - PART4 ----------
    // (1+N1)^z1 * wx^N1 = Bx * X^e mod N1^2

    FF_2048_toOctet(&OCT1, proofs->wx, FFLEN_2048);
    OCT_pad(&OCT1, FS_4096);

    FF_2048_toOctet(&OCT2, proofs->z1, FFLEN_2048);
    OCT_pad(&OCT2, HFS_4096);

    OCT_empty(&OCT3);
    PAILLIER_ENCRYPT(NULL, prover_paillier_pub, &OCT2, &OCT3,&OCT1); // OCT3 := (1+N1)^z1 * wx^N1

    OCT_pad(X, HFS_4096);
    FF_4096_fromOctet(ws4, X, FFLEN_4096);

    OCT_copy(&OCT1, E);
    OCT_pad(&OCT1, FS_2048);
    FF_4096_fromOctet(ws5, &OCT1, HFLEN_4096);

    // ws4 := X^e mod N1^2
    FF_4096_ct_pow(ws4, ws4, ws5, prover_paillier_pub->n2, FFLEN_4096, HFLEN_4096);

    FF_2048_toOctet(&OCT1, commits->Bx, 2 * FFLEN_2048);
    FF_4096_fromOctet(ws6,&OCT1, FFLEN_4096);

    FF_4096_zero(dws2, 2 * FFLEN_4096);
    FF_4096_mul(dws2, ws4, ws6, FFLEN_4096); // dws2 := (X^e mod N1^2) * Bx
    FF_4096_dmod(ws4, dws2, prover_paillier_pub->n2, FFLEN_4096); // := (X^e mod N1^2) * Bx mod N1^2

    FF_4096_fromOctet(ws6,&OCT3, FFLEN_4096);
    fail = (FF_4096_comp(ws4, ws6, FFLEN_2048) != 0);


    if (fail)
    {
        // ------------ CLEAR MEMORY ----------
        FF_2048_zero(p_gt, FFLEN_2048);
        FF_2048_zero(q_gt, FFLEN_2048);
        FF_2048_zero(p_proof, FFLEN_2048);
        FF_2048_zero(q_proof, FFLEN_2048);
        FF_2048_zero(ws1, FFLEN_2048);
        FF_2048_zero(ws2, FFLEN_2048);
        FF_2048_zero(ws3, FFLEN_2048);
        FF_2048_zero(dws, 2 * FFLEN_2048);

        return PiAffp_INVALID_PROOF_P4;
    }

    // ------------ VALIDATES THE PROOF - PART5 ----------
    // Gamma^z2 * wy^N1 = By * Y^e mod N1^2

    FF_2048_toOctet(&OCT1, proofs->wy, FFLEN_2048);
    OCT_pad(&OCT1, FS_4096);

    FF_2048_toOctet(&OCT2, proofs->z2, FFLEN_2048);
    OCT_pad(&OCT2, HFS_4096);

    OCT_empty(&OCT3);
    PAILLIER_ENCRYPT(NULL, prover_paillier_pub, &OCT2, &OCT3,&OCT1); // OCT3 := Gamma^z2 * wy^N1

    OCT_pad(Y, HFS_4096);
    FF_4096_fromOctet(ws4, Y, FFLEN_4096);

    OCT_copy(&OCT1, E);
    OCT_pad(&OCT1, FS_2048);
    FF_4096_fromOctet(ws5, &OCT1, HFLEN_4096);

    // ws4 := Y^e mod N1^2
    FF_4096_ct_pow(ws4, ws4, ws5, prover_paillier_pub->n2, FFLEN_4096, HFLEN_4096);

    FF_2048_toOctet(&OCT1, commits->By, 2 * FFLEN_2048);
    FF_4096_fromOctet(ws6,&OCT1, FFLEN_4096);

    FF_4096_zero(dws2, 2 * FFLEN_4096);
    FF_4096_mul(dws2, ws4, ws6, FFLEN_4096);                        // (Y^e mod N1^2) * By
    FF_4096_dmod(ws4, dws2, prover_paillier_pub->n2, FFLEN_4096);   // (Y^e mod N1^2) * By mod N1^2

    FF_4096_fromOctet(ws6,&OCT3, FFLEN_4096);
    fail = (FF_4096_comp(ws4, ws6, FFLEN_2048) != 0);

    // ------------ CLEAR MEMORY ----------
    FF_2048_zero(p_gt, FFLEN_2048);
    FF_2048_zero(q_gt, FFLEN_2048);
    FF_2048_zero(p_proof, FFLEN_2048);
    FF_2048_zero(q_proof, FFLEN_2048);
    FF_2048_zero(ws1, FFLEN_2048);
    FF_2048_zero(ws2, FFLEN_2048);
    FF_2048_zero(ws3, FFLEN_2048);
    FF_2048_zero(dws, 2 * FFLEN_2048);

    if (fail)
        return PiAffp_INVALID_PROOF_P5;

    // recall: we already checked 'z1' is in [0, ..., q^3] and 'z2' is in[0, ..., q^7] above

    return PiAffp_OK;
}
