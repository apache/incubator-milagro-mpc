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
 * @file bit_commitment.c
 * @brief ZKP for Polynomial Relations based on the Bit Commitment
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "amcl/bit_commitment.h"
#include "amcl/hash_utils.h"

static char* curve_order_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

/* Remark 1
 *
 * The generation of some random blinding values in this file uses
 * a modular reduction, producing a slightly biased distribution.
 * However, the random numbers reduced have significatively more
 * bits of entropy than the modulus, making this bias negligible.
 *
 * In particular we have moduli
 * |q^3|    ~ 768
 * |Nt*q|   ~ 2048 + 256
 * |Nt*q^3| ~ 2048 + 768
 *
 * used (respectively) to reduce random numbers of size 1024, 3096
 * and 3096. Each of these random numbers has at least 256 bits of
 * extra entropy, making the exploitation of this bias not viable.
 */

/* FF manipulation utilities
 *
 * These might be nice additions to milagro-crypto-c ff API
 *
 * TODO in milagro-crypto-c
 *  - Add asymmetric mul/mod using the internal ff api
 */

// Asymmetric mul. Assuming xlen * k = ylen for some integer k
//
// Efficiently compute product by breaking up y in k chunks of length xlen
// and computing the product separately. r must be different from x and y and
// it must have length at least rlen = xlen + ylen
void FF_2048_amul(BIG_1024_58 *r, BIG_1024_58 *x, int xlen, BIG_1024_58 *y, int ylen)
{
    int i;
    int rlen = xlen+ylen;

#ifndef C99
    BIG_1024_58 t[2*FFLEN_2048];
#else
    BIG_1024_58 t[rlen];
#endif

    FF_2048_zero(r, rlen);

    for (i = 0; i < ylen; i+=xlen)
    {
        FF_2048_zero(t, rlen);
        FF_2048_mul(t+i, x, y+i, xlen);
        FF_2048_add(r, r, t, rlen);
    }
}

// Asymmetric mod. Assuming plen * k = xlen for some integer k
//
// Starting from the top of x, select the top 2 * plen BIGs and reduce
// them mod p, reducing the length of x by a plen until x is completely reduced.
void FF_2048_amod(BIG_1024_58 *r, BIG_1024_58 *x, int xlen, BIG_1024_58 *p, int plen)
{
    int i;

#ifndef C99
    BIG_1024_58 t[2*FFLEN_2048];
#else
    BIG_1024_58 t[xlen];
#endif

    FF_2048_copy(t, x, xlen);

    for (i = xlen - 2*plen; i >= 0; i--)
    {
        FF_2048_dmod(t+i, t+i, p, plen);
    }

    FF_2048_copy(r, t, plen);
}

// Utility function to compute the triple power for verification purposes.
// h1^s1 * h2^s2 * z^(-e) mod P
//
// h1, h2 are reduced modulo P
// s1 is reduced modulo P-1 if indicated
// s2 is reduced modulo P-1
// z is reduced and inverted modulo P
// e is left as is
void BIT_COMMITMENT_triple_power(BIG_1024_58 *proof, BIG_1024_58 *h1, BIG_1024_58 *h2, BIG_1024_58 *s1, BIG_1024_58 *s2, BIG_1024_58 *z, BIG_1024_58 *e, BIG_1024_58 *p, int reduce_s1)
{
    BIG_1024_58 hws1[HFLEN_2048];
    BIG_1024_58 hws2[HFLEN_2048];
    BIG_1024_58 hws3[HFLEN_2048];
    BIG_1024_58 hws4[HFLEN_2048];
    BIG_1024_58 eneg[HFLEN_2048];

    FF_2048_copy(hws1, p, HFLEN_2048);
    FF_2048_dec(hws1, 1, HFLEN_2048);
    FF_2048_amod(hws4, s2, FFLEN_2048 + HFLEN_2048, hws1, HFLEN_2048);
    FF_2048_sub(eneg, hws1, e, HFLEN_2048);
    FF_2048_norm(eneg, HFLEN_2048);

    if (reduce_s1)
    {
        FF_2048_dmod(hws3, s1, hws1, HFLEN_2048);
    }
    else
    {
        FF_2048_copy(hws3, s1, HFLEN_2048);
    }

    FF_2048_dmod(hws1, h1, p, HFLEN_2048);
    FF_2048_dmod(hws2, h2, p, HFLEN_2048);

    FF_2048_dmod(proof, z, p, HFLEN_2048);
    FF_2048_ct_pow_3(proof, hws1, hws3, hws2, hws4, proof, eneg, p, HFLEN_2048, HFLEN_2048);

    // Clean memory
    FF_2048_zero(hws1, HFLEN_2048);
    FF_2048_zero(hws2, HFLEN_2048);
    FF_2048_zero(hws3, HFLEN_2048);
    FF_2048_zero(hws4, HFLEN_2048);
}


/* Hash helpers for challenge functions */

void BIT_COMMITMENT_hash_params(hash256 *sha, PAILLIER_public_key *key, BIT_COMMITMENT_pub *m)
{
    char oct[FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    // Process Paillier Public key
    FF_4096_toOctet(&OCT, key->n, HFLEN_4096);
    HASH_UTILS_hash_oct(sha, &OCT);

    // Process Bit Commitment modulus
    FF_2048_toOctet(&OCT, m->N, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_2048_toOctet(&OCT, m->b0, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_2048_toOctet(&OCT, m->b1, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);
}

void BIT_COMMITMENT_hash_commitment(hash256 *sha, BIT_COMMITMENT_commitment *c)
{
    char oct[2 * FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    FF_2048_toOctet(&OCT, c->z, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_4096_toOctet(&OCT, c->u, FFLEN_4096);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_2048_toOctet(&OCT, c->w, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);
}

void BIT_COMMITMENT_hash_muladd_commitment(hash256 *sha, BIT_COMMITMENT_muladd_commitment *c)
{
    char oct[2 * FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    FF_2048_toOctet(&OCT, c->z, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_2048_toOctet(&OCT, c->z1, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_2048_toOctet(&OCT, c->t, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_2048_toOctet(&OCT, c->v, 2 * FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_2048_toOctet(&OCT, c->w, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);
}

/* ZKP of knowledge and range of Paillier Ciphertext */

void BIT_COMMITMENT_commit(csprng *RNG, PAILLIER_private_key *key, BIT_COMMITMENT_pub *m, octet *X, BIT_COMMITMENT_rv *rv, BIT_COMMITMENT_commitment *c)
{
    BIG_1024_58 n[FFLEN_2048];
    BIG_1024_58 q[HFLEN_2048];
    BIG_1024_58 invp2q2[FFLEN_2048];
    BIG_1024_58 n2[2 * FFLEN_2048];

    BIG_1024_58 ws1[FFLEN_2048];
    BIG_1024_58 ws2[FFLEN_2048];
    BIG_1024_58 ws3[FFLEN_2048];
    BIG_1024_58 dws1[2 * FFLEN_2048];
    BIG_1024_58 dws2[2 * FFLEN_2048];

    char oct[2 * FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    // Curve order
    OCT_fromHex(&OCT, curve_order_hex);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(q, &OCT, HFLEN_2048);

    FF_2048_mul(n, key->p, key->q, HFLEN_2048);
    FF_2048_sqr(n2, n, FFLEN_2048);
    FF_2048_norm(n2, 2 * FFLEN_2048);
    FF_2048_invmodp(invp2q2, key->p2, key->q2, FFLEN_2048);

    if (RNG != NULL)
    {
        FF_2048_sqr(ws1, q, HFLEN_2048);
        FF_2048_mul(ws2, q, ws1, HFLEN_2048);

        // Generate alpha in [0, .., q^3]
        // See Remark 1 at the top for more information
        FF_2048_zero(rv->alpha, FFLEN_2048);
        FF_2048_random(rv->alpha, RNG, HFLEN_2048);
        FF_2048_mod(rv->alpha, ws2, HFLEN_2048);

        // Generate beta in [0, .., N]
        FF_2048_randomnum(rv->beta, n, RNG, FFLEN_2048);

        // Generate gamma in [0, .., Nt * q^3]
        // See Remark 1 at the top for more information
        FF_2048_amul(dws1, ws2, HFLEN_2048, m->N, FFLEN_2048);
        FF_2048_random(rv->gamma, RNG, FFLEN_2048 + HFLEN_2048);
        FF_2048_mod(rv->gamma, dws1, FFLEN_2048 + HFLEN_2048);

        // Generate rho in [0, .., Nt * q]
        // See Remark 1 at the top for more information
        FF_2048_amul(dws1, q, HFLEN_2048, m->N, FFLEN_2048);
        FF_2048_random(rv->rho, RNG, FFLEN_2048 + HFLEN_2048);
        FF_2048_mod(rv->rho, dws1, FFLEN_2048 + HFLEN_2048);
    }

    // Read input
    OCT_copy(&OCT, X);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_zero(dws1, FFLEN_2048 + HFLEN_2048);
    FF_2048_fromOctet(dws1, &OCT, HFLEN_2048);

    // Compute z and w
    FF_2048_ct_pow_2(c->z, m->b0, dws1, m->b1, rv->rho, m->N, FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    FF_2048_copy(dws1, rv->alpha, HFLEN_2048);
    FF_2048_ct_pow_2(c->w, m->b0, dws1, m->b1, rv->gamma, m->N, FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    // Compute u using CRT and Paillier PK trick

    // Compute 1 + n * alpha
    // Defer the increment after the modular reduction so it can
    // be performed without conversion to FF_4096
    FF_2048_zero(dws2, 2 * FFLEN_2048);
    FF_2048_amul(dws2, rv->alpha, HFLEN_2048, n, FFLEN_2048);

    // Compute mod P^2
    FF_2048_dmod(ws3, dws2, key->p2, FFLEN_2048);
    FF_2048_inc(ws3, 1, FFLEN_2048);
    FF_2048_norm(ws3, FFLEN_2048);

    FF_2048_ct_pow(ws1, rv->beta, n, key->p2, FFLEN_2048, FFLEN_2048);

    FF_2048_mul(dws1, ws1, ws3, FFLEN_2048);
    FF_2048_dmod(ws1, dws1, key->p2, FFLEN_2048);

    // Compute mod Q^2
    FF_2048_dmod(ws3, dws2, key->q2, FFLEN_2048);
    FF_2048_inc(ws3, 1, FFLEN_2048);
    FF_2048_norm(ws3, FFLEN_2048);

    FF_2048_ct_pow(ws2, rv->beta, n, key->q2, FFLEN_2048, FFLEN_2048);

    FF_2048_mul(dws1, ws2, ws3, FFLEN_2048);
    FF_2048_dmod(ws2, dws1, key->q2, FFLEN_2048);

    // Combine results
    FF_2048_crt(dws1, ws1, ws2, key->p2, invp2q2, n2, FFLEN_2048);

    // Convert u as FF_4096 since it is only used as such
    FF_2048_toOctet(&OCT, dws1, 2 * FFLEN_2048);
    FF_4096_fromOctet(c->u, &OCT, FFLEN_4096);

    // Clean memory
    FF_2048_zero(dws2, 2 * FFLEN_2048);
    FF_2048_zero(ws1, HFLEN_2048);
    FF_2048_zero(ws2, HFLEN_2048);
    FF_2048_zero(ws3, HFLEN_2048);
}

void BIT_COMMITMENT_prove(PAILLIER_private_key *key, octet *X, octet *R, BIT_COMMITMENT_rv *rv, octet *E, BIT_COMMITMENT_proof *p)
{
    BIG_1024_58 ws1[FFLEN_2048];
    BIG_1024_58 ws2[FFLEN_2048];
    BIG_1024_58 hws[HFLEN_2048];

    BIG_1024_58 r[2*FFLEN_2048];
    BIG_1024_58 e[HFLEN_2048];
    BIG_1024_58 m[HFLEN_2048];

    BIG_1024_58 sp[HFLEN_2048];
    BIG_1024_58 sq[HFLEN_2048];

    char oct[2*FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    // Read inputs
    OCT_copy(&OCT, X);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(m, &OCT, HFLEN_2048);

    OCT_copy(&OCT, R);
    FF_2048_fromOctet(r, &OCT, 2*FFLEN_2048);

    OCT_copy(&OCT, E);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(e, &OCT, HFLEN_2048);

    // Compute s = beta * r^e mod N using CRT
    FF_2048_amod(hws, r, 2*FFLEN_2048, key->p, HFLEN_2048);
    FF_2048_dmod(sp, rv->beta, key->p, HFLEN_2048);
    FF_2048_nt_pow(hws, hws, e, key->p, HFLEN_2048, HFLEN_2048);
    FF_2048_mul(ws1, sp, hws,  HFLEN_2048);
    FF_2048_dmod(sp, ws1, key->p, HFLEN_2048);

    FF_2048_amod(hws, r, 2*FFLEN_2048, key->q, HFLEN_2048);
    FF_2048_dmod(sq, rv->beta, key->q, HFLEN_2048);
    FF_2048_nt_pow(hws, hws, e, key->q, HFLEN_2048, HFLEN_2048);
    FF_2048_mul(ws1, sq, hws,  HFLEN_2048);
    FF_2048_dmod(sq, ws1, key->q, HFLEN_2048);

    FF_2048_mul(ws2, key->p, key->q, HFLEN_2048);
    FF_2048_crt(ws1, sp, sq, key->p, key->invpq, ws2, HFLEN_2048);

    // Convert s to FF_4096 since it is only used as such
    FF_2048_toOctet(&OCT, ws1, FFLEN_2048);
    OCT_pad(&OCT, FS_4096);
    FF_4096_fromOctet(p->s, &OCT, FFLEN_4096);

    // Compute s1 = e*m + alpha
    FF_2048_mul(ws1, e, m, HFLEN_2048);
    FF_2048_copy(p->s1, rv->alpha, FFLEN_2048);
    FF_2048_add(p->s1, p->s1, ws1, FFLEN_2048);
    FF_2048_norm(p->s1, FFLEN_2048);

    // Compute s2 = e*rho + gamma
    FF_2048_amul(r, e, HFLEN_2048, rv->rho, FFLEN_2048 + HFLEN_2048);
    FF_2048_copy(p->s2, rv->gamma, FFLEN_2048 + HFLEN_2048);
    FF_2048_add(p->s2, p->s2, r, FFLEN_2048 + HFLEN_2048);
    FF_2048_norm(p->s2, FFLEN_2048 + HFLEN_2048);

    // Clean memory
    FF_2048_zero(r, 2*FFLEN_2048);
    FF_2048_zero(ws1, FFLEN_2048);
    FF_2048_zero(ws2, FFLEN_2048);
    FF_2048_zero(sp, HFLEN_2048);
    FF_2048_zero(sq, HFLEN_2048);
    FF_2048_zero(m, HFLEN_2048);
}

int BIT_COMMITMENT_verify(PAILLIER_public_key *key, BIT_COMMITMENT_priv *m, octet *CT, BIT_COMMITMENT_commitment *c, octet *E, BIT_COMMITMENT_proof *p)
{
    int fail;

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

    // Read challenge
    OCT_copy(&OCT, E);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(e, &OCT, HFLEN_2048);
    OCT_pad(&OCT, HFS_4096);
    FF_4096_fromOctet(e_4096, &OCT, HFLEN_4096);

    // Read q and compute q^3
    OCT_fromHex(&OCT, curve_order_hex);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(hws1, &OCT, HFLEN_2048);
    FF_2048_sqr(ws, hws1, HFLEN_2048);
    FF_2048_mul(ws, ws, hws1, HFLEN_2048);

    if (FF_2048_comp(p->s1, ws, FFLEN_2048) > 0)
    {
        return BIT_COMMITMENT_FAIL;
    }

    // Split computation of proof for w using CRT.
    BIT_COMMITMENT_triple_power(wp_proof, m->b0, m->b1, p->s1, p->s2, c->z, e, m->mod.p, false);
    BIT_COMMITMENT_triple_power(wq_proof, m->b0, m->b1, p->s1, p->s2, c->z, e, m->mod.q, false);

    // Reduce w mod P and Q for comparison
    FF_2048_dmod(hws1, c->w, m->mod.p, HFLEN_2048);
    FF_2048_dmod(hws2, c->w, m->mod.q, HFLEN_2048);

    // Compare the results modulo P and Q
    // since w == w' mod PQ <==> w == w' mod P & w == w' mod Q
    fail = (FF_2048_comp(hws1, wp_proof, HFLEN_2048) != 0) || (FF_2048_comp(hws2, wq_proof, HFLEN_2048) != 0);

    // Clean memory
    FF_2048_zero(hws1, HFLEN_2048);
    FF_2048_zero(hws2, HFLEN_2048);
    FF_2048_zero(wp_proof, HFLEN_2048);
    FF_2048_zero(wq_proof, HFLEN_2048);

    if(fail)
    {
        return BIT_COMMITMENT_FAIL;
    }

    // Compute verification for u
    FF_2048_toOctet(&OCT, p->s1, HFLEN_2048);
    OCT_pad(&OCT, HFS_4096);
    FF_4096_fromOctet(s1, &OCT, HFLEN_4096);

    FF_4096_fromOctet(ws1_4096, CT, FFLEN_4096);
    FF_4096_invmodp(ws1_4096, ws1_4096, key->n2, FFLEN_4096);

    // u_proof = g^s1 * s^N * c^(-e) mod N^2
    FF_4096_mul(ws2_4096, key->n, s1, HFLEN_4096);
    FF_4096_inc(ws2_4096, 1, FFLEN_4096);
    FF_4096_norm(ws2_4096, FFLEN_4096);
    FF_4096_nt_pow_2(ws1_4096, p->s, key->n, ws1_4096, e_4096, key->n2, FFLEN_4096, HFLEN_4096);
    FF_4096_mul(dws_4096, ws1_4096, ws2_4096, FFLEN_4096);
    FF_4096_dmod(ws1_4096, dws_4096, key->n2, FFLEN_4096);

    if(FF_4096_comp(ws1_4096, c->u, FFLEN_4096) != 0)
    {
        return BIT_COMMITMENT_FAIL;
    }

    return BIT_COMMITMENT_OK;
}

void BIT_COMMITMENT_commitment_toOctets(octet *Z, octet *U, octet *W, BIT_COMMITMENT_commitment *c)
{
    FF_2048_toOctet(Z, c->z, FFLEN_2048);
    FF_4096_toOctet(U, c->u, FFLEN_4096);
    FF_2048_toOctet(W, c->w, FFLEN_2048);
}

void BIT_COMMITMENT_commitment_fromOctets(BIT_COMMITMENT_commitment *c, octet *Z, octet *U, octet *W)
{
    FF_2048_fromOctet(c->z, Z, FFLEN_2048);
    FF_4096_fromOctet(c->u, U, FFLEN_4096);
    FF_2048_fromOctet(c->w, W, FFLEN_2048);
}

void BIT_COMMITMENT_proof_toOctets(octet *S, octet *S1, octet *S2, BIT_COMMITMENT_proof *p)
{
    FF_4096_toOctet(S,  p->s,  HFLEN_4096);
    FF_2048_toOctet(S1, p->s1, HFLEN_2048);
    FF_2048_toOctet(S2, p->s2, FFLEN_2048 + HFLEN_2048);
}

void BIT_COMMITMENT_proof_fromOctets(BIT_COMMITMENT_proof *p, octet *S, octet *S1, octet *S2)
{
    FF_2048_zero(p->s1, FFLEN_2048);
    FF_4096_zero(p->s, FFLEN_4096);

    FF_4096_fromOctet(p->s,  S,  HFLEN_4096);
    FF_2048_fromOctet(p->s1, S1, HFLEN_2048);
    FF_2048_fromOctet(p->s2, S2, FFLEN_2048 + HFLEN_2048);
}

void BIT_COMMITMENT_rv_kill(BIT_COMMITMENT_rv *rv)
{
    FF_2048_zero(rv->alpha, HFLEN_2048);
    FF_2048_zero(rv->beta,  FFLEN_2048);
    FF_2048_zero(rv->gamma, FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(rv->rho,   FFLEN_2048 + HFLEN_2048);
}

/* ZKP of Knowledge and range of Paillier homomorphic mul/add */

void BIT_COMMITMENT_muladd_commit(csprng *RNG, PAILLIER_public_key *key, BIT_COMMITMENT_pub *m, octet *X, octet *Y, octet *C1, BIT_COMMITMENT_muladd_rv *rv, BIT_COMMITMENT_muladd_commitment *c)
{
    BIG_1024_58 q[HFLEN_2048];
    BIG_1024_58 q3[FFLEN_2048];
    BIG_1024_58 tws[FFLEN_2048 + HFLEN_2048];

    BIG_512_60 alpha[HFLEN_4096];
    BIG_512_60 beta[FFLEN_4096];
    BIG_512_60 gamma[HFLEN_4096];
    BIG_512_60 ws1[FFLEN_4096];
    BIG_512_60 ws2[FFLEN_4096];
    BIG_512_60 dws[2 * FFLEN_4096];

    char oct[2 * FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    // Curve order
    OCT_fromHex(&OCT, curve_order_hex);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(q, &OCT, HFLEN_2048);

    // Zero out beta since it's needed regardless of RNG
    FF_4096_zero(beta, FFLEN_4096);

    if (RNG != NULL)
    {
        FF_2048_sqr(q3, q, HFLEN_2048);
        FF_2048_mul(q3, q, q3, HFLEN_2048);

        // Generate alpha in [0, .., q^3]
        // See Remark 1 at the top for more information
        FF_2048_zero(rv->alpha, FFLEN_2048);
        FF_2048_random(rv->alpha, RNG, HFLEN_2048);
        FF_2048_mod(rv->alpha, q3, HFLEN_2048);

        // Generate beta in [0, .., N]
        FF_4096_randomnum(beta, key->n, RNG, HFLEN_4096);
        FF_4096_toOctet(&OCT, beta, HFLEN_4096);
        FF_2048_fromOctet(rv->beta, &OCT, FFLEN_2048);

        // Generate gamma in [0, .., N]
        FF_4096_randomnum(gamma, key->n, RNG, HFLEN_4096);
        FF_4096_toOctet(&OCT, gamma, HFLEN_4096);
        FF_2048_fromOctet(rv->gamma, &OCT, FFLEN_2048);

        // Generate rho, tau, sigma in [0, .., Nt * q]
        // See Remark 1 at the top for more information
        FF_2048_amul(tws, q, HFLEN_2048, m->N, FFLEN_2048);
        FF_2048_random(rv->rho, RNG, FFLEN_2048 + HFLEN_2048);
        FF_2048_mod(rv->rho, tws, FFLEN_2048 + HFLEN_2048);

        FF_2048_random(rv->tau, RNG, FFLEN_2048 + HFLEN_2048);
        FF_2048_mod(rv->tau, tws, FFLEN_2048 + HFLEN_2048);

        FF_2048_random(rv->sigma, RNG, FFLEN_2048 + HFLEN_2048);
        FF_2048_mod(rv->sigma, tws, FFLEN_2048 + HFLEN_2048);

        // Generate rho1 in [0, .., Nt * q^3]
        // See Remark 1 at the top for more information
        FF_2048_amul(tws, q3, HFLEN_2048, m->N, FFLEN_2048);
        FF_2048_random(rv->rho1, RNG, FFLEN_2048 + HFLEN_2048);
        FF_2048_mod(rv->rho1, tws, FFLEN_2048 + HFLEN_2048);
    }
    else
    {
        FF_2048_toOctet(&OCT, rv->beta, FFLEN_2048);
        FF_4096_fromOctet(beta, &OCT, HFLEN_4096);

        FF_2048_toOctet(&OCT, rv->gamma, FFLEN_2048);
        FF_4096_fromOctet(gamma, &OCT, HFLEN_4096);
    }

    // Compute z = h1^x * h2^rho mod Nt
    OCT_copy(&OCT, X);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_zero(tws, FFLEN_2048 + HFLEN_2048);
    FF_2048_fromOctet(tws, &OCT, HFLEN_2048);
    FF_2048_ct_pow_2(c->z, m->b0, tws, m->b1, rv->rho, m->N, FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    // Compute t = h1^y * h2^sigma mod Nt
    OCT_copy(&OCT, Y);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(tws, &OCT, HFLEN_2048);
    FF_2048_ct_pow_2(c->t, m->b0, tws, m->b1, rv->sigma, m->N, FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    // Compute z1 = h1^alpha * h2^rho1 mod Nt and
    FF_2048_copy(tws, rv->alpha, HFLEN_2048);
    FF_2048_ct_pow_2(c->z1, m->b0, tws, m->b1, rv->rho1, m->N, FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    // Compute w = h1^gamma * h2^tau mod Nt
    FF_2048_copy(tws, rv->gamma, FFLEN_2048);
    FF_2048_ct_pow_2(c->w,  m->b0, tws, m->b1, rv->tau,  m->N, FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    // Compute v = c1^alpha * g^gamma * beta^N mod n2
    FF_4096_fromOctet(ws2, C1, FFLEN_4096);

    FF_2048_toOctet(&OCT, rv->alpha, HFLEN_2048);
    OCT_pad(&OCT, HFS_4096);
    FF_4096_fromOctet(alpha, &OCT, HFLEN_4096);

    FF_4096_mul(ws1, key->n, gamma, HFLEN_4096);
    FF_4096_inc(ws1, 1, FFLEN_4096);
    FF_4096_norm(ws1, FFLEN_4096);
    FF_4096_ct_pow_2(ws2, ws2, alpha, beta, key->n, key->n2, FFLEN_4096, HFLEN_4096);
    FF_4096_mul(dws, ws1, ws2, FFLEN_4096);
    FF_4096_dmod(ws1, dws, key->n2, FFLEN_4096);

    FF_4096_toOctet(&OCT, ws1, FFLEN_4096);
    FF_2048_fromOctet(c->v, &OCT, 2 * FFLEN_2048);

    // Clean memory
    FF_4096_zero(alpha, HFLEN_4096);
    FF_4096_zero(beta,  FFLEN_4096);
    FF_4096_zero(gamma, HFLEN_4096);
}

void BIT_COMMITMENT_muladd_prove(PAILLIER_public_key *key, octet *X, octet *Y, octet *R, BIT_COMMITMENT_muladd_rv *rv, octet *E, BIT_COMMITMENT_muladd_proof *p)
{
    BIG_1024_58 hws[HFLEN_2048];
    BIG_1024_58 ws[FFLEN_2048];
    BIG_1024_58 dws[2*FFLEN_2048];

    BIG_1024_58 n[FFLEN_2048];
    BIG_1024_58 e[HFLEN_2048];

    char oct[2*FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    OCT_copy(&OCT, E);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(e, &OCT, HFLEN_2048);

    // Compute s = beta * r^e mod N
    OCT_copy(&OCT, R);
    FF_2048_fromOctet(dws, &OCT, 2*FFLEN_2048);

    FF_4096_toOctet(&OCT, key->n, HFLEN_4096);
    FF_2048_fromOctet(n, &OCT, FFLEN_2048);

    FF_2048_dmod(ws, dws, n, FFLEN_2048);
    FF_2048_nt_pow(ws, ws, e, n, FFLEN_2048, HFLEN_2048);
    FF_2048_mul(dws, rv->beta, ws, FFLEN_2048);
    FF_2048_dmod(p->s, dws, n, FFLEN_2048);

    // Compute s1 = e*x + alpha
    OCT_copy(&OCT, X);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(hws, &OCT, HFLEN_2048);

    FF_2048_zero(p->s1, FFLEN_2048);

    FF_2048_mul(ws, e, hws, HFLEN_2048);
    FF_2048_copy(p->s1, rv->alpha, HFLEN_2048);
    FF_2048_add(p->s1, p->s1, ws, HFLEN_2048);
    FF_2048_norm(p->s1, HFLEN_2048);

    // Compute s2 = e*rho + rho1
    FF_2048_amul(dws, e, HFLEN_2048, rv->rho, FFLEN_2048 + HFLEN_2048);
    FF_2048_copy(p->s2, rv->rho1, FFLEN_2048 + HFLEN_2048);
    FF_2048_add(p->s2, p->s2, dws, FFLEN_2048 + HFLEN_2048);
    FF_2048_norm(p->s2, FFLEN_2048 + HFLEN_2048);

    // Compute t1 = e*y + gamma
    OCT_copy(&OCT, Y);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(hws, &OCT, HFLEN_2048);

    FF_2048_mul(ws, e, hws, HFLEN_2048);
    FF_2048_copy(p->t1, rv->gamma, FFLEN_2048);
    FF_2048_add(p->t1, p->t1, ws, FFLEN_2048);
    FF_2048_norm(p->t1, FFLEN_2048);

    // Compute s2 = e*sigma + tau
    FF_2048_amul(dws, e, HFLEN_2048, rv->sigma, FFLEN_2048 + HFLEN_2048);
    FF_2048_copy(p->t2, rv->tau, FFLEN_2048 + HFLEN_2048);
    FF_2048_add(p->t2, p->t2, dws, FFLEN_2048 + HFLEN_2048);
    FF_2048_norm(p->t2, FFLEN_2048 + HFLEN_2048);

    // Clean memory
    FF_2048_zero(hws, HFLEN_2048);
    FF_2048_zero(ws,  FFLEN_2048);
    FF_2048_zero(dws, 2 * FFLEN_2048);
}

int BIT_COMMITMENT_muladd_verify(PAILLIER_private_key *key, BIT_COMMITMENT_priv *m, octet *C1, octet *C2, BIT_COMMITMENT_muladd_commitment *c, octet *E, BIT_COMMITMENT_muladd_proof *p)
{
    int fail;

    BIG_1024_58 e[FFLEN_2048];
    BIG_1024_58 q[HFLEN_2048];
    BIG_1024_58 n[FFLEN_2048];

    BIG_1024_58 p_proof[FFLEN_2048];
    BIG_1024_58 q_proof[FFLEN_2048];
    BIG_1024_58 p_gt[FFLEN_2048];
    BIG_1024_58 q_gt[FFLEN_2048];

    BIG_1024_58 c1[2 * FFLEN_2048];
    BIG_1024_58 c2[2 * FFLEN_2048];

    BIG_1024_58 ws1[FFLEN_2048];
    BIG_1024_58 ws2[FFLEN_2048];
    BIG_1024_58 ws3[FFLEN_2048];

    BIG_1024_58 dws[2 * FFLEN_2048];

    char oct[2*FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    // Check if s1 < q^3
    OCT_fromHex(&OCT, curve_order_hex);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(q, &OCT, HFLEN_2048);
    FF_2048_sqr(ws1, q, HFLEN_2048);
    FF_2048_mul(ws1, ws1, q, HFLEN_2048);

    if (FF_2048_comp(p->s1, ws1, HFLEN_2048) > 0)
    {
        return BIT_COMMITMENT_FAIL;
    }

    OCT_copy(&OCT, E);
    OCT_pad(&OCT, FS_2048);
    FF_2048_fromOctet(e, &OCT, FFLEN_2048);

    // Split check b0^s1 * b1^s2 * z^(-e) == z1 mod PQ using CRT
    BIT_COMMITMENT_triple_power(p_proof, m->b0, m->b1, p->s1, p->s2, c->z, e, m->mod.p, false);
    BIT_COMMITMENT_triple_power(q_proof, m->b0, m->b1, p->s1, p->s2, c->z, e, m->mod.q, false);

    FF_2048_dmod(p_gt, c->z1, m->mod.p, HFLEN_2048);
    FF_2048_dmod(q_gt, c->z1, m->mod.q, HFLEN_2048);

    fail = (FF_2048_comp(p_gt, p_proof, HFLEN_2048) != 0) || (FF_2048_comp(q_gt, q_proof, HFLEN_2048) != 0);

    if (fail)
    {
        // Clean memory
        FF_2048_zero(p_gt, HFLEN_2048);
        FF_2048_zero(q_gt, HFLEN_2048);
        FF_2048_zero(p_proof, HFLEN_2048);
        FF_2048_zero(q_proof, HFLEN_2048);

        return BIT_COMMITMENT_FAIL;
    }

    // Split check if b0^t1 * b1^t2 * t^(-e) == w mod PQ using CRT
    BIT_COMMITMENT_triple_power(p_proof, m->b0, m->b1, p->t1, p->t2, c->t, e, m->mod.p, 1);
    BIT_COMMITMENT_triple_power(q_proof, m->b0, m->b1, p->t1, p->t2, c->t, e, m->mod.q, 1);

    FF_2048_dmod(p_gt, c->w, m->mod.p, HFLEN_2048);
    FF_2048_dmod(q_gt, c->w, m->mod.q, HFLEN_2048);

    fail = (FF_2048_comp(p_gt, p_proof, HFLEN_2048) != 0) || (FF_2048_comp(q_gt, q_proof, HFLEN_2048) != 0);

    if (fail)
    {
        // Clean memory
        FF_2048_zero(p_gt, HFLEN_2048);
        FF_2048_zero(q_gt, HFLEN_2048);
        FF_2048_zero(p_proof, HFLEN_2048);
        FF_2048_zero(q_proof, HFLEN_2048);

        return BIT_COMMITMENT_FAIL;
    }

    // Split check c1^s1 * s^N * g^t1 * c2^(-e) == v mod N^2 using CRT
    FF_2048_mul(n, key->p, key->q, HFLEN_2048);

    FF_2048_fromOctet(c1, C1, 2 * FFLEN_2048);
    FF_2048_fromOctet(c2, C2, 2 * FFLEN_2048);

    // Compute check modulo p^2
    FF_2048_copy(ws3, key->p2, FFLEN_2048);
    FF_2048_zero(ws1, FFLEN_2048);
    FF_2048_copy(ws1, key->p, HFLEN_2048);
    FF_2048_sub(ws3, ws3, ws1, FFLEN_2048);
    FF_2048_sub(ws3, ws3, e, FFLEN_2048);
    FF_2048_norm(ws3, FFLEN_2048);

    FF_2048_dmod(ws1, c1, key->p2, FFLEN_2048);
    FF_2048_dmod(ws2, c2, key->p2, FFLEN_2048);

    FF_2048_ct_pow_3(p_proof, ws1, p->s1, p->s, n, ws2, ws3, key->p2, FFLEN_2048, FFLEN_2048);

    FF_2048_mul(dws, n, p->t1, FFLEN_2048);
    FF_2048_dmod(ws1, dws, key->p2, FFLEN_2048);
    FF_2048_inc(ws1, 1, FFLEN_2048);
    FF_2048_norm(ws1, FFLEN_2048);

    FF_2048_mul(dws, p_proof, ws1, FFLEN_2048);
    FF_2048_dmod(p_proof, dws, key->p2, FFLEN_2048);

    // Compute check modulo q^2
    FF_2048_copy(ws3, key->q2, FFLEN_2048);
    FF_2048_zero(ws1, FFLEN_2048);
    FF_2048_copy(ws1, key->q, HFLEN_2048);
    FF_2048_sub(ws3, ws3, ws1, FFLEN_2048);
    FF_2048_sub(ws3, ws3, e, FFLEN_2048);
    FF_2048_norm(ws3, FFLEN_2048);

    FF_2048_dmod(ws1, c1, key->q2, FFLEN_2048);
    FF_2048_dmod(ws2, c2, key->q2, FFLEN_2048);

    FF_2048_ct_pow_3(q_proof, ws1, p->s1, p->s, n, ws2, ws3, key->q2, FFLEN_2048, FFLEN_2048);

    FF_2048_mul(dws, n, p->t1, FFLEN_2048);
    FF_2048_dmod(ws1, dws, key->q2, FFLEN_2048);
    FF_2048_inc(ws1, 1, FFLEN_2048);

    FF_2048_mul(dws, q_proof, ws1, FFLEN_2048);
    FF_2048_dmod(q_proof, dws, key->q2, FFLEN_2048);

    FF_2048_dmod(p_gt, c->v, key->p2, FFLEN_2048);
    FF_2048_dmod(q_gt, c->v, key->q2, FFLEN_2048);

    fail = (FF_2048_comp(p_gt, p_proof, FFLEN_2048) != 0) || (FF_2048_comp(q_gt, q_proof, FFLEN_2048) != 0);

    // Clean memory
    FF_2048_zero(p_gt, FFLEN_2048);
    FF_2048_zero(q_gt, FFLEN_2048);
    FF_2048_zero(p_proof, FFLEN_2048);
    FF_2048_zero(q_proof, FFLEN_2048);
    FF_2048_zero(ws1, FFLEN_2048);
    FF_2048_zero(ws2, FFLEN_2048);
    FF_2048_zero(ws3, FFLEN_2048);
    FF_2048_zero(dws, 2 * FFLEN_2048);

    if (fail)
    {
        return BIT_COMMITMENT_FAIL;
    }

    return BIT_COMMITMENT_OK;
}

void BIT_COMMITMENT_muladd_commitment_toOctets(octet *Z, octet *Z1, octet *T, octet *V, octet *W, BIT_COMMITMENT_muladd_commitment *c)
{
    FF_2048_toOctet(Z,  c->z,  FFLEN_2048);
    FF_2048_toOctet(Z1, c->z1, FFLEN_2048);
    FF_2048_toOctet(T,  c->t,  FFLEN_2048);
    FF_2048_toOctet(V,  c->v,  2 * FFLEN_2048);
    FF_2048_toOctet(W,  c->w,  FFLEN_2048);
}

void BIT_COMMITMENT_muladd_commitment_fromOctets(BIT_COMMITMENT_muladd_commitment *c, octet *Z, octet *Z1, octet *T, octet *V, octet *W)
{
    FF_2048_fromOctet(c->z,  Z,  FFLEN_2048);
    FF_2048_fromOctet(c->z1, Z1, FFLEN_2048);
    FF_2048_fromOctet(c->t,  T,  FFLEN_2048);
    FF_2048_fromOctet(c->v,  V,  2 * FFLEN_2048);
    FF_2048_fromOctet(c->w,  W,  FFLEN_2048);
}

void BIT_COMMITMENT_muladd_proof_toOctets(octet *S, octet *S1, octet *S2, octet *T1, octet *T2, BIT_COMMITMENT_muladd_proof *p)
{
    FF_2048_toOctet(S,  p->s,  FFLEN_2048);
    FF_2048_toOctet(S1, p->s1, HFLEN_2048);
    FF_2048_toOctet(S2, p->s2, FFLEN_2048 + HFLEN_2048);
    FF_2048_toOctet(T1, p->t1, FFLEN_2048);
    FF_2048_toOctet(T2, p->t2, FFLEN_2048 + HFLEN_2048);
}

void BIT_COMMITMENT_muladd_proof_fromOctets(BIT_COMMITMENT_muladd_proof *p, octet *S, octet *S1, octet *S2, octet *T1, octet *T2)
{
    FF_2048_zero(p->s1, FFLEN_2048);

    FF_2048_fromOctet(p->s,  S,  FFLEN_2048);
    FF_2048_fromOctet(p->s1,  S1, HFLEN_2048);
    FF_2048_fromOctet(p->s2, S2, FFLEN_2048 + HFLEN_2048);
    FF_2048_fromOctet(p->t1, T1, FFLEN_2048);
    FF_2048_fromOctet(p->t2, T2, FFLEN_2048 + HFLEN_2048);
}

void BIT_COMMITMENT_muladd_rv_kill(BIT_COMMITMENT_muladd_rv *rv)
{
    FF_2048_zero(rv->alpha, HFLEN_2048);
    FF_2048_zero(rv->beta,  FFLEN_2048);
    FF_2048_zero(rv->gamma, FFLEN_2048);
    FF_2048_zero(rv->rho,   FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(rv->rho1,  FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(rv->sigma, FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(rv->tau,   FFLEN_2048 + HFLEN_2048);
}

/* ZKP of knowledge of DLOG */

void BIT_COMMITMENT_ECP_commit(ECP_SECP256K1 *G, BIG_1024_58 *alpha)
{
    BIG_1024_58 ff_alpha[HFLEN_2048];
    BIG_1024_58 ff_q[HFLEN_2048];

    BIG_256_56 eg_alpha;

    char oct[HFS_2048];
    octet OCT = {0, sizeof(oct), oct};
    char oct_alpha[EGS_SECP256K1];
    octet ALPHA = {0, sizeof(oct_alpha), oct_alpha};

    // Reduce alpha modulo curve order
    OCT_fromHex(&OCT, curve_order_hex);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(ff_q, &OCT, HFLEN_2048);

    FF_2048_copy(ff_alpha, alpha, HFLEN_2048);
    FF_2048_mod(ff_alpha, ff_q, HFLEN_2048);
    FF_2048_toOctet(&OCT, ff_alpha, HFLEN_2048);
    OCT_chop(&OCT, &ALPHA, HFS_2048 - EGS_SECP256K1);
    BIG_256_56_fromBytesLen(eg_alpha, ALPHA.val, ALPHA.len);

    // Commit to U = alpha.G
    ECP_SECP256K1_mul(G, eg_alpha);
}

int BIT_COMMITMENT_ECP_verify(ECP_SECP256K1 *G, ECP_SECP256K1 *X, ECP_SECP256K1 *U, octet *E, BIG_1024_58 *s1)
{
    BIG_256_56 e;
    BIG_256_56 eg_s1;

    BIG_1024_58 ff_s1[HFLEN_2048];
    BIG_1024_58 ff_q[HFLEN_2048];

    char oct[HFS_2048];
    octet OCT = {0, sizeof(oct), oct};

    char oct_s1[EGS_SECP256K1];
    octet S1 = {0, sizeof(oct_s1), oct_s1};

    /* Verify knowldege of DLOG X = x.G */

    BIG_256_56_fromBytesLen(e, E->val, E->len);

    // Reduce s1 modulo curve order
    OCT_fromHex(&OCT, curve_order_hex);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(ff_q, &OCT, HFLEN_2048);

    FF_2048_copy(ff_s1, s1, HFLEN_2048);
    FF_2048_mod(ff_s1, ff_q, HFLEN_2048);
    FF_2048_toOctet(&OCT, ff_s1, HFLEN_2048);
    OCT_chop(&OCT, &S1, HFS_2048 - EGS_SECP256K1);
    BIG_256_56_fromBytesLen(eg_s1, S1.val, S1.len);

    // Check U = s1.G - e.X
    ECP_SECP256K1_neg(X);
    ECP_SECP256K1_mul2(X, G, e, eg_s1);

    if (!ECP_SECP256K1_equals(X, U))
    {
        return BIT_COMMITMENT_FAIL;
    }

    return BIT_COMMITMENT_OK;
}
