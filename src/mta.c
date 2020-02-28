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

/* MPC definitions */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "amcl/mta.h"

static char* curve_order_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

/* Octet manipulation utilities */

static void OCT_hash(hash256 *sha, const octet *O)
{
    int i;

    for (i = 0; i < O->len; i++)
    {
        HASH256_process(sha, O->val[i]);
    }
}

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

/* Utilities to hash data for the RP/ZK challenge functions */

// Update the provided has with the public parameters for a RP/ZK run
void hash_RP_params(hash256 *sha, PAILLIER_public_key *key, COMMITMENTS_BC_pub_modulus *mod, BIG_256_56 q)
{
    char oct[FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    // Process Paillier Public key
    FF_4096_toOctet(&OCT, key->g, HFLEN_4096);
    OCT_hash(sha, &OCT);

    // Process Bit Commitment modulus
    FF_2048_toOctet(&OCT, mod->N, FFLEN_2048);
    OCT_hash(sha, &OCT);

    FF_2048_toOctet(&OCT, mod->b0, FFLEN_2048);
    OCT_hash(sha, &OCT);

    FF_2048_toOctet(&OCT, mod->b1, FFLEN_2048);
    OCT_hash(sha, &OCT);

    // Process curve orer
    BIG_256_56_toBytes(OCT.val, q);
    OCT.len = EGS_SECP256K1;
    OCT_hash(sha, &OCT);
}

// Update the provided hash with the data for the MTA ZK commitment
void hash_ZK_commitment(hash256 *sha, MTA_ZK_commitment *c)
{
    char oct[2 * FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    FF_2048_toOctet(&OCT, c->z, FFLEN_2048);
    OCT_hash(sha, &OCT);

    FF_2048_toOctet(&OCT, c->z1, FFLEN_2048);
    OCT_hash(sha, &OCT);

    FF_2048_toOctet(&OCT, c->t, FFLEN_2048);
    OCT_hash(sha, &OCT);

    FF_2048_toOctet(&OCT, c->v, 2 * FFLEN_2048);
    OCT_hash(sha, &OCT);

    FF_2048_toOctet(&OCT, c->w, FFLEN_2048);
    OCT_hash(sha, &OCT);
}

/* MTA descriptions */

// Client MTA first pass
void MPC_MTA_CLIENT1(csprng *RNG,  PAILLIER_public_key *PUB, octet *A, octet *CA, octet *R)
{
    char a1[FS_2048];
    octet A1 = {0,sizeof(a1),a1};

    OCT_copy(&A1, A);
    OCT_pad(&A1, FS_2048);

    PAILLIER_ENCRYPT(RNG, PUB, &A1, CA, R);

    // Clean memory
    OCT_clear(&A1);
}

// Client MtA second pass
void MPC_MTA_CLIENT2(PAILLIER_private_key *PRIV, octet *CB, octet *ALPHA)
{
    BIG_1024_58 q[HFLEN_2048];
    BIG_1024_58 alpha[HFLEN_2048];

    char t[FS_2048];
    octet T = {0,sizeof(t),t};

    // Curve order
    OCT_fromHex(&T, curve_order_hex);
    OCT_pad(&T, HFS_2048);
    FF_2048_fromOctet(q, &T, HFLEN_2048);

    PAILLIER_DECRYPT(PRIV, CB, &T);

    // alpha < q^3
    OCT_shl(&T, HFS_2048);
    FF_2048_fromOctet(alpha, &T, HFLEN_2048);

    // alpha = alpha mod q
    FF_2048_mod(alpha, q, HFLEN_2048);

    // Output alpha
    FF_2048_toOctet(&T, alpha, HFLEN_2048);
    OCT_chop(&T, ALPHA, HFS_2048 - EGS_SECP256K1);

    // Clean memory
    FF_2048_zero(alpha, FFLEN_2048);
    OCT_clear(&T);
}

// MtA server
void MPC_MTA_SERVER(csprng *RNG, PAILLIER_public_key *PUB, octet *B, octet *CA, octet *ZO, octet *R, octet *CB, octet *BETA)
{
    BIG_256_56 q;
    BIG_256_56 z;

    char zb[FS_2048];
    octet Z = {0,sizeof(zb),zb};

    char cz[FS_4096];
    octet CZ = {0,sizeof(cz),cz};

    char ct[FS_4096];
    octet CT = {0,sizeof(ct),ct};

    char b1[FS_2048];
    octet B1 = {0,sizeof(b1),b1};

    // Curve order
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    // Read B
    OCT_copy(&B1, B);
    OCT_pad(&B1, FS_2048);

    // Random z value
    if (RNG!=NULL)
    {
        BIG_256_56_randomnum(z, q, RNG);

        BIG_256_56_toBytes(Z.val, z);
        Z.len = EGS_SECP256K1;
    }
    else
    {
        BIG_256_56_fromBytesLen(z, ZO->val, ZO->len);
        OCT_copy(&Z, ZO);
    }

    OCT_pad(&Z, FS_2048);

    // beta = -z mod q
    BIG_256_56_sub(z, q, z);

    // CT = E_A(a.b)
    PAILLIER_MULT(PUB, CA, &B1, &CT);

    // CZ = E_A(z)
    PAILLIER_ENCRYPT(RNG, PUB, &Z, &CZ, R);

    // CB = E_A(a.b + z)
    PAILLIER_ADD(PUB, &CT, &CZ, CB);

    // Output Z for Debug
    if (ZO!=NULL)
    {
        OCT_chop(&Z, ZO, FS_2048 - EGS_SECP256K1);
    }

    // Output beta
    BIG_256_56_toBytes(BETA->val, z);
    BETA->len = EGS_SECP256K1;

    // Clean memory
    BIG_256_56_zero(z);
    OCT_clear(&B1);
}

/* sum = a1.b1 + alpha + beta  */
void MPC_SUM_MTA(const octet *A, const octet *B, const octet *ALPHA, const octet *BETA,  octet *SUM)
{
    BIG_256_56 a;
    BIG_256_56 b;
    BIG_256_56 alpha;
    BIG_256_56 beta;
    BIG_256_56 sum;
    BIG_256_56 q;

    // Curve order
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    // Load values
    BIG_256_56_fromBytesLen(a, A->val, A->len);
    BIG_256_56_fromBytesLen(b, B->val, B->len);
    BIG_256_56_fromBytesLen(alpha, ALPHA->val, ALPHA->len);
    BIG_256_56_fromBytesLen(beta, BETA->val, BETA->len);

    // sum = a.b mod q
    BIG_256_56_modmul(sum, a, b, q);

    // sum = sum + alpha  + beta
    BIG_256_56_add(sum, sum, alpha);
    BIG_256_56_add(sum, sum, beta);

    // sum = sum mod q
    BIG_256_56_mod(sum, q);

    // Output result
    SUM->len = EGS_SECP256K1;
    BIG_256_56_toBytes(SUM->val, sum);

    // Clean memory
    BIG_256_56_zero(a);
    BIG_256_56_zero(b);
    BIG_256_56_zero(alpha);
    BIG_256_56_zero(beta);
    BIG_256_56_zero(sum);
}

void MTA_ZK_random_challenge(csprng *RNG, octet *E)
{
    BIG_256_56 e;
    BIG_256_56 q;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    BIG_256_56_randomnum(e, q, RNG);

    BIG_256_56_toBytes(E->val, e);
    E->len = EGS_SECP256K1;
}

void MTA_RP_commit(csprng *RNG, PAILLIER_private_key *key, COMMITMENTS_BC_pub_modulus *mod,  octet *M, MTA_RP_commitment *c, MTA_RP_commitment_rv *rv)
{
    BIG_1024_58 n[FFLEN_2048];
    BIG_1024_58 g[FFLEN_2048];
    BIG_1024_58 q[HFLEN_2048];
    BIG_1024_58 ws1[FFLEN_2048];
    BIG_1024_58 ws2[FFLEN_2048];
    BIG_1024_58 dws[2 * FFLEN_2048];


    char oct[2 * FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    // Curve order
    OCT_fromHex(&OCT, curve_order_hex);
    FF_2048_zero(q, HFLEN_2048);
    BIG_512_60_fromBytesLen(q[0],OCT.val,OCT.len);

    FF_2048_mul(n, key->p, key->q, HFLEN_2048);
    FF_2048_copy(g, n, FFLEN_2048);
    FF_2048_inc(g, 1, FFLEN_2048);

    if (RNG != NULL)
    {
        // Generate alpha in [0, .., q^3]
        FF_2048_sqr(ws1, q, HFLEN_2048);
        FF_2048_mul(ws2, q, ws1, HFLEN_2048);

        FF_2048_zero(rv->alpha, FFLEN_2048);
        FF_2048_random(rv->alpha, RNG, HFLEN_2048);
        FF_2048_mod(rv->alpha, ws2, HFLEN_2048);

        // Generate beta in [0, .., N]
        FF_2048_randomnum(rv->beta, n, RNG, FFLEN_2048);

        // Generate gamma in [0, .., Nt * q^3]
        FF_2048_amul(dws, ws2, HFLEN_2048, mod->N, FFLEN_2048);
        FF_2048_random(rv->gamma, RNG, FFLEN_2048 + HFLEN_2048);
        FF_2048_mod(rv->gamma, dws, FFLEN_2048 + HFLEN_2048);

        // Generate rho in [0, .., Nt * q]
        FF_2048_amul(dws, q, HFLEN_2048, mod->N, FFLEN_2048);
        FF_2048_random(rv->rho, RNG, FFLEN_2048 + HFLEN_2048);
        FF_2048_mod(rv->rho, dws, FFLEN_2048 + HFLEN_2048);
    }

    // Read input
    OCT_copy(&OCT, M);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_zero(dws, FFLEN_2048 + HFLEN_2048);
    FF_2048_fromOctet(dws, &OCT, HFLEN_2048);

    // Compute z and w
    FF_2048_skpow2(c->z, mod->b0, dws, mod->b1, rv->rho, mod->N, FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    FF_2048_copy(dws, rv->alpha, HFLEN_2048);
    FF_2048_skpow2(c->w, mod->b0, dws, mod->b1, rv->gamma, mod->N, FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    // Compute u using CRT
    FF_2048_skpow2(ws1, g, rv->alpha, rv->beta, n, key->p2, FFLEN_2048, FFLEN_2048);
    FF_2048_skpow2(ws2, g, rv->alpha, rv->beta, n, key->q2, FFLEN_2048, FFLEN_2048);
    FF_2048_crt(dws, ws1, ws2, key->p2, key->q2, FFLEN_2048);

    // Convert u as FF_4096 since it is only used as such
    FF_2048_toOctet(&OCT, dws, 2 * FFLEN_2048);
    FF_4096_fromOctet(c->u, &OCT, FFLEN_4096);

    // Clean memory
    FF_2048_zero(dws, HFLEN_2048);
}

void MTA_RP_challenge(PAILLIER_public_key *key, COMMITMENTS_BC_pub_modulus *mod, const octet *CT, MTA_RP_commitment *c, octet *E)
{
    hash256 sha;

    char oct[2*FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    BIG_256_56 q;
    BIG_256_56 t;

    // Load curve order
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    HASH256_init(&sha);

    /* Bind to public parameters */
    hash_RP_params(&sha, key, mod, q);

    /* Bind to proof input */

    // Process ciphertext
    OCT_hash(&sha, CT);

    /* Bind to proof commitment */

    // Process z
    FF_2048_toOctet(&OCT, c->z, FFLEN_2048);
    OCT_hash(&sha, &OCT);

    // Process u
    FF_4096_toOctet(&OCT, c->u, FFLEN_4096);
    OCT_hash(&sha, &OCT);

    // Process w
    FF_2048_toOctet(&OCT, c->w, FFLEN_2048);
    OCT_hash(&sha, &OCT);

    /* Output */
    HASH256_hash(&sha, OCT.val);
    BIG_256_56_fromBytesLen(t, OCT.val, SHA256);
    BIG_256_56_mod(t, q);

    BIG_256_56_toBytes(E->val, t);
    E->len = EGS_SECP256K1;
}

void MTA_RP_prove(PAILLIER_private_key *key, MTA_RP_commitment_rv *rv, octet *M, octet *R, octet *E, MTA_RP_proof *p)
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
    OCT_copy(&OCT, M);
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
    FF_2048_pow(hws, hws, e, key->p, HFLEN_2048);
    FF_2048_mul(ws1, sp, hws,  HFLEN_2048);
    FF_2048_dmod(sp, ws1, key->p, HFLEN_2048);

    FF_2048_amod(hws, r, 2*FFLEN_2048, key->q, HFLEN_2048);
    FF_2048_dmod(sq, rv->beta, key->q, HFLEN_2048);
    FF_2048_pow(hws, hws, e, key->q, HFLEN_2048);
    FF_2048_mul(ws1, sq, hws,  HFLEN_2048);
    FF_2048_dmod(sq, ws1, key->q, HFLEN_2048);

    FF_2048_crt(ws1, sp, sq, key->p, key->q, HFLEN_2048);

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

// Utility function to compute the triple power for verification purposes.
// h1^s1 * h2^s2 * z^(-e) mod P
//
// h1, h2 are reduced modulo P
// s1 is reduced modulo P-1 if indicated
// s2 is reduced modulo P-1
// z is reduced and inverted modulo P
// e is left as is
void MTA_triple_power(BIG_1024_58 *proof, BIG_1024_58 *h1, BIG_1024_58 *h2, BIG_1024_58 *s1, BIG_1024_58 *s2, BIG_1024_58 *z, BIG_1024_58 *e, BIG_1024_58 *p, int reduce_s1)
{
    BIG_1024_58 hws1[HFLEN_2048];
    BIG_1024_58 hws2[HFLEN_2048];
    BIG_1024_58 hws3[HFLEN_2048];
    BIG_1024_58 hws4[HFLEN_2048];

    FF_2048_copy(hws1, p, HFLEN_2048);
    FF_2048_dec(hws1, 1, HFLEN_2048);
    FF_2048_amod(hws4, s2, FFLEN_2048 + HFLEN_2048, hws1, HFLEN_2048);

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
    FF_2048_invmodp(proof, proof, p, HFLEN_2048);
    FF_2048_skpow3(proof, hws1, hws3, hws2, hws4, proof, e, p, HFLEN_2048, HFLEN_2048);

    // Clean memory
    FF_2048_zero(hws1, HFLEN_2048);
    FF_2048_zero(hws2, HFLEN_2048);
    FF_2048_zero(hws3, HFLEN_2048);
    FF_2048_zero(hws4, HFLEN_2048);
}

int MTA_RP_verify(PAILLIER_public_key *key, COMMITMENTS_BC_priv_modulus *mod, octet *CT, octet *E, MTA_RP_commitment *co, MTA_RP_proof *p)
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
    BIG_512_60 ws_4096[FFLEN_4096];

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
        return MTA_FAIL;
    }

    // Split computation of proof for w using CRT.
    MTA_triple_power(wp_proof, mod->b0, mod->b1, p->s1, p->s2, co->z, e, mod->P, false);
    MTA_triple_power(wq_proof, mod->b0, mod->b1, p->s1, p->s2, co->z, e, mod->Q, false);

    // Reduce w mod P and Q for comparison
    FF_2048_dmod(hws1, co->w, mod->P, HFLEN_2048);
    FF_2048_dmod(hws2, co->w, mod->Q, HFLEN_2048);

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
        return MTA_FAIL;
    }

    // Compute verification for u
    FF_2048_toOctet(&OCT, p->s1, HFLEN_2048);
    OCT_pad(&OCT, HFS_4096);
    FF_4096_fromOctet(s1, &OCT, HFLEN_4096);

    FF_4096_fromOctet(ws_4096, CT, FFLEN_4096);
    FF_4096_invmodp(ws_4096, ws_4096, key->n2, FFLEN_4096);

    // u_proof = g^s1 * s^N * c^(-e) mod N^2
    FF_4096_pow3(ws_4096, key->g, s1, p->s, key->n, ws_4096, e_4096, key->n2, FFLEN_4096, HFLEN_4096);

    if(FF_4096_comp(ws_4096, co->u, FFLEN_4096) != 0)
    {
        return MTA_FAIL;
    }

    return MTA_OK;
}

void MTA_RP_commitment_toOctets(octet *Z, octet *U, octet *W, MTA_RP_commitment *c)
{
    FF_2048_toOctet(Z, c->z, FFLEN_2048);
    FF_4096_toOctet(U, c->u, FFLEN_4096);
    FF_2048_toOctet(W, c->w, FFLEN_2048);
}

void MTA_RP_commitment_fromOctets(MTA_RP_commitment *c, octet *Z, octet *U, octet *W)
{
    FF_2048_fromOctet(c->z, Z, FFLEN_2048);
    FF_4096_fromOctet(c->u, U, FFLEN_4096);
    FF_2048_fromOctet(c->w, W, FFLEN_2048);
}

void MTA_RP_proof_toOctets(octet *S, octet *S1, octet *S2, MTA_RP_proof *p)
{
    FF_4096_toOctet(S,  p->s,  HFLEN_4096);
    FF_2048_toOctet(S1, p->s1, HFLEN_2048);
    FF_2048_toOctet(S2, p->s2, FFLEN_2048 + HFLEN_2048);
}

void MTA_RP_proof_fromOctets(MTA_RP_proof *p, octet *S, octet *S1, octet *S2)
{
    FF_2048_zero(p->s1, FFLEN_2048);
    FF_4096_zero(p->s, FFLEN_4096);

    FF_4096_fromOctet(p->s,  S,  HFLEN_4096);
    FF_2048_fromOctet(p->s1, S1, HFLEN_2048);
    FF_2048_fromOctet(p->s2, S2, FFLEN_2048 + HFLEN_2048);
}

void MTA_RP_commitment_rv_kill(MTA_RP_commitment_rv *rv)
{
    FF_2048_zero(rv->alpha, HFLEN_2048);
    FF_2048_zero(rv->beta,  FFLEN_2048);
    FF_2048_zero(rv->gamma, FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(rv->rho,   FFLEN_2048 + HFLEN_2048);
}

void MTA_ZK_commit(csprng *RNG, PAILLIER_public_key *key, COMMITMENTS_BC_pub_modulus *mod,  octet *X, octet *Y, octet *C1, MTA_ZK_commitment *c, MTA_ZK_commitment_rv *rv)
{
    BIG_1024_58 q[HFLEN_2048];
    BIG_1024_58 q3[FFLEN_2048];
    BIG_1024_58 tws[FFLEN_2048 + HFLEN_2048];

    BIG_512_60 alpha[HFLEN_4096];
    BIG_512_60 beta[FFLEN_4096];
    BIG_512_60 gamma[HFLEN_4096];
    BIG_512_60 ws[FFLEN_4096];

    char oct[2 * FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    // Curve order
    OCT_fromHex(&OCT, curve_order_hex);
    FF_2048_zero(q, HFLEN_2048);
    BIG_512_60_fromBytesLen(q[0],OCT.val,OCT.len);

    // Zero out beta since it's needed regardless of RNG
    FF_4096_zero(beta, FFLEN_4096);

    if (RNG != NULL)
    {
        // Generate alpha in [0, .., q^3]
        FF_2048_sqr(q3, q, HFLEN_2048);
        FF_2048_mul(q3, q, q3, HFLEN_2048);

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
        FF_2048_amul(tws, q, HFLEN_2048, mod->N, FFLEN_2048);
        FF_2048_random(rv->rho, RNG, FFLEN_2048 + HFLEN_2048);
        FF_2048_mod(rv->rho, tws, FFLEN_2048 + HFLEN_2048);

        FF_2048_random(rv->tau, RNG, FFLEN_2048 + HFLEN_2048);
        FF_2048_mod(rv->tau, tws, FFLEN_2048 + HFLEN_2048);

        FF_2048_random(rv->sigma, RNG, FFLEN_2048 + HFLEN_2048);
        FF_2048_mod(rv->sigma, tws, FFLEN_2048 + HFLEN_2048);

        // Generate rho1 in [0, .., Nt * q^3]
        FF_2048_amul(tws, q3, HFLEN_2048, mod->N, FFLEN_2048);
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
    FF_2048_skpow2(c->z, mod->b0, tws, mod->b1, rv->rho, mod->N, FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    // Compute t = h1^y * h2^sigma mod Nt
    OCT_copy(&OCT, Y);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(tws, &OCT, HFLEN_2048);
    FF_2048_skpow2(c->t, mod->b0, tws, mod->b1, rv->sigma, mod->N, FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    // Compute z1 = h1^alpha * h2^rho1 mod Nt and
    FF_2048_copy(tws, rv->alpha, HFLEN_2048);
    FF_2048_skpow2(c->z1, mod->b0, tws, mod->b1, rv->rho1, mod->N, FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    // Compute w = h1^gamma * h2^tau mod Nt
    FF_2048_copy(tws, rv->gamma, FFLEN_2048);
    FF_2048_skpow2(c->w,  mod->b0, tws, mod->b1, rv->tau,  mod->N, FFLEN_2048, FFLEN_2048 + HFLEN_2048);

    // Compute v = c1^alpha * g^gamma * beta^N mod n2
    FF_4096_fromOctet(ws, C1, FFLEN_4096);

    FF_2048_toOctet(&OCT, rv->alpha, HFLEN_2048);
    OCT_pad(&OCT, HFS_4096);
    FF_4096_fromOctet(alpha, &OCT, HFLEN_4096);

    FF_4096_skpow3(ws, ws, alpha, key->g, gamma, beta, key->n, key->n2, FFLEN_4096, HFLEN_4096);

    FF_4096_toOctet(&OCT, ws, FFLEN_4096);
    FF_2048_fromOctet(c->v, &OCT, 2 * FFLEN_2048);

    // Clean memory
    FF_4096_zero(alpha, HFLEN_4096);
    FF_4096_zero(beta,  FFLEN_4096);
    FF_4096_zero(gamma, HFLEN_4096);
}

void MTA_ZK_challenge(PAILLIER_public_key *key, COMMITMENTS_BC_pub_modulus *mod, const octet *C1, const octet *C2, MTA_ZK_commitment *c, octet *E)
{
    hash256 sha;
    char digest[SHA256];

    BIG_256_56 q;
    BIG_256_56 t;

    // Load curve order
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    HASH256_init(&sha);

    /* Bind to public parameters */
    hash_RP_params(&sha, key, mod, q);

    /* Bind to proof input */
    OCT_hash(&sha, C1);
    OCT_hash(&sha, C2);

    /* Bind to proof commitment */
    hash_ZK_commitment(&sha, c);

    /* Output */
    HASH256_hash(&sha, digest);
    BIG_256_56_fromBytesLen(t, digest, SHA256);
    BIG_256_56_mod(t, q);

    BIG_256_56_toBytes(E->val, t);
    E->len = EGS_SECP256K1;
}

void MTA_ZK_prove(PAILLIER_public_key *key, MTA_ZK_commitment_rv *rv, octet *X, octet *Y, octet *R, octet *E, MTA_ZK_proof *p)
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
    FF_2048_skpow(ws, ws, e, n, FFLEN_2048, HFLEN_2048);
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
    FF_2048_zero(ws, FFLEN_2048);
    FF_2048_zero(dws, 2 * FFLEN_2048);
}

int MTA_ZK_verify(PAILLIER_private_key *key, COMMITMENTS_BC_priv_modulus *mod, octet *C1, octet *C2, octet *E, MTA_ZK_commitment *c, MTA_ZK_proof *p)
{
    int fail;

    BIG_1024_58 e[FFLEN_2048];
    BIG_1024_58 q[HFLEN_2048];
    BIG_1024_58 n[FFLEN_2048];
    BIG_1024_58 g[FFLEN_2048];

    BIG_1024_58 p_proof[FFLEN_2048];
    BIG_1024_58 q_proof[FFLEN_2048];
    BIG_1024_58 p_gt[FFLEN_2048];
    BIG_1024_58 q_gt[FFLEN_2048];

    BIG_1024_58 c1[2 * FFLEN_2048];
    BIG_1024_58 c2[2 * FFLEN_2048];

    BIG_1024_58 ws1[FFLEN_2048];
    BIG_1024_58 ws2[FFLEN_2048];

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
        return MTA_FAIL;
    }

    OCT_copy(&OCT, E);
    OCT_pad(&OCT, FS_2048);
    FF_2048_fromOctet(e, &OCT, FFLEN_2048);

    // Split check b0^s1 * b1^s2 * z^(-e) == z1 mod PQ using CRT
    MTA_triple_power(p_proof, mod->b0, mod->b1, p->s1, p->s2, c->z, e, mod->P, false);
    MTA_triple_power(q_proof, mod->b0, mod->b1, p->s1, p->s2, c->z, e, mod->Q, false);

    FF_2048_dmod(p_gt, c->z1, mod->P, HFLEN_2048);
    FF_2048_dmod(q_gt, c->z1, mod->Q, HFLEN_2048);

    fail = (FF_2048_comp(p_gt, p_proof, HFLEN_2048) != 0) || (FF_2048_comp(q_gt, q_proof, HFLEN_2048) != 0);

    if (fail)
    {
        // Clean memory
        FF_2048_zero(p_gt, HFLEN_2048);
        FF_2048_zero(q_gt, HFLEN_2048);
        FF_2048_zero(p_proof, HFLEN_2048);
        FF_2048_zero(q_proof, HFLEN_2048);

        return MTA_FAIL;
    }

    // Split check if b0^t1 * b1^t2 * t^(-e) == w mod PQ using CRT
    MTA_triple_power(p_proof, mod->b0, mod->b1, p->t1, p->t2, c->t, e, mod->P, 1);
    MTA_triple_power(q_proof, mod->b0, mod->b1, p->t1, p->t2, c->t, e, mod->Q, 1);

    FF_2048_dmod(p_gt, c->w, mod->P, HFLEN_2048);
    FF_2048_dmod(q_gt, c->w, mod->Q, HFLEN_2048);

    fail = (FF_2048_comp(p_gt, p_proof, HFLEN_2048) != 0) || (FF_2048_comp(q_gt, q_proof, HFLEN_2048) != 0);

    if (fail)
    {
        // Clean memory
        FF_2048_zero(p_gt, HFLEN_2048);
        FF_2048_zero(q_gt, HFLEN_2048);
        FF_2048_zero(p_proof, HFLEN_2048);
        FF_2048_zero(q_proof, HFLEN_2048);

        return MTA_FAIL;
    }

    // Split check c1^s1 * s^N * g^t1 * c2^(-e) == v mod N^2 using CRT
    FF_2048_mul(n, key->p, key->q, HFLEN_2048);
    FF_2048_copy(g, n, FFLEN_2048);
    FF_2048_inc(g, 1, FFLEN_2048);

    FF_2048_fromOctet(c1, C1, 2 * FFLEN_2048);
    FF_2048_fromOctet(c2, C2, 2 * FFLEN_2048);

    FF_2048_dmod(ws1, c1, key->p2, FFLEN_2048);
    FF_2048_dmod(ws2, c2, key->p2, FFLEN_2048);
    FF_2048_invmodp(ws2, ws2, key->p2, FFLEN_2048);
    FF_2048_pow4(p_proof, ws1, p->s1, p->s, n, g, p->t1, ws2, e, key->p2, FFLEN_2048, FFLEN_2048);

    FF_2048_dmod(ws1, c1, key->q2, FFLEN_2048);
    FF_2048_dmod(ws2, c2, key->q2, FFLEN_2048);
    FF_2048_invmodp(ws2, ws2, key->q2, FFLEN_2048);
    FF_2048_pow4(q_proof, ws1, p->s1, p->s, n, g, p->t1, ws2, e, key->q2, FFLEN_2048, FFLEN_2048);

    FF_2048_dmod(p_gt, c->v, key->p2, FFLEN_2048);
    FF_2048_dmod(q_gt, c->v, key->q2, FFLEN_2048);

    fail = (FF_2048_comp(p_gt, p_proof, FFLEN_2048) != 0) || (FF_2048_comp(q_gt, q_proof, FFLEN_2048) != 0);

    // Clean memory
    FF_2048_zero(p_gt, FFLEN_2048);
    FF_2048_zero(q_gt, FFLEN_2048);
    FF_2048_zero(p_proof, FFLEN_2048);
    FF_2048_zero(q_proof, FFLEN_2048);

    if (fail)
    {
        return MTA_FAIL;
    }

    return MTA_OK;
}

void MTA_ZK_commitment_toOctets(octet *Z, octet *Z1, octet *T, octet *V, octet *W, MTA_ZK_commitment *c)
{
    FF_2048_toOctet(Z,  c->z, FFLEN_2048);
    FF_2048_toOctet(Z1, c->z1,FFLEN_2048);
    FF_2048_toOctet(T,  c->t, FFLEN_2048);
    FF_2048_toOctet(V,  c->v, 2 * FFLEN_2048);
    FF_2048_toOctet(W,  c->w, FFLEN_2048);
}

void MTA_ZK_commitment_fromOctets(MTA_ZK_commitment *c, octet *Z, octet *Z1, octet *T, octet *V, octet *W)
{
    FF_2048_fromOctet(c->z,  Z,  FFLEN_2048);
    FF_2048_fromOctet(c->z1, Z1, FFLEN_2048);
    FF_2048_fromOctet(c->t,  T,  FFLEN_2048);
    FF_2048_fromOctet(c->v,  V,  2 * FFLEN_2048);
    FF_2048_fromOctet(c->w,  W,  FFLEN_2048);
}

void MTA_ZK_proof_toOctets(octet *S, octet *S1, octet *S2, octet *T1, octet *T2, MTA_ZK_proof *p)
{
    FF_2048_toOctet(S,  p->s,  FFLEN_2048);
    FF_2048_toOctet(S1, p->s1, HFLEN_2048);
    FF_2048_toOctet(S2, p->s2, FFLEN_2048 + HFLEN_2048);
    FF_2048_toOctet(T1, p->t1, FFLEN_2048);
    FF_2048_toOctet(T2, p->t2, FFLEN_2048 + HFLEN_2048);
}

void MTA_ZK_proof_fromOctets(MTA_ZK_proof *p, octet *S, octet *S1, octet *S2, octet *T1, octet *T2)
{
    FF_2048_zero(p->s1, FFLEN_2048);

    FF_2048_fromOctet(p->s,  S,  FFLEN_2048);
    FF_2048_fromOctet(p->s1,  S1, HFLEN_2048);
    FF_2048_fromOctet(p->s2, S2, FFLEN_2048 + HFLEN_2048);
    FF_2048_fromOctet(p->t1, T1, FFLEN_2048);
    FF_2048_fromOctet(p->t2, T2, FFLEN_2048 + HFLEN_2048);
}

void MTA_ZK_commitment_rv_kill(MTA_ZK_commitment_rv *rv)
{
    FF_2048_zero(rv->alpha, HFLEN_2048);
    FF_2048_zero(rv->beta,  FFLEN_2048);
    FF_2048_zero(rv->gamma, FFLEN_2048);
    FF_2048_zero(rv->rho,   FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(rv->rho1,  FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(rv->sigma, FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(rv->tau,   FFLEN_2048 + HFLEN_2048);
}

void MTA_ZKWC_commit(csprng *RNG, PAILLIER_public_key *key, COMMITMENTS_BC_pub_modulus *mod,  octet *X, octet *Y, octet *C1, MTA_ZKWC_commitment *c, MTA_ZKWC_commitment_rv *rv)
{
    BIG_1024_58 ff_alpha[HFLEN_2048];
    BIG_1024_58 ff_q[HFLEN_2048];

    BIG_256_56 alpha;

    char oct[HFS_2048];
    octet OCT = {0, sizeof(oct), oct};

    char oct_alpha[EGS_SECP256K1];
    octet ALPHA = {0, sizeof(oct_alpha), oct_alpha};

    /* Compute base commitment for the range and knowledge ZKP */

    MTA_ZK_commit(RNG, key, mod, X, Y, C1, &(c->zkc), rv);

    /* Compute commitment for DLOG knowledge ZKP */

    // Reduce alpha modulo curve order
    OCT_fromHex(&OCT, curve_order_hex);
    FF_2048_zero(ff_q, HFLEN_2048);
    BIG_1024_58_fromBytesLen(ff_q[0], OCT.val, OCT.len);

    FF_2048_copy(ff_alpha, rv->alpha, HFLEN_2048);
    FF_2048_mod(ff_alpha, ff_q, HFLEN_2048);
    FF_2048_toOctet(&OCT, ff_alpha, HFLEN_2048);
    OCT_chop(&OCT, &ALPHA, HFS_2048 - EGS_SECP256K1);
    BIG_256_56_fromBytesLen(alpha, ALPHA.val, ALPHA.len);

    // Commit to U = alpha.G
    ECP_SECP256K1_generator(&(c->U));
    ECP_SECP256K1_mul(&(c->U), alpha);
}

void MTA_ZKWC_challenge(PAILLIER_public_key *key, COMMITMENTS_BC_pub_modulus *mod, const octet *C1, const octet *C2, const octet *X, MTA_ZKWC_commitment *c, octet *E)
{
    hash256 sha;
    char digest[SHA256];

    char oct[EFS_SECP256K1 + 1];
    octet OCT = {0, sizeof(oct), oct};

    BIG_256_56 q;
    BIG_256_56 t;

    // Load curve order
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    HASH256_init(&sha);

    /* Bind to public parameters */
    hash_RP_params(&sha, key, mod, q);

    /* Bind to proof input */
    OCT_hash(&sha, C1);
    OCT_hash(&sha, C2);
    OCT_hash(&sha, X);

    /* Bind to proof commitment for DLOG */
    ECP_SECP256K1_toOctet(&OCT, &(c->U), true);
    OCT_hash(&sha, &OCT);

    /* Bind to proof commitment for Receiver ZK */
    hash_ZK_commitment(&sha, &(c->zkc));

    /* Output */
    HASH256_hash(&sha, digest);
    BIG_256_56_fromBytesLen(t, digest, SHA256);
    BIG_256_56_mod(t, q);

    BIG_256_56_toBytes(E->val, t);
    E->len = EGS_SECP256K1;
}

void MTA_ZKWC_prove(PAILLIER_public_key *key, MTA_ZKWC_commitment_rv *rv, octet *X, octet *Y, octet *R, octet *E, MTA_ZKWC_proof *p)
{
    MTA_ZK_prove(key, rv, X, Y, R, E, p);
}

int MTA_ZKWC_verify(PAILLIER_private_key *key, COMMITMENTS_BC_priv_modulus *mod, octet *C1, octet *C2, octet *X, octet *E, MTA_ZKWC_commitment *c, MTA_ZKWC_proof *p)
{
    int rc;

    BIG_256_56 e;
    BIG_256_56 s1;

    ECP_SECP256K1 x;
    ECP_SECP256K1 g;

    BIG_1024_58 ff_s1[HFLEN_2048];
    BIG_1024_58 ff_q[HFLEN_2048];

    char oct[HFS_2048];
    octet OCT = {0, sizeof(oct), oct};

    char oct_s1[EGS_SECP256K1];
    octet S1 = {0, sizeof(oct_s1), oct_s1};

    // Terminate early in case of invalid input
    rc = ECP_SECP256K1_fromOctet(&x, X);
    if (rc != 1)
    {
        return MTA_INVALID_ECP;
    }

    /* Verify base Receiver ZKP */

    rc = MTA_ZK_verify(key, mod, C1, C2, E, &(c->zkc), p);
    if (rc != MTA_OK)
    {
        return MTA_FAIL;
    }

    /* Verify knowldege of DLOG X = x.G */

    BIG_256_56_fromBytesLen(e, E->val, E->len);

    // Reduce s1 modulo curve order
    OCT_fromHex(&OCT, curve_order_hex);
    FF_2048_zero(ff_q, HFLEN_2048);
    BIG_1024_58_fromBytesLen(ff_q[0], OCT.val, OCT.len);

    FF_2048_copy(ff_s1, p->s1, HFLEN_2048);
    FF_2048_mod(ff_s1, ff_q, HFLEN_2048);
    FF_2048_toOctet(&OCT, ff_s1, HFLEN_2048);
    OCT_chop(&OCT, &S1, HFS_2048 - EGS_SECP256K1);
    BIG_256_56_fromBytesLen(s1, S1.val, S1.len);

    // Check U = s1.G - e.X
    ECP_SECP256K1_neg(&x);
    ECP_SECP256K1_generator(&g);
    ECP_SECP256K1_mul2(&x, &g, e, s1);

    if (!ECP_SECP256K1_equals(&x, &(c->U)))
    {
        return MTA_FAIL;
    }

    return MTA_OK;
}

void MTA_ZKWC_commitment_toOctets(octet *U, octet *Z, octet *Z1, octet *T, octet *V, octet *W, MTA_ZKWC_commitment *c)
{
    MTA_ZK_commitment_toOctets(Z, Z1, T, V, W, &(c->zkc));
    ECP_SECP256K1_toOctet(U, &(c->U), true);
}

int MTA_ZKWC_commitment_fromOctets(MTA_ZKWC_commitment *c, octet *U, octet *Z, octet *Z1, octet *T, octet *V, octet *W)
{
    if (ECP_SECP256K1_fromOctet(&(c->U), U) != 1)
    {
        return MTA_INVALID_ECP;
    }

    MTA_ZK_commitment_fromOctets(&(c->zkc), Z, Z1, T, V, W);

    return MTA_OK;
}

void MTA_ZKWC_proof_toOctets(octet *S, octet *S1, octet *S2, octet *T1, octet *T2, MTA_ZKWC_proof *p)
{
    MTA_ZK_proof_toOctets(S, S1, S2, T1, T2, p);
}

void MTA_ZKWC_proof_fromOctets(MTA_ZKWC_proof *p, octet *S, octet *S1, octet *S2, octet *T1, octet *T2)
{
    MTA_ZK_proof_fromOctets(p, S, S1, S2, T1, T2);
}

void MTA_ZKWC_commitment_rv_kill(MTA_ZKWC_commitment_rv *rv)
{
    MTA_ZK_commitment_rv_kill(rv);
}
