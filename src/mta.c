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

void OCT_hash(hash256 *sha, octet *O)
{
    int i;

    for (i = 0; i < O->len; i++)
    {
        HASH256_process(sha, O->val[i]);
    }
}

// Truncates an octet string
void OCT_truncate(octet *y,octet *x)
{
    /* y < x */
    int i=0;
    int j=0;
    if (x==NULL) return;
    if (y==NULL) return;

    for (i=0; i<y->len; i++)
    {
        j=x->len+i;
        if (i>=y->max)
        {
            y->len=y->max;
            return;
        }
        y->val[i]=x->val[j];
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
    OCT.len = MODBYTES_256_56;
    OCT_hash(sha, &OCT);
}

/* MTA descriptions */

// Client MTA first pass
void MPC_MTA_CLIENT1(csprng *RNG,  PAILLIER_public_key *PUB, octet *A, octet *CA, octet *R)
{
    // Read A
    char a1[FS_2048];
    octet A1 = {0,sizeof(a1),a1};
    OCT_clear(&A1);
    A1.len = FS_2048 - EGS_SECP256K1;
    OCT_joctet(&A1,A);

    PAILLIER_ENCRYPT(RNG, PUB, &A1, CA, R);
}

// Client MtA second pass
void MPC_MTA_CLIENT2(PAILLIER_private_key *PRIV, octet *CB, octet *ALPHA)
{
    BIG_512_60 q[FFLEN_4096];
    BIG_512_60 alpha[FFLEN_4096];

    char co[EGS_SECP256K1];
    octet CO = {0,sizeof(co),co};

    char t[FS_2048];
    octet T = {0,sizeof(t),t};

    // Curve order
    OCT_fromHex(&CO,curve_order_hex);
    FF_4096_zero(q, FFLEN_4096);
    BIG_512_60_fromBytesLen(q[0],CO.val,CO.len);

    PAILLIER_DECRYPT(PRIV, CB, &T);

    FF_4096_zero(alpha, FFLEN_4096);
    FF_4096_fromOctet(alpha,&T,HFLEN_4096);

    // alpha = alpha mod q
    FF_4096_mod(alpha, q, FFLEN_4096);

    // Output alpha
    char alpha1[FS_4096];
    octet ALPHA1 = {0,sizeof(alpha1),alpha1};
    FF_4096_toOctet(&ALPHA1, alpha, FFLEN_4096);
    OCT_clear(ALPHA);
    ALPHA->len = EGS_SECP256K1;
    ALPHA1.len = FS_4096 - EGS_SECP256K1;
    OCT_truncate(ALPHA,&ALPHA1);
}

// MtA server
void MPC_MTA_SERVER(csprng *RNG, PAILLIER_public_key *PUB, octet *B, octet *CA, octet *ZO, octet *R, octet *CB, octet *BETA)
{
    BIG_512_60 q[FFLEN_4096];
    BIG_512_60 z[FFLEN_4096];
    BIG_512_60 beta[FFLEN_4096];

    char co[EGS_SECP256K1];
    octet CO = {0,sizeof(co),co};

    char zb[FS_2048];
    octet Z = {0,sizeof(zb),zb};

    char cz[FS_4096];
    octet CZ = {0,sizeof(cz),cz};

    char ct[FS_4096];
    octet CT = {0,sizeof(ct),ct};

    char b1[FS_2048];
    octet B1 = {0,sizeof(b1),b1};

    // Curve order
    OCT_fromHex(&CO,curve_order_hex);
    FF_4096_zero(q, FFLEN_4096);
    BIG_512_60_fromBytesLen(q[0],CO.val,CO.len);

    // Read B
    OCT_clear(&B1);
    B1.len = FS_2048 - EGS_SECP256K1;
    OCT_joctet(&B1,B);

    // Random z value
    if (RNG!=NULL)
    {
        FF_4096_random(z,RNG,FFLEN_4096);
        FF_4096_mod(z,q,FFLEN_4096);
    }
    else
    {
        char z1[FS_4096];
        octet Z1 = {0,sizeof(z1),z1};
        OCT_clear(&Z1);
        Z1.len = FS_4096 - EGS_SECP256K1;
        ZO->len = EGS_SECP256K1;
        OCT_joctet(&Z1,ZO);
        FF_4096_zero(z, FFLEN_4096);
        FF_4096_fromOctet(z,&Z1,FFLEN_4096);
    }
    FF_4096_toOctet(&Z, z, HFLEN_4096);

    // beta = -z mod q
    FF_4096_sub(beta, q, z, FFLEN_4096);

    // CT = E_A(a.b)
    PAILLIER_MULT(PUB, CA, &B1, &CT);

    // CZ = E_A(z)
    PAILLIER_ENCRYPT(RNG, PUB, &Z, &CZ, R);

    // CB = E_A(a.b + z)
    PAILLIER_ADD(PUB, &CT, &CZ, CB);

    // Output Z for Debug
    if (ZO!=NULL)
    {
        char z1[FS_4096];
        octet Z1 = {0,sizeof(z1),z1};
        FF_4096_toOctet(&Z1, z, FFLEN_4096);
        OCT_clear(ZO);
        ZO->len = EGS_SECP256K1;
        Z1.len = FS_4096 - EGS_SECP256K1;
        OCT_truncate(ZO,&Z1);
    }

    // Output beta
    char beta1[FS_4096];
    octet BETA1 = {0,sizeof(beta1),beta1};
    FF_4096_toOctet(&BETA1, beta, FFLEN_4096);
    OCT_clear(BETA);
    BETA->len = EGS_SECP256K1;
    BETA1.len = FS_4096 - EGS_SECP256K1;
    OCT_truncate(BETA,&BETA1);
}

/* sum = a1.b1 + alpha + beta  */
void MPC_SUM_MTA(octet *A, octet *B, octet *ALPHA, octet *BETA,  octet *SUM)
{
    BIG_256_56 a;
    BIG_256_56 b;
    BIG_256_56 alpha;
    BIG_256_56 beta;
    BIG_256_56 sum;
    BIG_256_56 q;

    // Curve order
    BIG_256_56_rcopy(q,CURVE_Order_SECP256K1);

    // Load values
    BIG_256_56_fromBytes(a,A->val);
    BIG_256_56_fromBytes(b,B->val);
    BIG_256_56_fromBytes(alpha,ALPHA->val);
    BIG_256_56_fromBytes(beta,BETA->val);

    // sum = a.b mod q
    BIG_256_56_modmul(sum,a,b,q);

    // sum = sum + alpha  + beta
    BIG_256_56_add(sum,sum,alpha);
    BIG_256_56_add(sum,sum,beta);

    // sum = sum mod q
    BIG_256_56_mod(sum,q);

    // Output result
    SUM->len=EGS_SECP256K1;
    BIG_256_56_toBytes(SUM->val,sum);
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

void MTA_RP_challenge(PAILLIER_public_key *key, COMMITMENTS_BC_pub_modulus *mod, octet *CT, MTA_RP_commitment *c, octet *E)
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
    E->len = MODBYTES_256_56;
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
    FF_2048_zero(m, HFLEN_2048);
}

// Utility function to compute the triple power for verification
// purposes. It is NOT side channel resistant
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
    FF_2048_pow3(proof, hws1, hws3, hws2, hws4, proof, e, p, HFLEN_2048, HFLEN_2048);
}

int MTA_RP_verify(PAILLIER_public_key *key, COMMITMENTS_BC_priv_modulus *mod, octet *CT, octet *E, MTA_RP_commitment *co, MTA_RP_proof *p)
{
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
    MTA_triple_power(wp_proof, mod->b0, mod->b1, p->s1, p->s2, co->z, e, mod->P, 0);
    MTA_triple_power(wq_proof, mod->b0, mod->b1, p->s1, p->s2, co->z, e, mod->Q, 0);

    // Reduce w mod P and Q for comparison
    FF_2048_dmod(hws1, co->w, mod->P, HFLEN_2048);
    FF_2048_dmod(hws2, co->w, mod->Q, HFLEN_2048);

    // Compare the results modulo P and Q
    // since w == w' mod PQ <==> w == w' mod P & w == w' mod Q
    if ((FF_2048_comp(hws1, wp_proof, HFLEN_2048) != 0) || (FF_2048_comp(hws2, wq_proof, HFLEN_2048) != 0))
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
