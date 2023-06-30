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

#include "amcl/hidden_dlog.h"

/* Definitions for ZKPoK of a DLOG in a hidden order group */

// Window and table size for CT precomputation
// using 2^w ary method
#define C_WINDOW 4
#define C_SIZE 1 << C_WINDOW

// Window and table size for non CT precomputation
// using basic interleaving
#define N_WINDOW 5
#define N_SIZE 1 << (N_WINDOW - 1)

void HDLOG_commit(csprng *RNG, MODULUS_priv *m, BIG_1024_58 *ord, BIG_1024_58 *B0, HDLOG_iter_values R, HDLOG_iter_values RHO)
{
    int i;

    BIG_1024_58 fm1[HFLEN_2048];
    BIG_1024_58 rhoq[HFLEN_2048];
    BIG_1024_58 ND[HFLEN_2048];

    BIG_1024_58 ws[HFLEN_2048];
    BIG_1024_58 *WS[] = {ws};

    BIG_1024_58 T_mem[C_SIZE][HFLEN_2048];
    BIG_1024_58 *T[C_SIZE] = {0};

    for (i = 0; i < C_SIZE; i++)
    {
        T[i] = T_mem[i];
    }

    // Generate random values for commitments
    if (RNG != NULL)
    {
        for (i = 0; i < HDLOG_PROOF_ITERS; i++)
        {
            FF_2048_randomnum(R[i], ord, RNG, FFLEN_2048);
        }
    }

    // Compute exponents B0^R mod P for later use in CRT
    FF_2048_copy(fm1, m->p, HFLEN_2048);
    FF_2048_dec(fm1, 1, HFLEN_2048);

    FF_2048_dmod(ws, B0, m->p, HFLEN_2048);

    FF_2048_invmod2m(ND, m->p, HFLEN_2048);
    FF_2048_2w_precompute(WS, T, 1, C_WINDOW, m->p, ND, HFLEN_2048);

    for (i = 0; i < HDLOG_PROOF_ITERS; i++)
    {
        FF_2048_dmod(ws, R[i], fm1, HFLEN_2048);
        FF_2048_ct_2w_pow(RHO[i], T, WS, 1, C_WINDOW, m->p, ND, HFLEN_2048, HFLEN_2048);
    }

    // Compute exponents B0^R mod Q and recombine using CRT
    FF_2048_dmod(ws, B0, m->q, HFLEN_2048);
    FF_2048_invmod2m(ND, m->q, HFLEN_2048);
    FF_2048_2w_precompute(WS, T, 1, C_WINDOW, m->q, ND, HFLEN_2048);

    FF_2048_copy(fm1, m->q, HFLEN_2048);
    FF_2048_dec(fm1, 1, HFLEN_2048);

    for (i = 0; i < HDLOG_PROOF_ITERS; i++)
    {
        FF_2048_dmod(ws, R[i], fm1, HFLEN_2048);
        FF_2048_ct_2w_pow(rhoq, T, WS, 1, C_WINDOW, m->q, ND, HFLEN_2048, HFLEN_2048);

        FF_2048_crt(RHO[i], RHO[i], rhoq, m->p, m->invpq, m->n, HFLEN_2048);
    }

    // Clean memory
    FF_2048_zero(fm1,  HFLEN_2048);
    FF_2048_zero(ws,   HFLEN_2048);
    FF_2048_zero(rhoq, HFLEN_2048);
    FF_2048_zero(ND,   HFLEN_2048);
}


void HDLOG_challenge(BIG_1024_58 *N, BIG_1024_58 *B0, BIG_1024_58 *B1, HDLOG_iter_values RHO, const octet *ID, const octet *AD, octet *E)
{
    hash256 sha;

    int i;

    char w[FS_2048];
    octet W = {0, sizeof(w), w};

    HASH256_init(&sha);

    // Bind the public parameters
    FF_2048_toOctet(&W, N, FFLEN_2048);
    HASH_UTILS_hash_oct(&sha, &W);
    FF_2048_toOctet(&W, B0, FFLEN_2048);
    HASH_UTILS_hash_oct(&sha, &W);
    FF_2048_toOctet(&W, B1, FFLEN_2048);
    HASH_UTILS_hash_oct(&sha, &W);

    // Bind to commitment
    for (i = 0; i < HDLOG_PROOF_ITERS; i++)
    {
        FF_2048_toOctet(&W, RHO[i], FFLEN_2048);
        HASH_UTILS_hash_oct(&sha, &W);
    }

    // Bind to ID and optional AD
    HASH_UTILS_hash_i2osp4(&sha, ID->len);
    HASH_UTILS_hash_oct(&sha, ID);

    if (AD != NULL)
    {
        HASH_UTILS_hash_i2osp4(&sha, AD->len);
        HASH_UTILS_hash_oct(&sha, AD);
    }

    HASH256_hash(&sha, w);

    OCT_clear(E);
    OCT_jbytes(E, w, HDLOG_CHALLENGE_SIZE);
}

int HDLOG_challenge_CG21(BIG_1024_58 *N, BIG_1024_58 *B0, BIG_1024_58 *B1, HDLOG_iter_values RHO, const HDLOG_SSID *ssid,
                         octet *E, int n)
{
    hash256 sha;
    char o[SFS_SECP256K1 + 1];
    octet G_oct = {0, sizeof(o), o};

    char qq[EGS_SECP256K1];
    octet q_oct = {0, sizeof(qq), qq};


    char w[FS_2048];
    octet W = {0, sizeof(w), w};

    HASH256_init(&sha);

    // Bind the public parameters
    FF_2048_toOctet(&W, N, FFLEN_2048);
    HASH_UTILS_hash_oct(&sha, &W);

    FF_2048_toOctet(&W, B0, FFLEN_2048);
    HASH_UTILS_hash_oct(&sha, &W);

    FF_2048_toOctet(&W, B1, FFLEN_2048);
    HASH_UTILS_hash_oct(&sha, &W);

    HASH_UTILS_hash_oct(&sha, ssid->rid);
    HASH_UTILS_hash_oct(&sha, ssid->rho);

    CG21_get_G(&G_oct);
    CG21_get_q(&q_oct);

    HASH_UTILS_hash_oct(&sha, &G_oct);
    HASH_UTILS_hash_oct(&sha, &q_oct);

    // sort partial X[i] based on j_packed and process them into sha
    int rc = CG21_hash_set_X(&sha, ssid->X_set_packed, ssid->j_set_packed, n, EFS_SECP256K1 + 1);
    if (rc!=CG21_OK){
        return rc;
    }

    // Bind to commitment
    for (int i = 0; i < HDLOG_PROOF_ITERS; i++)
    {
        FF_2048_toOctet(&W, RHO[i], FFLEN_2048);
        HASH_UTILS_hash_oct(&sha, &W);
    }

    HASH256_hash(&sha, w);

    OCT_clear(E);
    OCT_jbytes(E, w, HDLOG_CHALLENGE_SIZE);

    return HDLOG_OK;
}


void HDLOG_prove(BIG_1024_58 *ord, BIG_1024_58 *alpha, HDLOG_iter_values R, octet *E, HDLOG_iter_values T)
{
    int i;
    int mask;

    BIG_1024_58 alphaneg[FFLEN_2048];

    FF_2048_sub(alphaneg, ord, alpha, FFLEN_2048);

    for (i = 0; i < HDLOG_CHALLENGE_SIZE; i++)
    {
        mask = 0x80;
        while (mask)
        {
            FF_2048_copy(*T, *R, FFLEN_2048);

            // No need to be constant time over the value of E
            // since it is public
            if (E->val[i] & mask)
            {
                FF_2048_add(*T, *T, alphaneg, FFLEN_2048);
                FF_2048_mod(*T, ord, FFLEN_2048);
            }

            // Advance mask and iter values
            mask>>=1;
            R++;
            T++;
        }
    }

    FF_2048_zero(alphaneg, FFLEN_2048);
}


int HDLOG_verify(BIG_1024_58 *N, BIG_1024_58 *B0, BIG_1024_58 *B1, HDLOG_iter_values RHO, const octet *E, HDLOG_iter_values T)
{
    int i;
    int mask;

    BIG_1024_58 ws[FFLEN_2048];
    BIG_1024_58 dws[2 * FFLEN_2048];
    BIG_1024_58 ND[FFLEN_2048];

    BIG_1024_58 PT_mem[N_SIZE][FFLEN_2048];
    BIG_1024_58 *PT[N_SIZE];

    for (i = 0; i < N_SIZE; i++)
    {
        PT[i] = PT_mem[i];
    }

    FF_2048_invmod2m(ND, N, FFLEN_2048);
    FF_2048_bi_precompute(&B0, PT, 1, N_WINDOW, N, ND, FFLEN_2048);

    for (i = 0; i < HDLOG_CHALLENGE_SIZE; i++)
    {
        mask = 0x80;
        while (mask)
        {
            FF_2048_bi_pow(ws, PT, (BIG_1024_58 **)(&T), 1, N_WINDOW, N, ND, FFLEN_2048, FFLEN_2048);

            // No need to be constant time over the value of E
            // since it is public
            if (E->val[i] & mask)
            {
                FF_2048_mul(dws, ws, B1, FFLEN_2048);
                FF_2048_dmod(ws, dws, N, FFLEN_2048);
            }

            if (FF_2048_comp(ws, *RHO, FFLEN_2048))
            {
                return HDLOG_FAIL;
            }

            // Advance mask and iter values
            mask>>=1;
            RHO++;
            T++;
        }
    }

    return HDLOG_OK;
}

void HDLOG_iter_values_toOctet(octet *O, HDLOG_iter_values v)
{
    int i;

    char w[FS_2048];
    octet W = {0, sizeof(w), w};

    OCT_clear(O);

    for (i = 0; i < HDLOG_PROOF_ITERS; i++)
    {
        FF_2048_toOctet(&W, v[i], FFLEN_2048);
        OCT_joctet(O, &W);
    }
}

int HDLOG_iter_values_fromOctet(HDLOG_iter_values v, octet *O)
{
    int i;

    char w[FS_2048];
    octet W = {0, sizeof(w), w};

    if (O->len != HDLOG_VALUES_SIZE)
    {
        return HDLOG_INVALID_VALUES;
    }

    for (i = HDLOG_PROOF_ITERS - 1; i >= 0; i--)
    {
        OCT_chop(O, &W, O->len - FS_2048);
        FF_2048_fromOctet(v[i], &W, FFLEN_2048);
    }

    // Restore length of O
    O->len = HDLOG_VALUES_SIZE;

    return HDLOG_OK;
}

void HDLOG_iter_values_kill(HDLOG_iter_values v)
{
    int i;

    for (i = 0; i < HDLOG_PROOF_ITERS; i++)
    {
        FF_2048_zero(v[i], FFLEN_2048);
    }
}
