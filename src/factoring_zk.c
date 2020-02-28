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

/* ZK proof of knowledge of factoring definitions */

#include <string.h>
#include "amcl/factoring_zk.h"

#define FACTORING_ZK_K 2

// Copy the internal state of an hash function
static void hash_copy(hash256 *dst, const hash256 *src)
{
    memcpy(dst->length, src->length, sizeof(dst->length));
    memcpy(dst->h, src->h, sizeof(dst->h));
    memcpy(dst->w, src->w, sizeof(dst->w));
    dst->hlen = src->hlen;
}

// utility function to has an octet
static void hash_oct(hash256 *sha, const octet *O)
{
    int i;

    for (i = 0; i < O->len; i++)
    {
        HASH256_process(sha, O->val[i]);
    }
}

// Compute generator bytes with MGF1 using SHA256.
// sha should be already initialized and contain the
// partial seed N, the seed is then completed with I2OSP(k, 4).
void generator(hash256 *sha, int k, octet *O)
{
    int i;
    char c[4];

    hash256 shai;

    OCT_empty(O);

    // Complete SEED with I2OSP(k, 4)
    c[0] = (k >> 24) & 0xFF;
    c[1] = (k >> 16) & 0xFF;
    c[2] = (k >> 8) & 0xFF;
    c[3] = k & 0xFF;

    HASH256_process(sha, c[0]);
    HASH256_process(sha, c[1]);
    HASH256_process(sha, c[2]);
    HASH256_process(sha, c[3]);

    for (i = 0; i < FS_2048 / SHA256; i++)
    {
        // Compute partial hash of SEED || I2OSP(i, 4)
        hash_copy(&shai, sha);
        c[0] = (i >> 24) & 0xFF;
        c[1] = (i >> 16) & 0xFF;
        c[2] = (i >> 8) & 0xFF;
        c[3] = i & 0xFF;

        HASH256_process(&shai, c[0]);
        HASH256_process(&shai, c[1]);
        HASH256_process(&shai, c[2]);
        HASH256_process(&shai, c[3]);

        // Append the digest to the ouptut octet
        HASH256_hash(&shai, O->val + O->len);
        O->len+=SHA256;
    }
}

/*
 *  Zi = MGF_SHA256(N, i)
 *  X  = H(Z1^r, Z2^r)
 *  e  = H'(N, Z1, Z2, X)
 *  y  = r + (N - phi(N)) * e
 */
void FACTORING_ZK_prove(csprng *RNG, octet *P, octet *Q, octet *R, octet *E, octet *Y)
{
    int i;

    hash256 sha;
    hash256 mgf;
    hash256 sha_x;
    hash256 sha_prime;

    BIG_1024_58 p[HFLEN_2048];
    BIG_1024_58 q[HFLEN_2048];
    BIG_1024_58 n[FFLEN_2048];

    BIG_1024_58 r[FFLEN_2048];
    BIG_1024_58 rp[HFLEN_2048];
    BIG_1024_58 rq[HFLEN_2048];
    BIG_1024_58 zrp[HFLEN_2048];
    BIG_1024_58 zrq[HFLEN_2048];
    BIG_1024_58 e[HFLEN_2048];

    // Workspaces
    BIG_1024_58 hws[HFLEN_2048];
    BIG_1024_58 ws[FFLEN_2048];

    char w[FS_2048];
    octet W = {0, sizeof(w), w};

    // Read modulus
    FF_2048_fromOctet(p, P, HFLEN_2048);
    FF_2048_fromOctet(q, Q, HFLEN_2048);
    FF_2048_mul(n, p, q, HFLEN_2048);

    if (RNG != NULL)
    {
        FF_2048_random(r, RNG, FFLEN_2048);
    }
    else
    {
        FF_2048_fromOctet(r, R, FFLEN_2048);
    }

    // Compute r mod (p-1) and r mod (q-1) for exponent with CRT
    FF_2048_copy(hws, p, HFLEN_2048);
    FF_2048_dec(hws, 1, HFLEN_2048);
    FF_2048_dmod(rp, r, hws, HFLEN_2048);

    FF_2048_copy(hws, q, HFLEN_2048);
    FF_2048_dec(hws, 1, HFLEN_2048);
    FF_2048_dmod(rq, r, hws, HFLEN_2048);

    // Process N in the hash function H(N, ?)
    HASH256_init(&sha);
    FF_2048_toOctet(&W, n, FFLEN_2048);
    hash_oct(&sha, &W);

    // Duplicate the state of H so it can be used as H'(N, ?)
    hash_copy(&sha_prime, &sha);

    // Compute X and e
    HASH256_init(&sha_x);

    for (i = 0; i < FACTORING_ZK_K; i++)
    {
        // generate Z_i and process it in H'
        hash_copy(&mgf, &sha);
        generator(&mgf, i, &W);

        FF_2048_fromOctet(ws, &W, FFLEN_2048);
        FF_2048_mod(ws, n, FFLEN_2048);

        FF_2048_toOctet(&W, ws, FFLEN_2048);
        hash_oct(&sha_prime, &W);

        // Compute Z_i ^ r mod P
        FF_2048_dmod(hws, ws, p, HFLEN_2048);
        FF_2048_skpow(zrp, hws, rp, p, HFLEN_2048, HFLEN_2048);

        // Compute Z_i ^ r mod Q
        FF_2048_dmod(hws, ws, q, HFLEN_2048);
        FF_2048_skpow(zrq, hws, rq, q, HFLEN_2048, HFLEN_2048);

        // Combine Z_i ^ r mod N with CRT
        FF_2048_crt(ws, zrp, zrq, p, q, HFLEN_2048);

        // Process Z_i ^ r mod N in H
        FF_2048_toOctet(&W, ws, FFLEN_2048);
        hash_oct(&sha_x, &W);
    }

    // Compute X = H(Z1, Z2)
    HASH256_hash(&sha_x, W.val);
    W.len = SHA256;

    // Compute e = H(N, Z1, Z2, X)
    hash_oct(&sha_prime, &W);
    HASH256_hash(&sha_prime, W.val);
    W.len = FACTORING_ZK_B;

    OCT_copy(E, &W);
    OCT_pad(&W, HFS_2048);
    FF_2048_fromOctet(e, &W, HFLEN_2048);

    // N - phi(N) = P + Q - 1
    FF_2048_add(hws, p, q, HFLEN_2048);
    FF_2048_dec(hws, 1, HFLEN_2048);

    // e * (N - phi(N))
    FF_2048_mul(ws, hws, e, HFLEN_2048);

    // y = r + e * (N - phi(N))
    FF_2048_add(ws, ws, r, FFLEN_2048);

    FF_2048_norm(ws, FFLEN_2048);
    FF_2048_toOctet(Y, ws, FFLEN_2048);

    // Clear memory
    FF_2048_zero(r,   FFLEN_2048);
    FF_2048_zero(n,   FFLEN_2048);
    FF_2048_zero(p,   HFLEN_2048);
    FF_2048_zero(q,   HFLEN_2048);
    FF_2048_zero(rp,  HFLEN_2048);
    FF_2048_zero(rq,  HFLEN_2048);
    FF_2048_zero(zrp, HFLEN_2048);
    FF_2048_zero(zrq, HFLEN_2048);
    FF_2048_zero(hws, HFLEN_2048);
}

int FACTORING_ZK_verify(octet *N, octet *E, octet *Y)
{
    int i;

    hash256 sha;
    hash256 mgf;
    hash256 sha_x;
    hash256 sha_prime;

    BIG_1024_58 n[FFLEN_2048];
    BIG_1024_58 exp[2 * FFLEN_2048];

    // Workspaces
    BIG_1024_58 ws[FFLEN_2048];
    BIG_1024_58 dws[2 * FFLEN_2048];

    char w[FS_2048];
    octet W = {0, sizeof(w), w};

    // 0 <= Y <= A by construction

    // Process N in the hash function H(N, ?)
    HASH256_init(&sha);
    hash_oct(&sha, N);

    // Duplicate the state of H so it can be used as H'(N, ?)
    hash_copy(&sha_prime, &sha);

    FF_2048_fromOctet(n, N, FFLEN_2048);

    OCT_copy(&W, E);
    OCT_pad(&W, FS_2048);
    FF_2048_fromOctet(ws, &W, FFLEN_2048);

    // Compute exponent N*e - Y = - R + e * phi(N)
    // The Z^exp need to be inverted after the computation
    FF_2048_mul(exp, n, ws, FFLEN_2048);
    FF_2048_norm(exp, FFLEN_2048);

    FF_2048_zero(dws, 2 * FFLEN_2048);
    FF_2048_fromOctet(dws, Y, FFLEN_2048);
    FF_2048_sub(exp, exp, dws, 2 * FFLEN_2048);
    FF_2048_norm(exp, 2 * FFLEN_2048);

    // Compute X and e
    HASH256_init(&sha_x);

    for (i = 0; i < FACTORING_ZK_K; i++)
    {
        // generate Z_i and process it in H'
        hash_copy(&mgf, &sha);
        generator(&mgf, i, &W);

        FF_2048_fromOctet(ws, &W, FFLEN_2048);
        FF_2048_mod(ws, n, FFLEN_2048);

        FF_2048_toOctet(&W, ws, FFLEN_2048);
        hash_oct(&sha_prime, &W);

        // Compute Z_i ^ r mod N and process it in H
        FF_2048_skpow(ws, ws, exp, n, FFLEN_2048, 2 * FFLEN_2048);
        FF_2048_invmodp(ws, ws, n, FFLEN_2048);

        FF_2048_toOctet(&W, ws, FFLEN_2048);
        hash_oct(&sha_x, &W);
    }

    // Compute X = H(Z1, Z2)
    HASH256_hash(&sha_x, W.val);
    W.len = SHA256;

    // Compute e = H(N, Z1, Z2, X)
    hash_oct(&sha_prime, &W);
    HASH256_hash(&sha_prime, W.val);
    W.len = FACTORING_ZK_B;

    if (!OCT_comp(&W, E))
    {
        return FACTORING_ZK_FAIL;
    }

    return FACTORING_ZK_OK;
}

