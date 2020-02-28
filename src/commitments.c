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

#include "amcl/commitments.h"

/* NM Commitments Definitions */

// Compute the hash of X || R
static void hash(const octet *X, const octet *R, octet *C)
{
    int i;
    hash256 sha256;

    HASH256_init(&sha256);

    // Process X
    for (i = 0; i < X->len; i++)
    {
        HASH256_process(&sha256, X->val[i]);
    }

    // Process R
    for (i = 0; i < R->len; i++)
    {
        HASH256_process(&sha256, R->val[i]);
    }

    // Output the digest in C
    HASH256_hash(&sha256, C->val);
    C->len = SHA256;
}

// Compute a commitment for the value X
void COMMITMENTS_NM_commit(csprng *RNG, const octet *X, octet *R, octet *C)
{
    if (RNG != NULL)
    {
        OCT_rand(R, RNG, SHA256);
    }

    hash(X, R, C);
}

// Verify the commitment for the value X
int COMMITMENTS_NM_decommit(const octet *X, const octet *R, octet *C)
{
    char d[SHA256];
    octet D = {0, sizeof(d), d};

    // Validate the length of R. This step MUST be performed
    // to make the scheme non malleable
    if (R->len != SHA256)
    {
        return COMMITMENTS_FAIL;
    }

    // Verify the commitment
    hash(X, R, &D);

    if (!OCT_comp(C, &D))
    {
        return COMMITMENTS_FAIL;
    }

    return COMMITMENTS_OK;
}

/* Bit Commitment Setup Definitions */

/*
 * Check if a number is a safe prime
 */
static int is_safe_prime(BIG_1024_58 *p, BIG_1024_58 *P, csprng *RNG, int n)
{
#ifndef C99
    BIG_1024_58 Pm1[FFLEN_2048];
    BIG_1024_58 f[FFLEN_2048];
#else
    BIG_1024_58 Pm1[n];
    BIG_1024_58 f[n];
#endif

    // Sieve small primes from P, p is already checked in Miller-Rabin
    sign32 sf=4849845;/* 3*5*.. *19 */

    if(FF_2048_cfactor(P, sf, n))
    {
        return 0;
    }

    // Check primality of p
    if (FF_2048_prime(p, RNG, n) == 0)
    {
        return 0;
    }

    // Simplified primality check for safe primes using
    // Pocklington's criterion
    //
    // If p is prime, P = 2p+1, 2^(P-1) = 1 mod P, then P is prime
    FF_2048_init(f, 2, n);
    FF_2048_copy(Pm1, P, n);
    FF_2048_dec(Pm1, 1, n);

    FF_2048_pow(f, f, Pm1, P, n);
    FF_2048_dec(f, 1, n);
    if (FF_2048_iszilch(f, n))
    {
        return 1;
    }

    return 0;
}

/*
 * Generate a safe prime P, such that P = 2 * p + 1
 * n is the size of P in BIGs
 */
void generate_safe_prime(csprng *RNG, BIG_1024_58 *p, BIG_1024_58 *P, int n)
{
    int lastbits;

    FF_2048_random(p, RNG, n);
    FF_2048_shr(p, n);

    // Make sure p = 3 mod 4
    lastbits = FF_2048_lastbits(p, 2);
    FF_2048_inc(p, 3 - lastbits, n);

    // P = 2p + 1
    FF_2048_copy(P, p, n);
    FF_2048_shl(P, n);
    FF_2048_inc(P, 1, n);

    while (!is_safe_prime(p, P, RNG, n))
    {
        // Increase p by 4 to keep it = 3 mod 4, P grows as 2*p
        FF_2048_inc(p, 4, n);
        FF_2048_inc(P, 8, n);
    }
}

/*
 * Find random element of order p in Z/PZ
 * Assuming P = 2p + 1 is a safe prime, i.e. phi(P) = 2p
 */
void bc_generator(csprng *RNG, BIG_1024_58* x, BIG_1024_58 *p, BIG_1024_58 *P, int n)
{
#ifndef C99
    BIG_1024_58 e[FFLEN_2048];
#else
    BIG_1024_58 e[n];
#endif

    FF_2048_randomnum(x, P, RNG, n);

    // While ord(x) = 2, try the next
    FF_2048_power(e, x, 2, P, n);
    FF_2048_dec(e, 1, n);
    while (FF_2048_iszilch(e, n))
    {
        FF_2048_inc(x, 1, n);

        FF_2048_power(e, x, 2, P, n);
        FF_2048_dec(e, 1, n);
    }

    // If ord(x) = 2p, square it.
    FF_2048_skpow(e, x, p, P, n, n);
    FF_2048_dec(e, 1, n);
    if (!FF_2048_iszilch(e, n))
    {
        FF_2048_power(x, x, 2, P, n);
    }
}

void COMMITMENTS_BC_setup(csprng *RNG, COMMITMENTS_BC_priv_modulus *m, octet *P, octet *Q, octet *B0, octet *ALPHA)
{
    BIG_1024_58 p[HFLEN_2048];
    BIG_1024_58 q[HFLEN_2048];
    BIG_1024_58 gp[HFLEN_2048];
    BIG_1024_58 gq[HFLEN_2048];
    BIG_1024_58 ap[HFLEN_2048];
    BIG_1024_58 aq[HFLEN_2048];

    /* Load or generate safe primes P, Q */

    if (P == NULL)
    {
        generate_safe_prime(RNG, p, m->P, HFLEN_2048);
    }
    else
    {
        FF_2048_fromOctet(m->P, P, HFLEN_2048);
        FF_2048_copy(p, m->P, HFLEN_2048);

        // Since P is odd, P>>1 == (P-1) / 2
        FF_2048_shr(p, HFLEN_2048);
    }

    if (Q == NULL)
    {
        generate_safe_prime(RNG, q, m->Q, HFLEN_2048);
    }
    else
    {
        FF_2048_fromOctet(m->Q, Q, HFLEN_2048);
        FF_2048_copy(q, m->Q, HFLEN_2048);

        // Since Q is odd, Q>>1 == (Q-1) / 2
        FF_2048_shr(q, HFLEN_2048);
    }

    FF_2048_mul(m->N, m->P, m->Q, HFLEN_2048);
    FF_2048_mul(m->pq, p, q, HFLEN_2048);

    /* Load or generate generator b0 and DLOG exponent alpha */

    if (B0 == NULL)
    {
        // Find a generator of G_pq in Z/NZ using the crt to
        // combine generators of G_p in Z/PZ and G_q in Z/QZ
        bc_generator(RNG, gp, p, m->P, HFLEN_2048);
        bc_generator(RNG, gq, q, m->Q, HFLEN_2048);

        FF_2048_crt(m->b0, gp, gq, m->P, m->Q, HFLEN_2048);
    }
    else
    {
        FF_2048_fromOctet(m->b0, B0, FFLEN_2048);

        FF_2048_dmod(gp, m->b0, m->P, HFLEN_2048);
        FF_2048_dmod(gq, m->b0, m->Q, HFLEN_2048);
    }

    if (ALPHA == NULL)
    {
        FF_2048_randomnum(m->alpha, m->pq, RNG, FFLEN_2048);

        // Look for invertible alpha and precompute inverse
        FF_2048_invmodp(m->ialpha, m->alpha, m->pq, FFLEN_2048);
        while (FF_2048_iszilch(m->ialpha, FFLEN_2048))
        {
            FF_2048_inc(m->alpha, 1, FFLEN_2048);
            FF_2048_invmodp(m->ialpha, m->alpha, m->pq, FFLEN_2048);
        }
    }
    else
    {
        // Load alpha and precompute inverse
        FF_2048_fromOctet(m->alpha, ALPHA, FFLEN_2048);
        FF_2048_invmodp(m->ialpha, m->alpha, m->pq, FFLEN_2048);
    }

    /* Compute b1 as b0 to the alpha using CRT */

    FF_2048_dmod(ap, m->alpha, p, HFLEN_2048);
    FF_2048_dmod(aq, m->alpha, q, HFLEN_2048);

    FF_2048_skpow(gp, gp, ap, m->P, HFLEN_2048, HFLEN_2048);
    FF_2048_skpow(gq, gq, aq, m->Q, HFLEN_2048, HFLEN_2048);

    FF_2048_crt(m->b1, gp, gq, m->P, m->Q, HFLEN_2048);

    // Clean memory
    FF_2048_zero(p,  HFLEN_2048);
    FF_2048_zero(q,  HFLEN_2048);
    FF_2048_zero(gp, HFLEN_2048);
    FF_2048_zero(gq, HFLEN_2048);
    FF_2048_zero(ap, HFLEN_2048);
    FF_2048_zero(aq, HFLEN_2048);
}

void COMMITMENTS_BC_kill_priv_modulus(COMMITMENTS_BC_priv_modulus *m)
{
    FF_2048_zero(m->P, HFLEN_2048);
    FF_2048_zero(m->Q, HFLEN_2048);
    FF_2048_zero(m->pq, FFLEN_2048);
    FF_2048_zero(m->alpha, FFLEN_2048);
    FF_2048_zero(m->ialpha, FFLEN_2048);
}

void COMMITMENTS_BC_export_public_modulus(COMMITMENTS_BC_pub_modulus *pub, COMMITMENTS_BC_priv_modulus *priv)
{
    FF_2048_copy(pub->b0, priv->b0, FFLEN_2048);
    FF_2048_copy(pub->b1, priv->b1, FFLEN_2048);
    FF_2048_copy(pub->N, priv->N, FFLEN_2048);
}
