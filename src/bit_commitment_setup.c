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

#include "amcl/bit_commitment_setup.h"


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

    FF_2048_nt_pow(f, f, Pm1, P, n, n);
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
#ifndef C99
    BIG_1024_58 r[HFLEN_2048];
    BIG_1024_58 twelve[HFLEN_2048];
#else
    BIG_1024_58 r[n];
    BIG_1024_58 twelve[n];
#endif
    FF_2048_init(twelve, 12, n);

    FF_2048_random(p, RNG, n);
    FF_2048_shr(p, n);

    // Make sure p = 11 mod 12
    //
    // p == 3 mod 4 for library
    // p == 2 mod 3 otherwise 3 | P
    //
    // Naive check for now. We can probably benefit from a custom mod3
    // sum((-1)^i * xi mod 3) that spits an integer
    // so we can do the lastbits check + mod3 check but this is negligible
    // compared to the search time
    FF_2048_copy(r, p, n);
    FF_2048_mod(r, twelve, n);
    FF_2048_inc(p, 11, n);
    FF_2048_sub(p, p, r, n);

    // P = 2p + 1
    FF_2048_copy(P, p, n);
    FF_2048_shl(P, n);
    FF_2048_inc(P, 1, n);

    while (!is_safe_prime(p, P, RNG, n))
    {
        // Increase p by 12 to keep it = 11 mod 12, P grows as 2*p
        FF_2048_inc(p, 12, n);
        FF_2048_inc(P, 24, n);
    }
}

/*
 * Find random element of order p in Z/PZ
 * Assuming P = 2p + 1 is a safe prime, i.e. phi(P) = 2p
 */
void bc_generator(csprng *RNG, BIG_1024_58* x, BIG_1024_58 *P, int n)
{
#ifndef C99
    BIG_1024_58 r[FFLEN_2048];
#else
    BIG_1024_58 r[n];
#endif

    FF_2048_randomnum(r, P, RNG, n);

    do
    {
        FF_2048_nt_pow_int(x, r, 2, P, n);
        FF_2048_inc(r, 1, n);
    }
    while (FF_2048_isunity(x, n));
}

void BIT_COMMITMENT_setup(csprng *RNG, BIT_COMMITMENT_priv *m, octet *P, octet *Q, octet *B0, octet *ALPHA)
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
        generate_safe_prime(RNG, p, m->mod.p, HFLEN_2048);
    }
    else
    {
        FF_2048_fromOctet(m->mod.p, P, HFLEN_2048);
        FF_2048_copy(p, m->mod.p, HFLEN_2048);

        // Since P is odd, P>>1 == (P-1) / 2
        FF_2048_shr(p, HFLEN_2048);
    }

    if (Q == NULL)
    {
        generate_safe_prime(RNG, q, m->mod.q, HFLEN_2048);
    }
    else
    {
        FF_2048_fromOctet(m->mod.q, Q, HFLEN_2048);
        FF_2048_copy(q, m->mod.q, HFLEN_2048);

        // Since Q is odd, Q>>1 == (Q-1) / 2
        FF_2048_shr(q, HFLEN_2048);
    }

    FF_2048_mul(m->mod.n, m->mod.p, m->mod.q, HFLEN_2048);
    FF_2048_mul(m->pq, p, q, HFLEN_2048);
    FF_2048_invmodp(m->mod.invpq, m->mod.p, m->mod.q, HFLEN_2048);

    /* Load or generate generator b0 and DLOG exponent alpha */

    if (B0 == NULL)
    {
        // Find a generator of G_pq in Z/NZ using the crt to
        // combine generators of G_p in Z/PZ and G_q in Z/QZ
        bc_generator(RNG, gp, m->mod.p, HFLEN_2048);
        bc_generator(RNG, gq, m->mod.q, HFLEN_2048);

        FF_2048_crt(m->b0, gp, gq, m->mod.p, m->mod.invpq, m->mod.n, HFLEN_2048);
    }
    else
    {
        FF_2048_fromOctet(m->b0, B0, FFLEN_2048);

        FF_2048_dmod(gp, m->b0, m->mod.p, HFLEN_2048);
        FF_2048_dmod(gq, m->b0, m->mod.q, HFLEN_2048);
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

    FF_2048_ct_pow(gp, gp, ap, m->mod.p, HFLEN_2048, HFLEN_2048);
    FF_2048_ct_pow(gq, gq, aq, m->mod.q, HFLEN_2048, HFLEN_2048);

    FF_2048_crt(m->b1, gp, gq, m->mod.p, m->mod.invpq, m->mod.n, HFLEN_2048);

    // Clean memory
    FF_2048_zero(p,  HFLEN_2048);
    FF_2048_zero(q,  HFLEN_2048);
    FF_2048_zero(gp, HFLEN_2048);
    FF_2048_zero(gq, HFLEN_2048);
    FF_2048_zero(ap, HFLEN_2048);
    FF_2048_zero(aq, HFLEN_2048);
}

void BIT_COMMITMENT_priv_fromOctets(BIT_COMMITMENT_priv *m, octet *P, octet *Q, octet *B0, octet * ALPHA)
{
    BIT_COMMITMENT_setup(NULL, m, P, Q, B0, ALPHA);
}

void BIT_COMMITMENT_priv_toOctets(octet *P, octet *Q, octet *B0, octet * ALPHA, BIT_COMMITMENT_priv *m)
{
    MODULUS_toOctets(P, Q, &m->mod);
    FF_2048_toOctet(B0, m->b0, FFLEN_2048);
    FF_2048_toOctet(ALPHA, m->alpha, FFLEN_2048);
}

void BIT_COMMITMENT_priv_kill(BIT_COMMITMENT_priv *m)
{
    MODULUS_kill(&m->mod);
    FF_2048_zero(m->pq, FFLEN_2048);
    FF_2048_zero(m->alpha, FFLEN_2048);
    FF_2048_zero(m->ialpha, FFLEN_2048);
}

void BIT_COMMITMENT_priv_to_pub(BIT_COMMITMENT_pub *pub, BIT_COMMITMENT_priv *priv)
{
    FF_2048_copy(pub->b0, priv->b0, FFLEN_2048);
    FF_2048_copy(pub->b1, priv->b1, FFLEN_2048);
    FF_2048_copy(pub->N, priv->mod.n, FFLEN_2048);
}

void BIT_COMMITMENT_pub_fromOctets(BIT_COMMITMENT_pub *m, octet *N, octet *B0, octet *B1)
{
    FF_2048_fromOctet(m->N,  N,  FFLEN_2048);
    FF_2048_fromOctet(m->b0, B0, FFLEN_2048);
    FF_2048_fromOctet(m->b1, B1, FFLEN_2048);
}

void BIT_COMMITMENT_pub_toOctets(octet *N, octet *B0, octet *B1, BIT_COMMITMENT_pub *m)
{
    FF_2048_toOctet(N,  m->N,  FFLEN_2048);
    FF_2048_toOctet(B0, m->b0, FFLEN_2048);
    FF_2048_toOctet(B1, m->b1, FFLEN_2048);
}

void BIT_COMMITMENT_setup_prove(csprng *RNG, BIT_COMMITMENT_priv *m, BIT_COMMITMENT_setup_proof *p, octet *ID, octet *AD)
{
    HDLOG_iter_values R;

    char e[HDLOG_CHALLENGE_SIZE];
    octet E = {0, sizeof(e), e};

    // Prove b1 = b0^alpha
    HDLOG_commit(RNG, &m->mod, m->pq, m->b0, R, p->rho);
    HDLOG_challenge(m->mod.n, m->b0, m->b1, p->rho, ID, AD, &E);
    HDLOG_prove(m->pq, m->alpha, R, &E, p->t);

    // Prove b0 = b1 ^ ialpha
    HDLOG_commit(RNG, &m->mod, m->pq, m->b1, R, p->irho);
    HDLOG_challenge(m->mod.n, m->b1, m->b0, p->irho, ID, AD, &E);
    HDLOG_prove(m->pq, m->ialpha, R, &E, p->it);

    // Clean memory
    HDLOG_iter_values_kill(R);
}

int BIT_COMMITMENT_setup_verify(BIT_COMMITMENT_pub *m, BIT_COMMITMENT_setup_proof *p, octet *ID, octet *AD)
{
    int rc;

    char e[HDLOG_CHALLENGE_SIZE];
    octet E = {0, sizeof(e), e};

    // Verify knowledge of DLOG of b1
    HDLOG_challenge(m->N, m->b0, m->b1, p->rho, ID, AD, &E);
    rc = HDLOG_verify(m->N, m->b0, m->b1, p->rho, &E, p->t);
    if (rc != HDLOG_OK)
    {
        printf("%d\n", rc);
        return BIT_COMMITMENT_INVALID_PROOF + 100;
    }

    // Verify knowledge of DLOG of b0
    HDLOG_challenge(m->N, m->b1, m->b0, p->irho, ID, AD, &E);
    rc = HDLOG_verify(m->N, m->b1, m->b0, p->irho, &E, p->it);
    if (rc != HDLOG_OK)
    {
        printf("%d\n", rc);
        return BIT_COMMITMENT_INVALID_PROOF;
    }

    return BIT_COMMITMENT_OK;
}

int BIT_COMMITMENT_setup_proof_fromOctets(BIT_COMMITMENT_setup_proof *p, octet *RHO, octet *IRHO, octet *T, octet *IT)
{
    if (HDLOG_iter_values_fromOctet(p->rho, RHO) != HDLOG_OK)
    {
        return BIT_COMMITMENT_INVALID_FORMAT;
    }

    if (HDLOG_iter_values_fromOctet(p->irho, IRHO) != HDLOG_OK)
    {
        return BIT_COMMITMENT_INVALID_FORMAT;
    }

    if (HDLOG_iter_values_fromOctet(p->t, T) != HDLOG_OK)
    {
        return BIT_COMMITMENT_INVALID_FORMAT;
    }

    if (HDLOG_iter_values_fromOctet(p->it, IT) != HDLOG_OK)
    {
        return BIT_COMMITMENT_INVALID_FORMAT;
    }

    return BIT_COMMITMENT_OK;
}

void BIT_COMMITMENT_setup_proof_toOctets(octet *RHO, octet *IRHO, octet *T, octet *IT, BIT_COMMITMENT_setup_proof *p)
{
    HDLOG_iter_values_toOctet(RHO,  p->rho);
    HDLOG_iter_values_toOctet(IRHO, p->irho);
    HDLOG_iter_values_toOctet(T,    p->t);
    HDLOG_iter_values_toOctet(IT,   p->it);
}
