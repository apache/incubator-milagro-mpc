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

/* Shamir Secret Sharing and Verifiable Secret Sharing API */

#include "amcl/shamir.h"

// Polynomial interpolation coefficients
static void SSS_lagrange_coefficients(int k, const octet* X, BIG_256_56* lc, const BIG_256_56 q)
{
    int i;

    BIG_256_56 x2[k];

    DBIG_256_56 w;

    for(i = 0; i < k; i++)
    {
        BIG_256_56_fromBytesLen(x2[i], X[i].val, X[i].len);
    }

    // Compute numerators in place using partial products
    // to achieve it in O(n)
    // c_i = x_0 * ... * x_(i-1) * x_(i+1) * ... * x_(k-1)

    // Compute partial left products
    // leave c_0 alone since it only has a right partial product
    BIG_256_56_copy(lc[1], x2[0]);

    for(i = 2; i < k; i++)
    {
        // lp_i = x_0 * ... * x_(i-1) = lp_(i-1) * x_(i-1)
        BIG_256_56_mul(w, lc[i-1], x2[i-1]);
        BIG_256_56_dmod(lc[i], w, q);
    }

    // Compute partial right products and combine

    // Store partial right products in c_0 so at the end
    // of the procedure c_0 = x_1 * ... x_(k-1)
    BIG_256_56_copy(lc[0], x2[k-1]);

    for(i = k-2; i > 0; i--)
    {
        // c_i = lp_i * rp_i
        BIG_256_56_mul(w, lc[i], lc[0]);
        BIG_256_56_dmod(lc[i], w, q);

        // rp_(i-1) = x_i * ... * x_k = x_i * rp_i
        BIG_256_56_mul(w, lc[0], x2[i]);
        BIG_256_56_dmod(lc[0], w, q);
    }

    BIG_256_56 cneg;
    BIG_256_56 denominator;
    BIG_256_56 s;

    for(i = 0; i < k; i++)
    {
        BIG_256_56_one(denominator);

        // cneg = -x_i mod r
        BIG_256_56_sub(cneg, q, x2[i]);

        for(int j = 0; j < k; j++)
        {
            if (i == j) continue;

            // denominator = denominator * (x_j - x_i)
            BIG_256_56_add(s, x2[j], cneg);
            BIG_256_56_norm(s);
            BIG_256_56_mul(w, denominator, s);
            BIG_256_56_dmod(denominator, w, q);
        }

        BIG_256_56_invmodp(denominator, denominator, q);
        BIG_256_56_mul(w, lc[i], denominator);
        BIG_256_56_dmod(lc[i], w, q);
    }
}

static void SSS_sample_polynomial(int k, csprng *RNG, BIG_256_56 *poly, const BIG_256_56 q, octet *S)
{
    // Read or generate secret
    if (S->len == 0)
    {
        BIG_256_56_randomnum(poly[0], q, RNG);
        BIG_256_56_toBytes(S->val, poly[0]);
        S->len = SGS_SECP256K1;
    }
    else
    {
        BIG_256_56_fromBytesLen(poly[0], S->val, S->len);
    }

    // Generate rest of polynomial: f(x) = (a_0) + a_1x + a_2x^2 ... a_{k-1}x^{k-1}
    for(int i = 1; i < k; i++)
    {
        BIG_256_56_randomnum(poly[i], q, RNG);
    }
}

static void SSS_eval_shares(int k, int n, BIG_256_56 *poly, const BIG_256_56 q, SSS_shares *shares)
{
    BIG_256_56 x;
    BIG_256_56 y;
    DBIG_256_56 w;

    /* Calculate shares for x = [1, .., n]
    * Each y = f(x) is computed as
    * y = (...((a_{k-1}x + a_{k-2})x + a_{k-3})x + ...)x + a_0
    */
    BIG_256_56_zero(x);

    for(int j = 0; j < n; j++)
    {
        BIG_256_56_inc(x, 1);
        BIG_256_56_zero(y);

        for(int i = k-1; i >= 0; i--)
        {
            BIG_256_56_mul(w, y, x);
            BIG_256_56_dmod(y, w, q);
            BIG_256_56_add(y, y, poly[i]);
            BIG_256_56_norm(y);
        }
        BIG_256_56_mod(y, q);

        // Output share
        BIG_256_56_toBytes(shares->X[j].val, x);
        shares->X[j].len = SGS_SECP256K1;

        BIG_256_56_toBytes(shares->Y[j].val, y);
        shares->Y[j].len = SGS_SECP256K1;
    }

    // Clean memory
    BIG_256_56_zero(y);
    BIG_256_56_dzero(w);
}

// Use lagrange coefficents to compute s = a_0. Output is NOT normed
static void SSS_interpolate(int k, const SSS_shares *shares, BIG_256_56 *coefs, const BIG_256_56 q, BIG_256_56 secret)
{
    BIG_256_56  w;
    DBIG_256_56 dw;

    BIG_256_56_zero(secret);

    for(int i = 0; i < k; i++)
    {
        BIG_256_56_fromBytes(w, shares->Y[i].val);

        BIG_256_56_mul(dw, w, coefs[i]);
        BIG_256_56_dmod(w, dw, q);
        BIG_256_56_add(secret, secret, w);
        BIG_256_56_norm(secret);

        // Reduce accumulator if necessary
        BIG_256_56_sub(w, secret, q);
        BIG_256_56_cmove(secret, w, BIG_256_56_comp(secret, q) == 1);
    }

    // Clean memory
    BIG_256_56_zero(w);
    BIG_256_56_dzero(dw);
}

void SSS_make_shares(int k, int n, csprng *RNG, SSS_shares *shares, octet* S)
{
# ifndef C99
    BIG_256_56 poly[128];
# else
    BIG_256_56 poly[k];
#endif

    BIG_256_56 q;
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    SSS_sample_polynomial(k, RNG, poly, q, S);
    SSS_eval_shares(k, n, poly, q, shares);

    // Clean memory
    for (int i = 0; i < k; i++)
    {
        BIG_256_56_zero(poly[i]);
    }
}

void SSS_recover_secret(int k, const SSS_shares *shares, octet* S)
{
# ifndef C99
    BIG_256_56 coefs[128];
# else
    BIG_256_56 coefs[k];
#endif

    BIG_256_56 q;
    BIG_256_56 secret;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    SSS_lagrange_coefficients(k, shares->X, coefs, q);
    SSS_interpolate(k, shares, coefs, q, secret);

    // Output secret
    BIG_256_56_toBytes(S->val, secret);
    S->len = SGS_SECP256K1;

    // Clean memory
    BIG_256_56_zero(secret);
}

void SSS_shamir_to_additive(int k, const octet *X_j, const octet *Y_j, const octet *X, octet *S)
{
    BIG_256_56 x_j;
    BIG_256_56 q;

    BIG_256_56 w;
    DBIG_256_56 dw;

    BIG_256_56 n;
    BIG_256_56 d;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    BIG_256_56_fromBytesLen(x_j, X_j->val, X_j->len);

    // Initialize accumulators for numerator and denominator
    BIG_256_56_one(n);
    BIG_256_56_one(d);

    // x_j = -x_j mod q
    BIG_256_56_sub(x_j, q, x_j);

    for (int i = 0; i < k-1; i++)
    {
        // n = prod(x_i)
        BIG_256_56_fromBytesLen(w, X[i].val, X[i].len);
        BIG_256_56_mul(dw, n, w);
        BIG_256_56_dmod(n, dw, q);

        // d = prod(x_i - x_j)
        BIG_256_56_add(w, w, x_j);
        BIG_256_56_norm(w);
        BIG_256_56_mul(dw, d, w);
        BIG_256_56_dmod(d, dw, q);
    }

    // s = n/d * y
    BIG_256_56_invmodp(d, d, q);
    BIG_256_56_mul(dw, n, d);
    BIG_256_56_dmod(w, dw, q);

    BIG_256_56_fromBytesLen(x_j, Y_j->val, Y_j->len);
    BIG_256_56_mul(dw, w, x_j);
    BIG_256_56_dmod(w, dw, q);

    // Output additive share
    BIG_256_56_toBytes(S->val, w);
    S->len = SGS_SECP256K1;

    // Clean memory
    BIG_256_56_zero(w);
    BIG_256_56_dzero(dw);
}

void VSS_make_shares(int k, int n, csprng *RNG, SSS_shares *shares, octet *C, octet *S)
{
# ifndef C99
    BIG_256_56 poly[128];
# else
    BIG_256_56 poly[k];
#endif

    int i;

    BIG_256_56 q;
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    ECP_SECP256K1 G;

    SSS_sample_polynomial(k, RNG, poly, q, S);
    SSS_eval_shares(k, n, poly, q, shares);

    // Make checks
    for (i = 0; i < k; i++)
    {
        ECP_SECP256K1_generator(&G);
        ECP_SECP256K1_mul(&G, poly[i]);
        ECP_SECP256K1_toOctet(C+i, &G, true);
    }

    // Clean memory
    for (i = 0; i < k; i++)
    {
        BIG_256_56_zero(poly[i]);
    }
}

int VSS_verify_shares(int k, const octet *X_j, const octet * Y_j, const octet *C)
{
    int rc;

    ECP_SECP256K1 G;
    ECP_SECP256K1 V;

    BIG_256_56  x;
    BIG_256_56 xn;
    BIG_256_56 q;
    DBIG_256_56 w;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    BIG_256_56_fromBytesLen(x, X_j->val, X_j->len);

    // Initialize accumulator and exponent
    rc = ECP_SECP256K1_fromOctet(&V, C);
    if (rc != 1)
    {
        return VSS_INVALID_CHECKS;
    }
    BIG_256_56_one(xn);

    for (int i = 1; i < k; i++)
    {
        rc = ECP_SECP256K1_fromOctet(&G, C+i);
        if (rc != 1)
        {
            return VSS_INVALID_CHECKS;
        }

        BIG_256_56_mul(w, xn, x);
        BIG_256_56_dmod(xn, w, q);

        ECP_SECP256K1_mul(&G, xn);
        ECP_SECP256K1_add(&V, &G);
    }

    // Compute ground truth
    ECP_SECP256K1_generator(&G);
    BIG_256_56_fromBytesLen(x, Y_j->val, Y_j->len);
    ECP_SECP256K1_mul(&G, x);

    if (!ECP_SECP256K1_equals(&G, &V))
    {
        return VSS_INVALID_SHARES;
    }

    return VSS_OK;
}
