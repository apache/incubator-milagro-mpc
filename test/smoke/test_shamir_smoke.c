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

/* SSS/VSS smoke test */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "amcl/shamir.h"

int main()
{
    int i;
    int rc;

    int n=4;
    int k=3;

    // Secret
    char s[SGS_SECP256K1];
    octet S = {0,sizeof(s),s};

    char s_golden[SGS_SECP256K1];
    octet S_GOLDEN = {0, sizeof(s_golden), s_golden};

    // Secret shares
    char x[n][SGS_SECP256K1];
    octet X[n];
    char y[n][SGS_SECP256K1];
    octet Y[n];

    for(i = 0; i < n; i++)
    {
        Y[i].max = SGS_SECP256K1;
        Y[i].len = SGS_SECP256K1;
        Y[i].val = y[i];

        X[i].max = SGS_SECP256K1;
        X[i].len = SGS_SECP256K1;
        X[i].val = x[i];
    }

    SSS_shares shares = {X, Y};

    // Deterministic RNG for testing
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    /* Shamir Secret Sharing */

    // Create random shares and test reconstruction
    SSS_make_shares(k, n, &RNG, &shares, &S_GOLDEN);
    SSS_recover_secret(k, &shares, &S);

    if (!OCT_comp(&S, &S_GOLDEN))
    {
        printf("FAILURE SSS_recover_secret - first k shares\n");
        exit(EXIT_FAILURE);
    }

    // Reconstruct secret using last k shares in X, Y
    shares.X = X + n - k;
    shares.Y = Y + n - k;
    SSS_recover_secret(k, &shares, &S);

    if (!OCT_comp(&S, &S_GOLDEN))
    {
        printf("FAILURE SSS_recover_secret - last k shares\n");
        exit(EXIT_FAILURE);
    }

    // Restore the shares
    shares.X = X;
    shares.Y = Y;

    /* Shamir to additive conversion */
    char sh[SGS_SECP256K1];
    octet SH = {0, sizeof(sh), sh};

    char others[k-1][SGS_SECP256K1];
    octet OTHERS[k-1];

    for (i = 0; i < k-1; i++)
    {
        OTHERS[i].max = SGS_SECP256K1;
        OTHERS[i].len = SGS_SECP256K1;
        OTHERS[i].val = others[i];
    }

    BIG_256_56 acc;
    BIG_256_56 share;
    BIG_256_56 q;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    BIG_256_56_zero(acc);

    for (i = 0; i < k; i++)
    {
        // Load other X shares into memory
        octet *other_shares_ptr = OTHERS;
        for (int j = 0; j < k; j++)
        {
            if (j == i) continue;

            OCT_copy(other_shares_ptr, X+j);
            other_shares_ptr++;
        }

        SSS_shamir_to_additive(k, X+i, Y+i, OTHERS, &SH);

        BIG_256_56_fromBytesLen(share, SH.val, SH.len);
        BIG_256_56_add(acc, acc, share);
        BIG_256_56_mod(acc, q);
    }

    BIG_256_56_toBytes(SH.val, acc);
    SH.len = SGS_SECP256K1;

    if (!OCT_comp(&SH, &S))
    {
        printf("FAILURE SSS_shamir_to_additive\n");
        exit(EXIT_FAILURE);
    }

    /* Verifiable Secret Sharing */

    // Additional checks for verification
    char c[k][1 + SFS_SECP256K1];
    octet C[k];

    for(i = 0; i < k; i++)
    {
        C[i].max = 1 + SFS_SECP256K1;
        C[i].len = 1 + SFS_SECP256K1;
        C[i].val = c[i];
    }

    // Resuse same S_GOLDEN from above to test path where the
    // secret is supplied
    VSS_make_shares(k, n, &RNG, &shares, C, &S_GOLDEN);

    for (i = 0; i < n; i++)
    {
        rc = VSS_verify_shares(k, X+i, Y+i, C);

        if (rc != VSS_OK)
        {
            printf("FAILURE VSS_verify_shares, share %d. rc %d\n", i, rc);
            exit(EXIT_FAILURE);
        }
    }

    // Test secret recovery when shares are generated using VSS
    SSS_recover_secret(k, &shares, &S);

    if (!OCT_comp(&S, &S_GOLDEN))
    {
        printf("FAILURE SSS_recover_secret - VSS shares\n");
        exit(EXIT_FAILURE);
    }

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
