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

/* SSS/VSS example */

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

    printf(" *** Shamir Secret Sharing *** \n");
    printf("\tk = %d, n = %d\n", k, n);

    // Compute shares. The secret is randomly generated here
    SSS_make_shares(k, n, &RNG, &shares, &S_GOLDEN);

    printf("\tS = ");
    OCT_output(&S_GOLDEN);

    printf("\nMake Shares\n");
    for(i = 0; i < n; i++)
    {
        printf("\tX[%d] = ", i);
        OCT_output(X+i);
        printf("\tY[%d] = ", i);
        OCT_output(Y+i);
        printf("\n");
    }

    printf("\nRecover Secret using first k shares\n");

    SSS_recover_secret(k, &shares, &S);

    printf("\tS = ");
    OCT_output(&S);

    if (!OCT_comp(&S, &S_GOLDEN))
    {
        printf("FAILURE - Secrets do not match\n");
        exit(EXIT_FAILURE);
    }

    /* Shamir to additive conversion */

    printf("\n *** Shamir to additive conversion *** \n");
    printf("\tUsing first %d shares from above\n", k);

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

    printf("\nConverted shares:\n");

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

        printf("\tSH_add[%d] = ", i);
        OCT_output(&SH);

        // Add to accumulator to recover secret using additive shares
        BIG_256_56_fromBytesLen(share, SH.val, SH.len);
        BIG_256_56_add(acc, acc, share);
        BIG_256_56_mod(acc, q);
    }

    BIG_256_56_toBytes(SH.val, acc);
    SH.len = SGS_SECP256K1;

    printf("\nReconstruct (additive) secret\n");
    printf("\tS = ");
    OCT_output(&SH);

    if (!OCT_comp(&SH, &S))
    {
        printf("FAILURE - Secrets do not match\n");
        exit(EXIT_FAILURE);
    }

    /* Verifiable Secret Sharing */
    printf("\n *** Verifiable Secret Sharing *** \n");
    printf("\tk = %d, n = %d\n", k, n);
    printf("\tS = ");
    OCT_output(&S);

    // Additional checks for verification
    char c[k][1 + SFS_SECP256K1];
    octet C[k];

    for(i = 0; i < k; i++)
    {
        C[i].max = 1 + SFS_SECP256K1;
        C[i].len = 1 + SFS_SECP256K1;
        C[i].val = c[i];
    }

    VSS_make_shares(k, n, &RNG, &shares, C, &S_GOLDEN);

    printf("\nMake Shares ...\n");
    for(i = 0; i < n; i++)
    {
        printf("\tX[%d] = ", i);
        OCT_output(X+i);
        printf("\tY[%d] = ", i);
        OCT_output(Y+i);
        printf("\n");
    }

    printf("\n.. and checks\n");
    for(i = 0; i < k; i++)
    {
        printf("\tC[%d] = ", i);
        OCT_output(C+i);
    }

    printf("\nVerify Shares\n");

    for (i = 0; i < n; i++)
    {
        printf("\tShare %d: ", i);
        rc = VSS_verify_shares(k, X+i, Y+i, C);

        if (rc == VSS_OK)
        {
            printf("Success\n");
        }
        else
        {
            printf("Failure\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("\nRecover Secret using first k shares\n");

    SSS_recover_secret(k, &shares, &S);

    printf("\tS = ");
    OCT_output(&S);

    if (!OCT_comp(&S, &S_GOLDEN))
    {
        printf("FAILURE - Secrets do not match\n");
        exit(EXIT_FAILURE);
    }
}


