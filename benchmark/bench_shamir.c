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

/*
 * Benchmark Shamir Secret Sharing
 */

#include "bench.h"
#include "amcl/shamir.h"

#define MIN_TIME    5.0
#define MIN_ITERS   10

char *S_hex = "fab4ce512dff74bd9c71c89a14de5b877af45dca0329ee3fcb72611c0784fef3";

int n = 30;
int k = 20;

int main()
{
    int i, rc;

    int iterations;
    clock_t start;
    double elapsed;

    // Secret
    char s[SGS_SECP256K1];
    octet S = {0,sizeof(s),s};

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

    // Additive share for conversion
    char sh[SGS_SECP256K1];
    octet SH = {0, sizeof(sh), sh};

    // Additional checks for verification
    char c[k][1 + SFS_SECP256K1];
    octet C[k];

    for(i = 0; i < k; i++)
    {
        C[i].max = 1 + SFS_SECP256K1;
        C[i].len = 1 + SFS_SECP256K1;
        C[i].val = c[i];
    }

    // Deterministic RNG for testing
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    // Load Secret from hex
    OCT_fromHex(&S, S_hex);

    /* Benchmark */
    print_system_info();

    printf("Timing info\n");
    printf("===========\n");

    // Shamir Secret Sharing
    iterations=0;
    start=clock();
    do
    {
        SSS_make_shares(k, n, &RNG, &shares, &S);
        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);

    elapsed= MILLISECOND * elapsed / iterations;
    printf("\tSSS_make_shares\t\t%8d iterations\t",iterations);
    printf("%8.2lf ms per iteration\n",elapsed);

    iterations=0;
    start=clock();
    do
    {
        SSS_recover_secret(k, &shares, &S);
        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);

    elapsed= MILLISECOND * elapsed / iterations;
    printf("\tSSS_recover_secret\t%8d iterations\t",iterations);
    printf("%8.2lf ms per iteration\n",elapsed);

    // Shamir to additive conversion
    iterations=0;
    start=clock();
    do
    {
        SSS_shamir_to_additive(k, X, Y, X+1, &SH);
        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);

    elapsed= MICROSECOND * elapsed / iterations;
    printf("\tSSS_shamir_to_additive\t%8d iterations\t",iterations);
    printf("%8.2lf us per iteration\n",elapsed);

    // Verifiable Secret Sharing
    iterations=0;
    start=clock();
    do
    {
        VSS_make_shares(k, n, &RNG, &shares, C, &S);
        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);

    elapsed= MILLISECOND * elapsed / iterations;
    printf("\tVSS_make_shares\t\t%8d iterations\t",iterations);
    printf("%8.2lf ms per iteration\n",elapsed);

    iterations=0;
    start=clock();
    do
    {
        rc = VSS_verify_shares(k, X, Y, C);
        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);

    if (rc != VSS_OK)
    {
        printf("FAILURE  VSS_verify_shares: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    elapsed= MILLISECOND * elapsed / iterations;
    printf("\tVSS_verify_shares\t%8d iterations\t",iterations);
    printf("%8.2lf ms per iteration\n",elapsed);

    exit(EXIT_SUCCESS);
}
