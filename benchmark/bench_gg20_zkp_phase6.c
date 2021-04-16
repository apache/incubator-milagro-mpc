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
 * Benchmark GG20 Phase 6 ZKP
 */

#include "bench.h"
#include "amcl/gg20_zkp.h"

#define MIN_TIME  5.0
#define MIN_ITERS 10

char *S_hex = "843b282505357e075bd98104f42fe7ea6b41310da7c769b4c402442c1ede922b";
char *L_hex = "584edf9db99551ff2e0d56218a44fea0943032f7864b8359c213ec36465512c5";

char *ECPR_hex = "03e03cda61f087f9ba381695dc816a4ca42f38bbfc3fc88ffe897594b94ee7b80b";
char *ECPT_hex = "02863528287942ab88dec016c2e1993bf9e459ffcbfcc48c25ef68f2ec750e55a8";
char *ECPS_hex = "02ef03c8ecb7cf65b58d85f368c5fc2725b4e4fe93306f98cf53f8e1531cea2bc4";

char *A_hex = "fab4ce512dff74bd9c71c89a14de5b877af45dca0329ee3fcb72611c0784fef3";
char *B_hex = "803ccd21cddad626e15f21b1ad787949e9beef08e6e68a9e00df59dec16ed290";

int main()
{
    int rc;

    int iterations;
    clock_t start;
    double elapsed;

    GG20_ZKP_rv                r;
    GG20_ZKP_phase6_commitment c;
    GG20_ZKP_proof             p;

    char id[32];
    octet ID = {0, sizeof(id), id};

    char ad[32];
    octet AD = {0, sizeof(ad), ad};

    char s[GGS_SECP256K1];
    octet S = {0, sizeof(s), s};

    char l[GGS_SECP256K1];
    octet L = {0, sizeof(l), l};

    char ecpr[GFS_SECP256K1+1];
    octet ECPR = {0, sizeof(ecpr), ecpr};

    char ecpt[GFS_SECP256K1+1];
    octet ECPT = {0, sizeof(ecpt), ecpt};

    char ecps[GFS_SECP256K1+1];
    octet ECPS = {0, sizeof(ecps), ecps};

    char e[GGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    char o[GGS_SECP256K1];
    octet O = {0, sizeof(o), o};

    // Deterministic RNG for testing
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    // Generate ID and AD
    OCT_rand(&ID, &RNG, ID.len);
    OCT_rand(&AD, &RNG, AD.len);

    // Load hex values
    OCT_fromHex(&S, S_hex);
    OCT_fromHex(&L, L_hex);

    OCT_fromHex(&ECPR, ECPR_hex);
    OCT_fromHex(&ECPT, ECPT_hex);
    OCT_fromHex(&ECPS, ECPS_hex);

    OCT_fromHex(&O, A_hex);
    BIG_256_56_fromBytesLen(r.a, O.val, O.len);

    OCT_fromHex(&O, B_hex);
    BIG_256_56_fromBytesLen(r.b, O.val, O.len);

    // Begin benchmark
    print_system_info();

    printf("Timing info\n");
    printf("===========\n");

    iterations = 0;
    start = clock();
    do
    {
        rc = GG20_ZKP_phase6_commit(NULL, &ECPR, &r, &c);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    if (rc != GG20_ZKP_OK)
    {
        printf("FAILURE  GG20_ZKP_phase6_commit rc %d\n", rc);
        exit(EXIT_FAILURE);
    }

    elapsed = MILLISECOND * elapsed / iterations;
    printf("\tGG20_ZKP_phase6_commit\t\t%8d iterations\t", iterations);
    printf("%8.2lf ms per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        GG20_ZKP_phase6_challenge(&ECPR, &ECPT, &ECPS, &c, &ID, &AD, &E);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    elapsed = MICROSECOND * elapsed / iterations;
    printf("\tGG20_ZKP_phase6_challenge\t%8d iterations\t", iterations);
    printf("%8.2lf us per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        GG20_ZKP_phase6_prove(&r, &E, &S, &L, &p);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    elapsed = MICROSECOND * elapsed / iterations;
    printf("\tGG20_ZKP_phase6_prove\t\t%8d iterations\t", iterations);
    printf("%8.2lf us per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        rc = GG20_ZKP_phase6_verify(&ECPR, &ECPT, &ECPS, &c, &E, &p);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    if (rc != GG20_ZKP_OK)
    {
        printf("FAILURE  GG20_ZKP_phase6_verify rc %d\n", rc);
        exit(EXIT_FAILURE);
    }

    elapsed = MILLISECOND * elapsed / iterations;
    printf("\tGG20_ZKP_phase6_verify\t\t%8d iterations\t", iterations);
    printf("%8.2lf ms per iteration\n", elapsed);

    exit(EXIT_SUCCESS);
}