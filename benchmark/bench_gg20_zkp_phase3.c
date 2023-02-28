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
 * Benchmark GG20 Phase 3 ZKP
 */

#include "bench.h"
#include "amcl/gg20_zkp.h"

#define MIN_TIME  5.0
#define MIN_ITERS 10

char *S_hex = "00f1f45c44eb4298562677dfc945064ac5d45d683ec2d87efbd2f527bb5a768c";
char *L_hex = "ab5aa1e7740f849b974fcaaa98840d828a42b16dd59be32f39e3c637730ee9e4";

char *V_hex = "02879452f0c552b01c2cc91101062ca02a1ff3eab1e9c18873992670198bf54f3e";

char *A_hex = "fab4ce512dff74bd9c71c89a14de5b877af45dca0329ee3fcb72611c0784fef3";
char *B_hex = "803ccd21cddad626e15f21b1ad787949e9beef08e6e68a9e00df59dec16ed290";

int main()
{
    int rc;

    int iterations;
    clock_t start;
    double elapsed;

    GG20_ZKP_rv    r;
    GG20_ZKP_proof p;

    char id[32];
    octet ID = {0, sizeof(id), id};

    char ad[32];
    octet AD = {0, sizeof(ad), ad};

    char s[GGS_SECP256K1];
    octet S = {0, sizeof(s), s};

    char l[GGS_SECP256K1];
    octet L = {0, sizeof(l), l};

    char v[GFS_SECP256K1+1];
    octet V = {0, sizeof(v), v};

    char c[GFS_SECP256K1+1];
    octet C = {0, sizeof(c), c};

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
    OCT_fromHex(&V, V_hex);

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
        GG20_ZKP_phase3_commit(NULL, &r, &C);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    elapsed = MILLISECOND * elapsed / iterations;
    printf("\tGG20_ZKP_phase3_commit\t\t%8d iterations\t", iterations);
    printf("%8.2lf ms per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        GG20_ZKP_phase3_challenge(&V, &C, &ID, &AD, &E);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    elapsed = MICROSECOND * elapsed / iterations;
    printf("\tGG20_ZKP_phase3_challenge\t%8d iterations\t", iterations);
    printf("%8.2lf us per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        GG20_ZKP_phase3_prove(&r, &E, &S, &L, &p);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    elapsed = MICROSECOND * elapsed / iterations;
    printf("\tGG20_ZKP_phase3_prove\t\t%8d iterations\t", iterations);
    printf("%8.2lf us per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        rc = GG20_ZKP_phase3_verify(&V, &C, &E, &p);
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
    printf("\tGG20_ZKP_phase3_verify\t\t%8d iterations\t", iterations);
    printf("%8.2lf ms per iteration\n", elapsed);

    exit(EXIT_SUCCESS);
}