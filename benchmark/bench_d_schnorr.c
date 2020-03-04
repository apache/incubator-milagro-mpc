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
 * Benchmark Schnorr's Proof.
 */

#include "bench.h"
#include "amcl/schnorr.h"

#define MIN_TIME    5.0
#define MIN_ITERS   10

// Proof input V = s.R + l.G
char *S_hex = "803ccd21cddad626e15f21b1ad787949e9beef08e6e68a9e00df59dec16ed290";
char *L_hex = "0c5afd75c3d8255e6c91dc4aac664337e1a87f74b40f35746fb8a81311715b31";
char *R_hex = "032cf4b348c9d00718f01ed98923e164df53b5e8bc4c2250662ed2df784e1784f4";
char *V_hex = "0381acba44dd777e95fdad8491e5aedfc5cdd2165070e2f29cc11a8e194cf3a65d";

// Random values for commitments
char *A_hex = "45ab980d9da6d7b45f35830afb6d5749fce755b86b83dd1720ab8b0c4ec05dd1";
char *B_hex = "2291376f2e6e023df783d7d3155616778fb436a1eb20708922050e421321625e";

int main()
{
    int rc;

    int iterations;
    clock_t start;
    double elapsed;

    char oct_s[SGS_SECP256K1];
    octet S = {0, sizeof(oct_s), oct_s};

    char oct_l[SGS_SECP256K1];
    octet L = {0, sizeof(oct_l), oct_l};

    char oct_r[SFS_SECP256K1 + 1];
    octet R = {0, sizeof(oct_r), oct_r};

    char v[SFS_SECP256K1+1];
    octet V = {0, sizeof(v), v};

    char a[SGS_SECP256K1];
    octet A = {0, sizeof(a), a};

    char b[SGS_SECP256K1];
    octet B = {0, sizeof(b), b};

    char c[SFS_SECP256K1+1];
    octet C = {0, sizeof(c), c};

    char e[SGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    char t[SGS_SECP256K1];
    octet T = {0, sizeof(t), t};

    char u[SGS_SECP256K1];
    octet U = {0, sizeof(u), u};

    // Load values
    OCT_fromHex(&S, S_hex);
    OCT_fromHex(&L, L_hex);
    OCT_fromHex(&R, R_hex);
    OCT_fromHex(&V, V_hex);

    OCT_fromHex(&A, A_hex);
    OCT_fromHex(&B, B_hex);

    print_system_info();

    printf("Timing info\n");
    printf("===========\n");

    iterations=0;
    start=clock();
    do
    {
        rc = SCHNORR_D_commit(NULL, &R, &A, &B, &C);
        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);

    if (rc != SCHNORR_OK)
    {
        printf("FAILURE SCHNORR_D_commit: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    elapsed= MICROSECOND * elapsed / iterations;
    printf("\tSCHNORR_D_commit\t%8d iterations\t",iterations);
    printf("%8.2lf us per iteration\n",elapsed);

    iterations=0;
    start=clock();
    do
    {
        SCHNORR_D_challenge(&R, &V, &C, &E);
        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);

    elapsed= MICROSECOND * elapsed / iterations;
    printf("\tSCHNORR_D_challenge\t%8d iterations\t",iterations);
    printf("%8.2lf us per iteration\n",elapsed);

    iterations=0;
    start=clock();
    do
    {
        SCHNORR_D_prove(&A, &B, &E, &S, &L, &T, &U);
        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);

    elapsed= MICROSECOND * elapsed / iterations;
    printf("\tSCHNORR_D_prove\t\t%8d iterations\t",iterations);
    printf("%8.2lf us per iteration\n",elapsed);

    iterations = 0;
    start = clock();
    do
    {
        rc = SCHNORR_D_verify(&R, &V, &C, &E, &T, &U);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    if (rc != SCHNORR_OK)
    {
        printf("FAILURE SCHNORR_D_verify: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    elapsed = MICROSECOND * elapsed / iterations;
    printf("\tSCHNORR_D_verify\t%8d iterations\t", iterations);
    printf("%8.2lf us per iteration\n", elapsed);

    exit(EXIT_SUCCESS);
}
