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
#include "amcl/ecdh_SECP256K1.h"
#include "amcl/mpc.h"

#define MIN_TIME    5.0
#define MIN_ITERS   10

char *M_hex  = "4b7df9714ecf795cfd698129a6f5250cfb64b739ad163da2da93c728c3bd19be";
char *PK_hex = "022008f40a4f5bc74ac3cbd41986e61e4229afae6658d51845978f18d33fe8318c";
char *S_hex = "90c2d9dba55ef93dbfb234d04a2bea475f7067787a57556736c876eced465154";
char *R_hex  = "028ae19ff44d023c774d6526a22bdb47ccfa5e22a91f9994a485660e9f2363da32";
char *RX_hex = "8ae19ff44d023c774d6526a22bdb47ccfa5e22a91f9994a485660e9f2363da32";

// Commitment random values
char *RHO_hex = "803ccd21cddad626e15f21b1ad787949e9beef08e6e68a9e00df59dec16ed290";
char *PHI_hex = "fab4ce512dff74bd9c71c89a14de5b877af45dca0329ee3fcb72611c0784fef3";

// Simulated second player commitment
char *V2_hex = "03a57c31470773c6468bce4a66cf73d07bede464782b211c9950bd233d66bb436a";
char *A2_hex = "03ce088cbd6dfc8975c9e618252c8f7ba935bb9938d33eb42e8e64ba71e229af53";

// Simulated second player proof
char *U2_hex = "0263f7eed14bfe58bee053e4766d36e8befeb4a509c062c12a77dc9225fff9bac6";
char *T2_hex = "03e1471efad959c8dfe58e8e29d255a9d5ebece0f4fd6d2c30557b54e865ec98e0";

int main()
{
    int rc;

    int iterations;
    clock_t start;
    double elapsed;

    char m[SHA256];
    octet M = {0, sizeof(m), m};

    char s[EGS_SECP256K1];
    octet S = {0, sizeof(s), s};

    char rx[EGS_SECP256K1];
    octet RX = {0, sizeof(rx), rx};

    char pk[EFS_SECP256K1 + 1];
    octet PK = {0, sizeof(pk), pk};

    char r[EFS_SECP256K1 + 1];
    octet R = {0, sizeof(r), r};

    char rho[EGS_SECP256K1];
    octet RHO = {0, sizeof(rho), rho};

    char phi[EGS_SECP256K1];
    octet PHI = {0, sizeof(phi), phi};

    char v1[EFS_SECP256K1 + 1];
    octet V1 = {0, sizeof(v1), v1};

    char v2[EFS_SECP256K1 + 1];
    octet V2 = {0, sizeof(v2), v2};

    octet *V[2] = {&V1, &V2};

    char a1[EFS_SECP256K1 + 1];
    octet A1 = {0, sizeof(a1), a1};

    char a2[EFS_SECP256K1 + 1];
    octet A2 = {0, sizeof(a2), a2};

    octet *A[2] = {&A1, &A2};

    char u1[EFS_SECP256K1 + 1];
    octet U1 = {0, sizeof(u1), u1};

    char u2[EFS_SECP256K1 + 1];
    octet U2 = {0, sizeof(u2), u2};

    octet *U[2] = {&U1, &U2};

    char t1[EFS_SECP256K1 + 1];
    octet T1 = {0, sizeof(t1), t1};

    char t2[EFS_SECP256K1 + 1];
    octet T2 = {0, sizeof(t2), t2};

    octet *T[2] = {&T1, &T2};

    // Deterministic RNG for testing
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    // Load input
    OCT_fromHex(&M,  M_hex);
    OCT_fromHex(&PK, PK_hex);
    OCT_fromHex(&S, S_hex);
    OCT_fromHex(&R,  R_hex);
    OCT_fromHex(&RX, RX_hex);

    OCT_fromHex(&RHO, RHO_hex);
    OCT_fromHex(&PHI, PHI_hex);

    OCT_fromHex(&V2, V2_hex);
    OCT_fromHex(&A2, A2_hex);

    OCT_fromHex(&U2, U2_hex);
    OCT_fromHex(&T2, T2_hex);

    print_system_info();

    printf("Timing info\n");
    printf("===========\n");

    iterations = 0;
    start = clock();
    do
    {
        rc = MPC_PHASE5_commit(NULL, &R, &S, &PHI, &RHO, V[0], A[0]);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    if (rc != MPC_OK)
    {
        printf("FAILURE MPC_PHASE5_commit: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    elapsed = MILLISECOND * elapsed / iterations;
    printf("\tMPC_PHASE5_commit\t\t%8d iterations\t", iterations);
    printf("%8.2lf ms per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        rc = MPC_PHASE5_prove(&PHI, &RHO, V, A, &PK, &M, &RX, U[0], T[0]);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    if (rc != MPC_OK)
    {
        printf("FAILURE MPC_PHASE5_prove: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    elapsed = MILLISECOND * elapsed / iterations;
    printf("\tMPC_PHASE5_prove\t\t%8d iterations\t", iterations);
    printf("%8.2lf ms per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        rc = MPC_PHASE5_verify(U, T);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    if (rc != MPC_OK)
    {
        printf("FAILURE MPC_PHASE5_verify: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    elapsed = MILLISECOND * elapsed / iterations;
    printf("\tMPC_PHASE5_verify\t\t%8d iterations\t", iterations);
    printf("%8.2lf ms per iteration\n", elapsed);

    exit(EXIT_SUCCESS);
}
