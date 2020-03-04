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

// MPC Phase 5 example

#include <amcl/ecdh_SECP256K1.h>
#include <amcl/mpc.h>

char *M_hex  = "4b7df9714ecf795cfd698129a6f5250cfb64b739ad163da2da93c728c3bd19be";
char *PK_hex = "022008f40a4f5bc74ac3cbd41986e61e4229afae6658d51845978f18d33fe8318c";
char *S1_hex = "90c2d9dba55ef93dbfb234d04a2bea475f7067787a57556736c876eced465154";
char *S2_hex = "8002233d6018c7e1497b42828e517364f0b5b79e9edb8a7d130fa21e76270ee2";
char *R_hex  = "028ae19ff44d023c774d6526a22bdb47ccfa5e22a91f9994a485660e9f2363da32";
char *RX_hex = "8ae19ff44d023c774d6526a22bdb47ccfa5e22a91f9994a485660e9f2363da32";

int main()
{
    int rc;

    char m[SHA256];
    octet M = {0, sizeof(m), m};

    char s1[EGS_SECP256K1];
    octet S1 = {0, sizeof(s1), s1};

    char s2[EGS_SECP256K1];
    octet S2 = {0, sizeof(s2), s2};

    char rx[EGS_SECP256K1];
    octet RX = {0, sizeof(rx), rx};

    char pk[EFS_SECP256K1 + 1];
    octet PK = {0, sizeof(pk), pk};

    char r[EFS_SECP256K1 + 1];
    octet R = {0, sizeof(r), r};

    char rho1[EGS_SECP256K1];
    octet RHO1 = {0, sizeof(rho1), rho1};

    char phi1[EGS_SECP256K1];
    octet PHI1 = {0, sizeof(phi1), phi1};

    char rho2[EGS_SECP256K1];
    octet RHO2 = {0, sizeof(rho2), rho2};

    char phi2[EGS_SECP256K1];
    octet PHI2 = {0, sizeof(phi2), phi2};

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
    OCT_fromHex(&S1, S1_hex);
    OCT_fromHex(&S2, S2_hex);
    OCT_fromHex(&R,  R_hex);
    OCT_fromHex(&RX, RX_hex);

    printf("MPC Phase 5 example\n");
    printf("\nCommon parameters:\n");
    printf("\tPK = ");
    OCT_output(&PK);
    printf("\tR  = ");
    OCT_output(&R);
    printf("\tRX = ");
    OCT_output(&RX);
    printf("\tM  = ");
    OCT_output(&M);

    printf("\n[Alice] Signature share\n\tS1 = ");
    OCT_output(&S1);
    printf("\n[Bob]   Signature share\n\tS2 = ");
    OCT_output(&S2);


    // Alice - generate commitments and broadcast
    printf("\n[Alice] Generate commitment\n");

    rc = MPC_PHASE5_commit(&RNG, &R, &S1, &PHI1, &RHO1, V[0], A[0]);
    if (rc != MPC_OK)
    {
        printf("FAILURE MPC_PHASE5_commit Alice. RC %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\tPHI = ");
    OCT_output(&PHI1);
    printf("\tRHO = ");
    OCT_output(&RHO1);
    printf("\tV = ");
    OCT_output(&V1);
    printf("\tA = ");
    OCT_output(&A1);

    // Bob - generate commitments and broadcast
    printf("\n[Bob]   Generate commitment\n");

    rc = MPC_PHASE5_commit(&RNG, &R, &S2, &PHI2, &RHO2, V[1], A[1]);
    if (rc != MPC_OK)
    {
        printf("FAILURE MPC_PHASE5_commit Bob. RC %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\tPHI = ");
    OCT_output(&PHI2);
    printf("\tRHO = ");
    OCT_output(&RHO2);
    printf("\tV = ");
    OCT_output(&V2);
    printf("\tA = ");
    OCT_output(&A2);

    // Alice - generate proof for commitments and broadcast
    printf("\n[Alice] Generate proof for commitments\n");

    rc = MPC_PHASE5_prove(&PHI1, &RHO1, V, A, &PK, &M, &RX, U[0], T[0]);
    if (rc != MPC_OK)
    {
        printf("FAILURE MPC_PHASE5_prove Alice. RC %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\tU = ");
    OCT_output(&U1);
    printf("\tT = ");
    OCT_output(&T1);

    // Bob - generate proof for commitments and broadcast
    printf("\n[Bob]   Generate proof for commitments\n");

    rc = MPC_PHASE5_prove(&PHI2, &RHO2, V, A, &PK, &M, &RX, U[1], T[1]);
    if (rc != MPC_OK)
    {
        printf("FAILURE MPC_PHASE5_prove Bob. RC %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\tU = ");
    OCT_output(&U2);
    printf("\tT = ");
    OCT_output(&T2);

    // Each player verifies if the total of the proof material is valid
    printf("\n[Both]  Verification\n");

    rc = MPC_PHASE5_verify(U, T);
    if (rc == MPC_OK)
    {
        printf("\tSuccess!\n");
    }
    else
    {
        printf("\tFailure!\n");
    }
}
