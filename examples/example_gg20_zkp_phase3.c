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

#include "amcl/gg20_zkp.h"

/* Example of GG20 Phase 3 ZKP */

char *S_hex = "00f1f45c44eb4298562677dfc945064ac5d45d683ec2d87efbd2f527bb5a768c";
char *L_hex = "ab5aa1e7740f849b974fcaaa98840d828a42b16dd59be32f39e3c637730ee9e4";

char *V_hex = "02879452f0c552b01c2cc91101062ca02a1ff3eab1e9c18873992670198bf54f3e";

int main()
{
    int rc;

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

    char t[GGS_SECP256K1];
    octet T = {0, sizeof(t), t};

    char u[GGS_SECP256K1];
    octet U = {0, sizeof(u), u};

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

    printf("Prove knowledge of s, l s.t V = s.G + l.H\n");
    printf("\tS = ");
    OCT_output(&S);
    printf("\tL = ");
    OCT_output(&L);
    printf("\tV = ");
    OCT_output(&V);

    // Commitment Phase
    GG20_ZKP_phase3_commit(&RNG, &r, &C);

    printf("\n[Alice] Compute commitment");
    printf("\n\t\tA = ");
    BIG_256_56_output(r.a);
    printf("\n\t\tB = ");
    BIG_256_56_output(r.b);
    printf("\n\t\tC = ");
    OCT_output(&C);

    GG20_ZKP_phase3_challenge(&V, &C, &ID, &AD, &E);

    printf("\n[Alice] Comupte pseudo random challenge");
    printf("\n\t\tE = ");
    OCT_output(&E);

    // Proof Phase
    GG20_ZKP_phase3_prove(&r, &E, &S, &L, &p);
    GG20_ZKP_proof_toOctets(&T, &U, &p);

    printf("\n[Alice] Compute proof and export it to octets for transmission");
    printf("\n\t\tT = ");
    OCT_output(&T);
    printf("\t\tU = ");
    OCT_output(&U);

    // Clean random values used for proof
    GG20_ZKP_rv_kill(&r);

    // Verification Phase - compute pseudorandom challenge and verify proof
    GG20_ZKP_phase3_challenge(&V, &C, &ID, &AD, &E);

    printf("\n[Bob  ] Compute pseudo random challenge");
    printf("\n\t\tE = ");
    OCT_output(&E);

    rc = GG20_ZKP_phase3_verify(&V, &C, &E, &p);

    printf("\n[Bob  ] Verify proof\n");

    if (rc == GG20_ZKP_OK)
    {
        printf("Success!\n");
    }
    else
    {
        printf("Failure!\n");
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}