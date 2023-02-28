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

/* Example of GG20 Phase 6 ZKP */

char *S_hex = "843b282505357e075bd98104f42fe7ea6b41310da7c769b4c402442c1ede922b";
char *L_hex = "584edf9db99551ff2e0d56218a44fea0943032f7864b8359c213ec36465512c5";

char *ECPR_hex = "03e03cda61f087f9ba381695dc816a4ca42f38bbfc3fc88ffe897594b94ee7b80b";
char *ECPT_hex = "02863528287942ab88dec016c2e1993bf9e459ffcbfcc48c25ef68f2ec750e55a8";
char *ECPS_hex = "02ef03c8ecb7cf65b58d85f368c5fc2725b4e4fe93306f98cf53f8e1531cea2bc4";

int main()
{
    int rc;

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

    char alpha[GFS_SECP256K1+1];
    octet ALPHA = {0, sizeof(alpha), alpha};

    char beta[GFS_SECP256K1+1];
    octet BETA = {0, sizeof(beta), beta};

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

    OCT_fromHex(&ECPR, ECPR_hex);
    OCT_fromHex(&ECPT, ECPT_hex);
    OCT_fromHex(&ECPS, ECPS_hex);

    printf("Prove knowledge of s, l s.t V = s.G + l.H, S = s.R\n");
    printf("\tS    = ");
    OCT_output(&S);
    printf("\tL    = ");
    OCT_output(&L);
    printf("\tECPR = ");
    OCT_output(&ECPR);
    printf("\tECPT = ");
    OCT_output(&ECPT);
    printf("\tECPS = ");
    OCT_output(&ECPS);

    // Commitment Phase
    rc = GG20_ZKP_phase6_commit(&RNG, &ECPR, &r, &c);
    if (rc != GG20_ZKP_OK)
    {
        printf("FAILURE Invalid R\n");
        exit(EXIT_FAILURE);
    }

    GG20_ZKP_phase6_commitment_toOctets(&ALPHA, &BETA, &c);

    printf("\n[Alice] Compute commitment and export it to octets for transmission");
    printf("\n\t\tA     = ");
    BIG_256_56_output(r.a);
    printf("\n\t\tB     = ");
    BIG_256_56_output(r.b);
    printf("\n\t\tALPHA = ");
    OCT_output(&ALPHA);
    printf("\t\tBETA  = ");
    OCT_output(&BETA);

    GG20_ZKP_phase6_challenge(&ECPR, &ECPT, &ECPS, &c, &ID, &AD, &E);

    printf("\n[Alice] Comupte pseudo random challenge");
    printf("\n\t\tE = ");
    OCT_output(&E);

    // Proof Phase
    GG20_ZKP_phase6_prove(&r, &E, &S, &L, &p);
    GG20_ZKP_proof_toOctets(&T, &U, &p);

    printf("\n[Alice] Compute proof and export it to octets for transmission");
    printf("\n\t\tT = ");
    OCT_output(&T);
    printf("\t\tU = ");
    OCT_output(&U);

    // Clean random values used for proof
    GG20_ZKP_rv_kill(&r);

    // Verification Phase - compute pseudorandom challenge and verify proof
    GG20_ZKP_phase6_challenge(&ECPR, &ECPT, &ECPS, &c, &ID, &AD, &E);

    printf("\n[Bob  ] Compute pseudo random challenge");
    printf("\n\t\tE = ");
    OCT_output(&E);

    rc = GG20_ZKP_phase6_verify(&ECPR, &ECPT, &ECPS, &c, &E, &p);

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