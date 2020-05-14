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

#include "amcl/schnorr.h"

/* Double Schnorr's proofs example */

int main()
{
    int rc;

    BIG_256_56 r;
    BIG_256_56 s;
    BIG_256_56 l;
    BIG_256_56 q;
    ECP_SECP256K1 G;
    ECP_SECP256K1 ECPR;

    char oct_s[SGS_SECP256K1];
    octet S = {0, sizeof(oct_s), oct_s};

    char oct_l[SGS_SECP256K1];
    octet L = {0, sizeof(oct_l), oct_l};

    char oct_r[SFS_SECP256K1 + 1];
    octet R = {0, sizeof(oct_r), oct_r};

    char v[SFS_SECP256K1+1];
    octet V = {0, sizeof(v), v};

    char id[32];
    octet ID = {0, sizeof(id), id};

    char ad[32];
    octet AD = {0, sizeof(ad), ad};

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

    // Deterministic RNG for example
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    ECP_SECP256K1_generator(&G);
    ECP_SECP256K1_generator(&ECPR);

    // Generate ID and AD
    OCT_rand(&ID, &RNG, ID.len);
    OCT_rand(&AD, &RNG, AD.len);

    // Generate public R
    BIG_256_56_randomnum(r, q, &RNG);
    ECP_SECP256K1_mul(&ECPR, r);

    ECP_SECP256K1_toOctet(&R, &ECPR, 1);

    // Generate double DLOG
    BIG_256_56_randomnum(s, q, &RNG);
    BIG_256_56_randomnum(l, q, &RNG);

    ECP_SECP256K1_mul2(&G, &ECPR, l, s);

    BIG_256_56_toBytes(S.val, s);
    BIG_256_56_toBytes(L.val, l);
    S.len = SGS_SECP256K1;
    L.len = SGS_SECP256K1;

    ECP_SECP256K1_toOctet(&V, &G, 1);

    printf("Double Schnorr's Proof of knowledge of a DLOG. V = s.R + l.G\n");
    printf("\ts  = ");
    OCT_output(&S);
    printf("\tl  = ");
    OCT_output(&L);
    printf("\tR  = ");
    OCT_output(&R);
    printf("\tV  = ");
    OCT_output(&V);
    printf("\tID = ");
    OCT_output(&ID);
    printf("\tAD = ");
    OCT_output(&AD);

    printf("\nGenerate a commitment C = a.R + b.G\n");
    rc = SCHNORR_D_commit(&RNG, &R, &A, &B, &C);
    if (rc != SCHNORR_OK)
    {
        printf("FAILURE SCHNORR_D_commit. RC %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\ta = ");
    OCT_output(&A);
    printf("\tb = ");
    OCT_output(&B);
    printf("\tC = ");
    OCT_output(&C);

    printf("\nGenerate a challenge from the public parameters\n");
    SCHNORR_D_challenge(&R, &V, &C, &ID, &AD, &E);

    printf("\te = ");
    OCT_output(&E);

    printf("\nGenerate the proof (t, u)\n");
    SCHNORR_D_prove(&A, &B, &E, &S, &L, &T, &U);

    printf("\tt = ");
    OCT_output(&T);
    printf("\tu = ");
    OCT_output(&U);

    printf("\nTransmit proof (C,t,u) for V\n");

    printf("\nCompute challenge from public parameters and verify proof\n");
    rc = SCHNORR_D_verify(&R, &V, &C, &E, &T, &U);
    if (rc != SCHNORR_OK)
    {
        printf("\tFailure! RC %d\n", rc);
    }
    else
    {
        printf("\tSuccess!\n");
    }
}