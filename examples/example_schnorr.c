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

/* Schnorr's proofs example */

int main()
{
    int rc;

    BIG_256_56 x;
    BIG_256_56 q;
    ECP_SECP256K1 G;

    char x_char[SGS_SECP256K1];
    octet X = {0, sizeof(x_char), x_char};

    char v[SFS_SECP256K1+1];
    octet V = {0, sizeof(v), v};

    char id[32];
    octet ID = {0, sizeof(id), id};

    char ad[32];
    octet AD = {0, sizeof(ad), ad};

    char r[SGS_SECP256K1];
    octet R = {0, sizeof(r), r};

    char c[SFS_SECP256K1+1];
    octet C = {0, sizeof(c), c};

    char e[SGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    char p[SGS_SECP256K1];
    octet P = {0, sizeof(p), p};

    // Deterministic RNG for example
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    // Generate ID and AD
    OCT_rand(&ID, &RNG, ID.len);
    OCT_rand(&AD, &RNG, AD.len);

    // Generate DLOG
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    BIG_256_56_randomnum(x, q, &RNG);

    ECP_SECP256K1_generator(&G);
    ECP_SECP256K1_mul(&G, x);

    BIG_256_56_toBytes(X.val, x);
    X.len = SGS_SECP256K1;

    ECP_SECP256K1_toOctet(&V, &G, 1);

    printf("Schnorr's Proof of knowledge of a DLOG. V = x.G\n");
    printf("\tx = ");
    OCT_output(&X);
    printf("\tV = ");
    OCT_output(&V);

    printf("\nGenerate a commitment C = r.G\n");
    SCHNORR_commit(&RNG, &R, &C);

    printf("\tr = ");
    OCT_output(&R);
    printf("\tC = ");
    OCT_output(&C);

    printf("\nGenerate a challenge from the public parameters\n");
    SCHNORR_challenge(&V, &C, &ID, &AD, &E);

    printf("\te = ");
    OCT_output(&E);

    printf("\nGenerate the proof p\n");
    SCHNORR_prove(&R, &E, &X, &P);

    printf("\tp = ");
    OCT_output(&P);

    printf("\nTransmit proof (C,p) for V\n");

    printf("\nCompute challenge from public parameters and verify proof\n");
    rc = SCHNORR_verify(&V, &C, &E, &P);
    if (rc)
    {
        printf("\tFailure! RC %d\n", rc);
    }
    else
    {
        printf("\tSuccess!\n");
    }
}