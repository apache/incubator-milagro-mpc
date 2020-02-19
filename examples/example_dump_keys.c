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

// Dump Paillier keys

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <amcl/randapi.h>
#include <amcl/utils.h>
#include <amcl/ecdh_SECP256K1.h>
#include <amcl/ecdh_support.h>
#include <amcl/paillier.h>
#include <amcl/mpc.h>

int main()
{
    char* seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30";
    char seed[16] = {0};
    octet SEED = {sizeof(seed),sizeof(seed),seed};

    // CSPRNG
    csprng RNG;

    // fake random source
    OCT_fromHex(&SEED,seed_hex);

    // initialise strong RNG
    CREATE_CSPRNG(&RNG,&SEED);

    // Paillier Keys
    PAILLIER_private_key PRIV1;
    PAILLIER_public_key PUB1;
    PAILLIER_private_key PRIV2;
    PAILLIER_public_key PUB2;
    PAILLIER_public_key PUB3;

    // Paillier public key
    char n[FS_4096] = {0};
    octet N = {0,sizeof(n),n};

    // Paillier private key
    char p[HFS_2048] = {0};
    octet P = {0,sizeof(p),p};
    char q[HFS_2048] = {0};
    octet Q = {0,sizeof(q),q};

    // Generating Paillier key pair
    PAILLIER_KEY_PAIR(&RNG, NULL, NULL, &PUB1, &PRIV1);

    // Write public key to octet
    PAILLIER_PK_toOctet(&N, &PUB1);

    // Read public key from octet
    PAILLIER_PK_fromOctet(&PUB2, &N);

    FF_2048_toOctet(&P, PRIV1.p, HFLEN_2048);
    FF_2048_toOctet(&Q, PRIV1.q, HFLEN_2048);

    // Write secret key to octets
    MPC_DUMP_PAILLIER_SK(&PRIV1, &P, &Q);

    // Read secret key from octets
    PAILLIER_KEY_PAIR(NULL, &P, &Q, &PUB3, &PRIV2);

    char a1[FS_2048];
    octet A1 = {0,sizeof(a1),a1};
    char b1[FS_2048];
    octet B1 = {0,sizeof(b1),b1};
    char ca1[FS_4096];
    octet CA1 = {0,sizeof(ca1),ca1};

    char a2[FS_2048];
    octet A2 = {0,sizeof(a2),a2};
    char b2[FS_2048];
    octet B2 = {0,sizeof(b2),b2};
    char ca2[FS_4096];
    octet CA2 = {0,sizeof(ca2),ca2};

    int v = 5;
    BIG_1024_58 pt[FFLEN_2048];
    FF_2048_init(pt, v, FFLEN_2048);
    FF_2048_toOctet(&A1, pt, FFLEN_2048);
    FF_2048_toOctet(&A2, pt, FFLEN_2048);

    printf("A1: ");
    OCT_output(&A1);
    printf("\n");

    PAILLIER_ENCRYPT(&RNG, &PUB1, &A1, &CA1, NULL);
    printf("CA1: ");
    OCT_output(&CA1);
    printf("\n");

    PAILLIER_DECRYPT(&PRIV1, &CA1, &B1);
    printf("B1: ");
    OCT_output(&B1);
    printf("\n");

    printf("A2: ");
    OCT_output(&A2);
    printf("\n");

    PAILLIER_ENCRYPT(&RNG, &PUB2, &A2, &CA2, NULL);
    printf("CA2: ");
    OCT_output(&CA2);
    printf("\n");

    PAILLIER_DECRYPT(&PRIV2, &CA2, &B2);
    printf("B2: ");
    OCT_output(&B2);
    printf("\n");
}
