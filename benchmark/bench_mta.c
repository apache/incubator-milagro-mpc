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
   Benchmark Paillier crypto system.
 */

#include "bench.h"
#include <amcl/randapi.h>
#include <amcl/mta.h>

#define MIN_TIME 5.0
#define MIN_ITERS 10

char* a_hex = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";

char* b_hex = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";

int main()
{
    int iterations;
    clock_t start;
    double elapsed;

    // Paillier Keys
    PAILLIER_private_key PRIV;
    PAILLIER_public_key PUB;

    char a[FS_2048];
    octet A = {0,sizeof(a),a};

    char b[FS_2048];
    octet B = {0,sizeof(b),b};

    char ca[FS_4096];
    octet CA = {0,sizeof(ca),ca};

    char cb[FS_4096];
    octet CB = {0,sizeof(cb),cb};

    char alpha[FS_2048];
    octet ALPHA = {0,sizeof(alpha),alpha};

    char beta[FS_2048];
    octet BETA = {0,sizeof(beta),beta};

    // Load values
    OCT_fromHex(&A,a_hex);
    OCT_fromHex(&B,b_hex);

    print_system_info();

    printf("Timing info\n");
    printf("===========\n");

    char* seedHex = "78d0fb6705ce77dee47d03eb5b9c5d30";
    char seed[16] = {0};
    octet SEED = {sizeof(seed),sizeof(seed),seed};

    // CSPRNG
    csprng RNG;

    // fake random source
    OCT_fromHex(&SEED,seedHex);

    // initialise strong RNG
    CREATE_CSPRNG(&RNG,&SEED);

    // Generating Paillier key pair
    PAILLIER_KEY_PAIR(&RNG, NULL, NULL, &PUB, &PRIV);

    iterations=0;
    start=clock();
    do
    {
        MPC_MTA_CLIENT1(&RNG, &PUB, &A, &CA, NULL);
        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);
    elapsed=1000.0*elapsed/iterations;
    printf("MPC_MTA_CLIENT1\t%8d iterations\t",iterations);
    printf("%8.2lf ms per iteration\n",elapsed);

    iterations=0;
    start=clock();
    do
    {

        MPC_MTA_SERVER(&RNG, &PUB, &B, &CA, NULL, NULL, &CB, &BETA);
        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);
    elapsed=1000.0*elapsed/iterations;
    printf("MPC_MTA_SERVER\t%8d iterations\t",iterations);
    printf("%8.2lf ms per iteration\n",elapsed);

    iterations=0;
    start=clock();
    do
    {
        MPC_MTA_CLIENT2(&PRIV, &CB, &ALPHA);
        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);
    elapsed=1000.0*elapsed/iterations;
    printf("MPC_MTA_CLIENT2\t%8d iterations\t",iterations);
    printf("%8.2lf ms per iteration\n",elapsed);

    exit(EXIT_SUCCESS);
}
