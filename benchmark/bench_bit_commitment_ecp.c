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
   Benchmark Bit Commitment Paillier muladd Proof.
 */

#include "bench.h"
#include "amcl/bit_commitment.h"

#define MIN_TIME 5.0
#define MIN_ITERS 10

char *ALPHA_hex = "00000000000000000000000000000000000000000000000000000000000000001ff0a71a5b642d440b19a143dd95c2fe12b62b4e66fcfaf623bf9baea2dfdf2ecd25286192dfb043c1eef7b5bd763f72389fae5aefbfaf476abcaedad3acf299aaec8cad2f9e61dd07b9027e6df317ead1f33876ce5ab88c63b933ccfeed39f8";

char *R_hex = "020397904ae1a4181314106a8c968e7fcfbaef2b337f1574f0adc5245fc31b8729";
char *X_hex = "033049ded76beb67586e2ff29f4751a4ee25f5a6fc0c66d6efee0799f0070e4536";

char *E_hex  = "5de0ddb8904e679dd599bbed2b0dbbe86e5f34852f4903addcd0907737f8ca44";
char *S1_hex = "00000000000000000000000000000000000000000000000000000000000000001ff0a71a5b642d440b19a143dd95c2fe12b62b4e66fcfaf623bf9baea2dfdf2edad24be4486d1c9a1d9b9a6225b714dd89e1869d22b6bebc172773ae07cfbf3c4d6181bf190a2bf8dbf13d7620fdb6b0cedef398fd50efe5c652969380249a94";

int main()
{
    int rc;

    int iterations;
    clock_t start;
    double elapsed;

    ECP_SECP256K1 R;
    ECP_SECP256K1 X;
    ECP_SECP256K1 U;

    BIG_1024_58 alpha[HFLEN_2048];
    BIG_1024_58 s1[HFLEN_2048];

    char oct[HFS_2048];
    octet OCT = {0, sizeof(oct), oct};

    // Load hex values
    OCT_fromHex(&OCT, R_hex);
    rc = ECP_SECP256K1_fromOctet(&R, &OCT);
    if (rc != 1)
    {
        printf("Invalid R hex\n");
        exit(EXIT_FAILURE);
    }

    OCT_fromHex(&OCT, X_hex);
    rc = ECP_SECP256K1_fromOctet(&X, &OCT);
    if (rc != 1)
    {
        printf("Invalid X hex\n");
        exit(EXIT_FAILURE);
    }

    OCT_fromHex(&OCT, ALPHA_hex);
    FF_2048_fromOctet(alpha, &OCT, HFLEN_2048);
    OCT_fromHex(&OCT, S1_hex);
    FF_2048_fromOctet(s1, &OCT, HFLEN_2048);

    OCT_fromHex(&OCT, E_hex);

    print_system_info();

    printf("Timing info\n");
    printf("===========\n");

    iterations = 0;
    start = clock();
    do
    {
        ECP_SECP256K1_copy(&U, &R);
        BIT_COMMITMENT_ECP_commit(&U, alpha);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    elapsed = MICROSECOND * elapsed / iterations;
    printf("\tBIT_COMMITMENT_ECP_commit\t%8d iterations\t", iterations);
    printf("%8.2lf us per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        rc = BIT_COMMITMENT_ECP_verify(&R, &X, &U, &OCT, s1);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    elapsed = MICROSECOND * elapsed / iterations;
    printf("\tBIT_COMMITMENT_ECP_verify\t%8d iterations\t", iterations);
    printf("%8.2lf us per iteration\n", elapsed);

    exit(EXIT_SUCCESS);
}