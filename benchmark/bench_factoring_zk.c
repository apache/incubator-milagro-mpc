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
   Benchmark ZKP of knowledge of factoring.
 */

#include "bench.h"
#include "amcl/factoring_zk.h"

#define MIN_TIME 5.0
#define MIN_ITERS 10

char *ID_str = "unique_identifier_123";
char *AD_hex = "d7d3155616778fb436a1eb2070892205";

char *P_hex = "e008507e09c24d756280f3d94912fb9ac16c0a8a1757ee01a350736acfc7f65880f87eca55d6680253383fc546d03fd9ebab7d8fa746455180888cb7c17edf58d3327296468e5ab736374bc9a0fa02606ed5d3a4a5fb1677891f87fbf3c655c3e0549a86b17b7ddce07c8f73e253105e59f5d3ed2c7ba5bdf8495df40ae71a7f";
char *Q_hex = "dbffe278edd44c2655714e5a4cc82e66e46063f9ab69df9d0ed20eb3d7f2d8c7d985df71c28707f32b961d160ca938e9cf909cd77c4f8c630aec34b67714cbfd4942d7147c509db131bc2d6a667eb30df146f64b710f8f5247848b0a75738a38772e31014fd63f0b769209928d586499616dcc90700b393156e12eea7e15a835";
char *N_hex = "c0870b552afb6c8c09f79e39ad6ca17ca93085c2cd7a726ade69574961ff9ce8ad33c7dda2e0703a3b0010c2e5bb7552c74164ce8dd011d85e5969090df53fe10e39cbe530704da32ff07228a6b6da34a5929e8a231c3080d812dc6e93affd81682339a6aee192927c582da8941bebf46e13c4ea3918a1477951fa66d367e70d8551b1869316d48317e0702d7bce242a326000f3dc763c44eba2044a1df713a94c1339edd464b145dcadf94e6e61be73dc270c878e1a28be720df2209202d00e101c3b255b757eaf547acd863d51eb676b851511b3dadeda926714719dceddd3af7908893ae65f2b95ee5c4d36cc6862cbe6886a62d7c1e2d0db48c399a6d44b";
char *R_hex = "c05f6c79e81fab2f1aa6af48dc5afa89a21c0aee03e93944cacfefef1be90f41ec8c2055760beafa9ed87dd67dbd56b33a2568dfec62a03f06c4f8449a93eee858507f4b602bf305e1c9968d9f5b6dc3120c27e053a1d7e51590e0bacb8d36c27bccce1a57c1e3aeb0832905d4e2bb8eaee883b4df042d8660cf3e0c9777b6be34c18bef02347f92cb71f372f61c018860211932dd46de8f925212d7afe6dd2f3cda05f8d5a6bd1b138b66c5efd7fca31f926c721f6d4207b97fc01cdf325da21233f6df37adbcd67472b332f7490a4a96e0fef31beef55b9446067b8e8d807384e3d31051c7a1f27296a6ae111b30c3d1f3f81666fd9ad99df531bb68428029";

int main()
{
    int rc;

    int iterations;
    clock_t start;
    double elapsed;

    char p[HFS_2048] = {0};
    octet P = {0, sizeof(p), p};

    char q[HFS_2048];
    octet Q = {0, sizeof(q), q};

    char n[FS_2048];
    octet N = {0, sizeof(n), n};

    char id[32];
    octet ID = {0, sizeof(id), id};

    char ad[32];
    octet AD = {0, sizeof(ad), ad};

    char r[FS_2048];
    octet R = {0, sizeof(r), r};

    char e[FACTORING_ZK_B];
    octet E = {0, sizeof(e), e};

    char y[FS_2048];
    octet Y = {0, sizeof(y), y};

    FACTORING_ZK_modulus m;

    // Load values
    OCT_jstring(&ID, ID_str);
    OCT_fromHex(&AD, AD_hex);

    OCT_fromHex(&P, P_hex);
    OCT_fromHex(&Q, Q_hex);
    OCT_fromHex(&N, N_hex);
    OCT_fromHex(&R, R_hex);

    print_system_info();

    printf("Timing info\n");
    printf("===========\n");

    iterations = 0;
    start = clock();
    do
    {
        FACTORING_ZK_modulus_fromOctets(&m, &P, &Q);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    elapsed = MILLISECOND * elapsed / iterations;
    printf("\tFACTORING_ZK_modulus_fromOctets\t%8d iterations\t", iterations);
    printf("%8.2lf ms per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        FACTORING_ZK_prove(NULL, &m, &ID, &AD, &R, &E, &Y);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    elapsed = MILLISECOND * elapsed / iterations;
    printf("\tFACTORING_ZK_prove\t\t%8d iterations\t", iterations);
    printf("%8.2lf ms per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        rc = FACTORING_ZK_verify(&N, &E, &Y, &ID, &AD);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    if (rc != FACTORING_ZK_OK)
    {
        printf("FAILURE FACTORING_ZK_verify: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    elapsed = MILLISECOND * elapsed / iterations;
    printf("\tFACTORING_ZK_verify\t\t%8d iterations\t", iterations);
    printf("%8.2lf ms per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        FACTORING_ZK_modulus_kill(&m);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    elapsed = MICROSECOND * elapsed / iterations;
    printf("\tFACTORING_ZK_modulus_kill\t%8d iterations\t", iterations);
    printf("%8.2lf us per iteration\n", elapsed);

    exit(EXIT_SUCCESS);
}
