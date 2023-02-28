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
   Benchmark modulus utilities.
 */

#include "bench.h"
#include "amcl/modulus.h"

#define MIN_TIME 5.0
#define MIN_ITERS 10

char *P_hex = "e008507e09c24d756280f3d94912fb9ac16c0a8a1757ee01a350736acfc7f65880f87eca55d6680253383fc546d03fd9ebab7d8fa746455180888cb7c17edf58d3327296468e5ab736374bc9a0fa02606ed5d3a4a5fb1677891f87fbf3c655c3e0549a86b17b7ddce07c8f73e253105e59f5d3ed2c7ba5bdf8495df40ae71a7f";
char *Q_hex = "dbffe278edd44c2655714e5a4cc82e66e46063f9ab69df9d0ed20eb3d7f2d8c7d985df71c28707f32b961d160ca938e9cf909cd77c4f8c630aec34b67714cbfd4942d7147c509db131bc2d6a667eb30df146f64b710f8f5247848b0a75738a38772e31014fd63f0b769209928d586499616dcc90700b393156e12eea7e15a835";

int main()
{
    int iterations;
    clock_t start;
    double elapsed;

    char p[HFS_2048] = {0};
    octet P = {0, sizeof(p), p};

    char q[HFS_2048];
    octet Q = {0, sizeof(q), q};

    MODULUS_priv m;

    // Load values
    OCT_fromHex(&P, P_hex);
    OCT_fromHex(&Q, Q_hex);

    print_system_info();

    printf("Timing info\n");
    printf("===========\n");

    iterations = 0;
    start = clock();
    do
    {
        MODULUS_fromOctets(&m, &P, &Q);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    elapsed = MICROSECOND * elapsed / iterations;
    printf("\tMODULUS_fromOctets\t%8d iterations\t", iterations);
    printf("%8.2lf us per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        MODULUS_toOctets(&P, &Q, &m);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    elapsed = MICROSECOND * elapsed / iterations;
    printf("\tMODULUS_toOctets\t%8d iterations\t", iterations);
    printf("%8.2lf us per iteration\n", elapsed);


    iterations = 0;
    start = clock();
    do
    {
        MODULUS_kill(&m);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    elapsed = MICROSECOND * elapsed / iterations;
    printf("\tMODULUS_kill\t\t%8d iterations\t", iterations);
    printf("%8.2lf us per iteration\n", elapsed);

    exit(EXIT_SUCCESS);
}
