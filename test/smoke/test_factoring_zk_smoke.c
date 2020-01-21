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

/* ZK proof of knowldege of factoring smoke test */

#include "amcl/factoring_zk.h"

char *P_hex = "e008507e09c24d756280f3d94912fb9ac16c0a8a1757ee01a350736acfc7f65880f87eca55d6680253383fc546d03fd9ebab7d8fa746455180888cb7c17edf58d3327296468e5ab736374bc9a0fa02606ed5d3a4a5fb1677891f87fbf3c655c3e0549a86b17b7ddce07c8f73e253105e59f5d3ed2c7ba5bdf8495df40ae71a7f";
char *Q_hex = "dbffe278edd44c2655714e5a4cc82e66e46063f9ab69df9d0ed20eb3d7f2d8c7d985df71c28707f32b961d160ca938e9cf909cd77c4f8c630aec34b67714cbfd4942d7147c509db131bc2d6a667eb30df146f64b710f8f5247848b0a75738a38772e31014fd63f0b769209928d586499616dcc90700b393156e12eea7e15a835";

int main()
{
    char p[HFS_2048] = {0};
    octet P = {0, sizeof(p), p};

    char q[HFS_2048];
    octet Q = {0, sizeof(q), q};

    char n[FS_2048];
    octet N = {0, sizeof(n), n};

    char e[FACTORING_ZK_B];
    octet E = {0, sizeof(e), e};

    char y[FS_2048];
    octet Y = {0, sizeof(y), y};

    FACTORING_ZK_modulus m;

    BIG_1024_58 zero[HFLEN_2048];
    FF_2048_zero(zero, HFLEN_2048);

    // Deterministic RNG for testing
    char seed[64] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    // Load RSA modulus
    OCT_fromHex(&P, P_hex);
    OCT_fromHex(&Q, Q_hex);

    FF_2048_fromOctet(m.p, &P, HFLEN_2048);
    FF_2048_fromOctet(m.q, &Q, HFLEN_2048);

    FF_2048_mul(m.n, m.p, m.q, HFLEN_2048);

    // ZK proof
    FACTORING_ZK_prove(&m, &RNG, NULL, &E, &Y);

    FF_2048_toOctet(&N, m.n, FFLEN_2048);

    // Verify proof
    if (!FACTORING_ZK_verify(&N, &E, &Y))
    {
        printf("FAILURE FACTORING_ZK_verify\n");
        exit(EXIT_FAILURE);
    }

    // Kill modulus
    FACTORING_ZK_kill_modulus(&m);
    if (FF_2048_comp(m.p, zero, HFLEN_2048))
    {
        printf("FAILUER FACTORING_ZK_kill_modulus. P not zeroed\n");
        exit(EXIT_FAILURE);
    }

    if (FF_2048_comp(m.q, zero, HFLEN_2048))
    {
        printf("FAILUER FACTORING_ZK_kill_modulus. Q not zeroed\n");
        exit(EXIT_FAILURE);
    }

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
