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

#include <string.h>
#include "commitments.c"

/* BC Commitment internals unit tests */

char *Phex = "CA5F37B7C0DDF6530B30A41116588218DE95F1F36B807FD7C28E4C467EE3F35967BC01D28B71F8A627A353675A81C86A1FF03DCECAF1686891183FA317BA34A4A1148D40A89F1F3AC0C200511C6CFE02342CD75354C25A2E069886DD4FB73BD365660D163F1282B143119AB8F375A73875EC16B634F52593B73BC6D875F2D3EF";

char *X0hex = "4f2f4a6e3ee87e36d1c4f653478fe7cead1d6bfdf67e106f3a26709924123831a18002638685f6ddafcfa33f17eab7cfaf15f28b7bdf798f71b18462db94d9a97ad250738076703522f9e947c2c6dec7045917f39bb602ab3cf1d00766ac7c641dcf7ba02e6b236b19354dddbef694e7c5a5307ead266dc69e39781cc17217b8";
char *X1hex = "1241075d9b641c4f3da110d5c0fb5b7e7334e7d826c6a4ee76ebb1ae780ef1d78fa5579660a5ed3e881075f51fe4a018a526be4da49fce408842391f925b2baf4af87c62f0c92166b54020b9878a2e17fad87b4d801ea1cc786f29a877cf95020484166bfc8dbbe799c8934aca74f34ac51bac8b4753191d302c813f6691cf79";

int main()
{
    char o[HFS_2048];
    octet O = {0, sizeof(o), o};

    BIG_1024_58 P[HFLEN_2048];
    BIG_1024_58 p[HFLEN_2048];
    BIG_1024_58 x0[HFLEN_2048];
    BIG_1024_58 x1[HFLEN_2048];
    BIG_1024_58 x[HFLEN_2048];

    // Load values
    OCT_fromHex(&O, Phex);
    FF_2048_fromOctet(P, &O, HFLEN_2048);
    FF_2048_copy(p, P, HFLEN_2048);
    FF_2048_shr(p, HFLEN_2048);

    OCT_fromHex(&O, X0hex);
    FF_2048_fromOctet(x0, &O, HFLEN_2048);

    OCT_fromHex(&O, X1hex);
    FF_2048_fromOctet(x1, &O, HFLEN_2048);

    // Deterministic RNG for testing
    csprng RNG;
    char seed[32] = {0};

    /* Test utility to find generators of G_pq as subgroup of Z/PQZ */

    // Using seed 0 the generated number has order p
    // and is not squared
    RAND_seed(&RNG, 32, seed);
    bc_generator(&RNG, x, p, P, HFLEN_2048);

    if (FF_2048_comp(x, x0, HFLEN_2048) != 0)
    {
        printf("FAILURE bc_generator. Seed 0\n");
        exit(EXIT_FAILURE);
    }

    // Using seed 1 the generated number has order 2p
    // and is squared
    seed[0]+=1;
    RAND_seed(&RNG, 32, seed);
    bc_generator(&RNG, x, p, P, HFLEN_2048);

    if (FF_2048_comp(x, x1, HFLEN_2048) != 0)
    {
        printf("FAILURE bc_generator. Seed 1\n");
        exit(EXIT_FAILURE);
    }

    /* Test safe prime primality test */

    // Test OK
    if (!is_safe_prime(p, P, &RNG, HFLEN_2048))
    {
        printf("FAILURE is_safe_prime OK\n");
        exit(EXIT_FAILURE);
    }

    // Test FAIL - p not prime
    FF_2048_dec(p, 1, HFLEN_2048);
    if(is_safe_prime(p, P, &RNG, HFLEN_2048))
    {
        printf("FAILURE is_safe_prime FAIL - p small factor\n");
        exit(EXIT_FAILURE);
    }

    FF_2048_inc(p, 1, HFLEN_2048);

    // Test FAIL - P has small factor
    FF_2048_dec(P, 1, HFLEN_2048);
    if(is_safe_prime(p, P, &RNG, HFLEN_2048))
    {
        printf("FAILURE is_safe_prime FAIL - P small factor\n");
        exit(EXIT_FAILURE);
    }

    FF_2048_inc(P, 1, HFLEN_2048);

    // Test FAIL - P not passing Fermat base 2 test
    // Increase P by 2 * 3 * ... * 19 + 1
    FF_2048_inc(P, 4849846, HFLEN_2048);

    if(is_safe_prime(p, P, &RNG, HFLEN_2048))
    {
        printf("FAILURE is_safe_prime FAIL - P small factor\n");
        exit(EXIT_FAILURE);
    }

    FF_2048_dec(P, 4849846, HFLEN_2048);

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
