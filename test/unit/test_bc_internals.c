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
#include "test.h"
#include "commitments.c"

/* BC Commitment internals unit tests */

char *Phex = "CA5F37B7C0DDF6530B30A41116588218DE95F1F36B807FD7C28E4C467EE3F35967BC01D28B71F8A627A353675A81C86A1FF03DCECAF1686891183FA317BA34A4A1148D40A89F1F3AC0C200511C6CFE02342CD75354C25A2E069886DD4FB73BD365660D163F1282B143119AB8F375A73875EC16B634F52593B73BC6D875F2D3EF";

int main()
{
    int rc;

    char o[HFS_2048];
    octet O = {0, sizeof(o), o};

    BIG_1024_58 P[HFLEN_2048];
    BIG_1024_58 p[HFLEN_2048];
    BIG_1024_58 x[HFLEN_2048];

    // Load P and p = (P-1)/2
    OCT_fromHex(&O, Phex);
    FF_2048_fromOctet(P, &O, HFLEN_2048);
    FF_2048_copy(p, P, HFLEN_2048);
    FF_2048_shr(p, HFLEN_2048);

    // Deterministic RNG for testing
    csprng RNG;
    char seed[32] = {0};
    RAND_seed(&RNG, 32, seed);

    /* Test utility to find generators of G_p as subgroup of Z/PZ */
    bc_generator(&RNG, x, P, HFLEN_2048);
    assert(NULL, "bc_generator - returned unity", !FF_2048_isunity(x, HFLEN_2048));
    FF_2048_nt_pow(x, x, p, P, HFLEN_2048, HFLEN_2048);
    assert(NULL, "bc_generator - order is not P", FF_2048_isunity(x, HFLEN_2048));

    /* Test safe prime primality test */

    // Test OK
    rc = is_safe_prime(p, P, &RNG, HFLEN_2048);
    assert(NULL, "is_safe_prime OK", rc);

    // Test FAIL - p not prime
    FF_2048_dec(p, 1, HFLEN_2048);
    rc = !is_safe_prime(p, P, &RNG, HFLEN_2048);
    assert(NULL, "is_safe_prime FAIL - p small factor", rc);

    FF_2048_inc(p, 1, HFLEN_2048);

    // Test FAIL - P has small factor
    FF_2048_dec(P, 1, HFLEN_2048);
    rc = !is_safe_prime(p, P, &RNG, HFLEN_2048);
    assert(NULL, "is_safe_prime FAIL - P small factor", rc);

    FF_2048_inc(P, 1, HFLEN_2048);

    // Test FAIL - P not passing Fermat base 2 test
    // Increase P by 2 * 3 * ... * 19 + 1
    FF_2048_inc(P, 4849846, HFLEN_2048);
    rc = !is_safe_prime(p, P, &RNG, HFLEN_2048);
    assert(NULL, "is_safe_prime FAIL - P fails Fermat", rc);

    FF_2048_dec(P, 4849846, HFLEN_2048);

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
