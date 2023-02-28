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

/* GG20 ZKPs alternative generator integrity check
 *
 * The purpose of this test is to check that the alternative
 * generator for the GG20 ZKP is generated from the standard
 * generator so that it is a NUMS number and the DLOG w.r.t the
 * standard generator is not known
 */

#include <string.h>
#include "amcl/gg20_zkp.h"
#include "amcl/hash_utils.h"

int main()
{
    int rc;
    int attempt = 0;

    hash256 sha_seed;
    hash256 sha_attempt;

    BIG_256_56 p;

    char digest[SHA256];

    ECP_SECP256K1 H;
    ECP_SECP256K1 H_GOLDEN;

    char o[GFS_SECP256K1 + 1];
    octet O = {0, sizeof(o), o};

    // Compute H using repeated hases of the standard generator
    HASH256_init(&sha_seed);

    ECP_SECP256K1_generator(&H);
    ECP_SECP256K1_toOctet(&O, &H, true);
    HASH_UTILS_hash_oct(&sha_seed, &O);

    do
    {
        HASH_UTILS_hash_copy(&sha_attempt, &sha_seed);
        HASH_UTILS_hash_i2osp4(&sha_attempt, attempt);
        attempt++;

        HASH256_hash(&sha_attempt, digest);
        BIG_256_56_fromBytesLen(p, digest, GGS_SECP256K1);

        rc = ECP_SECP256K1_setx(&H, p, 0);

        // The cofactor check is trivial for secp256k1
        // but it MUST be included if we decide to support
        // curves with cofactor != 1
    }
    while(rc != 1);

    // Check that the computed generator is equal to the one hard-coded
    // in the library
    GG20_ZKP_generator_2(&H_GOLDEN);

    if (!ECP_SECP256K1_equals(&H, &H_GOLDEN))
    {
        printf("FAILURE mismatching generators\n");
        exit(EXIT_FAILURE);
    }

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
