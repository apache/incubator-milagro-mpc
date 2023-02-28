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

#include "amcl/gg20_zkp.h"
#include "amcl/mpc.h"

void big_245_56_cleaned(BIG_256_56 a, char *name)
{
    if (!BIG_256_56_iszilch(a))
    {
        printf("FAILURE GG20_ZKP_rv_kill. %s is not clean.\n", name);
        exit(EXIT_FAILURE);
    }
}

/* GG20 Phase 3 ZKP smoke test */

int main()
{
    int rc;

    BIG_256_56 s;
    BIG_256_56 q;

    GG20_ZKP_rv    r;
    GG20_ZKP_proof p;

    char id[32];
    octet ID = {0, sizeof(id), id};

    char ad[32];
    octet AD = {0, sizeof(ad), ad};

    char oct_s[GGS_SECP256K1];
    octet S = {0, sizeof(oct_s), oct_s};

    char oct_l[GGS_SECP256K1];
    octet L = {0, sizeof(oct_l), oct_l};

    char v[GFS_SECP256K1+1];
    octet V = {0, sizeof(v), v};

    char c[GFS_SECP256K1+1];
    octet C = {0, sizeof(c), c};

    char e[GGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    // Deterministic RNG for testing
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    // Generate ID and AD
    OCT_rand(&ID, &RNG, ID.len);
    OCT_rand(&AD, &RNG, AD.len);

    // Generate s, l and compute V = s.G + l.H
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    BIG_256_56_randomnum(s, q, &RNG);

    BIG_256_56_toBytes(S.val, s);
    S.len = GGS_SECP256K1;

    MPC_PHASE3_T(&RNG, &S, &L, &V);

    // Run test
    GG20_ZKP_phase3_commit(&RNG, &r, &C);
    GG20_ZKP_phase3_challenge(&V, &C, &ID, &AD, &E);
    GG20_ZKP_phase3_prove(&r, &E, &S, &L, &p);

    rc = GG20_ZKP_phase3_verify(&V, &C, &E, &p);
    if (rc != GG20_ZKP_OK)
    {
        printf("FAILURE GG20_ZKP_phase3_verify. rc %d\n", rc);
        exit(EXIT_FAILURE);
    }

    // Clean memory
    GG20_ZKP_rv_kill(&r);
    big_245_56_cleaned(r.a, "a");
    big_245_56_cleaned(r.b, "b");

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}