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

/* GG20 Phase 6 ZKP smoke test */

int main()
{
    int rc;

    BIG_256_56 s;
    BIG_256_56 l;
    BIG_256_56 q;

    ECP_SECP256K1 G;

    GG20_ZKP_rv                rv;
    GG20_ZKP_phase6_commitment c;
    GG20_ZKP_proof             p;

    char id[32];
    octet ID = {0, sizeof(id), id};

    char ad[32];
    octet AD = {0, sizeof(ad), ad};

    char oct_s[GGS_SECP256K1];
    octet S = {0, sizeof(oct_s), oct_s};

    char oct_l[GGS_SECP256K1];
    octet L = {0, sizeof(oct_l), oct_l};

    char r[GFS_SECP256K1+1];
    octet R = {0, sizeof(r), r};

    char t[GFS_SECP256K1+1];
    octet T = {0, sizeof(t), t};

    char ecps[GFS_SECP256K1+1];
    octet ECPS = {0, sizeof(ecps), ecps};

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

    MPC_PHASE3_T(&RNG, &S, &L, &T);

    // Generate R and S = s.R
    BIG_256_56_randomnum(l, q, &RNG);

    ECP_SECP256K1_generator(&G);
    ECP_SECP256K1_mul(&G, l);
    ECP_SECP256K1_toOctet(&R, &G, true);

    MPC_ECP_GENERATE_CHECK(&R, &S, &ECPS);

    // Run test
    rc = GG20_ZKP_phase6_commit(&RNG, &R, &rv, &c);
    if (rc != GG20_ZKP_OK)
    {
        printf("FAILURE GG20_ZKP_phase6_commit. rc %d\n", rc);
        exit(EXIT_FAILURE);
    }

    GG20_ZKP_phase6_challenge(&R, &T, &ECPS, &c, &ID, &AD, &E);
    GG20_ZKP_phase6_prove(&rv, &E, &S, &L, &p);

    rc = GG20_ZKP_phase6_verify(&R, &T, &ECPS, &c, &E, &p);
    if (rc != GG20_ZKP_OK)
    {
        printf("FAILURE GG20_ZKP_phase6_verify. rc %d\n", rc);
        exit(EXIT_FAILURE);
    }

    // Clean memory
    GG20_ZKP_rv_kill(&rv);
    big_245_56_cleaned(rv.a, "a");
    big_245_56_cleaned(rv.b, "b");

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}