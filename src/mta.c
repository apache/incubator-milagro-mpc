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

/* MPC definitions */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "amcl/mta.h"
#include "amcl/hash_utils.h"

static char* curve_order_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

/* MTA descriptions */

// Client MTA first pass
void MTA_CLIENT1(csprng *RNG,  PAILLIER_public_key *PUB, octet *A, octet *CA, octet *R)
{
    char a1[FS_2048];
    octet A1 = {0,sizeof(a1),a1};

    OCT_copy(&A1, A);
    OCT_pad(&A1, FS_2048);

    PAILLIER_ENCRYPT(RNG, PUB, &A1, CA, R);

    // Clean memory
    OCT_clear(&A1);
}

// Client MtA second pass
void MTA_CLIENT2(PAILLIER_private_key *PRIV, octet *CB, octet *ALPHA)
{
    BIG_1024_58 q[HFLEN_2048];
    BIG_1024_58 alpha[HFLEN_2048];

    char t[FS_2048];
    octet T = {0,sizeof(t),t};

    // Curve order
    OCT_fromHex(&T, curve_order_hex);
    OCT_pad(&T, HFS_2048);
    FF_2048_fromOctet(q, &T, HFLEN_2048);

    PAILLIER_DECRYPT(PRIV, CB, &T);

    // alpha < q^3
    OCT_shl(&T, HFS_2048);
    FF_2048_fromOctet(alpha, &T, HFLEN_2048);

    // alpha = alpha mod q
    FF_2048_mod(alpha, q, HFLEN_2048);

    // Output alpha
    FF_2048_toOctet(&T, alpha, HFLEN_2048);
    OCT_chop(&T, ALPHA, HFS_2048 - EGS_SECP256K1);

    // Clean memory
    FF_2048_zero(alpha, FFLEN_2048);
    OCT_clear(&T);
}

// MtA server
void MTA_SERVER(csprng *RNG, PAILLIER_public_key *PUB, octet *B, octet *CA, octet *ZO, octet *R, octet *CB, octet *BETA)
{
    BIG_256_56 q;
    BIG_256_56 z;

    char zb[FS_2048];
    octet Z = {0,sizeof(zb),zb};

    char cz[FS_4096];
    octet CZ = {0,sizeof(cz),cz};

    char ct[FS_4096];
    octet CT = {0,sizeof(ct),ct};

    char b1[FS_2048];
    octet B1 = {0,sizeof(b1),b1};

    // Curve order
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    // Read B
    OCT_copy(&B1, B);
    OCT_pad(&B1, FS_2048);

    // Random z value
    if (RNG!=NULL)
    {
        BIG_256_56_randomnum(z, q, RNG);

        BIG_256_56_toBytes(Z.val, z);
        Z.len = EGS_SECP256K1;
    }
    else
    {
        BIG_256_56_fromBytesLen(z, ZO->val, ZO->len);
        OCT_copy(&Z, ZO);
    }

    OCT_pad(&Z, FS_2048);

    // beta = -z mod q
    BIG_256_56_sub(z, q, z);

    // CT = E_A(a.b)
    PAILLIER_MULT(PUB, CA, &B1, &CT);

    // CZ = E_A(z)
    PAILLIER_ENCRYPT(RNG, PUB, &Z, &CZ, R);

    // CB = E_A(a.b + z)
    PAILLIER_ADD(PUB, &CT, &CZ, CB);

    // Output Z for Debug
    if (ZO!=NULL)
    {
        OCT_chop(&Z, ZO, FS_2048 - EGS_SECP256K1);
    }

    // Output beta
    BIG_256_56_toBytes(BETA->val, z);
    BETA->len = EGS_SECP256K1;

    // Clean memory
    BIG_256_56_zero(z);
    OCT_clear(&B1);
}

// Set the initial value for the MTA accumulators
void MTA_ACCUMULATOR_SET(BIG_256_56 accum, octet *V1, octet *V2)
{
    BIG_256_56 v1;
    BIG_256_56 v2;
    DBIG_256_56 w;

    BIG_256_56_fromBytesLen(v1, V1->val, V1->len);
    BIG_256_56_fromBytesLen(v2, V2->val, V2->len);

    BIG_256_56_mul(w, v1, v2);
    BIG_256_56_rcopy(v1, CURVE_Order_SECP256K1);
    BIG_256_56_dmod(accum, w, v1);

    // Clean memory
    BIG_256_56_zero(v2);
    BIG_256_56_dzero(w);
}

// Add a value to the accumulator
void MTA_ACCUMULATOR_ADD(BIG_256_56 accum, octet *V)
{
    BIG_256_56 v;

    BIG_256_56_fromBytesLen(v, V->val, V->len);

    BIG_256_56_add(accum, accum, v);
    BIG_256_56_rcopy(v, CURVE_Order_SECP256K1);
    BIG_256_56_mod(accum, v);

    // Clean memory
    BIG_256_56_zero(v);
}
