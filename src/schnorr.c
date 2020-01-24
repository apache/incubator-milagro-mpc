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

#include "amcl/schnorr.h"

void hash_octet(hash256 *sha, octet *O)
{
    int i;

    for (i = 0; i < O->len; i++)
    {
        HASH256_process(sha, O->val[i]);
    }
}

/* Classic Schnorr's Proof Definitions */

void SCHNORR_commit(csprng *RNG, octet *R, octet *C)
{
    BIG_256_56 r;
    BIG_256_56 q;
    ECP_SECP256K1 G;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    // Read or generate secret R
    if (RNG != NULL)
    {
        BIG_256_56_randomnum(r, q, RNG);
        BIG_256_56_toBytes(R->val, r);
        R->len = MODBYTES_256_56;
    }
    else
    {
        BIG_256_56_fromBytesLen(r, R->val, R->len);
    }

    // Generate commitment r.G
    ECP_SECP256K1_generator(&G);
    ECP_SECP256K1_mul(&G,r);

    // Output C compressed
    ECP_SECP256K1_toOctet(C, &G, 1);

    // Clean memory
    BIG_256_56_zero(r);
}

void SCHNORR_challenge(octet *V, octet *C, octet *E)
{
    hash256 sha;

    BIG_256_56 e;
    BIG_256_56 q;
    ECP_SECP256K1 G;

    char o[2 * SFS_SECP256K1 + 1];
    octet O = {0, sizeof(o), o};

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    ECP_SECP256K1_generator(&G);
    ECP_SECP256K1_toOctet(&O, &G, 1);

    // e = H(G,C,V) mod q
    HASH256_init(&sha);
    hash_octet(&sha, &O);
    hash_octet(&sha, C);
    hash_octet(&sha, V);
    HASH256_hash(&sha, o);

    BIG_256_56_fromBytesLen(e, o, SHA256);
    BIG_256_56_mod(e, q);

    BIG_256_56_toBytes(E->val, e);
    E->len = MODBYTES_256_56;
}

void SCHNORR_prove(octet *R, octet *E, octet *X, octet *P)
{
    BIG_256_56 r;
    BIG_256_56 e;
    BIG_256_56 x;
    BIG_256_56 p;
    BIG_256_56 q;
    DBIG_256_56 d;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    // Read octets
    BIG_256_56_fromBytesLen(r, R->val, R->len);
    BIG_256_56_fromBytesLen(e, E->val, E->len);
    BIG_256_56_fromBytesLen(x, X->val, X->len);

    // Generate proof r - (e * x) mod the curve order
    BIG_256_56_mul(d, e, x);
    BIG_256_56_dmod(p, d, q);
    BIG_256_56_modneg(p, p, q);
    BIG_256_56_add(p, p, r);
    BIG_256_56_mod(p, q);

    BIG_256_56_toBytes(P->val, p);
    P->len = MODBYTES_256_56;

    // Clean memory
    BIG_256_56_zero(r);
    BIG_256_56_zero(x);
}

int SCHNORR_verify(octet *V, octet*C, octet *E, octet *P)
{
    int rc;

    ECP_SECP256K1 G;
    ECP_SECP256K1 GT;
    ECP_SECP256K1 CO;

    BIG_256_56 e;
    BIG_256_56 p;

    // Read octets
    rc = ECP_SECP256K1_fromOctet(&GT, V);
    if (!rc)
    {
        return SCHNORR_INVALID_ECP;
    }

    rc = ECP_SECP256K1_fromOctet(&CO, C);
    if (!rc)
    {
        return SCHNORR_INVALID_ECP;
    }

    BIG_256_56_fromBytesLen(e, E->val, E->len);
    BIG_256_56_fromBytesLen(p, P->val, P->len);

    // Verify C == p.G + e.V
    ECP_SECP256K1_generator(&G);
    ECP_SECP256K1_mul2(&G, &GT, p, e);

    rc = ECP_SECP256K1_equals(&CO, &G);
    if (!rc)
    {
        return SCHNORR_FAIL;
    }

    return SCHNORR_OK;
}
