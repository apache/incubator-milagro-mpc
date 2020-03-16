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

static void hash_octet(hash256 *sha, const octet *O)
{
    int i;

    for (i = 0; i < O->len; i++)
    {
        HASH256_process(sha, O->val[i]);
    }
}

void SCHNORR_random_challenge(csprng *RNG, octet *E)
{
    BIG_256_56 e;
    BIG_256_56 q;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    BIG_256_56_randomnum(e, q, RNG);

    BIG_256_56_toBytes(E->val, e);
    E->len = SGS_SECP256K1;
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
        R->len = SGS_SECP256K1;
    }
    else
    {
        BIG_256_56_fromBytesLen(r, R->val, R->len);
    }

    // Generate commitment r.G
    ECP_SECP256K1_generator(&G);
    ECP_SECP256K1_mul(&G, r);

    // Output C compressed
    ECP_SECP256K1_toOctet(C, &G, true);

    // Clean memory
    BIG_256_56_zero(r);
}

void SCHNORR_challenge(const octet *V, const octet *C, octet *E)
{
    hash256 sha;

    BIG_256_56 e;
    BIG_256_56 q;
    ECP_SECP256K1 G;

    char o[SFS_SECP256K1 + 1];
    octet O = {0, sizeof(o), o};

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    ECP_SECP256K1_generator(&G);
    ECP_SECP256K1_toOctet(&O, &G, true);

    // e = H(G,C,V) mod q
    HASH256_init(&sha);
    hash_octet(&sha, &O);
    hash_octet(&sha, C);
    hash_octet(&sha, V);
    HASH256_hash(&sha, o);

    BIG_256_56_fromBytesLen(e, o, SHA256);
    BIG_256_56_mod(e, q);

    BIG_256_56_toBytes(E->val, e);
    E->len = SGS_SECP256K1;
}

void SCHNORR_prove(const octet *R, const octet *E, const octet *X, octet *P)
{
    BIG_256_56 r;
    BIG_256_56 e;
    BIG_256_56 x;
    BIG_256_56 q;
    DBIG_256_56 d;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    // Read octets
    BIG_256_56_fromBytesLen(r, R->val, R->len);
    BIG_256_56_fromBytesLen(e, E->val, E->len);
    BIG_256_56_fromBytesLen(x, X->val, X->len);

    // Generate proof r - (e * x) mod the curve order
    BIG_256_56_mul(d, e, x);
    BIG_256_56_dmod(x, d, q);
    BIG_256_56_modneg(x, x, q);
    BIG_256_56_add(x, x, r);
    BIG_256_56_mod(x, q);

    BIG_256_56_toBytes(P->val, x);
    P->len = SGS_SECP256K1;

    // Clean memory
    BIG_256_56_zero(r);
    BIG_256_56_dzero(d);
}

int SCHNORR_verify(octet *V, octet*C, const octet *E, const octet *P)
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

int SCHNORR_D_commit(csprng *RNG, octet *R, octet *A, octet *B, octet *C)
{
    BIG_256_56 a;
    BIG_256_56 b;
    BIG_256_56 q;

    ECP_SECP256K1 G;
    ECP_SECP256K1 ECPR;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    ECP_SECP256K1_generator(&G);

    if (!ECP_SECP256K1_fromOctet(&ECPR, R))
    {
        return SCHNORR_INVALID_ECP;
    }

    // Read or generate secrets A, B
    if (RNG != NULL)
    {
        BIG_256_56_randomnum(a, q, RNG);
        BIG_256_56_randomnum(b, q, RNG);
        BIG_256_56_toBytes(A->val, a);
        BIG_256_56_toBytes(B->val, b);
        A->len = SGS_SECP256K1;
        B->len = SGS_SECP256K1;
    }
    else
    {
        BIG_256_56_fromBytesLen(a, A->val, A->len);
        BIG_256_56_fromBytesLen(b, B->val, B->len);
    }

    // Generate commitment C = a.R + b.G
    ECP_SECP256K1_mul2(&ECPR, &G, a, b);
    ECP_SECP256K1_toOctet(C, &ECPR, true);

    // Clean memory
    BIG_256_56_zero(a);
    BIG_256_56_zero(b);

    return SCHNORR_OK;
}

void SCHNORR_D_challenge(const octet *R, const octet *V, const octet *C, octet *E)
{
    hash256 sha;

    BIG_256_56 e;
    BIG_256_56 q;
    ECP_SECP256K1 G;

    char o[SFS_SECP256K1 + 1];
    octet O = {0, sizeof(o), o};

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    ECP_SECP256K1_generator(&G);
    ECP_SECP256K1_toOctet(&O, &G, true);

    // e = H(G,R,C,V) mod q
    HASH256_init(&sha);
    hash_octet(&sha, &O);
    hash_octet(&sha, R);
    hash_octet(&sha, C);
    hash_octet(&sha, V);
    HASH256_hash(&sha, o);

    BIG_256_56_fromBytesLen(e, o, SHA256);
    BIG_256_56_mod(e, q);

    BIG_256_56_toBytes(E->val, e);
    E->len = MODBYTES_256_56;
}

void SCHNORR_D_prove(const octet *A, const octet *B, const octet *E, const octet *S, const octet *L, octet *T, octet *U)
{
    BIG_256_56 r;
    BIG_256_56 e;
    BIG_256_56 x;
    BIG_256_56 q;
    DBIG_256_56 d;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    BIG_256_56_fromBytesLen(e, E->val, E->len);

    // Generate proof t = a + (e * s) mod the curve order
    BIG_256_56_fromBytesLen(x, S->val, S->len);
    BIG_256_56_fromBytesLen(r, A->val, A->len);

    BIG_256_56_mul(d, e, x);
    BIG_256_56_dmod(x, d, q);
    BIG_256_56_add(x, x, r);
    BIG_256_56_mod(x, q);

    BIG_256_56_toBytes(T->val, x);
    T->len = SGS_SECP256K1;

    // Generate proof u = b + (e * l) mod the curve order
    BIG_256_56_fromBytesLen(x, L->val, L->len);
    BIG_256_56_fromBytesLen(r, B->val, B->len);

    BIG_256_56_mul(d, e, x);
    BIG_256_56_dmod(x, d, q);
    BIG_256_56_add(x, x, r);
    BIG_256_56_mod(x, q);

    BIG_256_56_toBytes(U->val, x);
    U->len = SGS_SECP256K1;

    // Clean memory
    BIG_256_56_zero(r);
    BIG_256_56_dzero(d);
}

int SCHNORR_D_verify(octet *R, octet *V, octet *C, const octet *E, const octet *T, const octet *U)
{
    ECP_SECP256K1 G;
    ECP_SECP256K1 ECPR;
    ECP_SECP256K1 ECPV;
    ECP_SECP256K1 ECPC;

    BIG_256_56 t;
    BIG_256_56 u;

    // Read octets
    if (!ECP_SECP256K1_fromOctet(&ECPV, V))
    {
        return SCHNORR_INVALID_ECP;
    }

    if (!ECP_SECP256K1_fromOctet(&ECPR, R))
    {
        return SCHNORR_INVALID_ECP;
    }

    if (!ECP_SECP256K1_fromOctet(&ECPC, C))
    {
        return SCHNORR_INVALID_ECP;
    }

    BIG_256_56_fromBytesLen(t, T->val, T->len);
    BIG_256_56_fromBytesLen(u, U->val, U->len);

    // Compute verification t.R + u.G
    ECP_SECP256K1_generator(&G);
    ECP_SECP256K1_mul2(&ECPR, &G, t, u);

    // Compute ground truth C + e.V
    BIG_256_56_fromBytesLen(t, E->val, E->len);
    ECP_SECP256K1_mul(&ECPV, t);
    ECP_SECP256K1_add(&ECPV, &ECPC);

    if (!ECP_SECP256K1_equals(&ECPV, &ECPR))
    {
        return SCHNORR_FAIL;
    }

    return SCHNORR_OK;
}
