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
#include "amcl/hash_utils.h"

/* Rom for SEC256K1 alternative generator
 *
 * This is tested in the unit tests to make sure it is a NUMS number
 */

const BIG_256_56 CURVE_G2x_SECP256K1= {0x072FA321534A94L, 0x1E5494E1366DF5L, 0x5544A7C6B1AE84L, 0x361809F7E86B0AL, 0x00000050E61A4DL};
const BIG_256_56 CURVE_G2y_SECP256K1= {0x2EDE1FF33BE530L, 0x3BF41E26F5E241L, 0xB21F8B17AFDFBFL, 0xC7F68F0FD917E8L, 0x000000F1AF85F2L};

void GG20_ZKP_generator_2(ECP_SECP256K1 *G)
{
    BIG_256_56 x,y;

    BIG_256_56_rcopy(x,CURVE_G2x_SECP256K1);
    BIG_256_56_rcopy(y,CURVE_G2y_SECP256K1);

    ECP_SECP256K1_set(G,x,y);
}

/* Octet functions */

void GG20_ZKP_proof_fromOctets(GG20_ZKP_proof *p, octet *T, octet *U)
{
    BIG_256_56_fromBytesLen(p->t, T->val, T->len);
    BIG_256_56_fromBytesLen(p->u, U->val, U->len);
}

void GG20_ZKP_proof_toOctets(octet *T, octet *U, GG20_ZKP_proof *p)
{
    BIG_256_56_toBytes(T->val, p->t);
    T->len = GGS_SECP256K1;

    BIG_256_56_toBytes(U->val, p->u);
    U->len = GGS_SECP256K1;
}

int GG20_ZKP_phase6_commitment_fromOctets(GG20_ZKP_phase6_commitment *c, octet *ALPHA, octet *BETA)
{
    if (!ECP_SECP256K1_fromOctet(&(c->ALPHA), ALPHA))
    {
        return GG20_ZKP_INVALID_ECP;
    }

    if (!ECP_SECP256K1_fromOctet(&(c->BETA), BETA))
    {
        return GG20_ZKP_INVALID_ECP;
    }

    return GG20_ZKP_OK;
}

void GG20_ZKP_phase6_commitment_toOctets(octet *ALPHA, octet *BETA, GG20_ZKP_phase6_commitment *c)
{
    ECP_SECP256K1_toOctet(ALPHA, &(c->ALPHA), true);
    ECP_SECP256K1_toOctet(BETA, &(c->BETA), true);
}

/* Cleanup functions definitions */

void GG20_ZKP_rv_kill(GG20_ZKP_rv *r)
{
    BIG_256_56_zero(r->a);
    BIG_256_56_zero(r->b);
}

/* Phase 3 Proof Definitions */

void GG20_ZKP_phase3_commit(csprng *RNG, GG20_ZKP_rv *r, octet *C)
{
    BIG_256_56 q;

    ECP_SECP256K1 G;
    ECP_SECP256K1 H;

    ECP_SECP256K1_generator(&G);
    GG20_ZKP_generator_2(&H);

    // Read or generate secrets A, B
    if (RNG != NULL)
    {
        BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

        BIG_256_56_randomnum(r->a, q, RNG);
        BIG_256_56_randomnum(r->b, q, RNG);
    }

    // Generate commitment C = a.G + b.H
    ECP_SECP256K1_mul2(&G, &H, r->a, r->b);
    ECP_SECP256K1_toOctet(C, &G, true);
}

void GG20_ZKP_phase3_challenge(const octet *V, const octet *C, const octet *ID, const octet *AD, octet *E)
{
    hash256 sha;

    BIG_256_56 e;
    BIG_256_56 q;
    ECP_SECP256K1 G;

    char o[GFS_SECP256K1 + 1];
    octet O = {0, sizeof(o), o};

    HASH256_init(&sha);

    /* Bind Curve generators */
    ECP_SECP256K1_generator(&G);
    ECP_SECP256K1_toOctet(&O, &G, true);
    HASH_UTILS_hash_oct(&sha, &O);

    GG20_ZKP_generator_2(&G);
    ECP_SECP256K1_toOctet(&O, &G, true);
    HASH_UTILS_hash_oct(&sha, &O);

    /* Bind Commitment */
    HASH_UTILS_hash_oct(&sha, C);

    /* Bind Proof Input */
    HASH_UTILS_hash_oct(&sha, V);

    /* Bind ID and AD */
    HASH_UTILS_hash_i2osp4(&sha, ID->len);
    HASH_UTILS_hash_oct(&sha, ID);

    if (AD != NULL)
    {
        HASH_UTILS_hash_i2osp4(&sha, AD->len);
        HASH_UTILS_hash_oct(&sha, AD);
    }

    // Compute challenge
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    HASH_UTILS_rejection_sample_mod_BIG(&sha, q, e);

    BIG_256_56_toBytes(E->val, e);
    E->len = MODBYTES_256_56;
}

void GG20_ZKP_phase3_prove(GG20_ZKP_rv *r, const octet *E, const octet *S, const octet *L, GG20_ZKP_proof *p)
{
    BIG_256_56 e;
    BIG_256_56 q;

    DBIG_256_56 d;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    BIG_256_56_fromBytesLen(e, E->val, E->len);
    BIG_256_56_modneg(e, e, q);

    // Generate proof t = a - (e * s) mod the curve order
    BIG_256_56_fromBytesLen(p->t, S->val, S->len);

    BIG_256_56_mul(d, e, p->t);
    BIG_256_56_dmod(p->t, d, q);
    BIG_256_56_add(p->t, p->t, r->a);
    BIG_256_56_mod(p->t, q);

    // Generate proof u = b - (e * l) mod the curve order
    BIG_256_56_fromBytesLen(p->u, L->val, L->len);

    BIG_256_56_mul(d, e, p->u);
    BIG_256_56_dmod(p->u, d, q);
    BIG_256_56_add(p->u, p->u, r->b);
    BIG_256_56_mod(p->u, q);

    // Clean memory
    BIG_256_56_dzero(d);
}

int GG20_ZKP_phase3_verify(octet *V, octet *C, const octet *E, GG20_ZKP_proof *p)
{
    ECP_SECP256K1 G;
    ECP_SECP256K1 H;

    BIG_256_56 e;

    BIG_256_56_fromBytesLen(e, E->val, E->len);

    // Compute first part of verification t.G + u.H
    ECP_SECP256K1_generator(&G);
    GG20_ZKP_generator_2(&H);
    ECP_SECP256K1_mul2(&G, &H, p->t, p->u);

    // Compute second part of verification e.V
    if (!ECP_SECP256K1_fromOctet(&H, V))
    {
        return GG20_ZKP_INVALID_ECP;
    }

    ECP_SECP256K1_mul(&H, e);

    // Combine full verification t.G + u.H + e.V
    ECP_SECP256K1_add(&G, &H);

    // Read commitment and verify
    if (!ECP_SECP256K1_fromOctet(&H, C))
    {
        return GG20_ZKP_INVALID_ECP;
    }

    if (!ECP_SECP256K1_equals(&G, &H))
    {
        return GG20_ZKP_FAIL;
    }

    return GG20_ZKP_OK;
}

/* Phase 6 Proof Definitions */

int GG20_ZKP_phase6_commit(csprng *RNG, octet *R, GG20_ZKP_rv *r, GG20_ZKP_phase6_commitment *c)
{
    BIG_256_56 q;

    // Read or generate secrets A, B
    if (RNG != NULL)
    {
        BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

        BIG_256_56_randomnum(r->a, q, RNG);
        BIG_256_56_randomnum(r->b, q, RNG);
    }


    // Generate commitment BETA = a.G + b.H
    // Use ALPHA as temporary workspace
    ECP_SECP256K1_generator(&(c->BETA));
    GG20_ZKP_generator_2(&(c->ALPHA));

    ECP_SECP256K1_mul2(&(c->BETA), &(c->ALPHA), r->a, r->b);

    // Generate commitment ALPHA = a.R
    if (!ECP_SECP256K1_fromOctet(&(c->ALPHA), R))
    {
        return GG20_ZKP_INVALID_ECP;
    }

    ECP_SECP256K1_mul(&(c->ALPHA), r->a);

    return GG20_ZKP_OK;
}

void GG20_ZKP_phase6_challenge(const octet *R, const octet *T, const octet *S, GG20_ZKP_phase6_commitment *c, const octet *ID, const octet *AD, octet *E)
{
    hash256 sha;

    BIG_256_56 e;
    BIG_256_56 q;

    ECP_SECP256K1 G;

    char o[GFS_SECP256K1 + 1];
    octet O = {0, sizeof(o), o};

    HASH256_init(&sha);

    /* Bind Curve generators */
    ECP_SECP256K1_generator(&G);
    ECP_SECP256K1_toOctet(&O, &G, true);
    HASH_UTILS_hash_oct(&sha, &O);

    GG20_ZKP_generator_2(&G);
    ECP_SECP256K1_toOctet(&O, &G, true);
    HASH_UTILS_hash_oct(&sha, &O);

    /* Bind R as an additional generator */
    HASH_UTILS_hash_oct(&sha, R);

    /* Bind Commitment */
    ECP_SECP256K1_toOctet(&O, &(c->ALPHA), true);
    HASH_UTILS_hash_oct(&sha, &O);
    ECP_SECP256K1_toOctet(&O, &(c->BETA), true);
    HASH_UTILS_hash_oct(&sha, &O);

    /* Bind Proof Input */
    HASH_UTILS_hash_oct(&sha, T);
    HASH_UTILS_hash_oct(&sha, S);

    /* Bind ID and AD */
    HASH_UTILS_hash_i2osp4(&sha, ID->len);
    HASH_UTILS_hash_oct(&sha, ID);

    if (AD != NULL)
    {
        HASH_UTILS_hash_i2osp4(&sha, AD->len);
        HASH_UTILS_hash_oct(&sha, AD);
    }

    // Compute challenge
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    HASH_UTILS_rejection_sample_mod_BIG(&sha, q, e);

    BIG_256_56_toBytes(E->val, e);
    E->len = MODBYTES_256_56;
}

void GG20_ZKP_phase6_prove(GG20_ZKP_rv *r, const octet *E, const octet *S, const octet *L, GG20_ZKP_proof *p)
{
    // The same values from the Phase 3 Proof can be used here
    GG20_ZKP_phase3_prove(r, E, S, L, p);
}

int GG20_ZKP_phase6_verify(octet *R, octet *T, octet *S, GG20_ZKP_phase6_commitment *c, const octet *E, GG20_ZKP_proof *p)
{
    ECP_SECP256K1 G;
    ECP_SECP256K1 H;

    BIG_256_56 e;

    BIG_256_56_fromBytesLen(e, E->val, E->len);

    /* Compute verification for t.R + e.S =? ALPHA */
    if (!ECP_SECP256K1_fromOctet(&G, R))
    {
        return GG20_ZKP_INVALID_ECP;
    }

    if (!ECP_SECP256K1_fromOctet(&H, S))
    {
        return GG20_ZKP_INVALID_ECP;
    }

    ECP_SECP256K1_mul2(&G, &H, p->t, e);

    if (!ECP_SECP256K1_equals(&G, &(c->ALPHA)))
    {
        return GG20_ZKP_FAIL;
    }

    /* Compute verification for t.G + u.H + e.T =? BETA */

    // Compute first part of verification t.G + u.H
    ECP_SECP256K1_generator(&G);
    GG20_ZKP_generator_2(&H);
    ECP_SECP256K1_mul2(&G, &H, p->t, p->u);

    // Read e and T
    if (!ECP_SECP256K1_fromOctet(&H, T))
    {
        return GG20_ZKP_INVALID_ECP;
    }

    ECP_SECP256K1_mul(&H, e);

    // Combine full verification t.G + u.H + e.V
    ECP_SECP256K1_add(&G, &H);

    if (!ECP_SECP256K1_equals(&G, &(c->BETA)))
    {
        return GG20_ZKP_FAIL;
    }

    return GG20_ZKP_OK;
}
