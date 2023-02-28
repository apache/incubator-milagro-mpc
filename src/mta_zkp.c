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

/**
 * @file mta_zkp.c
 * @brief High level wrapping for the MTA proofs based on the Bit Commitment proofs
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "amcl/hash_utils.h"
#include "amcl/mta_zkp.h"

/* MTA Range Proof */

void MTA_RP_commit(csprng *RNG, PAILLIER_private_key *key, BIT_COMMITMENT_pub *mod,  octet *M,  MTA_RP_rv *rv, MTA_RP_commitment *c)
{
    BIT_COMMITMENT_commit(RNG, key, mod, M, (BIT_COMMITMENT_rv*)rv, (BIT_COMMITMENT_commitment*)c);
}

void MTA_RP_challenge(PAILLIER_public_key *key, BIT_COMMITMENT_pub *mod, const octet *CT, MTA_RP_commitment *c, const octet *ID, const octet *AD, octet *E)
{
    hash256 sha;


    BIG_256_56 q;
    BIG_256_56 t;

    HASH256_init(&sha);

    /* Bind to public parameters */
    BIT_COMMITMENT_hash_params(&sha, key, mod);

    /* Bind to proof input */
    HASH_UTILS_hash_oct(&sha, CT);

    /* Bind to proof commitment */
    BIT_COMMITMENT_hash_commitment(&sha, (BIT_COMMITMENT_commitment*)c);

    /* Bind to ID and optional AD */
    HASH_UTILS_hash_i2osp4(&sha, ID->len);
    HASH_UTILS_hash_oct(&sha, ID);

    if (AD != NULL)
    {
        HASH_UTILS_hash_i2osp4(&sha, AD->len);
        HASH_UTILS_hash_oct(&sha, AD);
    }

    /* Output */
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    HASH_UTILS_rejection_sample_mod_BIG(&sha, q, t);

    BIG_256_56_toBytes(E->val, t);
    E->len = EGS_SECP256K1;
}

void MTA_RP_prove(PAILLIER_private_key *key, octet *M, octet *R, MTA_RP_rv *rv, octet *E, MTA_RP_proof *p)
{
    BIT_COMMITMENT_prove(key, M, R, (BIT_COMMITMENT_rv*)rv, E, (BIT_COMMITMENT_proof*)p);
}

int MTA_RP_verify(PAILLIER_public_key *key, BIT_COMMITMENT_priv *mod, octet *CT, MTA_RP_commitment *c, octet *E, MTA_RP_proof *p)
{
    return BIT_COMMITMENT_verify(key, mod, CT, (BIT_COMMITMENT_commitment*)c, E, (BIT_COMMITMENT_proof*) p);
}

void MTA_RP_commitment_toOctets(octet *Z, octet *U, octet *W, MTA_RP_commitment *c)
{
    BIT_COMMITMENT_commitment_toOctets(Z, U, W, (BIT_COMMITMENT_commitment*)c);
}

void MTA_RP_commitment_fromOctets(MTA_RP_commitment *c, octet *Z, octet *U, octet *W)
{
    BIT_COMMITMENT_commitment_fromOctets((BIT_COMMITMENT_commitment*)c, Z, U, W);
}

void MTA_RP_proof_toOctets(octet *S, octet *S1, octet *S2, MTA_RP_proof *p)
{
    BIT_COMMITMENT_proof_toOctets(S, S1, S2, (BIT_COMMITMENT_proof*)p);
}

void MTA_RP_proof_fromOctets(MTA_RP_proof *p, octet *S, octet *S1, octet *S2)
{
    BIT_COMMITMENT_proof_fromOctets((BIT_COMMITMENT_proof*)p, S, S1, S2);
}

void MTA_RP_rv_kill(MTA_RP_rv *rv)
{
    BIT_COMMITMENT_rv_kill((BIT_COMMITMENT_rv*)rv);
}


/* MTA Receiver Proof */

void MTA_ZK_commit(csprng *RNG, PAILLIER_public_key *key, BIT_COMMITMENT_pub *mod,  octet *X, octet *Y, octet *C1, MTA_ZK_rv *rv, MTA_ZK_commitment *c)
{
    BIT_COMMITMENT_muladd_commit(RNG, key, mod, X, Y, C1, (BIT_COMMITMENT_muladd_rv*)rv, (BIT_COMMITMENT_muladd_commitment*)c);
}

void MTA_ZK_challenge(PAILLIER_public_key *key, BIT_COMMITMENT_pub *mod, const octet *C1, const octet *C2, MTA_ZK_commitment *c, const octet *ID, const octet *AD, octet *E)
{
    hash256 sha;

    BIG_256_56 q;
    BIG_256_56 t;

    HASH256_init(&sha);

    /* Bind to public parameters */
    BIT_COMMITMENT_hash_params(&sha, key, mod);

    /* Bind to proof input */
    HASH_UTILS_hash_oct(&sha, C1);
    HASH_UTILS_hash_oct(&sha, C2);

    /* Bind to proof commitment */
    BIT_COMMITMENT_hash_muladd_commitment(&sha, c);

    /* Bind to ID and optional AD */
    HASH_UTILS_hash_i2osp4(&sha, ID->len);
    HASH_UTILS_hash_oct(&sha, ID);

    if (AD != NULL)
    {
        HASH_UTILS_hash_i2osp4(&sha, AD->len);
        HASH_UTILS_hash_oct(&sha, AD);
    }

    /* Output */
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    HASH_UTILS_rejection_sample_mod_BIG(&sha, q, t);

    BIG_256_56_toBytes(E->val, t);
    E->len = EGS_SECP256K1;
}

void MTA_ZK_prove(PAILLIER_public_key *key, octet *X, octet *Y, octet *R, MTA_ZK_rv *rv, octet *E, MTA_ZK_proof *p)
{
    BIT_COMMITMENT_muladd_prove(key, X, Y, R, (BIT_COMMITMENT_muladd_rv*)rv, E, (BIT_COMMITMENT_muladd_proof*)p);
}

int MTA_ZK_verify(PAILLIER_private_key *key, BIT_COMMITMENT_priv *mod, octet *C1, octet *C2, MTA_ZK_commitment *c, octet *E, MTA_ZK_proof *p)
{
    return BIT_COMMITMENT_muladd_verify(key, mod, C1, C2, (BIT_COMMITMENT_muladd_commitment *)c, E, (BIT_COMMITMENT_muladd_proof*)p);
}

void MTA_ZK_commitment_toOctets(octet *Z, octet *Z1, octet *T, octet *V, octet *W, MTA_ZK_commitment *c)
{
    BIT_COMMITMENT_muladd_commitment_toOctets(Z, Z1, T, V, W, c);
}

void MTA_ZK_commitment_fromOctets(MTA_ZK_commitment *c, octet *Z, octet *Z1, octet *T, octet *V, octet *W)
{
    BIT_COMMITMENT_muladd_commitment_fromOctets(c, Z, Z1, T, V, W);
}

void MTA_ZK_proof_toOctets(octet *S, octet *S1, octet *S2, octet *T1, octet *T2, MTA_ZK_proof *p)
{
    BIT_COMMITMENT_muladd_proof_toOctets(S, S1, S2, T1, T2, p);
}

void MTA_ZK_proof_fromOctets(MTA_ZK_proof *p, octet *S, octet *S1, octet *S2, octet *T1, octet *T2)
{
    BIT_COMMITMENT_muladd_proof_fromOctets(p, S, S1, S2, T1, T2);
}

void MTA_ZK_rv_kill(MTA_ZK_rv *rv)
{
    BIT_COMMITMENT_muladd_rv_kill(rv);
}

/* MTA Receiver Proof with check for known DLOG */

void MTA_ZKWC_commit(csprng *RNG, PAILLIER_public_key *key, BIT_COMMITMENT_pub *mod, octet *X, octet *Y, octet *C1, MTA_ZKWC_rv *rv, MTA_ZKWC_commitment *c)
{
    /* Compute base commitment for the range and knowledge ZKP */
    BIT_COMMITMENT_muladd_commit(RNG, key, mod, X, Y, C1, (BIT_COMMITMENT_muladd_rv*)rv, &(c->mc));

    /* Compute commitment for DLOG knowledge ZKP */
    ECP_SECP256K1_generator(&(c->U));
    BIT_COMMITMENT_ECP_commit(&(c->U), rv->alpha);
}

void MTA_ZKWC_challenge(PAILLIER_public_key *key, BIT_COMMITMENT_pub *mod, const octet *C1, const octet *C2, const octet *X, MTA_ZKWC_commitment *c, const octet *ID, const octet *AD, octet *E)
{
    hash256 sha;

    char oct[EFS_SECP256K1 + 1];
    octet OCT = {0, sizeof(oct), oct};

    ECP_SECP256K1 G;

    BIG_256_56 q;
    BIG_256_56 t;

    HASH256_init(&sha);

    /* Bind to public parameters */
    BIT_COMMITMENT_hash_params(&sha, key, mod);

    // Bind to Curve generator
    ECP_SECP256K1_generator(&G);
    ECP_SECP256K1_toOctet(&OCT, &G, true);
    HASH_UTILS_hash_oct(&sha, &OCT);

    /* Bind to proof input */
    HASH_UTILS_hash_oct(&sha, C1);
    HASH_UTILS_hash_oct(&sha, C2);
    HASH_UTILS_hash_oct(&sha, X);

    /* Bind to proof commitment for DLOG */
    ECP_SECP256K1_toOctet(&OCT, &(c->U), true);
    HASH_UTILS_hash_oct(&sha, &OCT);

    /* Bind to proof commitment for muladd ZKP */
    BIT_COMMITMENT_hash_muladd_commitment(&sha, &(c->mc));

    /* Bind to ID and optional AD */
    HASH_UTILS_hash_i2osp4(&sha, ID->len);
    HASH_UTILS_hash_oct(&sha, ID);

    if (AD != NULL)
    {
        HASH_UTILS_hash_i2osp4(&sha, AD->len);
        HASH_UTILS_hash_oct(&sha, AD);
    }

    /* Output */
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    HASH_UTILS_rejection_sample_mod_BIG(&sha, q, t);

    BIG_256_56_toBytes(E->val, t);
    E->len = EGS_SECP256K1;
}

void MTA_ZKWC_prove(PAILLIER_public_key *key, octet *X, octet *Y, octet *R, MTA_ZKWC_rv *rv, octet *E, MTA_ZKWC_proof *p)
{
    BIT_COMMITMENT_muladd_prove(key, X, Y, R, (BIT_COMMITMENT_muladd_rv*)rv, E, (BIT_COMMITMENT_muladd_proof*)p);
}

int MTA_ZKWC_verify(PAILLIER_private_key *key, BIT_COMMITMENT_priv *mod, octet *C1, octet *C2, octet *X, MTA_ZKWC_commitment *c, octet *E, MTA_ZKWC_proof *p)
{
    int rc;

    ECP_SECP256K1 x;
    ECP_SECP256K1 g;

    ECP_SECP256K1_generator(&g);

    // Terminate early in case of invalid input
    rc = ECP_SECP256K1_fromOctet(&x, X);
    if (rc != 1)
    {
        return MTA_INVALID_ECP;
    }

    /* Verify additional DLOG proof */
    rc = BIT_COMMITMENT_ECP_verify(&g, &x, &(c->U), E, p->s1);
    if (rc != BIT_COMMITMENT_OK)
    {
        return rc;
    }

    /* Verify muladd proof*/
    return BIT_COMMITMENT_muladd_verify(key, mod, C1, C2, &(c->mc), E, p);
}

void MTA_ZKWC_commitment_toOctets(octet *U, octet *Z, octet *Z1, octet *T, octet *V, octet *W, MTA_ZKWC_commitment *c)
{
    BIT_COMMITMENT_muladd_commitment_toOctets(Z, Z1, T, V, W, &(c->mc));
    ECP_SECP256K1_toOctet(U, &(c->U), true);
}

int MTA_ZKWC_commitment_fromOctets(MTA_ZKWC_commitment *c, octet *U, octet *Z, octet *Z1, octet *T, octet *V, octet *W)
{
    if (ECP_SECP256K1_fromOctet(&(c->U), U) != 1)
    {
        return MTA_INVALID_ECP;
    }

    BIT_COMMITMENT_muladd_commitment_fromOctets(&(c->mc), Z, Z1, T, V, W);

    return MTA_OK;
}

void MTA_ZKWC_proof_toOctets(octet *S, octet *S1, octet *S2, octet *T1, octet *T2, MTA_ZKWC_proof *p)
{
    BIT_COMMITMENT_muladd_proof_toOctets(S, S1, S2, T1, T2, p);
}

void MTA_ZKWC_proof_fromOctets(MTA_ZKWC_proof *p, octet *S, octet *S1, octet *S2, octet *T1, octet *T2)
{
    BIT_COMMITMENT_muladd_proof_fromOctets(p, S, S1, S2, T1, T2);
}

void MTA_ZKWC_rv_kill(MTA_ZKWC_rv *rv)
{
    BIT_COMMITMENT_muladd_rv_kill(rv);
}
