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
 * @file ggn.c
 * @brief High level wrapping for the GGN proof based on the Bit Commitment proofs
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "amcl/hash_utils.h"
#include "amcl/ggn.h"

int GGN_commit(csprng *RNG, PAILLIER_private_key *key, BIT_COMMITMENT_pub *mod, octet *R, octet *M,  GGN_rv *rv, GGN_commitment *c)
{
    // Read base ECp for DLOG commitment
    if (ECP_SECP256K1_fromOctet(&(c->u1), R) != 1)
    {
        return GGN_INVALID_ECP;
    }

    /* Commitment for the base Paillier plaintext proof */
    BIT_COMMITMENT_commit(RNG, key, mod, M, (BIT_COMMITMENT_rv*)rv, (BIT_COMMITMENT_commitment*)c);

    /* Commitment for the additional DLOG proof */
    BIT_COMMITMENT_ECP_commit(&(c->u1), rv->alpha);

    return GGN_OK;
}

void GGN_challenge(PAILLIER_public_key *key, BIT_COMMITMENT_pub *m, const octet *R, const octet *Rt, const octet *CT, GGN_commitment *c, const octet *ID, const octet *AD, octet *E)
{
    hash256 sha;

    char oct[EFS_SECP256K1 + 1];
    octet OCT = {0, sizeof(oct), oct};

    BIG_256_56 q;
    BIG_256_56 t;

    HASH256_init(&sha);

    /* Bind to public parameters */
    BIT_COMMITMENT_hash_params(&sha, key, m);

    /* Bind to proof input */
    HASH_UTILS_hash_oct(&sha, CT);
    HASH_UTILS_hash_oct(&sha, R);
    HASH_UTILS_hash_oct(&sha, Rt);

    /* Bind to proof commitment */
    BIT_COMMITMENT_hash_commitment(&sha, (BIT_COMMITMENT_commitment*)&(c->c));

    ECP_SECP256K1_toOctet(&OCT, &(c->u1), true);
    HASH_UTILS_hash_oct(&sha, &OCT);

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

void GGN_prove(PAILLIER_private_key *key, octet *K, octet *R, GGN_rv *rv, octet *E, GGN_proof *p)
{
    BIT_COMMITMENT_prove(key, K, R, (BIT_COMMITMENT_rv*)rv, E, (BIT_COMMITMENT_proof*)p);
}

int GGN_verify(PAILLIER_public_key *key, BIT_COMMITMENT_priv *m, octet *R, octet *Rt, octet *CT, GGN_commitment *c, octet *E, GGN_proof *p)
{
    int rc;

    ECP_SECP256K1 ECPR;
    ECP_SECP256K1 ECPRT;

    // Terminate early in case of invalid input
    rc = ECP_SECP256K1_fromOctet(&ECPR, R);
    if (rc != 1)
    {
        return GGN_INVALID_ECP;
    }

    rc = ECP_SECP256K1_fromOctet(&ECPRT, Rt);
    if (rc != 1)
    {
        return GGN_INVALID_ECP;
    }

    /* Verify additional DLOG proof */
    rc = BIT_COMMITMENT_ECP_verify(&ECPR, &ECPRT, &(c->u1), E, p->s1);
    if (rc != BIT_COMMITMENT_OK)
    {
        return rc;
    }

    return BIT_COMMITMENT_verify(key, m, CT, (BIT_COMMITMENT_commitment*)c, E, (BIT_COMMITMENT_proof*) p);
}

void GGN_commitment_toOctets(octet *Z, octet *U1, octet *U2, octet *U3, GGN_commitment *c)
{

    BIT_COMMITMENT_commitment_toOctets(Z, U2, U3, (BIT_COMMITMENT_commitment*)c);
    ECP_SECP256K1_toOctet(U1, &(c->u1), true);
}

int GGN_commitment_fromOctets(GGN_commitment *c, octet *Z, octet *U1, octet *U2, octet *U3)
{
    if (ECP_SECP256K1_fromOctet(&(c->u1), U1) != 1)
    {
        return GGN_INVALID_ECP;
    }

    BIT_COMMITMENT_commitment_fromOctets((BIT_COMMITMENT_commitment*)c, Z, U2, U3);

    return GGN_OK;
}

void GGN_proof_toOctets(octet *S1, octet *S2, octet *S3, GGN_proof *p)
{
    BIT_COMMITMENT_proof_toOctets(S1, S2, S3, (BIT_COMMITMENT_proof*)p);
}

void GGN_proof_fromOctets(GGN_proof *p, octet *S1, octet *S2, octet *S3)
{
    BIT_COMMITMENT_proof_fromOctets((BIT_COMMITMENT_proof*)p, S1, S2, S3);
}

void GGN_rv_kill(GGN_rv *rv)
{
    BIT_COMMITMENT_rv_kill((BIT_COMMITMENT_rv*)rv);
}

