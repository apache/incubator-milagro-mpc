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

#include "amcl/nm_commitment.h"

/* NM Commitment Definitions */

// Compute the hash of X || R
static void hash(const octet *X, const octet *R, octet *C)
{
    int i;
    hash256 sha256;

    HASH256_init(&sha256);

    // Process X
    for (i = 0; i < X->len; i++)
    {
        HASH256_process(&sha256, X->val[i]);
    }

    // Process R
    for (i = 0; i < R->len; i++)
    {
        HASH256_process(&sha256, R->val[i]);
    }

    // Output the digest in C
    HASH256_hash(&sha256, C->val);
    C->len = SHA256;
}

// Compute a commitment for the value X
void NM_COMMITMENT_commit(csprng *RNG, const octet *X, octet *R, octet *C)
{
    if (RNG != NULL)
    {
        OCT_rand(R, RNG, SHA256);
    }

    hash(X, R, C);
}

// Verify the commitment for the value X
int NM_COMMITMENT_decommit(const octet *X, const octet *R, octet *C)
{
    char d[SHA256];
    octet D = {0, sizeof(d), d};

    // Validate the length of R. This step MUST be performed
    // to make the scheme non malleable
    if (R->len != SHA256)
    {
        return NM_COMMITMENT_FAIL;
    }

    // Verify the commitment
    hash(X, R, &D);

    if (!OCT_comp(C, &D))
    {
        return NM_COMMITMENT_FAIL;
    }

    return NM_COMMITMENT_OK;
}
