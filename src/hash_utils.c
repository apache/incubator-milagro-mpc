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

#include <string.h>
#include "amcl/hash_utils.h"
#include "amcl/ff_2048.h"

/* Hash utilities for pseudo-random challenges generation */

// Chunks necessary for the sampling mod FF.
// Sampling double the necessary chunks to remove bias
#define HASH_UTILS_FF_CHUNKS 2 * FS_2048 / SHA256


// Copy the internal state of an hash function
void HASH_UTILS_hash_copy(hash256 *dst, const hash256 *src)
{
    memcpy(dst->length, src->length, sizeof(dst->length));
    memcpy(dst->h, src->h, sizeof(dst->h));
    memcpy(dst->w, src->w, sizeof(dst->w));
    dst->hlen = src->hlen;
}

// utility function to hash an octet
void HASH_UTILS_hash_oct(hash256 *sha, const octet *O)
{
    int i;

    for (i = 0; i < O->len; i++)
    {
        HASH256_process(sha, O->val[i]);
    }
}

void HASH_UTILS_hash_i2osp4(hash256 *sha, const int i)
{
    HASH256_process(sha, (i >> 24) & 0xFF);
    HASH256_process(sha, (i >> 16) & 0xFF);
    HASH256_process(sha, (i >> 8) & 0xFF);
    HASH256_process(sha, i & 0xFF);
}

// Sample mod n using MGF1 using SHA256 and sampling double the
// amount of necesary random data to make bias negligible
void HASH_UTILS_sample_mod_FF(hash256 *sha, BIG_1024_58 *n, BIG_1024_58 *x)
{
    int i;
    hash256 shai;

    char w[2 * FS_2048];
    octet W = {0, sizeof(w), w};

    BIG_1024_58 dws[2 * FFLEN_2048];

    for (i = 0; i < HASH_UTILS_FF_CHUNKS; i++)
    {
        // Compute partial hash of SEED || I2OSP(i, 4)
        HASH_UTILS_hash_copy(&shai, sha);
        HASH_UTILS_hash_i2osp4(&shai, i);

        // Append the digest to the ouptut octet
        HASH256_hash(&shai, W.val + W.len);
        W.len+=SHA256;
    }

    // Reduce modulo n
    FF_2048_fromOctet(dws, &W, 2 * FFLEN_2048);
    FF_2048_dmod(x, dws, n, FFLEN_2048);
}

void HASH_UTILS_rejection_sample_mod_BIG(hash256 *sha, BIG_256_56 q, BIG_256_56 x)
{
    hash256 shai;

    char digest[SHA256];

    int attempt = 0;

    do
    {
        HASH_UTILS_hash_copy(&shai, sha);
        HASH_UTILS_hash_i2osp4(&shai, attempt);

        HASH256_hash(&shai, digest);
        BIG_256_56_fromBytesLen(x, digest, SHA256);

        attempt++;
    }
    while(BIG_256_56_comp(x, q) >= 0);
}
