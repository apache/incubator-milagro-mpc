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

/* Bit commitment setup smoke test */

#include <stdio.h>
#include "amcl/bit_commitment_setup.h"

char *Phex = "CA5F37B7C0DDF6530B30A41116588218DE95F1F36B807FD7C28E4C467EE3F35967BC01D28B71F8A627A353675A81C86A1FF03DCECAF1686891183FA317BA34A4A1148D40A89F1F3AC0C200511C6CFE02342CD75354C25A2E069886DD4FB73BD365660D163F1282B143119AB8F375A73875EC16B634F52593B73BC6D875F2D3EF";
char *Qhex = "C2FC545C1C803F6C7625FBC4ECF9355734D6B6058FD714816D3ECFB93F1F705C9CE90D4F8796A05148AB5ABC201F90889231CC6BF5F68ED15EE4D901F603930A280EEABF10C613BFCB67A816363C839EB902B02607EB48AB8325E2B72620D4D294A232803217090DFB50AF8C620D4679E77CE3053437ED518F4F68840DCF1AA3";

void ff_2048_cleaned(BIG_1024_58 *a, char *name, int n)
{
    if(!FF_2048_iszilch(a, n))
    {
        fprintf(stderr, "FAILURE BIT_COMMITMENT_priv_kill. %s was not cleaned\n", name);
        exit(EXIT_FAILURE);
    }
}

int main()
{
    int rc;

    char p[HFS_2048];
    octet P = {0, sizeof(p), p};

    char q[HFS_2048];
    octet Q = {0, sizeof(q), q};

    BIT_COMMITMENT_priv priv;

    BIG_1024_58 e[FFLEN_2048];

    // Material for proof
    BIT_COMMITMENT_pub pub;

    BIT_COMMITMENT_setup_proof proof;

    char id[32];
    octet ID = {0, sizeof(id), id};

    char ad[32];
    octet AD = {0, sizeof(ad), ad};

    // Load values
    OCT_fromHex(&P, Phex);
    OCT_fromHex(&Q, Qhex);

    // Deterministic RNG for testing
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    // Generate ID and AD
    OCT_rand(&ID, &RNG, ID.len);
    OCT_rand(&AD, &RNG, AD.len);

    BIT_COMMITMENT_setup(&RNG, &priv, &P, &Q, NULL, NULL);

    // Check that b0, b1, alpha, ialpha are of the correct form
    FF_2048_nt_pow(e, priv.b0, priv.alpha, priv.mod.n, FFLEN_2048, FFLEN_2048);
    if (FF_2048_comp(e, priv.b1, FFLEN_2048) != 0)
    {
        printf("FAILURE BIT_COMMITMENT_setup. b1 != b0^alpha");
        exit(EXIT_FAILURE);
    }

    FF_2048_nt_pow(e, priv.b1, priv.ialpha, priv.mod.n, FFLEN_2048, FFLEN_2048);
    if (FF_2048_comp(e, priv.b0, FFLEN_2048) != 0)
    {
        printf("FAILURE BIT_COMMITMENT_setup. b0 != b1^ialpha");
        exit(EXIT_FAILURE);
    }

    // Prove b0, b1, n are of the correct form
    BIT_COMMITMENT_setup_prove(&RNG, &priv, &proof, &ID, &AD);
    BIT_COMMITMENT_priv_to_pub(&pub, &priv);
    rc = BIT_COMMITMENT_setup_verify(&pub, &proof, &ID, &AD);

    if (rc != BIT_COMMITMENT_OK)
    {
        printf("FAILURE BIT_COMMITMENT_setup_verify smoke test. error code %d\n", rc);
        exit(EXIT_FAILURE);
    }

    BIT_COMMITMENT_priv_kill(&priv);

    // Check that modulus was correctly killed
    ff_2048_cleaned(priv.mod.p,      "P",      HFLEN_2048);
    ff_2048_cleaned(priv.mod.q,      "Q",      HFLEN_2048);
    ff_2048_cleaned(priv.mod.invpq,  "invPQ",  HFLEN_2048);
    ff_2048_cleaned(priv.pq,         "pq",     FFLEN_2048);
    ff_2048_cleaned(priv.alpha,      "alpha",  FFLEN_2048);
    ff_2048_cleaned(priv.ialpha,     "ialpha", FFLEN_2048);

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
