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

/* NM commitment smoke test */

#include <stdio.h>
#include "amcl/bit_commitment.h"

char *Phex = "CA5F37B7C0DDF6530B30A41116588218DE95F1F36B807FD7C28E4C467EE3F35967BC01D28B71F8A627A353675A81C86A1FF03DCECAF1686891183FA317BA34A4A1148D40A89F1F3AC0C200511C6CFE02342CD75354C25A2E069886DD4FB73BD365660D163F1282B143119AB8F375A73875EC16B634F52593B73BC6D875F2D3EF";
char *Qhex = "C2FC545C1C803F6C7625FBC4ECF9355734D6B6058FD714816D3ECFB93F1F705C9CE90D4F8796A05148AB5ABC201F90889231CC6BF5F68ED15EE4D901F603930A280EEABF10C613BFCB67A816363C839EB902B02607EB48AB8325E2B72620D4D294A232803217090DFB50AF8C620D4679E77CE3053437ED518F4F68840DCF1AA3";

int main()
{
    int rc;

    char p[HFS_2048];
    octet P = {0, sizeof(p), p};

    char q[HFS_2048];
    octet Q = {0, sizeof(q), q};

    BIT_COMMITMENT_priv priv;

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

    printf("Setup modulus for the Bit Commitment\n");

    // Using externally generated primes
    // Set P and Q to null to randomly generate the primes
    BIT_COMMITMENT_setup(&RNG, &priv, &P, &Q, NULL, NULL);

    printf("\n\tP      = ");
    FF_2048_output(priv.mod.p, HFLEN_2048);
    printf("\n\tQ      = ");
    FF_2048_output(priv.mod.q, HFLEN_2048);
    printf("\n\tN      = ");
    FF_2048_output(priv.mod.n, FFLEN_2048);
    printf("\n\tpq     = ");
    FF_2048_output(priv.pq, FFLEN_2048);
    printf("\n\tALPHA  = ");
    FF_2048_output(priv.alpha, FFLEN_2048);
    printf("\n\tIALPHA = ");
    FF_2048_output(priv.ialpha, FFLEN_2048);
    printf("\n\tB0     = ");
    FF_2048_output(priv.b0, FFLEN_2048);
    printf("\n\tB1     = ");
    FF_2048_output(priv.b1, FFLEN_2048);
    printf("\n");

    // Prove b0, b1, n are of the correct form
    printf("\nProve the generated parameters are well formed\n");

    BIT_COMMITMENT_setup_prove(&RNG, &priv, &proof, &ID, &AD);
    printf("\tProof omitted for briefness\n");

    printf("\nVerify the proof\n");
    BIT_COMMITMENT_priv_to_pub(&pub, &priv);
    rc = BIT_COMMITMENT_setup_verify(&pub, &proof, &ID, &AD);
    if (rc != BIT_COMMITMENT_OK)
    {
        printf("\tFailure! RC %d\n", rc);
    }
    else
    {
        printf("\tSuccess!\n");
    }

    printf("\nClear secret values from the modulus");
    BIT_COMMITMENT_priv_kill(&priv);

    printf("\n\tP      = ");
    FF_2048_output(priv.mod.p, HFLEN_2048);
    printf("\n\tQ      = ");
    FF_2048_output(priv.mod.q, HFLEN_2048);
    printf("\n\tN      = ");
    FF_2048_output(priv.mod.n, FFLEN_2048);
    printf("\n\tpq     = ");
    FF_2048_output(priv.pq, FFLEN_2048);
    printf("\n\tALPHA  = ");
    FF_2048_output(priv.alpha, FFLEN_2048);
    printf("\n\tIALPHA = ");
    FF_2048_output(priv.ialpha, FFLEN_2048);
    printf("\n\tB0     = ");
    FF_2048_output(priv.b0, FFLEN_2048);
    printf("\n\tB1     = ");
    FF_2048_output(priv.b1, FFLEN_2048);
    printf("\n");

    // Clean memory
    OCT_clear(&P);
    OCT_clear(&Q);
}
