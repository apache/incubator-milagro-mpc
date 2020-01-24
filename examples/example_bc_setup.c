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
#include "amcl/commitments.h"

char *Phex = "CA5F37B7C0DDF6530B30A41116588218DE95F1F36B807FD7C28E4C467EE3F35967BC01D28B71F8A627A353675A81C86A1FF03DCECAF1686891183FA317BA34A4A1148D40A89F1F3AC0C200511C6CFE02342CD75354C25A2E069886DD4FB73BD365660D163F1282B143119AB8F375A73875EC16B634F52593B73BC6D875F2D3EF";
char *Qhex = "C2FC545C1C803F6C7625FBC4ECF9355734D6B6058FD714816D3ECFB93F1F705C9CE90D4F8796A05148AB5ABC201F90889231CC6BF5F68ED15EE4D901F603930A280EEABF10C613BFCB67A816363C839EB902B02607EB48AB8325E2B72620D4D294A232803217090DFB50AF8C620D4679E77CE3053437ED518F4F68840DCF1AA3";

int main()
{
    char p[HFS_2048];
    octet P = {0, sizeof(p), p};

    char q[HFS_2048];
    octet Q = {0, sizeof(q), q};

    COMMITMENTS_BC_priv_modulus m;

    // Load values
    OCT_fromHex(&P, Phex);
    OCT_fromHex(&Q, Qhex);

    // Deterministic RNG for testing
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    printf("Setup modulus for the Bit Commitment\n");

    // Using externally generated primes
    // Set P and Q to null to randomly generate the primes
    COMMITMENTS_BC_setup(&RNG, &m, &P, &Q, NULL, NULL);

    printf("\n\tP      = ");
    FF_2048_output(m.P, HFLEN_2048);
    printf("\n\tQ      = ");
    FF_2048_output(m.Q, HFLEN_2048);
    printf("\n\tN      = ");
    FF_2048_output(m.N, FFLEN_2048);
    printf("\n\tpq     = ");
    FF_2048_output(m.pq, FFLEN_2048);
    printf("\n\tALPHA  = ");
    FF_2048_output(m.alpha, FFLEN_2048);
    printf("\n\tIALPHA = ");
    FF_2048_output(m.ialpha, FFLEN_2048);
    printf("\n\tB0     = ");
    FF_2048_output(m.b0, FFLEN_2048);
    printf("\n\tB1     = ");
    FF_2048_output(m.b1, FFLEN_2048);

    printf("Clear secret values from the modulus");
    COMMITMENTS_BC_kill_priv_modulus(&m);

    printf("\n\tP      = ");
    FF_2048_output(m.P, HFLEN_2048);
    printf("\n\tQ      = ");
    FF_2048_output(m.Q, HFLEN_2048);
    printf("\n\tN      = ");
    FF_2048_output(m.N, FFLEN_2048);
    printf("\n\tpq     = ");
    FF_2048_output(m.pq, FFLEN_2048);
    printf("\n\tALPHA  = ");
    FF_2048_output(m.alpha, FFLEN_2048);
    printf("\n\tIALPHA = ");
    FF_2048_output(m.ialpha, FFLEN_2048);
    printf("\n\tB0     = ");
    FF_2048_output(m.b0, FFLEN_2048);
    printf("\n\tB1     = ");
    FF_2048_output(m.b1, FFLEN_2048);

    // Clean memory
    OCT_clear(&P);
    OCT_clear(&Q);
}
