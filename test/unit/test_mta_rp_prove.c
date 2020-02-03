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
#include "test.h"
#include "amcl/mta.h"

/* MTA Range Proof proof unit tests */

#define LINE_LEN 2048

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_mta_rp_prove [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    MTA_RP_commitment_rv rv;
    const char *ALPHAline = "ALPHA = ";
    const char *BETAline  = "BETA = ";
    const char *GAMMAline = "GAMMA = ";
    const char *RHOline   = "RHO = ";

    char m[MODBYTES_256_56];
    octet M = {0, sizeof(m), m};
    const char *Mline = "M = ";

    char r[2*FS_2048];
    octet R = {0, sizeof(r), r};
    const char *Rline = "R = ";

    char e[MODBYTES_256_56];
    octet E = {0, sizeof(e), e};
    const char *Eline = "E = ";

    char p[HFS_2048];
    octet P = {0, sizeof(p), p};
    const char *Pline = "P = ";

    char q[HFS_2048];
    octet Q = {0, sizeof(q), q};
    const char *Qline = "Q = ";

    PAILLIER_private_key priv;
    PAILLIER_public_key pub;

    MTA_RP_proof proof;
    MTA_RP_proof proof_golden;
    const char *Sline = "S = ";
    const char *S1line = "S1 = ";
    const char *S2line = "S2 = ";

    // Make sure proof is properly zeroed before starting test
    FF_4096_zero(proof_golden.s,  FFLEN_4096);
    FF_2048_zero(proof_golden.s1, FFLEN_2048);

    // Line terminating a test vector
    const char *last_line = S2line;

    /* Test happy path using test vectors */
    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        scan_int(&testNo, line, TESTline);

        // Read inputs
        scan_OCTET(fp, &M, line, Mline);
        scan_OCTET(fp, &E, line, Eline);
        scan_OCTET(fp, &R, line, Rline);
        scan_OCTET(fp, &P, line, Pline);
        scan_OCTET(fp, &Q, line, Qline);

        scan_FF_2048(fp, rv.alpha, line, ALPHAline, HFLEN_2048);
        scan_FF_2048(fp, rv.beta,  line, BETAline,  FFLEN_2048);
        scan_FF_2048(fp, rv.gamma, line, GAMMAline, FFLEN_2048 + HFLEN_2048);
        scan_FF_2048(fp, rv.rho,   line, RHOline,   FFLEN_2048 + HFLEN_2048);

        // Read ground truth
        scan_FF_4096(fp, proof_golden.s,  line, Sline,  HFLEN_4096);
        scan_FF_2048(fp, proof_golden.s1, line, S1line, HFLEN_2048);
        scan_FF_2048(fp, proof_golden.s2, line, S2line, FFLEN_2048 + HFLEN_2048);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            PAILLIER_KEY_PAIR(NULL, &P, &Q, &pub, &priv);

            MTA_RP_prove(&priv, &rv, &M, &R, &E, &proof);

            compare_FF_4096(fp, testNo, "MTA_RP_proof p.s",  proof.s,  proof_golden.s,  FFLEN_4096);
            compare_FF_2048(fp, testNo, "MTA_RP_proof p.s1", proof.s1, proof_golden.s1, FFLEN_2048);
            compare_FF_2048(fp, testNo, "MTA_RP_proof p.s2", proof.s2, proof_golden.s2, FFLEN_2048 + HFLEN_2048);

            // Mark that at least one test vector was executed
            test_run = 1;
        }
    }

    fclose(fp);

    if (test_run == 0)
    {
        printf("ERROR no test vector was executed\n");
        exit(EXIT_FAILURE);
    }

    printf("SUCCESS");
    exit(EXIT_SUCCESS);
}
