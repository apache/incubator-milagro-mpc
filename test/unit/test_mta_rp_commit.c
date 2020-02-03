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

/* MTA Range Proof commitment unit tests */

#define LINE_LEN 2048

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_mta_rp_commit [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    MTA_RP_commitment co;
    MTA_RP_commitment co_golden;
    const char *Zline = "Z = ";
    const char *Uline = "U = ";
    const char *Wline = "W = ";

    MTA_RP_commitment_rv rv;
    const char *ALPHAline = "ALPHA = ";
    const char *BETAline  = "BETA = ";
    const char *GAMMAline = "GAMMA = ";
    const char *RHOline   = "RHO = ";

    COMMITMENTS_BC_pub_modulus mod;
    const char *NTline = "NT = ";
    const char *H1line = "H1 = ";
    const char *H2line = "H2 = ";

    char m[MODBYTES_256_56];
    octet M = {0, sizeof(m), m};
    const char *Mline = "M = ";


    char p[HFS_2048];
    octet P = {0, sizeof(p), p};
    const char *Pline = "P = ";

    char q[HFS_2048];
    octet Q = {0, sizeof(q), q};
    const char *Qline = "Q = ";

    PAILLIER_private_key priv;
    PAILLIER_public_key pub;


    // Line terminating a test vector
    const char *last_line = Wline;

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
        scan_OCTET(fp, &P, line, Pline);
        scan_OCTET(fp, &Q, line, Qline);

        scan_FF_2048(fp, mod.b0, line, H1line, FFLEN_2048);
        scan_FF_2048(fp, mod.b1, line, H2line, FFLEN_2048);
        scan_FF_2048(fp, mod.N, line, NTline, FFLEN_2048);

        scan_FF_2048(fp, rv.alpha, line, ALPHAline, HFLEN_2048);
        scan_FF_2048(fp, rv.beta,  line, BETAline,  FFLEN_2048);
        scan_FF_2048(fp, rv.gamma, line, GAMMAline, FFLEN_2048 + HFLEN_2048);
        scan_FF_2048(fp, rv.rho,   line, RHOline,   FFLEN_2048 + HFLEN_2048);

        // Read ground truth
        scan_FF_2048(fp, co_golden.z, line, Zline, FFLEN_2048);
        scan_FF_4096(fp, co_golden.u, line, Uline, FFLEN_4096);
        scan_FF_2048(fp, co_golden.w, line, Wline, FFLEN_2048);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            PAILLIER_KEY_PAIR(NULL, &P, &Q, &pub, &priv);

            MTA_RP_commit(NULL, &priv, &mod, &M, &co, &rv);

            compare_FF_2048(fp, testNo, "MTA_RP_commit co.z", co.z, co_golden.z, FFLEN_2048);
            compare_FF_4096(fp, testNo, "MTA_RP_commit co.u", co.u, co_golden.u, FFLEN_4096);
            compare_FF_2048(fp, testNo, "MTA_RP_commit co.w", co.w, co_golden.w, FFLEN_2048);

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
