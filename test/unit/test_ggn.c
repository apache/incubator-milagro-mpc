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
#include "amcl/ggn.h"

/* GGN Proof unit tests */

#define LINE_LEN 2048
#define IDLEN 16
#define ADLEN 16

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_GGN [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    GGN_commitment co;
    const char *Zline = "Z = ";
    const char *U1line = "U1 = ";
    const char *U2line = "U2 = ";
    const char *U3line = "U3 = ";

    BIT_COMMITMENT_pub mod;
    const char *NTline = "NT = ";
    const char *H1line = "H1 = ";
    const char *H2line = "H2 = ";

    PAILLIER_public_key pub;
    const char *Nline = "N = ";

    char c[2*FS_2048];
    octet C = {0, sizeof(c), c};
    const char *Cline = "C = ";

    char ecpr[EGS_SECP256K1 + 1];
    octet ECPR = {0, sizeof(ecpr), ecpr};
    const char *ECPRline = "ECPR = ";

    char ecprt[EGS_SECP256K1 + 1];
    octet ECPRt = {0, sizeof(ecprt), ecprt};
    const char *ECPRtline = "ECPRT = ";

    char e_golden[MODBYTES_512_60];
    octet E_GOLDEN = {0, sizeof(e_golden), e_golden};
    const char *Eline = "E = ";

    char e[MODBYTES_512_60];
    octet E = {0, sizeof(e), e};

    char id[IDLEN];
    octet ID = {0, sizeof(id), id};
    const char *IDline = "ID = ";

    char ad[ADLEN];
    octet AD = {0, sizeof(ad), ad};
    octet *AD_ptr = NULL;
    const char *ADline = "AD = ";

    // Line terminating a test vector
    const char *last_line = Eline;

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

        // Read ID and AD
        scan_OCTET(fp, &ID, line, IDline);
        scan_OCTET(fp, &AD, line, ADline);

        // Read inputs
        scan_OCTET(fp, &C, line, Cline);
        scan_OCTET(fp, &ECPR,  line, ECPRline);
        scan_OCTET(fp, &ECPRt,  line, ECPRtline);

        scan_FF_2048(fp, mod.b0, line, H1line, FFLEN_2048);
        scan_FF_2048(fp, mod.b1, line, H2line, FFLEN_2048);
        scan_FF_2048(fp, mod.N, line, NTline, FFLEN_2048);

        scan_FF_2048(fp, co.c.z, line, Zline, FFLEN_2048);
        scan_FF_4096(fp, co.c.u, line, U2line, FFLEN_4096);
        scan_FF_2048(fp, co.c.w, line, U3line, FFLEN_2048);

        scan_ECP_SECP256K1(fp, &(co.u1), line, U1line);

        scan_FF_4096(fp, pub.n, line, Nline, HFLEN_4096);

        // Read ground truth
        scan_OCTET(fp, &E_GOLDEN, line, Eline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            // Also input AD if it is not empty
            AD_ptr = NULL;
            if (AD.len > 0)
            {
                AD_ptr = &AD;
            }

            GGN_challenge(&pub, &mod, &ECPR, &ECPRt, &C, &co, &ID, AD_ptr, &E);

            compare_OCT(fp, testNo, "GGN_challenge. E", &E, &E_GOLDEN);

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
