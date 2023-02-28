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

/* GG20 Phase 6 ZKP challenge unit test */

#include <string.h>
#include "test.h"
#include "amcl/gg20_zkp.h"

#define LINE_LEN 1024
#define IDLEN 16
#define ADLEN 16

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_gg20_zkp_phase6_challenge [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    char r[GFS_SECP256K1 + 1];
    octet R = {0, sizeof(r), r};
    const char *Rline = "R = ";

    char t[GFS_SECP256K1 + 1];
    octet T = {0, sizeof(t), t};
    const char *ECPTline = "ECPT = ";

    char s[GFS_SECP256K1 + 1];
    octet S = {0, sizeof(s), s};
    const char *Sline = "ECPS = ";

    GG20_ZKP_phase6_commitment c;
    const char *ALPHAline = "ALPHA = ";
    const char *BETAline = "BETA = ";

    char e[GGS_SECP256K1];
    char e_golden[GGS_SECP256K1];
    octet E = {0, sizeof(e), e};
    octet E_GOLDEN = {0, sizeof(e_golden), e_golden};
    const char *Eline = "E = ";

    char id[IDLEN];
    octet ID = {0, sizeof(id), id};
    const char *IDline = "ID = ";

    char ad[IDLEN];
    octet AD = {0, sizeof(ad), ad};
    octet *AD_ptr = NULL;
    const char *ADline = "AD = ";

    // Line terminating a test vector
    const char *last_line = Eline;

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        scan_int(&testNo, line, TESTline);

        scan_OCTET(fp, &R, line, Rline);
        scan_OCTET(fp, &T, line, ECPTline);
        scan_OCTET(fp, &S, line, Sline);

        scan_ECP_SECP256K1(fp, &(c.ALPHA), line, ALPHAline);
        scan_ECP_SECP256K1(fp, &(c.BETA),  line, BETAline);

        scan_OCTET(fp, &ID, line, IDline);
        scan_OCTET(fp, &AD, line, ADline);

        scan_OCTET(fp, &E_GOLDEN, line, Eline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            // Also input AD if it is not empty
            AD_ptr = NULL;
            if (AD.len > 0)
            {
                AD_ptr = &AD;
            }

            GG20_ZKP_phase6_challenge(&R, &T, &S, &c, &ID, AD_ptr, &E);

            compare_OCT(fp, testNo, "GG20_ZKP_phase6_challenge", &E, &E_GOLDEN);

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

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
