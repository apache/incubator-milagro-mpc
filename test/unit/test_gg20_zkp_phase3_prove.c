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

/* GG20 Phase 3 ZKP prove unit test */

#include <string.h>
#include "test.h"
#include "amcl/gg20_zkp.h"

#define LINE_LEN 1024

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_gg20_zkp_phase3_prove [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    GG20_ZKP_rv r;
    const char *Aline = "A = ";
    const char *Bline = "B = ";

    char e[GGS_SECP256K1];
    octet E = {0, sizeof(e), e};
    const char *Eline = "E = ";

    char s[GGS_SECP256K1];
    octet S = {0, sizeof(s), s};
    const char *Sline = "S = ";

    char l[GGS_SECP256K1];
    octet L = {0, sizeof(l), l};
    const char *Lline = "L = ";

    GG20_ZKP_proof p;
    GG20_ZKP_proof p_golden;
    const char *Tline = "T = ";
    const char *Uline = "U = ";

    // Line terminating a test vector
    const char *last_line = Uline;

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        scan_int(&testNo, line, TESTline);

        scan_BIG_256_56(fp, r.a, line, Aline);
        scan_BIG_256_56(fp, r.b, line, Bline);

        scan_OCTET(fp, &E, line, Eline);

        scan_OCTET(fp, &S, line, Sline);
        scan_OCTET(fp, &L, line, Lline);

        scan_BIG_256_56(fp, p_golden.t, line, Tline);
        scan_BIG_256_56(fp, p_golden.u, line, Uline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            GG20_ZKP_phase3_prove(&r, &E, &S, &L, &p);

            compare_BIG_256_56(fp, testNo, "GG20_ZKP_phase3_prove t", p_golden.t, p.t);
            compare_BIG_256_56(fp, testNo, "GG20_ZKP_phase3_prove u", p_golden.u, p.u);

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
