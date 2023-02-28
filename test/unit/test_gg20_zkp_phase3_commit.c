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

/* GG20 Phase 3 ZKP commit unit test */

#include <string.h>
#include "test.h"
#include "amcl/gg20_zkp.h"

#define LINE_LEN 1024

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_gg20_zkp_phase3_commit [path to test vector file]\n");
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

    char c[GFS_SECP256K1 + 1];
    char c_golden[GFS_SECP256K1 + 1];
    octet C = {0, sizeof(c), c};
    octet C_GOLDEN = {0, sizeof(c_golden), c_golden};
    const char *Cline = "C = ";

    // Line terminating a test vector
    const char *last_line = Cline;

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

        scan_OCTET(fp, &C_GOLDEN, line, Cline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            GG20_ZKP_phase3_commit(NULL, &r, &C);

            compare_OCT(fp, testNo, "GG20_ZKP_phase3_commit", &C, &C_GOLDEN);

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
