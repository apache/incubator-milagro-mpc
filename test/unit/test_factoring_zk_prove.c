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

/* ZKP of factoring prove unit test */

#include <string.h>
#include "test.h"
#include "amcl/factoring_zk.h"

#define LINE_LEN 2000
#define IDLEN 16
#define ADLEN 16

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_factoring_zk_prove [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    char r[FS_2048];
    octet R = {0, sizeof(r), r};
    const char *Rline = "R = ";

    char egolden[FACTORING_ZK_B];
    octet EGOLDEN = {0, sizeof(egolden), egolden};
    const char *Eline = "E = ";

    char ygolden[FS_2048];
    octet YGOLDEN = {0, sizeof(ygolden), ygolden};
    const char *Yline = "Y = ";

    char p[HFS_2048];
    octet P = {0, sizeof(p), p};
    const char *Pline = "P = ";

    char q[HFS_2048];
    octet Q = {0, sizeof(q), q};
    const char *Qline = "Q = ";

    char n[FS_2048];
    octet N = {0, sizeof(n), n};
    const char *Nline = "N = ";

    char id[IDLEN];
    octet ID = {0, sizeof(id), id};
    const char *IDline = "ID = ";

    char ad[ADLEN];
    octet AD = {0, sizeof(ad), ad};
    octet *AD_ptr = NULL;
    const char *ADline = "AD = ";

    char e[FACTORING_ZK_B];
    octet E = {0, sizeof(e), e};

    char y[FS_2048];
    octet Y = {0, sizeof(y), y};

    // Line terminating a test vector
    const char *last_line = Yline;

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

        // Read modulus
        scan_OCTET(fp, &P, line, Pline);
        scan_OCTET(fp, &Q, line, Qline);
        scan_OCTET(fp, &N, line, Nline);

        // Read non-random R
        scan_OCTET(fp, &R, line, Rline);

        // Read ground truth
        scan_OCTET(fp, &EGOLDEN, line, Eline);
        scan_OCTET(fp, &YGOLDEN, line, Yline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            // Also input AD if it is not empty
            if (AD.len > 0)
            {
                AD_ptr = &AD;
            }

            FACTORING_ZK_prove(NULL, &P, &Q, &ID, AD_ptr, &R, &E, &Y);

            compare_OCT(fp, testNo, "FACTORING_ZK_prove E", &E, &EGOLDEN);
            compare_OCT(fp, testNo, "FACTORING_ZK_prove Y", &Y, &YGOLDEN);

            // Mark that at least one test vector was executed
            test_run = 1;

            // Restore AD_ptr
            AD_ptr = NULL;
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
