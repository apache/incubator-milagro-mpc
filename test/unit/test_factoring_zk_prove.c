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

    FACTORING_ZK_modulus m;
    const char *Nline = "N = ";
    const char *Pline = "P = ";
    const char *Qline = "Q = ";

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

        // Read modulus
        scan_FF_2048(fp, m.p, line, Pline, HFLEN_2048);
        scan_FF_2048(fp, m.q, line, Qline, HFLEN_2048);
        scan_FF_2048(fp, m.n, line, Nline, FFLEN_2048);

        // Read non-random R
        scan_OCTET(fp, &R, line, Rline);

        // Read ground truth
        scan_OCTET(fp, &EGOLDEN, line, Eline);
        scan_OCTET(fp, &YGOLDEN, line, Yline);

        // Read Y and run test
        if (!strncmp(line, last_line, strlen(last_line)))
        {
            FACTORING_ZK_prove(&m, NULL, &R, &E, &Y);

            compare_OCT(fp, testNo, "FACTORING_ZK_prove E", &E, &EGOLDEN);
            compare_OCT(fp, testNo, "FACTORING_ZK_prove Y", &Y, &YGOLDEN);

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
