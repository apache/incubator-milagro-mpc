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
#include "amcl/hidden_dlog.h"

#define IDLEN 16
#define ADLEN 16
#define LINE_LEN 65555

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_hidden_dlog_commit [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    BIG_1024_58 N[FFLEN_2048];
    const char *Nline = "N = ";

    BIG_1024_58 B0[FFLEN_2048];
    const char *B0line = "B0 = ";

    BIG_1024_58 B1[FFLEN_2048];
    const char *B1line = "B1 = ";

    HDLOG_iter_values RHO;
    const char *RHOline = "RHO = ";

    char id[IDLEN];
    octet ID = {0, sizeof(id), id};
    const char *IDline = "ID = ";

    char ad[ADLEN];
    octet AD = {0, sizeof(ad), ad};
    octet *AD_ptr = NULL;
    const char *ADline = "AD = ";

    char e[HDLOG_CHALLENGE_SIZE];
    char e_golden[HDLOG_CHALLENGE_SIZE];
    octet E = {0, sizeof(e), e};
    octet E_GOLDEN = {0, sizeof(e_golden), e_golden};
    const char *Eline = "E = ";

    // Line terminating a test vector
    const char *last_line = Eline;

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    /* Test happy path using test vectors */

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        scan_int(&testNo, line, TESTline);

        scan_FF_2048(fp, N,  line, Nline,  FFLEN_2048);
        scan_FF_2048(fp, B0, line, B0line, FFLEN_2048);
        scan_FF_2048(fp, B1, line, B1line, FFLEN_2048);

        scan_HDLOG_iv(fp, RHO, line, RHOline);

        scan_OCTET(fp, &ID, line, IDline);
        scan_OCTET(fp, &AD, line, ADline);

        scan_OCTET(fp, &E_GOLDEN, line, Eline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            if (AD.len > 0)
            {
                AD_ptr = &AD;
            }

            HDLOG_challenge(N, B0, B1, RHO, &ID, AD_ptr, &E);

            compare_OCT(fp, testNo, "HDLOG_challenge E", &E, &E_GOLDEN);

            // Mark that at least one test vector was executed
            test_run = 1;

            AD_ptr = NULL;
        }
    }

    fclose(fp);

    if (test_run == 0)
    {
        printf("ERROR no test vector was executed\n");
        exit(EXIT_FAILURE);
    }

    /* Test unhappy path */


    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
