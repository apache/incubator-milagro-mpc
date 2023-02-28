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

#define LINE_LEN 65555

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_hidden_dlog_commit [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int rc;
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

    HDLOG_iter_values T;
    const char *Tline = "T = ";

    char e[HDLOG_CHALLENGE_SIZE];
    octet E = {0, sizeof(e), e};
    const char *Eline = "E = ";

    // Line terminating a test vector
    const char *last_line = Tline;

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
        scan_HDLOG_iv(fp, T,   line, Tline);

        scan_OCTET(fp, &E, line, Eline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            rc = HDLOG_verify(N, B0, B1, RHO, &E, T);

            assert_tv(fp, testNo, "HDLOG_verify", rc == HDLOG_OK);

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

    /* Test unhappy path */
    FF_2048_zero(T[1], FFLEN_2048);

    rc = HDLOG_verify(N, B0, B1, RHO, &E, T);

    assert(NULL, "HDLOG_verify. Invalid proof", rc == HDLOG_FAIL);

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
