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

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    char p[HFS_2048];
    octet P = {0, sizeof(p), p};
    const char *Pline = "P = ";

    char q[HFS_2048];
    octet Q = {0, sizeof(q), q};
    const char *Qline = "Q = ";

    BIG_1024_58 ord[FFLEN_2048];
    const char *ORDline = "ORD = ";

    BIG_1024_58 b0[FFLEN_2048];
    const char *B0line = "B0 = ";

    HDLOG_iter_values R;
    const char *Rline = "R = ";

    HDLOG_iter_values RHO;
    HDLOG_iter_values RHOgolden;
    const char *RHOline = "RHO = ";

    MODULUS_priv m;

    // Line terminating a test vector
    const char *last_line = RHOline;

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

        scan_OCTET(fp, &P, line, Pline);
        scan_OCTET(fp, &Q, line, Qline);

        scan_FF_2048(fp, ord, line, ORDline, FFLEN_2048);
        scan_FF_2048(fp, b0,  line, B0line,  FFLEN_2048);

        scan_HDLOG_iv(fp, R,         line, Rline);
        scan_HDLOG_iv(fp, RHOgolden, line, RHOline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            MODULUS_fromOctets(&m, &P, &Q);
            HDLOG_commit(NULL, &m, ord, b0, R, RHO);

            compare_HDLOG_iv(fp, testNo, "HDLOG_commit RHO", RHO, RHOgolden);

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
