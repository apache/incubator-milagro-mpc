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
        printf("usage: ./test_factoring_zk_verify [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int rc;
    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    char n[FS_2048];
    octet N = {0, sizeof(n), n};
    const char *Nline = "N = ";

    char e[FACTORING_ZK_B];
    octet E = {0, sizeof(e), e};
    const char *Eline = "E = ";

    char y[FS_2048];
    octet Y = {0, sizeof(y), y};
    const char *Yline = "Y = ";

    // Line terminating a test vector
    const char *last_line = Yline;

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

        scan_OCTET(fp, &N, line, Nline);
        scan_OCTET(fp, &E, line, Eline);
        scan_OCTET(fp, &Y, line, Yline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            rc = FACTORING_ZK_verify(&N, &E, &Y);
            assert_tv(fp, testNo, "FACTORING_ZK_verify", rc);

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
    E.val[0]++;

    rc = !FACTORING_ZK_verify(&N, &E, &Y);
    assert(NULL, "FACTORING_ZK_verify. Invalid E", rc);

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
