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
#include "amcl/commitments.h"

/* NM Commitment unit tests */

#define LINE_LEN 256

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_nm_commit [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int rc;
    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    const char *Xline = "X = ";
    char x_golden[LINE_LEN];
    octet X_GOLDEN = {0, sizeof(x_golden), x_golden};

    const char *Rline = "R = ";
    char r_golden[SHA256];
    octet R_GOLDEN = {0, sizeof(r_golden), r_golden};

    char r[SHA256];
    octet R = {0, sizeof(r), r};

    const char *Cline = "C = ";
    char c_golden[SHA256];
    octet C_GOLDEN = {0, sizeof(c_golden), c_golden};

    char c[SHA256];
    octet C = {0, sizeof(c), c};

    // Line terminating a test vector
    const char *last_line = Cline;

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

        // Read ground truth
        scan_OCTET(fp, &X_GOLDEN, line, Xline);
        scan_OCTET(fp, &R_GOLDEN, line, Rline);
        scan_OCTET(fp, &C_GOLDEN, line, Cline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            COMMITMENTS_NM_commit(NULL, &X_GOLDEN, &R_GOLDEN, &C);
            compare_OCT(fp, testNo, "COMMITMENT_NM_commit", &C_GOLDEN, &C);

            rc = COMMITMENTS_NM_decommit(&X_GOLDEN, &R_GOLDEN, &C_GOLDEN);
            assert_tv(fp, testNo, "COMMITMENTS_NM_DECOMMIT", rc);

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

    /* Test COMMITMENTS_NM_decommit unhappy paths */

    // Test invalid length of decommitment
    OCT_copy(&R, &R_GOLDEN);
    R.len--;

    rc = !COMMITMENTS_NM_decommit(&X_GOLDEN, &R, &C_GOLDEN);
    assert(NULL, "COMMITMENTS_NM_decommit. Invalid R length", rc);

    // Test wrong decommitment
    OCT_copy(&R, &R_GOLDEN);
    R.val[0]--;

    rc = !COMMITMENTS_NM_decommit(&X_GOLDEN, &R, &C_GOLDEN);
    assert(NULL, "COMMITMENTS_NM_decommit. Invalid R", rc);

    printf("SUCCESS");
    exit(EXIT_SUCCESS);
}
