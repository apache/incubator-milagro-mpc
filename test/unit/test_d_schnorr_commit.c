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
#include "amcl/schnorr.h"

/* Double Schnorr's Proof commitment unit test */

#define LINE_LEN 256

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_schnorr_d_commit [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int rc;
    int test_run = 0;

    char err_msg[128];

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    char a[SGS_SECP256K1];
    octet A = {0, sizeof(a), a};
    const char *Aline = "A = ";

    char b[SGS_SECP256K1];
    octet B = {0, sizeof(b), b};
    const char *Bline = "B = ";

    char r[SFS_SECP256K1+1];
    octet R = {0, sizeof(r), r};
    const char *Rline = "R = ";

    char c_golden[SFS_SECP256K1+1];
    octet C_GOLDEN = {0, sizeof(c_golden), c_golden};
    const char *Cline = "C = ";

    char c[SFS_SECP256K1+1];
    octet C = {0, sizeof(c), c};

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

        // Read input
        scan_OCTET(fp, &R, line, Rline);
        scan_OCTET(fp, &A, line, Aline);
        scan_OCTET(fp, &B, line, Bline);

        // Read ground truth
        scan_OCTET(fp, &C_GOLDEN, line, Cline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            rc = SCHNORR_D_commit(NULL, &R, &A, &B, &C);
            sprintf(err_msg, "FAILURE SCHNORR_D_commit. rc %d", rc);
            assert_tv(fp, testNo, err_msg, rc == SCHNORR_OK);

            compare_OCT(fp, testNo, "SCHNORR_D_commit", &C, &C_GOLDEN);

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

    // Test invalid R
    rc = SCHNORR_D_commit(NULL, &A, &A, &B, &C);
    sprintf(err_msg, "FAILURE SCHNORR_D_commit invalid R. rc %d", rc);
    assert_tv(fp, testNo, err_msg, rc == SCHNORR_INVALID_ECP);

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
