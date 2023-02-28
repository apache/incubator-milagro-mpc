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
#include "amcl/bit_commitment.h"

/* Bit Commitment DLOG commit unit test */

#define LINE_LEN 512

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_bit_commitment_ecp_commit [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int rc;
    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    ECP_SECP256K1 R;
    const char *Rline = "R = ";

    ECP_SECP256K1 X;
    const char *Xline = "X = ";

    ECP_SECP256K1 U;
    const char *Uline = "U = ";

    char e[EGS_SECP256K1];
    octet E = {0, sizeof(e), e};
    const char *Eline = "E = ";

    BIG_1024_58 s1[HFLEN_2048];
    const char *S1line = "S1 = ";

    // Line terminating a test vector
    const char *last_line = S1line;

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

        scan_ECP_SECP256K1(fp, &R, line, Rline);
        scan_ECP_SECP256K1(fp, &X, line, Xline);
        scan_ECP_SECP256K1(fp, &U, line, Uline);

        scan_OCTET(fp, &E, line, Eline);

        scan_FF_2048(fp, s1, line, S1line, HFLEN_2048);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            rc = BIT_COMMITMENT_ECP_verify(&R, &X, &U, &E, s1);
            assert_tv(fp, testNo, "BIT_COMMITMENT_ECP_verify", rc == BIT_COMMITMENT_OK);

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
    rc = BIT_COMMITMENT_ECP_verify(&R, &X, &U, &E, s1);
    assert(NULL, "BIT_COMMITMENT_ECP_verify. Invalid U\n", rc == BIT_COMMITMENT_FAIL);

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
