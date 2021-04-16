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

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    BIG_1024_58 alpha[HFLEN_2048];
    const char *ALPHAline = "ALPHA = ";

    ECP_SECP256K1 R;
    const char *Rline = "R = ";

    ECP_SECP256K1 U;
    const char *Uline = "U = ";

    // Line terminating a test vector
    const char *last_line = Uline;

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        scan_int(&testNo, line, TESTline);

        scan_FF_2048(fp, alpha, line, ALPHAline, HFLEN_2048);

        scan_ECP_SECP256K1(fp, &R, line, Rline);
        scan_ECP_SECP256K1(fp, &U, line, Uline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            BIT_COMMITMENT_ECP_commit(&R, alpha);
            compare_ECP_SECP256K1(fp, testNo, "BIT_COMMITMENT_ECP_commit", &R, &U);

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
