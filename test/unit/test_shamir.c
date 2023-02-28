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
#include "amcl/shamir.h"

/*
 * Test Shamir Secret Sharing interoperability
 */

#define LINE_LEN      1024
#define OCT_ARRAY_LEN 16

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_shamir [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int i;
    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    const char *Kline = "K = ";
    int k;

    const char *Nline = "N = ";
    int n;

    const char *Xline = "X = ";
    char x[OCT_ARRAY_LEN][SGS_SECP256K1];
    octet X[OCT_ARRAY_LEN];

    const char *Yline = "Y = ";
    char y[OCT_ARRAY_LEN][SGS_SECP256K1];
    octet Y[OCT_ARRAY_LEN];

    SSS_shares shares = {X, Y};

    const char *Sline = "SECRET = ";
    char s_golden[SGS_SECP256K1];
    char s[SGS_SECP256K1];
    octet S_GOLDEN = {0, sizeof(s_golden), s_golden};
    octet S = {0, sizeof(s), s};

    for (i = 0; i < OCT_ARRAY_LEN; i++)
    {
        X[i].val = x[i];
        X[i].len = 0;
        X[i].max = sizeof(x[i]);

        Y[i].val = y[i];
        Y[i].len = 0;
        Y[i].max = sizeof(y[i]);
    }

    // Line terminating a test vector
    const char *last_line = Yline;

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    /* Test happy path with test vectors */
    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        scan_int(&testNo, line, TESTline);

        scan_int(&k, line, Kline);
        scan_int(&n, line, Nline);

        scan_OCTET_ARRAY(fp, X, line, Xline, n);
        scan_OCTET_ARRAY(fp, Y, line, Yline, n);

        scan_OCTET(fp, &S_GOLDEN, line, Sline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            for (i = 0; i < n-k; i++)
            {
                SSS_recover_secret(k, &shares, &S);

                compare_OCT(fp, testNo, "SSS_recover_secret", &S, &S_GOLDEN);

                shares.X++;
                shares.Y++;
            }

            // Restore shares pointers
            shares.X = X;
            shares.Y = Y;

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
