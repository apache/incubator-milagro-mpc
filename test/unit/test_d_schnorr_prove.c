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

/* Double Schnorr's Proof prove unit test */

#define LINE_LEN 256

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_shcnorr_d_prove [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;

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

    char e[SGS_SECP256K1];
    octet E = {0, sizeof(e), e};
    const char *Eline = "E = ";

    char s[SGS_SECP256K1];
    octet S = {0, sizeof(s), s};
    const char *Sline = "S = ";

    char l[SGS_SECP256K1];
    octet L = {0, sizeof(l), l};
    const char *Lline = "L = ";

    char t_golden[SGS_SECP256K1];
    octet T_GOLDEN = {0, sizeof(t_golden), t_golden};
    const char *Tline = "T = ";

    char u_golden[SGS_SECP256K1];
    octet U_GOLDEN = {0, sizeof(u_golden), u_golden};
    const char *Uline = "U = ";

    char t[SGS_SECP256K1];
    octet T = {0, sizeof(t), t};

    char u[SGS_SECP256K1];
    octet U = {0, sizeof(u), u};

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

        // Read input
        scan_OCTET(fp, &A, line, Aline);
        scan_OCTET(fp, &B, line, Bline);
        scan_OCTET(fp, &E, line, Eline);
        scan_OCTET(fp, &S, line, Sline);
        scan_OCTET(fp, &L, line, Lline);

        // Read ground truth
        scan_OCTET(fp, &T_GOLDEN, line, Tline);
        scan_OCTET(fp, &U_GOLDEN, line, Uline);

        // Read P and run test
        if (!strncmp(line, last_line, strlen(last_line)))
        {
            SCHNORR_D_prove(&A, &B, &E, &S, &L, &T, &U);
            compare_OCT(fp, testNo, "SCHNORR_D_prove T", &T, &T_GOLDEN);
            compare_OCT(fp, testNo, "SCHNORR_D_prove U", &U, &U_GOLDEN);

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
