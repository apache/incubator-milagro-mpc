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

/* Schnorr's Proof prove unit test */

#define LINE_LEN 256

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_shcnorr_prove [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    char r[SGS_SECP256K1];
    octet R = {0, sizeof(r), r};
    const char *Rline = "R = ";

    char e[SGS_SECP256K1];
    octet E = {0, sizeof(e), e};
    const char *Eline = "E = ";

    char x[SGS_SECP256K1];
    octet X = {0, sizeof(x), x};
    const char *Xline = "X = ";

    char p_golden[SGS_SECP256K1];
    octet P_GOLDEN = {0, sizeof(p_golden), p_golden};
    const char *Pline = "P = ";

    char p[SGS_SECP256K1];
    octet P = {0, sizeof(p), p};

    // Line terminating a test vector
    const char *last_line = Pline;

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
        scan_OCTET(fp, &E, line, Eline);
        scan_OCTET(fp, &X, line, Xline);

        // Read ground truth
        scan_OCTET(fp, &P_GOLDEN, line, Pline);

        // Read P and run test
        if (!strncmp(line, last_line, strlen(last_line)))
        {
            SCHNORR_prove(&R, &E, &X, &P);
            compare_OCT(fp, testNo, "SCHNORR_prove", &P, &P_GOLDEN);

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
