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

/* Double Schnorr's Proof challenge unit test */

#define LINE_LEN 256
#define IDLEN 16
#define ADLEN 16

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_d_schnorr_challenge [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    char r[SFS_SECP256K1+1];
    octet R = {0, sizeof(r), r};
    const char *Rline = "R = ";

    char v[SFS_SECP256K1+1];
    octet V = {0, sizeof(v), v};
    const char *Vline = "V = ";

    char id[IDLEN];
    octet ID = {0, sizeof(id), id};
    const char *IDline = "ID = ";

    char ad[ADLEN];
    octet AD = {0, sizeof(ad), ad};
    const octet *AD_ptr = NULL;
    const char *ADline = "AD = ";

    char c[SFS_SECP256K1+1];
    octet C = {0, sizeof(c), c};
    const char *Cline = "C = ";

    char e_golden[SGS_SECP256K1];
    octet E_GOLDEN = {0, sizeof(e_golden), e_golden};
    const char *Eline = "E = ";

    char e[SGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    // Line terminating a test vector
    const char *last_line = ADline;

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

        // Read ID and AD
        scan_OCTET(fp, &ID, line, IDline);
        scan_OCTET(fp, &AD, line, ADline);

        // Read inputs
        scan_OCTET(fp, &R, line, Rline);
        scan_OCTET(fp, &V, line, Vline);
        scan_OCTET(fp, &C, line, Cline);

        // Read ground truth
        scan_OCTET(fp, &E_GOLDEN, line, Eline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            // Also input AD if it is not empty
            if (AD.len > 0)
            {
                AD_ptr = &AD;
            }

            SCHNORR_D_challenge(&R, &V, &C, &ID, AD_ptr, &E);
            compare_OCT(fp, testNo, "SCHNORR_D_challenge", &E, &E_GOLDEN);

            // Mark that at least one test vector was executed
            test_run = 1;

            // Restore AD_ptr
            AD_ptr = NULL;
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
