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

/* Double Schnorr's Proof challenge verify test */

#define LINE_LEN 256

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_schnorr_d_verify [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int rc;
    int test_run = 0;

    char err_msg[128];

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

    char c[SFS_SECP256K1+1];
    octet C = {0, sizeof(c), c};
    const char *Cline = "C = ";

    char e[SGS_SECP256K1];
    octet E = {0, sizeof(e), e};
    const char *Eline = "E = ";

    char t[SGS_SECP256K1];
    octet T = {0, sizeof(t), t};
    const char *Tline = "T = ";

    char u[SGS_SECP256K1];
    octet U = {0, sizeof(u), u};
    const char *Uline = "U = ";

    // Line terminating a test vector
    const char *last_line = Uline;

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

        // Read input
        scan_OCTET(fp, &R, line, Rline);
        scan_OCTET(fp, &V, line, Vline);
        scan_OCTET(fp, &C, line, Cline);
        scan_OCTET(fp, &E, line, Eline);
        scan_OCTET(fp, &T, line, Tline);
        scan_OCTET(fp, &U, line, Uline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            rc = SCHNORR_D_verify(&R, &V, &C, &E, &T, &U);
            sprintf(err_msg, "SCHNORR_D_verify. rc %d", rc);
            assert_tv(fp, testNo, err_msg, rc == SCHNORR_OK);

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
    char zero[SFS_SECP256K1+1] = {0};
    octet ZERO = {0, sizeof(zero), zero};

    rc = SCHNORR_D_verify(&ZERO, &V, &C, &E, &T, &U);
    sprintf(err_msg, "SCHNORR_D_verify invalid R. rc %d", rc);
    assert(NULL, err_msg, rc == SCHNORR_INVALID_ECP);

    rc = SCHNORR_D_verify(&R, &ZERO, &C, &E, &T, &U);
    sprintf(err_msg, "SCHNORR_D_verify invalid V. rc %d", rc);
    assert(NULL, err_msg, rc == SCHNORR_INVALID_ECP);

    rc = SCHNORR_D_verify(&R, &V, &ZERO, &E, &T, &U);
    sprintf(err_msg, "SCHNORR_D_verify invalid C. rc %d", rc);
    assert(NULL, err_msg, rc == SCHNORR_INVALID_ECP);

    rc = SCHNORR_D_verify(&R, &V, &C, &E, &ZERO, &U);
    sprintf(err_msg, "SCHNORR_D_verify invalid proof. rc %d", rc);
    assert(NULL, err_msg, rc == SCHNORR_FAIL);

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
