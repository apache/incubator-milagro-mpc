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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "amcl/commitments.h"

/* NM Commitment unit tests */

#define LINE_LEN 256

void read_OCTET(octet *OCT, char *string)
{
    int len = strlen(string);
    char buff[len];
    memcpy(buff, string, len);
    char *end = strchr(buff, ',');
    if (end == NULL)
    {
        printf("ERROR unexpected test vector %s\n", string);
        exit(EXIT_FAILURE);
    }
    end[0] = '\0';
    OCT_fromHex(OCT, buff);
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_nm_commit [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int len = 0;
    FILE *fp;

    char line[LINE_LEN] = {0};
    char *linePtr = NULL;

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

    /* Test happy path using test vectors */
    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        // Read TEST number
        if (!strncmp(line, TESTline, strlen(TESTline)))
        {
            len = strlen(TESTline);
            linePtr = line + len;
            sscanf(linePtr, "%d\n", &testNo);
        }

        // Read X
        if (!strncmp(line, Xline, strlen(Xline)))
        {
            len = strlen(Xline);
            linePtr = line + len;
            read_OCTET(&X_GOLDEN, linePtr);
#ifdef DEBUG
            printf("X = ");
            OCT_output(&X_GOLDEN);
#endif
        }

        // Read R
        if (!strncmp(line, Rline, strlen(Rline)))
        {
            len = strlen(Rline);
            linePtr = line + len;
            read_OCTET(&R_GOLDEN, linePtr);
#ifdef DEBUG
            printf("R = ");
            OCT_output(&R_GOLDEN);
#endif
        }

        // Read C and start test
        if (!strncmp(line, Cline, strlen(Cline)))
        {
            len = strlen(Cline);
            linePtr = line + len;
            read_OCTET(&C_GOLDEN, linePtr);
#ifdef DEBUG
            printf("\nC_GOLDEN = ");
            OCT_output(&C_GOLDEN);
#endif

            // Test COMMITMENTS_NM_commit
            COMMITMENTS_NM_commit(NULL, &X_GOLDEN, &R_GOLDEN, &C);
#ifdef DEBUG
            printf("\nC = ");
            OCT_output(&C);
#endif

            if (!OCT_comp(&C_GOLDEN, &C))
            {
                printf("FAILURE COMMITMENT_NM_commit. Test %d\n", testNo);
                exit(EXIT_FAILURE);
            }

            // Test COMMITMENTS_NM_decommit
            if (!COMMITMENTS_NM_decommit(&X_GOLDEN, &R_GOLDEN, &C_GOLDEN))
            {
                printf("FAILURE COMMITMENTS_NM_decommit. Test %d\n", testNo);
                exit(EXIT_FAILURE);
            }
        }
    }

    /* Test COMMITMENTS_NM_decommit unhappy paths */

    // Test invalid length of decommitment
    OCT_copy(&R, &R_GOLDEN);
    R.len--;

    if (COMMITMENTS_NM_decommit(&X_GOLDEN, &R, &C_GOLDEN))
    {
        printf("FAILURE COMMITMENTS_NM_decommit. Invalid R length\n");
        exit(EXIT_FAILURE);
    }

    // Test wrong decommitment
    OCT_copy(&R, &R_GOLDEN);
    R.val[0]--;

    if (COMMITMENTS_NM_decommit(&X_GOLDEN, &R, &C_GOLDEN))
    {
        printf("FAILURE COMMITMENTS_NM_decommit. Invalid R\n");
        exit(EXIT_FAILURE);
    }

    printf("SUCCESS");
    exit(EXIT_SUCCESS);
}
