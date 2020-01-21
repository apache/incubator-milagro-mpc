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
#include "amcl/schnorr.h"

/* Schnorr's Proof challenge verify test */

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

    int rc;
    FILE *fp;

    char line[LINE_LEN] = {0};
    char *linePtr = NULL;

    const char *TESTline = "TEST = ";
    int testNo = 0;

    char v[SFS_SECP256K1+1];
    octet V = {0, sizeof(v), v};
    const char *Vline = "V = ";

    char c[SFS_SECP256K1+1];
    octet C = {0, sizeof(c), c};
    const char *Cline = "C = ";

    char e[SGS_SECP256K1];
    octet E = {0, sizeof(e), e};
    const char *Eline = "E = ";

    char p[SGS_SECP256K1];
    octet P = {0, sizeof(p), p};
    const char *Pline = "P = ";

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    /* Test happy path with test vectors */
    while (fgets(line, LINE_LEN, fp) != NULL)
    {    
        // Read TEST number
        if (!strncmp(line, TESTline, strlen(TESTline)))
        {
            linePtr = line + strlen(TESTline);
            sscanf(linePtr, "%d\n", &testNo);
        }

        // Read V
        if (!strncmp(line, Vline, strlen(Vline)))
        {
            linePtr = line + strlen(Vline);
            read_OCTET(&V, linePtr);
        }

        // Read C
        if (!strncmp(line, Cline, strlen(Cline)))
        {
            linePtr = line + strlen(Cline);
            read_OCTET(&C, linePtr);
        }

        // Read E
        if (!strncmp(line, Eline, strlen(Eline)))
        {
            linePtr = line + strlen(Eline);
            read_OCTET(&E, linePtr);
        }

        // Read P and run test
        if (!strncmp(line, Pline, strlen(Pline)))
        {
            linePtr = line + strlen(Pline);
            read_OCTET(&P, linePtr);

            rc = SCHNORR_verify(&V, &C, &E, &P);
            if (rc != SCHNORR_OK)
            {
                printf("FAILURE SCHNORR_verify. RC %d, Test %d", rc, testNo);
                exit(EXIT_FAILURE);
            }
        }
    }

    /* Test unhappy path */
    char zero[SFS_SECP256K1+1] = {0};
    octet ZERO = {0, sizeof(zero), zero};

    rc = SCHNORR_verify(&ZERO, &C, &E, &P);
    if (rc != SCHNORR_INVALID_ECP)
    {
        printf("FAILURE SCHNORR_verify invalid V. RC %d", rc);
        exit(EXIT_FAILURE);
    }

    rc = SCHNORR_verify(&V, &ZERO, &E, &P);
    if (rc != SCHNORR_INVALID_ECP)
    {
        printf("FAILURE SCHNORR_verify invalid C. RC %d", rc);
        exit(EXIT_FAILURE);
    }

    rc = SCHNORR_verify(&V, &C, &E, &ZERO);
    if (rc != SCHNORR_FAIL)
    {
        printf("FAILURE SCHNORR_verify invalid proof. RC %d", rc);
        exit(EXIT_FAILURE);
    }

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}