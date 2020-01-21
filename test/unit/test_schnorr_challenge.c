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

/* Schnorr's Proof challenge unit test */

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
        printf("usage: ./test_nm_challenge [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int len = 0;
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

    char e_golden[SGS_SECP256K1];
    octet E_GOLDEN = {0, sizeof(e_golden), e_golden};
    const char *Eline = "E = ";

    char e[SGS_SECP256K1];
    octet E = {0, sizeof(e), e};

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

        // Read V
        if (!strncmp(line, Vline, strlen(Vline)))
        {
            len = strlen(Vline);
            linePtr = line + len;
            read_OCTET(&V, linePtr);
        }

        // Read C
        if (!strncmp(line, Cline, strlen(Cline)))
        {
            len = strlen(Cline);
            linePtr = line + len;
            read_OCTET(&C, linePtr);
        }

        // Read E and run test
        if (!strncmp(line, Eline, strlen(Eline)))
        {
            len = strlen(Eline);
            linePtr = line + len;
            read_OCTET(&E_GOLDEN, linePtr);

            SCHNORR_challenge(&V, &C, &E);

            if (!OCT_comp(&E, &E_GOLDEN))
            {
                printf("FAILURE SCHNORR_challenge. Test %d\n", testNo);
                exit(EXIT_FAILURE);
            }
        }
    }

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}