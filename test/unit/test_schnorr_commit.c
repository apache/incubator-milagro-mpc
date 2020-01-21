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

/* Schnorr's Proof commitment unit test */

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
        printf("usage: ./test_schnorr_commit [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int len = 0;
    FILE *fp;

    char line[LINE_LEN] = {0};
    char *linePtr = NULL;

    const char *TESTline = "TEST = ";
    int testNo = 0;

    char r[SGS_SECP256K1];
    octet R = {0, sizeof(r), r};
    const char *Rline = "R = ";

    char c_golden[SFS_SECP256K1+1];
    octet C_GOLDEN = {0, sizeof(c_golden), c_golden};
    const char *Cline = "C = ";

    char c[SFS_SECP256K1+1];
    octet C = {0, sizeof(c), c};

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

        // Read R
        if (!strncmp(line, Rline, strlen(Rline)))
        {
            len = strlen(Rline);
            linePtr = line + len;
            read_OCTET(&R, linePtr);
        }

        // Read C and run test
        if (!strncmp(line, Cline, strlen(Cline)))
        {
            len = strlen(Cline);
            linePtr = line + len;
            read_OCTET(&C_GOLDEN, linePtr);

            SCHNORR_commit(NULL, &R, &C);

            if (!OCT_comp(&C, &C_GOLDEN))
            {
                printf("FAILURE SCHNORR_commit. Test %d\n", testNo);
                exit(EXIT_FAILURE);
            }
        }
    }

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}