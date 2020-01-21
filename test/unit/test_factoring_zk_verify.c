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

/* ZKP of factoring prove unit test */

#include <string.h>
#include "amcl/factoring_zk.h"

#define LINE_LEN 2000

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
        printf("usage: ./test_factoring_zk_verify [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int len = 0;
    FILE *fp;

    char line[LINE_LEN] = {0};
    char *linePtr = NULL;

    const char *TESTline = "TEST = ";
    int testNo = 0;

    char n[FS_2048];
    octet N = {0, sizeof(n), n};
    const char *Nline = "N = ";

    char e[FACTORING_ZK_B];
    octet E = {0, sizeof(e), e};
    const char *Eline = "E = ";

    char y[FS_2048];
    octet Y = {0, sizeof(y), y};
    const char *Yline = "Y = ";

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    /* Test happy path using test vectors */

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        // Read TEST Number
        if (!strncmp(line, TESTline, strlen(TESTline)))
        {
            len = strlen(TESTline);
            linePtr = line + len;
            sscanf(linePtr, "%d\n", &testNo);
        }

        // Read N
        if (!strncmp(line, Nline, strlen(Nline)))
        {
            len = strlen(Nline);
            linePtr = line + len;
            read_OCTET(&N, linePtr);
        }

        // Read E
        if (!strncmp(line, Eline, strlen(Eline)))
        {
            len = strlen(Eline);
            linePtr = line + len;
            read_OCTET(&E, linePtr);
        }

        // Read Y and run test
        if (!strncmp(line, Yline, strlen(Yline)))
        {
            len = strlen(Yline);
            linePtr = line + len;
            read_OCTET(&Y, linePtr);

            if (!FACTORING_ZK_verify(&N, &E, &Y))
            {
                printf("FAILURE FACTORING_ZK_verify. Test %d\n", testNo);
                exit(EXIT_FAILURE);
            }
        }
    }

    /* Test unhappy path */
    E.val[0]++;

    if (FACTORING_ZK_verify(&N, &E, &Y))
    {
        printf("Failure FACTORING_ZK_verify. Invalid E");
        exit(EXIT_FAILURE);
    }

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
