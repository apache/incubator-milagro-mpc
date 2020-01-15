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

void read_FF_2048(BIG_1024_58 *x, char *string, int n)
{
    int len = strlen(string);
    char oct[len / 2];
    octet OCT = {0, len / 2, oct};

    read_OCTET(&OCT, string);
    FF_2048_fromOctet(x, &OCT, n);
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_paillier_decrypt [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int len = 0;
    FILE *fp;

    char line[LINE_LEN] = {0};
    char *linePtr = NULL;

    const char *TESTline = "TEST = ";
    int testNo = 0;

    char r[FS_2048];
    octet R = {0, sizeof(r), r};
    const char *Rline = "R = ";

    char egolden[FACTORING_ZK_B];
    octet EGOLDEN = {0, sizeof(egolden), egolden};
    const char *Eline = "E = ";

    char ygolden[FS_2048];
    octet YGOLDEN = {0, sizeof(ygolden), ygolden};
    const char *Yline = "Y = ";

    FACTORING_ZK_modulus m;
    const char *Nline = "N = ";
    const char *Pline = "P = ";
    const char *Qline = "Q = ";

    char e[FACTORING_ZK_B];
    octet E = {0, sizeof(e), e};

    char y[FS_2048];
    octet Y = {0, sizeof(y), y};

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        // Read TEST Number
        if (!strncmp(line, TESTline, strlen(TESTline)))
        {
            len = strlen(TESTline);
            linePtr = line + len;
            sscanf(linePtr, "%d\n", &testNo);
            printf("TEST = %d\n", testNo);
        }

        // Read N
        if (!strncmp(line, Nline, strlen(Nline)))
        {
            len = strlen(Nline);
            linePtr = line + len;
            read_FF_2048(m.n, linePtr, FFLEN_2048);
        }

        // Read P
        if (!strncmp(line, Pline, strlen(Pline)))
        {
            len = strlen(Pline);
            linePtr = line + len;
            read_FF_2048(m.p, linePtr, HFLEN_2048);
        }

        // Read Q
        if (!strncmp(line, Qline, strlen(Qline)))
        {
            len = strlen(Qline);
            linePtr = line + len;
            read_FF_2048(m.q, linePtr, HFLEN_2048);
        }

        // Read R
        if (!strncmp(line, Rline, strlen(Rline)))
        {
            len = strlen(Rline);
            linePtr = line + len;
            read_OCTET(&R, linePtr);
        }

        // Read E
        if (!strncmp(line, Eline, strlen(Eline)))
        {
            len = strlen(Eline);
            linePtr = line + len;
            read_OCTET(&EGOLDEN, linePtr);
        }

        // Read Y and run test
        if (!strncmp(line, Yline, strlen(Yline)))
        {
            len = strlen(Yline);
            linePtr = line + len;
            read_OCTET(&YGOLDEN, linePtr);

            FACTORING_ZK_prove(&m, NULL, &R, &E, &Y);
            if (!OCT_comp(&EGOLDEN, &E))
            {
                printf("FAILURE FACTORING_ZK_prove E. Test %d\n", testNo);
                exit(EXIT_FAILURE);
            }

            if (!OCT_comp(&YGOLDEN, &Y))
            {
                printf("FAILURE FACTORING_ZK_prove Y. Test %d\n", testNo);
                exit(EXIT_FAILURE);
            }
        }
    }

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
