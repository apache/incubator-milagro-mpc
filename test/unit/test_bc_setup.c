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
#include "amcl/commitments.h"

/* BC Commitment setup unit tests */

#define LINE_LEN 1024

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

void compare_FF_2048(int testNo, char* name, BIG_1024_58 *x, BIG_1024_58 *y, int n)
{
    if(FF_2048_comp(x, y, n))
    {
        fprintf(stderr, "FAILURE COMMITMENTS_BC_setup %s. Test %d\n", name, testNo);
        exit(EXIT_FAILURE);
    }
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

    char p[HFS_2048];
    octet P = {0, sizeof(p), p};
    const char *Pline = "P = ";

    char q[FS_2048];
    octet Q = {0, sizeof(q), q};
    const char *Qline = "Q = ";

    char alpha[FS_2048];
    octet ALPHA = {0, sizeof(alpha), alpha};
    const char *ALPHAline = "ALPHA = ";

    char b0[FS_2048];
    octet B0 = {0, sizeof(b0), b0};
    const char *B0line = "B0 = ";

    COMMITMENTS_BC_priv_modulus m;
    const char *Nline =  "N = ";
    const char *PQline = "PQ = ";

    COMMITMENTS_BC_priv_modulus m_golden;
    const char *IALPHAline = "IALPHA = ";
    const char *B1line = "B1 = ";

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
        }

        // Read P
        if (!strncmp(line, Pline, strlen(Pline)))
        {
            len = strlen(Pline);
            linePtr = line + len;
            read_OCTET(&P, linePtr);
            FF_2048_fromOctet(m_golden.P, &P, HFLEN_2048);
        }

        // Read Q
        if (!strncmp(line, Qline, strlen(Qline)))
        {
            len = strlen(Qline);
            linePtr = line + len;
            read_OCTET(&Q, linePtr);
            FF_2048_fromOctet(m_golden.Q, &Q, HFLEN_2048);
        }

        // Read PQ
        if (!strncmp(line, PQline, strlen(PQline)))
        {
            len = strlen(PQline);
            linePtr = line + len;
            read_FF_2048(m.pq, linePtr, FFLEN_2048);
            FF_2048_copy(m_golden.pq, m.pq, FFLEN_2048);
        }

        // Read N
        if (!strncmp(line, Nline, strlen(Nline)))
        {
            len = strlen(Nline);
            linePtr = line + len;
            read_FF_2048(m.N, linePtr, FFLEN_2048);
            FF_2048_copy(m_golden.N, m.N, FFLEN_2048);
        }

        // Read ALPHA
        if (!strncmp(line, ALPHAline, strlen(ALPHAline)))
        {
            len = strlen(ALPHAline);
            linePtr = line + len;
            read_OCTET(&ALPHA, linePtr);
            FF_2048_fromOctet(m_golden.alpha, &ALPHA, FFLEN_2048);
        }

        // Read B0
        if (!strncmp(line, B0line, strlen(B0line)))
        {
            len = strlen(B0line);
            linePtr = line + len;
            read_OCTET(&B0, linePtr);
            FF_2048_fromOctet(m_golden.b0, &B0, FFLEN_2048);
        }


        // Read IALPHA
        if (!strncmp(line, IALPHAline, strlen(IALPHAline)))
        {
            len = strlen(IALPHAline);
            linePtr = line + len;
            read_FF_2048(m_golden.ialpha, linePtr, FFLEN_2048);
        }

        // Read B1 and run test
        if (!strncmp(line, B1line, strlen(B1line)))
        {
            len = strlen(B1line);
            linePtr = line + len;
            read_FF_2048(m_golden.b1, linePtr, FFLEN_2048);

            csprng RNG;
            char seed[32] = {0};
            RAND_seed(&RNG, 32, seed);

            // Run test
            COMMITMENTS_BC_setup(&RNG, &m, &P, &Q, &B0, &ALPHA);

            compare_FF_2048(testNo, "P",      m.P,      m_golden.P,      HFLEN_2048);
            compare_FF_2048(testNo, "Q",      m.Q,      m_golden.Q,      HFLEN_2048);
            compare_FF_2048(testNo, "N",      m.N,      m_golden.N,      FFLEN_2048);
            compare_FF_2048(testNo, "pq",     m.pq,     m_golden.pq,     FFLEN_2048);
            compare_FF_2048(testNo, "alpha",  m.alpha,  m_golden.alpha,  FFLEN_2048);
            compare_FF_2048(testNo, "ialpha", m.ialpha, m_golden.ialpha, FFLEN_2048);
            compare_FF_2048(testNo, "b0",     m.b0,     m_golden.b0,     FFLEN_2048);
            compare_FF_2048(testNo, "b1",     m.b1,     m_golden.b1,     FFLEN_2048);
        }
    }

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
