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
#include "amcl/commitments.h"

/* BC Commitment setup unit tests */

#define LINE_LEN 1024

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_nm_commit [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

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

    // Line terminating a test vector
    const char *last_line = B1line;

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        scan_int(&testNo, line, TESTline);

        // Test input
        scan_OCTET(fp, &P, line, Pline);
        scan_OCTET(fp, &Q, line, Qline);
        scan_OCTET(fp, &ALPHA, line, ALPHAline);
        scan_OCTET(fp, &B0, line, B0line);

        // Ground truth
        scan_FF_2048(fp, m_golden.P, line, Pline, HFLEN_2048);
        scan_FF_2048(fp, m_golden.Q, line, Qline, HFLEN_2048);
        scan_FF_2048(fp, m_golden.pq, line, PQline, FFLEN_2048);
        scan_FF_2048(fp, m_golden.N, line, Nline, FFLEN_2048);
        scan_FF_2048(fp, m_golden.alpha, line, ALPHAline, FFLEN_2048);
        scan_FF_2048(fp, m_golden.ialpha, line, IALPHAline, FFLEN_2048);
        scan_FF_2048(fp, m_golden.b0, line, B0line, FFLEN_2048);
        scan_FF_2048(fp, m_golden.b1, line, B1line, FFLEN_2048);

        // Run test when the whole test vector has been read
        if (!strncmp(line, last_line, strlen(last_line)))
        {
            COMMITMENTS_BC_setup(NULL, &m, &P, &Q, &B0, &ALPHA);

            compare_FF_2048(fp, testNo, "COMMITMENTS_BC_setup P",      m.P,      m_golden.P,      HFLEN_2048);
            compare_FF_2048(fp, testNo, "COMMITMENTS_BC_setup Q",      m.Q,      m_golden.Q,      HFLEN_2048);
            compare_FF_2048(fp, testNo, "COMMITMENTS_BC_setup N",      m.N,      m_golden.N,      FFLEN_2048);
            compare_FF_2048(fp, testNo, "COMMITMENTS_BC_setup pq",     m.pq,     m_golden.pq,     FFLEN_2048);
            compare_FF_2048(fp, testNo, "COMMITMENTS_BC_setup alpha",  m.alpha,  m_golden.alpha,  FFLEN_2048);
            compare_FF_2048(fp, testNo, "COMMITMENTS_BC_setup ialpha", m.ialpha, m_golden.ialpha, FFLEN_2048);
            compare_FF_2048(fp, testNo, "COMMITMENTS_BC_setup b0",     m.b0,     m_golden.b0,     FFLEN_2048);
            compare_FF_2048(fp, testNo, "COMMITMENTS_BC_setup b1",     m.b1,     m_golden.b1,     FFLEN_2048);

            // Mark that at least one test vector has been executed
            test_run = 1;
        }
    }

    fclose(fp);

    if (test_run == 0)
    {
        printf("ERROR no test vector executed\n");
        exit(EXIT_FAILURE);
    }

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
