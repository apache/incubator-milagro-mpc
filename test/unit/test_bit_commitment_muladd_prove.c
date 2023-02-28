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
#include "amcl/bit_commitment.h"

/* Bit Commitment Paillier muladd Proof prove unit test */

#define LINE_LEN 2048

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_bit_commitment_muladd_prove [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    BIT_COMMITMENT_muladd_rv rv;
    const char *ALPHAline = "ALPHA = ";
    const char *BETAline  = "BETA = ";
    const char *GAMMAline = "GAMMA = ";
    const char *RHOline   = "RHO = ";
    const char *RHO1line  = "RHO1 = ";
    const char *SIGMAline = "SIGMA = ";
    const char *TAUline   = "TAU = ";

    char x[MODBYTES_256_56];
    octet X = {0, sizeof(x), x};
    const char *Xline = "X = ";

    char y[MODBYTES_256_56];
    octet Y = {0, sizeof(y), y};
    const char *Yline = "Y = ";

    char r[2*FS_2048];
    octet R = {0, sizeof(r), r};
    const char *Rline = "R = ";

    char e[MODBYTES_256_56];
    octet E = {0, sizeof(e), e};
    const char *Eline = "E = ";

    char n[FS_2048];
    octet N = {0, sizeof(n), n};
    const char *Nline = "N = ";

    PAILLIER_public_key key;

    BIT_COMMITMENT_muladd_proof p;
    BIT_COMMITMENT_muladd_proof p_golden;
    const char *Sline  = "S = ";
    const char *S1line = "S1 = ";
    const char *S2line = "S2 = ";
    const char *T1line = "T1 = ";
    const char *T2line = "T2 = ";

    // Make sure proof is properly zeroed before starting test
    FF_2048_zero(p_golden.s1, FFLEN_2048);

    // Line terminating a test vector
    const char *last_line = T2line;

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

        // Read inputs
        scan_OCTET(fp, &E, line, Eline);
        scan_OCTET(fp, &R, line, Rline);
        scan_OCTET(fp, &X,  line, Xline);
        scan_OCTET(fp, &Y,  line, Yline);
        scan_OCTET(fp, &N,  line, Nline);

        scan_FF_2048(fp, rv.alpha, line, ALPHAline, HFLEN_2048);
        scan_FF_2048(fp, rv.beta,  line, BETAline,  FFLEN_2048);
        scan_FF_2048(fp, rv.gamma, line, GAMMAline, FFLEN_2048);
        scan_FF_2048(fp, rv.rho,   line, RHOline,   FFLEN_2048 + HFLEN_2048);
        scan_FF_2048(fp, rv.rho1,  line, RHO1line,  FFLEN_2048 + HFLEN_2048);
        scan_FF_2048(fp, rv.sigma, line, SIGMAline, FFLEN_2048 + HFLEN_2048);
        scan_FF_2048(fp, rv.tau,   line, TAUline,   FFLEN_2048 + HFLEN_2048);

        // Read ground truth
        scan_FF_2048(fp, p_golden.s,  line, Sline,  FFLEN_2048);
        scan_FF_2048(fp, p_golden.s1, line, S1line, HFLEN_2048);
        scan_FF_2048(fp, p_golden.s2, line, S2line, FFLEN_2048 + HFLEN_2048);
        scan_FF_2048(fp, p_golden.t1, line, T1line, FFLEN_2048);
        scan_FF_2048(fp, p_golden.t2, line, T2line, FFLEN_2048 + HFLEN_2048);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            PAILLIER_PK_fromOctet(&key, &N);

            BIT_COMMITMENT_muladd_prove(&key, &X, &Y, &R, &rv, &E, &p);

            compare_FF_2048(fp, testNo, "BIT_COMMITMENT_muladd_proof p.s",  p.s,  p_golden.s,  FFLEN_2048);
            compare_FF_2048(fp, testNo, "BIT_COMMITMENT_muladd_proof p.s1", p.s1, p_golden.s1, FFLEN_2048);
            compare_FF_2048(fp, testNo, "BIT_COMMITMENT_muladd_proof p.s2", p.s2, p_golden.s2, FFLEN_2048 + HFLEN_2048);
            compare_FF_2048(fp, testNo, "BIT_COMMITMENT_muladd_proof p.t1", p.t1, p_golden.t1, FFLEN_2048);
            compare_FF_2048(fp, testNo, "BIT_COMMITMENT_muladd_proof p.t2", p.t2, p_golden.t2, FFLEN_2048 + HFLEN_2048);

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

    printf("SUCCESS");
    exit(EXIT_SUCCESS);
}
