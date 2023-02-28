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

/* Bit Commitment Paillier muladd Proof octet functions unit test */

#define LINE_LEN 2048

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_bit_commitment_muladd_octets [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    BIT_COMMITMENT_muladd_commitment c;
    BIT_COMMITMENT_muladd_commitment c_reloaded;
    const char *Zline  = "Z = ";
    const char *Z1line = "Z1 = ";
    const char *Tline  = "T = ";
    const char *Vline  = "V = ";
    const char *Wline  = "W = ";

    BIT_COMMITMENT_muladd_proof p;
    BIT_COMMITMENT_muladd_proof p_reloaded;
    const char *Sline  = "S = ";
    const char *S1line = "S1 = ";
    const char *S2line = "S2 = ";
    const char *T1line = "T1 = ";
    const char *T2line = "T2 = ";

    char oct1[FS_2048];
    octet OCT1 = {0, sizeof(oct1), oct1};

    char oct2[2 * FS_2048];
    octet OCT2 = {0, sizeof(oct2), oct2};

    char oct3[2 * FS_2048];
    octet OCT3 = {0, sizeof(oct3), oct3};

    char oct4[2 * FS_2048];
    octet OCT4 = {0, sizeof(oct4), oct4};

    char oct5[2 * FS_2048];
    octet OCT5 = {0, sizeof(oct5), oct5};

    // Make sure proof is properly zeroed before starting test
    FF_2048_zero(p.s1, FFLEN_2048);

    // Line terminating a test vector
    const char *last_line = Wline;

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        scan_int(&testNo, line, TESTline);

        scan_FF_2048(fp, c.z,  line, Zline,  FFLEN_2048);
        scan_FF_2048(fp, c.z1, line, Z1line, FFLEN_2048);
        scan_FF_2048(fp, c.t,  line, Tline,  FFLEN_2048);
        scan_FF_2048(fp, c.v,  line, Vline,  2 * FFLEN_2048);
        scan_FF_2048(fp, c.w,  line, Wline,  FFLEN_2048);

        scan_FF_2048(fp, p.s,  line, Sline,  FFLEN_2048);
        scan_FF_2048(fp, p.s1, line, S1line, HFLEN_2048);
        scan_FF_2048(fp, p.s2, line, S2line, FFLEN_2048 + HFLEN_2048);
        scan_FF_2048(fp, p.t1, line, T1line, FFLEN_2048);
        scan_FF_2048(fp, p.t2, line, T2line, FFLEN_2048 + HFLEN_2048);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            // Dump and reload commitment
            BIT_COMMITMENT_muladd_commitment_toOctets(&OCT1, &OCT2, &OCT3, &OCT4, &OCT5, &c);
            BIT_COMMITMENT_muladd_commitment_fromOctets(&c_reloaded, &OCT1, &OCT2, &OCT3, &OCT4, &OCT5);

            compare_FF_2048(fp, testNo, "c.z",  c.z,  c_reloaded.z,  FFLEN_2048);
            compare_FF_2048(fp, testNo, "c.z1", c.z1, c_reloaded.z1, FFLEN_2048);
            compare_FF_2048(fp, testNo, "c.t",  c.t,  c_reloaded.t,  FFLEN_2048);
            compare_FF_2048(fp, testNo, "c.v",  c.v,  c_reloaded.v,  2 * FFLEN_2048);
            compare_FF_2048(fp, testNo, "c.w",  c.w,  c_reloaded.w,  FFLEN_2048);

            BIT_COMMITMENT_muladd_proof_toOctets(&OCT1, &OCT2, &OCT3, &OCT4, &OCT5, &p);
            BIT_COMMITMENT_muladd_proof_fromOctets(&p_reloaded, &OCT1, &OCT2, &OCT3, &OCT4, &OCT5);

            compare_FF_2048(fp, testNo, "p.s",  p.s,  p_reloaded.s,  FFLEN_2048);
            compare_FF_2048(fp, testNo, "p.s1", p.s1, p_reloaded.s1, FFLEN_2048);
            compare_FF_2048(fp, testNo, "p.s2", p.s2, p_reloaded.s2, FFLEN_2048 + HFLEN_2048);
            compare_FF_2048(fp, testNo, "p.t1", p.t1, p_reloaded.t1, FFLEN_2048);
            compare_FF_2048(fp, testNo, "p.t2", p.t2, p_reloaded.t2, FFLEN_2048 + HFLEN_2048);

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
