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
#include "amcl/mta.h"

/* MTA Range Proof dump/load to octets unit tests */

#define LINE_LEN 2048

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_mta_rp_octets [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    MTA_RP_commitment co;
    MTA_RP_commitment co_reloaded;
    const char *Zline = "Z = ";
    const char *Uline = "U = ";
    const char *Wline = "W = ";

    MTA_RP_proof proof;
    MTA_RP_proof proof_reloaded;
    const char *Sline =  "S = ";
    const char *S1line = "S1 = ";
    const char *S2line = "S2 = ";

    char oct1[FS_2048];
    octet OCT1 = {0, sizeof(oct1), oct1};

    char oct2[2 * FS_2048];
    octet OCT2 = {0, sizeof(oct2), oct2};

    char oct3[2 * FS_2048];
    octet OCT3 = {0, sizeof(oct3), oct3};

    // Make sure proof is properly zeroed before starting test
    FF_4096_zero(proof.s,  FFLEN_4096);
    FF_2048_zero(proof.s1, FFLEN_2048);

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

        // Read inputs
        scan_FF_2048(fp, co.z, line, Zline, FFLEN_2048);
        scan_FF_4096(fp, co.u, line, Uline, FFLEN_4096);
        scan_FF_2048(fp, co.w, line, Wline, FFLEN_2048);

        scan_FF_4096(fp, proof.s,  line, Sline,  HFLEN_4096);
        scan_FF_2048(fp, proof.s1, line, S1line, HFLEN_2048);
        scan_FF_2048(fp, proof.s2, line, S2line, FFLEN_2048 + HFLEN_2048);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            // Dump and reload commitment
            MTA_RP_commitment_toOctets(&OCT1, &OCT2, &OCT3, &co);
            MTA_RP_commitment_fromOctets(&co_reloaded, &OCT1, &OCT2, &OCT3);

            compare_FF_2048(fp, testNo, "co.z", co.z, co_reloaded.z, FFLEN_2048);
            compare_FF_4096(fp, testNo, "co.u", co.u, co_reloaded.u, FFLEN_4096);
            compare_FF_2048(fp, testNo, "co.w", co.w, co_reloaded.w, FFLEN_2048);

            MTA_RP_proof_toOctets(&OCT1, &OCT2, &OCT3, &proof);
            MTA_RP_proof_fromOctets(&proof_reloaded, &OCT1, &OCT2, &OCT3);

            compare_FF_4096(fp, testNo, "proof.s",  proof.s,  proof_reloaded.s,  FFLEN_4096);
            compare_FF_2048(fp, testNo, "proof.s1", proof.s1, proof_reloaded.s1, FFLEN_2048);
            compare_FF_2048(fp, testNo, "proof.s2", proof.s2, proof_reloaded.s2, FFLEN_2048 + HFLEN_2048);

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
