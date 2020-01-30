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

    COMMITMENTS_BC_priv_modulus mod;
    const char *PTline = "PT = ";
    const char *QTline = "QT = ";
    const char *H1line = "H1 = ";
    const char *H2line = "H2 = ";

    MTA_RP_proof proof;
    MTA_RP_proof proof_reloaded;
    const char *Sline =  "S = ";
    const char *S1line = "S1 = ";
    const char *S2line = "S2 = ";

    char c[2*FS_2048];
    octet C = {0, sizeof(c), c};
    const char *Cline = "C = ";

    char e[MODBYTES_256_56];
    octet E = {0, sizeof(e), e};
    const char *Eline = "E = ";

    char n[FS_2048];
    octet N = {0, sizeof(n), n};
    const char *Nline = "N = ";

    char oct1[FS_2048];
    octet OCT1 = {0, sizeof(oct1), oct1};

    char oct2[2 * FS_2048];
    octet OCT2 = {0, sizeof(oct2), oct2};

    char oct3[2 * FS_2048];
    octet OCT3 = {0, sizeof(oct3), oct3};

    PAILLIER_public_key pub;

    // Make sure proof is properly zeroed before starting test
    FF_4096_zero(proof.s,  FFLEN_4096);
    FF_2048_zero(proof.s1, FFLEN_2048);

    // Line terminating a test vector
    const char *last_line = QTline;

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
        scan_OCTET(fp, &C, line, Cline);
        scan_OCTET(fp, &E, line, Eline);
        scan_OCTET(fp, &N, line, Nline);

        scan_FF_2048(fp, mod.b0, line, H1line, FFLEN_2048);
        scan_FF_2048(fp, mod.b1, line, H2line, FFLEN_2048);
        scan_FF_2048(fp, mod.P, line, PTline, HFLEN_2048);
        scan_FF_2048(fp, mod.Q, line, QTline, HFLEN_2048);

        scan_FF_2048(fp, co.z, line, Zline, FFLEN_2048);
        scan_FF_4096(fp, co.u, line, Uline, FFLEN_4096);
        scan_FF_2048(fp, co.w, line, Wline, FFLEN_2048);

        scan_FF_4096(fp, proof.s,  line, Sline,  HFLEN_4096);
        scan_FF_2048(fp, proof.s1, line, S1line, HFLEN_2048);
        scan_FF_2048(fp, proof.s2, line, S2line, FFLEN_2048 + HFLEN_2048);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            PAILLIER_PK_fromOctet(&pub, &N);

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
