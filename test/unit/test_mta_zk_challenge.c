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

/* MTA Receiver ZK Proof challenge unit tests */

#define LINE_LEN 2048

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_mta_zk_challenge [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    MTA_ZK_commitment c;
    const char *Zline  = "Z = ";
    const char *Z1line = "Z1 = ";
    const char *Tline  = "T = ";
    const char *Vline  = "V = ";
    const char *Wline  = "W = ";

    COMMITMENTS_BC_pub_modulus mod;
    const char *NTline = "NT = ";
    const char *H1line = "H1 = ";
    const char *H2line = "H2 = ";

    PAILLIER_public_key key;
    const char *Nline = "N = ";

    char c1[2*FS_2048];
    octet C1 = {0, sizeof(c1), c1};
    const char *C1line = "C1 = ";

    char c2[2*FS_2048];
    octet C2 = {0, sizeof(c2), c2};
    const char *C2line = "C2 = ";

    char e_golden[MODBYTES_512_60];
    octet E_GOLDEN = {0, sizeof(e_golden), e_golden};
    const char *Eline = "E = ";

    char e[MODBYTES_512_60];
    octet E = {0, sizeof(e), e};

    // Line terminating a test vector
    const char *last_line = Eline;

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
        scan_OCTET(fp, &C1, line, C1line);
        scan_OCTET(fp, &C2, line, C2line);

        scan_FF_2048(fp, mod.b0, line, H1line, FFLEN_2048);
        scan_FF_2048(fp, mod.b1, line, H2line, FFLEN_2048);
        scan_FF_2048(fp, mod.N, line, NTline, FFLEN_2048);

        scan_FF_2048(fp, c.z,  line, Zline,  FFLEN_2048);
        scan_FF_2048(fp, c.z1, line, Z1line, FFLEN_2048);
        scan_FF_2048(fp, c.t,  line, Tline,  FFLEN_2048);
        scan_FF_2048(fp, c.v,  line, Vline,  2 * FFLEN_2048);
        scan_FF_2048(fp, c.w,  line, Wline,  FFLEN_2048);

        scan_FF_4096(fp, key.n, line, Nline, HFLEN_4096);

        // Read ground truth
        scan_OCTET(fp, &E_GOLDEN, line, Eline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            MTA_ZK_challenge(&key, &mod, &C1, &C2, &c, &E);

            compare_OCT(fp, testNo, "MTA_ZK_challenge. E", &E, &E_GOLDEN);

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
