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

/* MTA Receiver ZK Proof with check commitment unit tests */

#define LINE_LEN 2048

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_mta_zkwc_commit [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    MTA_ZKWC_commitment c;
    MTA_ZKWC_commitment c_golden;
    const char *Uline  = "U = ";
    const char *Zline  = "Z = ";
    const char *Z1line = "Z1 = ";
    const char *Tline  = "T = ";
    const char *Vline  = "V = ";
    const char *Wline  = "W = ";

    MTA_ZKWC_commitment_rv rv;
    const char *ALPHAline = "ALPHA = ";
    const char *BETAline  = "BETA = ";
    const char *GAMMAline = "GAMMA = ";
    const char *RHOline   = "RHO = ";
    const char *RHO1line  = "RHO1 = ";
    const char *SIGMAline = "SIGMA = ";
    const char *TAUline   = "TAU = ";

    COMMITMENTS_BC_pub_modulus mod;
    const char *NTline = "NT = ";
    const char *H1line = "H1 = ";
    const char *H2line = "H2 = ";

    char x[MODBYTES_256_56];
    octet X = {0, sizeof(x), x};
    const char *Xline = "X = ";

    char y[MODBYTES_256_56];
    octet Y = {0, sizeof(y), y};
    const char *Yline = "Y = ";

    char c1[2 * FS_2048];
    octet C1 = {0, sizeof(c1), c1};
    const char *C1line = "C1 = ";

    char n[FS_2048];
    octet N = {0, sizeof(n), n};
    const char *Nline = "N = ";

    PAILLIER_public_key key;

    // Line terminating a test vector
    const char *last_line = Uline;

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
        scan_OCTET(fp, &X,  line, Xline);
        scan_OCTET(fp, &Y,  line, Yline);
        scan_OCTET(fp, &C1, line, C1line);
        scan_OCTET(fp, &N,  line, Nline);

        scan_FF_2048(fp, mod.b0, line, H1line, FFLEN_2048);
        scan_FF_2048(fp, mod.b1, line, H2line, FFLEN_2048);
        scan_FF_2048(fp, mod.N,  line, NTline, FFLEN_2048);

        scan_FF_2048(fp, rv.alpha, line, ALPHAline, HFLEN_2048);
        scan_FF_2048(fp, rv.beta,  line, BETAline,  FFLEN_2048);
        scan_FF_2048(fp, rv.gamma, line, GAMMAline, FFLEN_2048);
        scan_FF_2048(fp, rv.rho,   line, RHOline,   FFLEN_2048 + HFLEN_2048);
        scan_FF_2048(fp, rv.rho1,  line, RHO1line,  FFLEN_2048 + HFLEN_2048);
        scan_FF_2048(fp, rv.sigma, line, SIGMAline, FFLEN_2048 + HFLEN_2048);
        scan_FF_2048(fp, rv.tau,   line, TAUline,   FFLEN_2048 + HFLEN_2048);

        // Read ground truth
        scan_FF_2048(fp, c_golden.zkc.z,  line, Zline,  FFLEN_2048);
        scan_FF_2048(fp, c_golden.zkc.z1, line, Z1line, FFLEN_2048);
        scan_FF_2048(fp, c_golden.zkc.t,  line, Tline,  FFLEN_2048);
        scan_FF_2048(fp, c_golden.zkc.v,  line, Vline,  2 * FFLEN_2048);
        scan_FF_2048(fp, c_golden.zkc.w,  line, Wline,  FFLEN_2048);

        scan_ECP_SECP256K1(fp, &(c_golden.U), line, Uline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            PAILLIER_PK_fromOctet(&key, &N);

            ECP_SECP256K1_inf(&(c.U));

            MTA_ZKWC_commit(NULL, &key, &mod, &X, &Y, &C1, &c, &rv);

            compare_FF_2048(fp, testNo, "MTA_ZKWC_commit c.z",  c.zkc.z,  c_golden.zkc.z,  FFLEN_2048);
            compare_FF_2048(fp, testNo, "MTA_ZKWC_commit c.z1", c.zkc.z1, c_golden.zkc.z1, FFLEN_2048);
            compare_FF_2048(fp, testNo, "MTA_ZKWC_commit c.t",  c.zkc.t,  c_golden.zkc.t,  FFLEN_2048);
            compare_FF_2048(fp, testNo, "MTA_ZKWC_commit c.v",  c.zkc.v,  c_golden.zkc.v,  2 * FFLEN_2048);
            compare_FF_2048(fp, testNo, "MTA_ZKWC_commit c.w",  c.zkc.w,  c_golden.zkc.w,  FFLEN_2048);

            compare_ECP_SECP256K1(fp, testNo, "MTA_ZKWC_commit c.U", &(c.U), &(c_golden.U));

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
