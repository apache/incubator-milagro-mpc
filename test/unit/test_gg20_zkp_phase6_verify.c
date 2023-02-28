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

/* GG20 Phase 3 ZKP verify unit test */

#include <string.h>
#include "test.h"
#include "amcl/gg20_zkp.h"

#define LINE_LEN 1024

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_gg20_zkp_phase3_verify [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int rc;
    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    char r[GFS_SECP256K1 + 1];
    octet R = {0, sizeof(r), r};
    const char *Rline = "R = ";

    char t[GFS_SECP256K1 + 1];
    octet T = {0, sizeof(t), t};
    const char *ECPTline = "ECPT = ";

    char s[GFS_SECP256K1 + 1];
    octet S = {0, sizeof(s), s};
    const char *ECPSline = "ECPS = ";

    GG20_ZKP_phase6_commitment c;
    const char *ALPHAline = "ALPHA = ";
    const char *BETAline = "BETA = ";

    char e[GGS_SECP256K1];
    octet E = {0, sizeof(e), e};
    const char *Eline = "E = ";

    GG20_ZKP_proof p;
    const char *Tline = "T = ";
    const char *Uline = "U = ";

    // Line terminating a test vector
    const char *last_line = Uline;

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    /* Test Happy Path using test vectors */

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        scan_int(&testNo, line, TESTline);

        scan_OCTET(fp, &R, line, Rline);
        scan_OCTET(fp, &T, line, ECPTline);
        scan_OCTET(fp, &S, line, ECPSline);

        scan_ECP_SECP256K1(fp, &(c.ALPHA), line, ALPHAline);
        scan_ECP_SECP256K1(fp, &(c.BETA),  line, BETAline);

        scan_OCTET(fp, &E, line, Eline);

        scan_BIG_256_56(fp, p.t, line, Tline);
        scan_BIG_256_56(fp, p.u, line, Uline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            rc = GG20_ZKP_phase6_verify(&R, &T, &S, &c, &E, &p);
            assert_tv(fp, testNo, "GG20_ZKP_phase6_verify", rc == GG20_ZKP_OK);

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

    /* Test unhappy paths */

    // Test Invalid R
    rc = GG20_ZKP_phase6_verify(&E, &T, &S, &c, &E, &p);
    assert(fp, "GG20_ZKP_phase6 verify invalid R", rc == GG20_ZKP_INVALID_ECP);

    // Test Invalid T
    rc = GG20_ZKP_phase6_verify(&R, &E, &S, &c, &E, &p);
    assert(fp, "GG20_ZKP_phase6 verify invalid E", rc == GG20_ZKP_INVALID_ECP);

    // Test Invalid S
    rc = GG20_ZKP_phase6_verify(&R, &T, &E, &c, &E, &p);
    assert(fp, "GG20_ZKP_phase6 verify invalid S", rc == GG20_ZKP_INVALID_ECP);

    // Test invalid Proof u
    BIG_256_56_inc(p.u, 1);
    rc = GG20_ZKP_phase6_verify(&R, &T, &S, &c, &E, &p);
    assert(fp, "GG20_ZKP_phase3 verify invalid proof u", rc == GG20_ZKP_FAIL);
    BIG_256_56_dec(p.u, 1);

    // Test invalid Proof t
    BIG_256_56_inc(p.t, 1);
    rc = GG20_ZKP_phase6_verify(&R, &T, &S, &c, &E, &p);
    assert(fp, "GG20_ZKP_phase3 verify invalid proof t", rc == GG20_ZKP_FAIL);
    BIG_256_56_dec(p.t, 1);

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
