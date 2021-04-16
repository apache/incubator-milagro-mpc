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

/* GG20 ZKPs octet functions unit test */

#include <string.h>
#include "test.h"
#include "amcl/gg20_zkp.h"

#define LINE_LEN 1024

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_gg20_zkp_octets [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int rc;
    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    char alpha[GFS_SECP256K1 + 1];
    char alpha_golden[GFS_SECP256K1 + 1];
    octet ALPHA = {0, sizeof(alpha), alpha};
    octet ALPHA_GOLDEN = {0, sizeof(alpha_golden), alpha_golden};
    const char *ALPHAline = "ALPHA = ";

    char beta[GFS_SECP256K1 + 1];
    char beta_golden[GFS_SECP256K1 + 1];
    octet BETA = {0, sizeof(beta), beta};
    octet BETA_GOLDEN = {0, sizeof(beta_golden), beta_golden};
    const char *BETAline = "BETA = ";

    char t[GGS_SECP256K1];
    char t_golden[GGS_SECP256K1];
    octet T = {0, sizeof(t), t};
    octet T_GOLDEN = {0, sizeof(t_golden), t_golden};
    const char *Tline = "T = ";

    char u[GFS_SECP256K1];
    char u_golden[GFS_SECP256K1];
    octet U = {0, sizeof(u), u};
    octet U_GOLDEN = {0, sizeof(u_golden), u_golden};
    const char *Uline = "U = ";

    GG20_ZKP_proof p;
    GG20_ZKP_phase6_commitment c;

    // Line terminating a test vector
    const char *last_line = Uline;

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    /* Test Happy Paths with test vectors */

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        scan_int(&testNo, line, TESTline);

        scan_OCTET(fp, &ALPHA_GOLDEN, line, ALPHAline);
        scan_OCTET(fp, &BETA_GOLDEN,  line, BETAline);

        scan_OCTET(fp, &T_GOLDEN, line, Tline);
        scan_OCTET(fp, &U_GOLDEN, line, Uline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            // Phase 6 Commitment test
            rc = GG20_ZKP_phase6_commitment_fromOctets(&c, &ALPHA_GOLDEN, &BETA_GOLDEN);
            assert_tv(fp, testNo, "GG20_ZKP_phase6_commitment_fromOctet", rc == GG20_ZKP_OK);

            GG20_ZKP_phase6_commitment_toOctets(&ALPHA, &BETA, &c);

            compare_OCT(fp, testNo, "GG20_ZKP_phase6_commitment octets ALPHA", &ALPHA, &ALPHA_GOLDEN);
            compare_OCT(fp, testNo, "GG20_ZKP_phase6_commitment octets BETA",  &BETA,  &BETA_GOLDEN);

            // Proof test
            GG20_ZKP_proof_fromOctets(&p, &T_GOLDEN, &U_GOLDEN);
            GG20_ZKP_proof_toOctets(&T, &U, &p);

            compare_OCT(fp, testNo, "GG20_ZKP_proof octet T", &T, &T_GOLDEN);
            compare_OCT(fp, testNo, "GG20_ZKP_proof octet U", &U, &U_GOLDEN);

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

    // Invalid Phase 6 Commitment ALPHA
    rc = GG20_ZKP_phase6_commitment_fromOctets(&c, &T, &BETA);
    assert(fp, "GG20_ZKP_phase6_commitment_fromOctets invalid ALPHA", rc == GG20_ZKP_INVALID_ECP);


    // Invalid Phase 6 Commitment BETA
    rc = GG20_ZKP_phase6_commitment_fromOctets(&c, &ALPHA, &U);
    assert(fp, "GG20_ZKP_phase6_commitment_fromOctets invalid BETA", rc == GG20_ZKP_INVALID_ECP);

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
