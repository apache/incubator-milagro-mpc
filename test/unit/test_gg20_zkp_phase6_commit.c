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

/* GG20 Phase 6 ZKP commit unit test */

#include <string.h>
#include "test.h"
#include "amcl/gg20_zkp.h"

#define LINE_LEN 1024

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_gg20_zkp_phase6_commit [path to test vector file]\n");
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

    GG20_ZKP_rv rv;
    const char *Aline = "A = ";
    const char *Bline = "B = ";

    GG20_ZKP_phase6_commitment c;
    GG20_ZKP_phase6_commitment c_golden;
    const char *ALPHAline = "ALPHA = ";
    const char *BETAline = "BETA = ";

    // Line terminating a test vector
    const char *last_line = BETAline;

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        scan_int(&testNo, line, TESTline);

        scan_OCTET(fp, &R, line, Rline);

        scan_BIG_256_56(fp, rv.a, line, Aline);
        scan_BIG_256_56(fp, rv.b, line, Bline);

        scan_ECP_SECP256K1(fp, &(c_golden.ALPHA), line, ALPHAline);
        scan_ECP_SECP256K1(fp, &(c_golden.BETA),  line, BETAline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            rc = GG20_ZKP_phase6_commit(NULL, &R, &rv, &c);
            assert_tv(fp, testNo, "GG20_ZKP_phase6_commit", rc == GG20_ZKP_OK);

            compare_ECP_SECP256K1(fp, testNo, "GG20_ZKP_phase6_commit ALPHA", &(c.ALPHA), &(c_golden.ALPHA));
            compare_ECP_SECP256K1(fp, testNo, "GG20_ZKP_phase6_commit BETA",  &(c.BETA),  &(c_golden.BETA));

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

    // Test invalid R
    R.val[0] = 0xFF;
    rc = GG20_ZKP_phase6_commit(NULL, &R, &rv, &c);
    assert(NULL, "GG20_ZKP_phase6_commit invalid R", rc == GG20_ZKP_INVALID_ECP);

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
