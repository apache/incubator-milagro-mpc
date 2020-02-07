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
#include "amcl/mpc.h"
#include "amcl/ecdh_SECP256K1.h"

/* MPC Phase 5 commitment unit test */

#define LINE_LEN 256

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_phase5_commit [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int rc;
    int test_run = 0;

    char err_msg[128];

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    char s[EGS_SECP256K1];
    octet S = {0, sizeof(s), s};
    const char *Sline = "S = ";

    char r[EFS_SECP256K1 + 1];
    octet R = {0, sizeof(r), r};
    const char *Rline = "R = ";

    char phi[EGS_SECP256K1];
    octet PHI = {0, sizeof(phi), phi};
    const char *PHIline = "PHI = ";

    char rho[EGS_SECP256K1];
    octet RHO = {0, sizeof(rho), rho};
    const char *RHOline = "RHO = ";

    char v_golden[EFS_SECP256K1 + 1];
    octet V_GOLDEN = {0, sizeof(v_golden), v_golden};
    const char *Vline = "V1 = ";

    char a_golden[EFS_SECP256K1 + 1];
    octet A_GOLDEN = {0, sizeof(a_golden), a_golden};
    const char *Aline = "A1 = ";

    char v[EFS_SECP256K1 + 1];
    octet V = {0, sizeof(v), v};

    char a[EFS_SECP256K1 + 1];
    octet A = {0, sizeof(a), a};

    // Line terminating a test vector
    const char *last_line = Aline;

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        scan_int(&testNo, line, TESTline);

        // Read input
        scan_OCTET(fp, &S,   line, Sline);
        scan_OCTET(fp, &R,   line, Rline);
        scan_OCTET(fp, &PHI, line, PHIline);
        scan_OCTET(fp, &RHO, line, RHOline);

        // Read ground truth
        scan_OCTET(fp, &V_GOLDEN, line, Vline);
        scan_OCTET(fp, &A_GOLDEN, line, Aline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            rc = MPC_PHASE5_commit(NULL, &R, &S, &PHI, &RHO, &V, &A);
            sprintf(err_msg, "FAILURE MPC_PHASE5_commit. RC %d", rc);
            assert_tv(fp, testNo, err_msg, rc == MPC_OK);

            compare_OCT(fp, testNo, "FAILURE MPC_PHASE5_commit V", &V, &V_GOLDEN);
            compare_OCT(fp, testNo, "FAILURE MPC_PHASE5_commit A", &A, &A_GOLDEN);

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

    rc = MPC_PHASE5_commit(NULL, &S, &S, &PHI, &RHO, &V, &A);
    sprintf(err_msg, "FAILURE MPC_PHASE5_commit invalid R. RC %d", rc);
    assert_tv(fp, testNo, err_msg, rc == MPC_INVALID_ECP);

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
