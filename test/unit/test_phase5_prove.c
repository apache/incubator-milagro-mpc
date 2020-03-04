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

/* MPC Phase 5 proof unit test */

#define LINE_LEN 256

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_phase5_prove [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int rc;
    int test_run = 0;

    char err_msg[128];

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    char phi[EGS_SECP256K1];
    octet PHI = {0, sizeof(phi), phi};
    const char *PHIline = "PHI = ";

    char rho[EGS_SECP256K1];
    octet RHO = {0, sizeof(rho), rho};
    const char *RHOline = "RHO = ";

    char pk[EFS_SECP256K1 + 1];
    octet PK = {0, sizeof(pk), pk};
    const char *PKline = "PK = ";

    char m[SHA256];
    octet M = {0, sizeof(m), m};
    const char *Mline = "M = ";

    char rx[EFS_SECP256K1 + 1];
    octet RX = {0, sizeof(rx), rx};
    const char *RXline = "RX = ";

    char v1[EFS_SECP256K1 + 1];
    octet V1 = {0, sizeof(v1), v1};
    const char *V1line = "V1 = ";

    char v2[EFS_SECP256K1 + 1];
    octet V2 = {0, sizeof(v2), v2};
    const char *V2line = "V2 = ";

    octet *V[2] = {&V1, &V2};

    char a1[EFS_SECP256K1 + 1];
    octet A1 = {0, sizeof(a1), a1};
    const char *A1line = "A1 = ";

    char a2[EFS_SECP256K1 + 1];
    octet A2 = {0, sizeof(a2), a2};
    const char *A2line = "A2 = ";

    octet *A[2] = {&A1, &A2};

    char u_golden[EFS_SECP256K1 + 1];
    octet U_GOLDEN = {0, sizeof(u_golden), u_golden};
    const char *Uline = "U1 = ";

    char t_golden[EFS_SECP256K1 + 1];
    octet T_GOLDEN = {0, sizeof(t_golden), t_golden};
    const char *Tline = "T1 = ";

    char u[EFS_SECP256K1 + 1];
    octet U = {0, sizeof(u), u};

    char t[EFS_SECP256K1 + 1];
    octet T = {0, sizeof(t), t};

    // Line terminating a test vector
    const char *last_line = Tline;

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
        scan_OCTET(fp, &PHI, line, PHIline);
        scan_OCTET(fp, &RHO, line, RHOline);
        scan_OCTET(fp, &V1,  line, V1line);
        scan_OCTET(fp, &V2,  line, V2line);
        scan_OCTET(fp, &A1,  line, A1line);
        scan_OCTET(fp, &A2,  line, A2line);
        scan_OCTET(fp, &PK,  line, PKline);
        scan_OCTET(fp, &RX,  line, RXline);

        // Read
        scan_OCTET(fp, &M,   line, Mline);

        // Read ground truth
        scan_OCTET(fp, &T_GOLDEN, line, Tline);
        scan_OCTET(fp, &U_GOLDEN, line, Uline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            rc = MPC_PHASE5_prove(&PHI, &RHO, V, A, &PK, &M, &RX, &U, &T);
            sprintf(err_msg, "FAILURE MPC_PHASE5_prove. RC %d", rc);
            assert_tv(fp, testNo, err_msg, rc == MPC_OK);

            compare_OCT(fp, testNo, "FAILURE MPC_PHASE5_prove U", &U, &U_GOLDEN);
            compare_OCT(fp, testNo, "FAILURE MPC_PHASE5_prove T", &T, &T_GOLDEN);

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

    // Invalid V[0]
    V[0] = &PHI;

    rc = MPC_PHASE5_prove(&PHI, &RHO, V, A, &PK, &M, &RX, &U_GOLDEN, &T_GOLDEN);
    sprintf(err_msg, "FAILURE MPC_PHASE5_prove invalid V1. RC %d", rc);
    assert_tv(fp, testNo, err_msg, rc == MPC_INVALID_ECP);

    V[0] = &V1;

    // Invalid V[1]
    V[1] = &PHI;

    rc = MPC_PHASE5_prove(&PHI, &RHO, V, A, &PK, &M, &RX, &U_GOLDEN, &T_GOLDEN);
    sprintf(err_msg, "FAILURE MPC_PHASE5_prove invalid V2. RC %d", rc);
    assert_tv(fp, testNo, err_msg, rc == MPC_INVALID_ECP);

    V[1] = &V2;

    // Invalid A[0]
    A[0] = &PHI;

    rc = MPC_PHASE5_prove(&PHI, &RHO, V, A, &PK, &M, &RX, &U_GOLDEN, &T_GOLDEN);
    sprintf(err_msg, "FAILURE MPC_PHASE5_prove invalid A1. RC %d", rc);
    assert_tv(fp, testNo, err_msg, rc == MPC_INVALID_ECP);

    A[0] = &A1;

    // Invalid A[1]
    A[1] = &PHI;

    rc = MPC_PHASE5_prove(&PHI, &RHO, V, A, &PK, &M, &RX, &U_GOLDEN, &T_GOLDEN);
    sprintf(err_msg, "FAILURE MPC_PHASE5_prove invalid A2. RC %d", rc);
    assert_tv(fp, testNo, err_msg, rc == MPC_INVALID_ECP);

    A[1] = &A2;

    // Invalid PK
    rc = MPC_PHASE5_prove(&PHI, &RHO, V, A, &PHI, &M, &RX, &U_GOLDEN, &T_GOLDEN);
    sprintf(err_msg, "FAILURE MPC_PHASE5_prove invalid PK. RC %d", rc);
    assert_tv(fp, testNo, err_msg, rc == MPC_INVALID_ECP);

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
