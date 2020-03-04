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

/* MPC Phase 5 verification unit test */

#define LINE_LEN 256

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_phase5_verify [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int rc;
    int test_run = 0;

    char err_msg[128];

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    char u1[EFS_SECP256K1 + 1];
    octet U1 = {0, sizeof(u1), u1};
    const char *U1line = "U1 = ";

    char u2[EFS_SECP256K1 + 1];
    octet U2 = {0, sizeof(u2), u2};
    const char *U2line = "U2 = ";

    octet *U[2] = {&U1, &U2};

    char t1[EFS_SECP256K1 + 1];
    octet T1 = {0, sizeof(t1), t1};
    const char *T1line = "T1 = ";

    char t2[EFS_SECP256K1 + 1];
    octet T2 = {0, sizeof(t2), t2};
    const char *T2line = "T2 = ";

    octet *T[2] = {&T1, &T2};

    char zero[EGS_SECP256K1];
    octet ZERO = {0, sizeof(zero), zero};

    // Line terminating a test vector
    const char *last_line = T2line;

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
        scan_OCTET(fp, &U1, line, U1line);
        scan_OCTET(fp, &U2, line, U2line);
        scan_OCTET(fp, &T1, line, T1line);
        scan_OCTET(fp, &T2, line, T2line);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            rc = MPC_PHASE5_verify(U, T);
            sprintf(err_msg, "FAILURE MPC_PHASE5_verify. RC %d", rc);
            assert_tv(fp, testNo, err_msg, rc == MPC_OK);

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

    OCT_clear(&ZERO);
    ZERO.len = ZERO.max;

    // Invalid U[0]
    U[0] = &ZERO;

    rc = MPC_PHASE5_verify(U, T);
    sprintf(err_msg, "FAILURE MPC_PHASE5_verify invalid U1. RC %d", rc);
    assert_tv(fp, testNo, err_msg, rc == MPC_INVALID_ECP);

    U[0] = &U1;

    // Invalid U[1]
    U[1] = &ZERO;

    rc = MPC_PHASE5_verify(U, T);
    sprintf(err_msg, "FAILURE MPC_PHASE5_verify invalid U2. RC %d", rc);
    assert_tv(fp, testNo, err_msg, rc == MPC_INVALID_ECP);

    U[1] = &U2;

    // Invalid T[0]
    T[0] = &ZERO;

    rc = MPC_PHASE5_verify(U, T);
    sprintf(err_msg, "FAILURE MPC_PHASE5_verify invalid T1. RC %d", rc);
    assert_tv(fp, testNo, err_msg, rc == MPC_INVALID_ECP);

    T[0] = &T1;

    // Invalid T[1]
    T[1] = &ZERO;

    rc = MPC_PHASE5_verify(U, T);
    sprintf(err_msg, "FAILURE MPC_PHASE5_verify invalid T2. RC %d", rc);
    assert_tv(fp, testNo, err_msg, rc == MPC_INVALID_ECP);

    T[1] = &T2;

    // Invalid Proof
    T[1] = T[0];

    rc = MPC_PHASE5_verify(U, T);
    sprintf(err_msg, "FAILURE MPC_PHASE5_verify invalid proof. RC %d", rc);
    assert_tv(fp, testNo, err_msg, rc == MPC_FAIL);

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
