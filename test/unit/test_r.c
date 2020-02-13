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
#include <amcl/ecdh_SECP256K1.h>
#include <amcl/mta.h>
#include <amcl/mpc.h>
#include "test.h"

#define LINE_LEN 2000

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_r [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int rc;
    int test_run = 0;

    char err_msg[128];

    FILE *fp;
    char line[LINE_LEN]= {0};

    const char* TESTline = "TEST = ";
    int testNo=0;

    // Test result
    int result=0;
    const char* RESULTline = "RESULT = ";

    // Alice
    char p1[FS_2048]= {0};
    octet P1 = {0,sizeof(p1),p1};
    const char* P1line = "P1 = ";

    char q1[FS_2048]= {0};
    octet Q1 = {0,sizeof(q1),q1};
    const char* Q1line = "Q1 = ";

    char a1[FS_2048]= {0};
    octet A1 = {0,sizeof(a1),a1};
    const char* A1line = "A1 = ";

    char b1[FS_2048]= {0};
    octet B1 = {0,sizeof(b1),b1};
    const char* B1line = "B1 = ";

    char r21[FS_4096]= {0};
    octet R21 = {0,sizeof(r21),r21};
    const char* R21line = "R21 = ";

    char r11[FS_4096]= {0};
    octet R11 = {0,sizeof(r11),r11};
    const char* R11line = "R11 = ";

    char z21[FS_2048]= {0};
    octet Z21 = {0,sizeof(z21),z21};
    const char* Z21line = "Z21 = ";

    // Bob
    char p2[FS_2048]= {0};
    octet P2 = {0,sizeof(p2),p2};
    const char* P2line = "P2 = ";

    char q2[FS_2048]= {0};
    octet Q2 = {0,sizeof(q2),q2};
    const char* Q2line = "Q2 = ";

    char a2[FS_2048]= {0};
    octet A2 = {0,sizeof(a2),a2};
    const char* A2line = "A2 = ";

    char b2[FS_2048]= {0};
    octet B2 = {0,sizeof(b2),b2};
    const char* B2line = "B2 = ";

    char r22[FS_4096]= {0};
    octet R22 = {0,sizeof(r22),r22};
    const char* R22line = "R22 = ";

    char r12[FS_4096]= {0};
    octet R12 = {0,sizeof(r12),r12};
    const char* R12line = "R12 = ";

    char z12[FS_2048]= {0};
    octet Z12 = {0,sizeof(z12),z12};
    const char* Z12line = "Z12 = ";

    char gammapt1[EFS_SECP256K1+1];
    octet GAMMAPT1 = {0,sizeof(gammapt1),gammapt1};
    const char* GAMMAPT1line = "GAMMAPT1 = ";

    char gammapt2[EFS_SECP256K1+1];
    octet GAMMAPT2 = {0,sizeof(gammapt2),gammapt2};
    const char* GAMMAPT2line = "GAMMAPT2 = ";

    char sig_rgolden[EGS_SECP256K1];
    octet SIG_RGOLDEN = {0,sizeof(sig_rgolden),sig_rgolden};
    const char* SIG_Rline = "SIG_R = ";

    char alpha1[EGS_SECP256K1];
    octet ALPHA1 = {0,sizeof(alpha1),alpha1};

    char beta1[EGS_SECP256K1];
    octet BETA1 = {0,sizeof(beta1),beta1};

    char alpha2[EGS_SECP256K1];
    octet ALPHA2 = {0,sizeof(alpha2),alpha2};

    char beta2[EGS_SECP256K1];
    octet BETA2 = {0,sizeof(beta2),beta2};

    char sum1[EGS_SECP256K1];
    octet SUM1 = {0,sizeof(sum1),sum1};

    char sum2[EGS_SECP256K1];
    octet SUM2 = {0,sizeof(sum2),sum2};

    char invkgamma[EGS_SECP256K1];
    octet INVKGAMMA = {0,sizeof(invkgamma),invkgamma};

    char sig_r[EGS_SECP256K1];
    octet SIG_R = {0,sizeof(sig_r),sig_r};

    char ca11[FS_4096];
    octet CA11 = {0,sizeof(ca11),ca11};

    char ca22[FS_4096];
    octet CA22 = {0,sizeof(ca22),ca22};

    char cb21[FS_4096];
    octet CB21 = {0,sizeof(cb21),cb21};

    char cb12[FS_4096];
    octet CB12 = {0,sizeof(cb12),cb12};

    // Paillier Keys
    PAILLIER_private_key PRIV1;
    PAILLIER_public_key PUB1;
    PAILLIER_private_key PRIV2;
    PAILLIER_public_key PUB2;

    // Line terminating a test vector
    const char *last_line = RESULTline;

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
        scan_OCTET(fp, &P1, line,  P1line);
        scan_OCTET(fp, &Q1, line,  Q1line);
        scan_OCTET(fp, &A1, line,  A1line);
        scan_OCTET(fp, &B1, line,  B1line);
        scan_OCTET(fp, &R11, line, R11line);
        scan_OCTET(fp, &R21, line, R21line);
        scan_OCTET(fp, &Z21, line, Z21line);

        scan_OCTET(fp, &P2, line,  P2line);
        scan_OCTET(fp, &Q2, line,  Q2line);
        scan_OCTET(fp, &A2, line,  A2line);
        scan_OCTET(fp, &B2, line,  B2line);
        scan_OCTET(fp, &R12, line, R12line);
        scan_OCTET(fp, &R22, line, R22line);
        scan_OCTET(fp, &Z12, line, Z12line);

        scan_OCTET(fp, &GAMMAPT1, line, GAMMAPT1line);
        scan_OCTET(fp, &GAMMAPT2, line, GAMMAPT2line);

        // Read ground truth
        scan_OCTET(fp, &SIG_RGOLDEN, line, SIG_Rline);

        scan_int(&result, line, RESULTline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            // Generating Paillier key pairs
            PAILLIER_KEY_PAIR(NULL, &P1, &Q1, &PUB1, &PRIV1);
            PAILLIER_KEY_PAIR(NULL, &P2, &Q2, &PUB2, &PRIV2);

            // ALPHA1 + BETA2 = A1 * B2
            MPC_MTA_CLIENT1(NULL, &PUB1, &A1, &CA11, &R11);

            MPC_MTA_SERVER(NULL,  &PUB1, &B2, &CA11, &Z12, &R12, &CB12, &BETA2);

            MPC_MTA_CLIENT2(&PRIV1, &CB12, &ALPHA1);

            // ALPHA2 + BETA1 = A2 * B1
            MPC_MTA_CLIENT1(NULL, &PUB2, &A2, &CA22, &R22);

            MPC_MTA_SERVER(NULL,  &PUB2, &B1, &CA22, &Z21, &R21, &CB21, &BETA1);

            MPC_MTA_CLIENT2(&PRIV2, &CB21, &ALPHA2);

            // sum = A1.B1 + alpha1 + beta1
            MPC_SUM_MTA(&A1, &B1, &ALPHA1, &BETA1, &SUM1);

            // sum = A2.B2 + alpha2 + beta2
            MPC_SUM_MTA(&A2, &B2, &ALPHA2, &BETA2, &SUM2);

            // Calculate the inverse of kgamma
            MPC_INVKGAMMA(&SUM1, &SUM2, &INVKGAMMA);

            // Calculate the R signature component
            rc = MPC_R(&INVKGAMMA, &GAMMAPT1, &GAMMAPT2, &SIG_R);

            sprintf(err_msg, "MPC_R rc: %d", rc);
            assert_tv(fp, testNo, err_msg, rc == 0);
            compare_OCT(fp, testNo, "SIG_R != SIG_RGOLDEN", &SIG_R, &SIG_RGOLDEN);

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

    printf("SUCCESS TEST R GENERATION PASSED\n");
    exit(EXIT_SUCCESS);
}
