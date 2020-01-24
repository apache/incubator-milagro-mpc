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
#include <amcl/paillier.h>
#include <amcl/mpc.h>
#include "test.h"

#define LINE_LEN 2000

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_mta [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN]= {0};

    // Paillier Keys
    PAILLIER_private_key PRIV;
    PAILLIER_public_key PUB;

    const char* TESTline = "TEST = ";
    int testNo=0;

    // Test result
    int result=0;
    const char* RESULTline = "RESULT = ";

    char p[FS_2048]= {0};
    octet P = {0,sizeof(p),p};
    const char* Pline = "P = ";

    char q[FS_2048]= {0};
    octet Q = {0,sizeof(q),q};
    const char* Qline = "Q = ";

    char a[FS_2048]= {0};
    octet A = {0,sizeof(a),a};
    const char* Aline = "A = ";

    char b[FS_2048]= {0};
    octet B = {0,sizeof(b),b};
    const char* Bline = "B = ";

    char z[FS_2048]= {0};
    octet Z = {0,sizeof(z),z};
    const char* Zline = "Z = ";

    char r1[FS_4096]= {0};
    octet R1 = {0,sizeof(r1),r1};
    const char* R1line = "R1 = ";

    char r2[FS_4096]= {0};
    octet R2 = {0,sizeof(r2),r2};
    const char* R2line = "R2 = ";

    char ca[FS_4096]= {0};
    octet CA = {0,sizeof(ca),ca};

    char cagolden[FS_4096]= {0};
    octet CAGOLDEN = {0,sizeof(cagolden),cagolden};
    const char* CAline = "CA = ";

    char cb[FS_4096]= {0};
    octet CB = {0,sizeof(cb),cb};

    char cbgolden[FS_4096]= {0};
    octet CBGOLDEN = {0,sizeof(cbgolden),cbgolden};
    const char* CBline = "CB = ";

    char alpha[FS_2048]= {0};
    octet ALPHA = {0,sizeof(alpha),alpha};

    char alphagolden[FS_2048]= {0};
    octet ALPHAGOLDEN = {0,sizeof(alphagolden),alphagolden};
    const char* ALPHAline = "ALPHA = ";

    char beta[FS_2048]= {0};
    octet BETA = {0,sizeof(beta),beta};

    char betagolden[FS_2048]= {0};
    octet BETAGOLDEN = {0,sizeof(betagolden),betagolden};
    const char* BETAline = "BETA = ";

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
        scan_OCTET(fp, &P,  line, Pline);
        scan_OCTET(fp, &Q,  line, Qline);
        scan_OCTET(fp, &A,  line, Aline);
        scan_OCTET(fp, &B,  line, Bline);
        scan_OCTET(fp, &Z,  line, Zline);
        scan_OCTET(fp, &R1, line, R1line);
        scan_OCTET(fp, &R2, line, R2line);

        // Read ground truth
        scan_OCTET(fp, &CAGOLDEN, line, CAline);
        scan_OCTET(fp, &CBGOLDEN, line, CBline);
        scan_OCTET(fp, &BETAGOLDEN, line, BETAline);
        scan_OCTET(fp, &ALPHAGOLDEN, line, ALPHAline);

        scan_int(&result, line, RESULTline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            //  Paillier key pair
            PAILLIER_KEY_PAIR(NULL, &P, &Q, &PUB, &PRIV);

            MPC_MTA_CLIENT1(NULL, &PUB, &A, &CA, &R1);
            compare_OCT(fp, testNo, "CA != CAGOLDEN", &CA, &CAGOLDEN);

            MPC_MTA_SERVER(NULL, &PUB, &B, &CA, &Z, &R2, &CB, &BETA);
            compare_OCT(fp, testNo, "CB != CBGOLDEN", &CB, &CBGOLDEN);
            compare_OCT(fp, testNo, "BETA != BETAGOLDEN", &BETA, &BETAGOLDEN);

            MPC_MTA_CLIENT2(&PRIV, &CB, &ALPHA);
            compare_OCT(fp, testNo, "ALPHA != ALPHAGOLDEN", &ALPHA, &ALPHAGOLDEN);

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

    printf("SUCCESS TEST MTA PASSED\n");
    exit(EXIT_SUCCESS);
}
