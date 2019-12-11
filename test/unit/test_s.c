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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <amcl/randapi.h>
#include <amcl/ecdh_SECP256K1.h>
#include <amcl/ecdh_support.h>
#include <amcl/paillier.h>
#include <amcl/mpc.h>

#define LINE_LEN 2000


int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_paillier_decrypt [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int len=0;
    FILE *fp;

    char line[LINE_LEN]= {0};
    char *linePtr=NULL;

    int applyVector=0;

    const char* TESTline = "TEST = ";
    int testNo=0;

    // Test result
    int result=0;
    const char* RESULTline = "RESULT = ";

    // Alice
    char n1[FS_2048]= {0};
    octet N1 = {0,sizeof(n1),n1};
    const char* N1line = "N1 = ";

    char g1[FS_2048]= {0};
    octet G1 = {0,sizeof(g1),g1};
    const char* G1line = "G1 = ";

    char l1[FS_2048] = {0};
    octet L1 = {0,sizeof(l1),l1};
    const char* L1line = "L1 = ";

    char m1[FS_2048]= {0};
    octet M1 = {0,sizeof(m1),m1};
    const char* M1line = "M1 = ";

    char k1[FS_2048]= {0};
    octet K1 = {0,sizeof(k1),k1};
    const char* K1line = "K1 = ";

    char w1[FS_2048]= {0};
    octet W1 = {0,sizeof(w1),w1};
    const char* W1line = "W1 = ";

    char r21[FS_2048]= {0};
    octet R21 = {0,sizeof(r21),r21};
    const char* R21line = "R21 = ";

    char r11[FS_2048]= {0};
    octet R11 = {0,sizeof(r11),r11};
    const char* R11line = "R11 = ";

    char z21[FS_2048]= {0};
    octet Z21 = {0,sizeof(z21),z21};
    const char* Z21line = "Z21 = ";

    // Bob
    char n2[FS_2048]= {0};
    octet N2 = {0,sizeof(n2),n2};
    const char* N2line = "N2 = ";

    char g2[FS_2048]= {0};
    octet G2 = {0,sizeof(g2),g2};
    const char* G2line = "G2 = ";

    char l2[FS_2048] = {0};
    octet L2 = {0,sizeof(l2),l2};
    const char* L2line = "L2 = ";

    char m2[FS_2048]= {0};
    octet M2 = {0,sizeof(m2),m2};
    const char* M2line = "M2 = ";

    char k2[FS_2048]= {0};
    octet K2 = {0,sizeof(k2),k2};
    const char* K2line = "K2 = ";

    char w2[FS_2048]= {0};
    octet W2 = {0,sizeof(w2),w2};
    const char* W2line = "W2 = ";

    char r22[FS_2048]= {0};
    octet R22 = {0,sizeof(r22),r22};
    const char* R22line = "R22 = ";

    char r12[FS_2048]= {0};
    octet R12 = {0,sizeof(r12),r12};
    const char* R12line = "R12 = ";

    char z12[FS_2048]= {0};
    octet Z12 = {0,sizeof(z12),z12};
    const char* Z12line = "Z12 = ";

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

    char ca11[FS_4096];
    octet CA11 = {0,sizeof(ca11),ca11};

    char ca22[FS_4096];
    octet CA22 = {0,sizeof(ca22),ca22};

    char cb21[FS_4096];
    octet CB21 = {0,sizeof(cb21),cb21};

    char cb12[FS_4096];
    octet CB12 = {0,sizeof(cb12),cb12};

    char sig_r[EGS_SECP256K1];
    octet SIG_R = {0,sizeof(sig_r),sig_r};
    const char* SIG_Rline = "SIG_R = ";

    char sig_sgolden[EGS_SECP256K1];
    octet SIG_SGOLDEN = {0,sizeof(sig_sgolden),sig_sgolden};
    const char* SIG_Sline = "SIG_S = ";

    char sig_s1[EGS_SECP256K1];
    octet SIG_S1 = {0,sizeof(sig_s1),sig_s1};

    char sig_s2[EGS_SECP256K1];
    octet SIG_S2 = {0,sizeof(sig_s2),sig_s2};

    char sig_s[EGS_SECP256K1];
    octet SIG_S = {0,sizeof(sig_s),sig_s};

    char m[2000];
    octet M = {0,sizeof(m),m};
    const char* Mline = "M = ";

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        // Read TEST Number
        if (!strncmp(line,TESTline, strlen(TESTline)))
        {
            len = strlen(TESTline);
            linePtr = line + len;
            sscanf(linePtr,"%d\n",&testNo);
            printf("TEST = %d\n",testNo);
        }

        // Read N1
        if (!strncmp(line,N1line, strlen(N1line)))
        {
            len = strlen(N1line);
            linePtr = line + len;
            read_OCTET(&N1,linePtr);
#ifdef DEBUG
            printf("N1 = ");
            OCT_output(&N1);
#endif
        }

        // Read G1
        if (!strncmp(line,G1line, strlen(G1line)))
        {
            len = strlen(G1line);
            linePtr = line + len;
            read_OCTET(&G1,linePtr);
#ifdef DEBUG
            printf("G1 = ");
            OCT_output(&G1);
#endif
        }

        // Read L1
        if (!strncmp(line,L1line, strlen(L1line)))
        {
            len = strlen(L1line);
            linePtr = line + len;
            read_OCTET(&L1,linePtr);
#ifdef DEBUG
            printf("L1 = ");
            OCT_output(&L1);
#endif
        }

        // Read M1
        if (!strncmp(line,M1line, strlen(M1line)))
        {
            len = strlen(M1line);
            linePtr = line + len;
            read_OCTET(&M1,linePtr);
#ifdef DEBUG
            printf("M1 = ");
            OCT_output(&M1);
#endif
        }

        // Read K1
        if (!strncmp(line,K1line, strlen(K1line)))
        {
            len = strlen(K1line);
            linePtr = line + len;
            read_OCTET(&K1,linePtr);
#ifdef DEBUG
            printf("K1 = ");
            OCT_output(&K1);
#endif
        }

        // Read W1
        if (!strncmp(line,W1line, strlen(W1line)))
        {
            len = strlen(W1line);
            linePtr = line + len;
            read_OCTET(&W1,linePtr);
#ifdef DEBUG
            printf("W1 = ");
            OCT_output(&W1);
#endif
        }

        // Read R21
        if (!strncmp(line,R21line, strlen(R21line)))
        {
            len = strlen(R21line);
            linePtr = line + len;
            read_OCTET(&R21,linePtr);
#ifdef DEBUG
            printf("R21 = ");
            OCT_output(&R21);
#endif
        }

        // Read R11
        if (!strncmp(line,R11line, strlen(R11line)))
        {
            len = strlen(R11line);
            linePtr = line + len;
            read_OCTET(&R11,linePtr);
#ifdef DEBUG
            printf("R11 = ");
            OCT_output(&R11);
#endif
        }

        // Read Z21
        if (!strncmp(line,Z21line, strlen(Z21line)))
        {
            len = strlen(Z21line);
            linePtr = line + len;
            read_OCTET(&Z21,linePtr);
#ifdef DEBUG
            printf("Z21 = ");
            OCT_output(&Z21);
#endif
        }

        // Read N2
        if (!strncmp(line,N2line, strlen(N2line)))
        {
            len = strlen(N2line);
            linePtr = line + len;
            read_OCTET(&N2,linePtr);
#ifdef DEBUG
            printf("N2 = ");
            OCT_output(&N2);
#endif
        }

        // Read G2
        if (!strncmp(line,G2line, strlen(G2line)))
        {
            len = strlen(G2line);
            linePtr = line + len;
            read_OCTET(&G2,linePtr);
#ifdef DEBUG
            printf("G2 = ");
            OCT_output(&G2);
#endif
        }

        // Read L2
        if (!strncmp(line,L2line, strlen(L2line)))
        {
            len = strlen(L2line);
            linePtr = line + len;
            read_OCTET(&L2,linePtr);
#ifdef DEBUG
            printf("L2 = ");
            OCT_output(&L2);
#endif
        }

        // Read M2
        if (!strncmp(line,M2line, strlen(M2line)))
        {
            len = strlen(M2line);
            linePtr = line + len;
            read_OCTET(&M2,linePtr);
#ifdef DEBUG
            printf("M2 = ");
            OCT_output(&M2);
#endif
        }

        // Read K2
        if (!strncmp(line,K2line, strlen(K2line)))
        {
            len = strlen(K2line);
            linePtr = line + len;
            read_OCTET(&K2,linePtr);
#ifdef DEBUG
            printf("K2 = ");
            OCT_output(&K2);
#endif
        }

        // Read W2
        if (!strncmp(line,W2line, strlen(W2line)))
        {
            len = strlen(W2line);
            linePtr = line + len;
            read_OCTET(&W2,linePtr);
#ifdef DEBUG
            printf("W2 = ");
            OCT_output(&W2);
#endif
        }

        // Read R22
        if (!strncmp(line,R22line, strlen(R22line)))
        {
            len = strlen(R22line);
            linePtr = line + len;
            read_OCTET(&R22,linePtr);
#ifdef DEBUG
            printf("R22 = ");
            OCT_output(&R22);
#endif
        }

        // Read R12
        if (!strncmp(line,R12line, strlen(R12line)))
        {
            len = strlen(R12line);
            linePtr = line + len;
            read_OCTET(&R12,linePtr);
#ifdef DEBUG
            printf("R12 = ");
            OCT_output(&R12);
#endif
        }

        // Read Z12
        if (!strncmp(line,Z12line, strlen(Z12line)))
        {
            len = strlen(Z12line);
            linePtr = line + len;
            read_OCTET(&Z12,linePtr);
#ifdef DEBUG
            printf("Z12 = ");
            OCT_output(&Z12);
#endif
        }

        // Read SIG_R
        if (!strncmp(line,SIG_Rline, strlen(SIG_Rline)))
        {
            len = strlen(SIG_Rline);
            linePtr = line + len;
            read_OCTET(&SIG_R,linePtr);
#ifdef DEBUG
            printf("SIG_R = ");
            OCT_output(&SIG_R);
#endif
        }

        // Read SIG_S
        if (!strncmp(line,SIG_Sline, strlen(SIG_Sline)))
        {
            len = strlen(SIG_Sline);
            linePtr = line + len;
            read_OCTET(&SIG_SGOLDEN,linePtr);
#ifdef DEBUG
            printf("SIG_SGOLDEN = ");
            OCT_output(&SIG_SGOLDEN);
#endif
        }

        // Read M
        if (!strncmp(line,Mline, strlen(Mline)))
        {
            len = strlen(Mline);
            linePtr = line + len;
            read_OCTET(&M,linePtr);
#ifdef DEBUG
            printf("M = ");
            OCT_output(&M);
#endif
        }

        // Read expected result
        if (!strncmp(line,RESULTline, strlen(RESULTline)))
        {
            len = strlen(RESULTline);
            linePtr = line + len;
            sscanf(linePtr,"%d\n",&result);
            applyVector=1;
#ifdef DEBUG
            printf("RESULT = %d\n\n", result);
#endif
        }

        if (applyVector)
        {
            applyVector=0;

            // ALPHA1 + BETA2 = K1 * W2
            int rc = MPC_MTA_CLIENT1(NULL, &N1, &G1, &K1, &CA11, &R11);
            if (rc)
            {
                fprintf(stderr, "FAILURE MPC_MTA_CLIENT1 Test %d rc: %d\n", testNo, rc);
                fclose(fp);
                exit(EXIT_FAILURE);
            }

            rc = MPC_MTA_SERVER(NULL,  &N1, &G1, &W2, &CA11, &Z12, &R12, &CB12, &BETA2);
            if (rc)
            {
                fprintf(stderr, "FAILURE MPC_MTA_SERVER Test %d rc: %d\n", testNo, rc);
                fclose(fp);
                exit(EXIT_FAILURE);
            }

            rc = MPC_MTA_CLIENT2(&N1, &L1, &M1, &CB12, &ALPHA1);
            if (rc)
            {
                fprintf(stderr, "FAILURE MPC_MTA_CLIENT2 Test %d rc: %d\n", testNo, rc);
                fclose(fp);
                exit(EXIT_FAILURE);
            }

            // ALPHA2 + BETA1 = K2 * W1
            rc = MPC_MTA_CLIENT1(NULL, &N2, &G2, &K2, &CA22, &R22);
            if (rc)
            {
                fprintf(stderr, "FAILURE MPC_MTA_CLIENT1 rc: %d\n", rc);
                exit(EXIT_FAILURE);
            }

            rc = MPC_MTA_SERVER(NULL,  &N2, &G2, &W1, &CA22, &Z21, &R21, &CB21, &BETA1);
            if (rc)
            {
                fprintf(stderr, "FAILURE MPC_MTA_SERVER rc: %d\n", rc);
                exit(EXIT_FAILURE);
            }

            rc = MPC_MTA_CLIENT2(&N2, &L2, &M2, &CB21, &ALPHA2);
            if (rc)
            {
                fprintf(stderr, "FAILURE MPC_MTA_CLIENT2 rc: %d\n", rc);
                exit(EXIT_FAILURE);
            }

            // sum = K1.W1 + alpha1  + beta1
            rc = MPC_SUM_MTA(&K1, &W1, &ALPHA1, &BETA1, NULL, NULL, &SUM1);
            if (rc)
            {
                fprintf(stderr, "FAILURE MPC_SUM_MTA rc: %d\n", rc);
                exit(EXIT_FAILURE);
            }

            // sum = K2.W2 + alpha2  + beta2
            rc = MPC_SUM_MTA(&K2, &W2, &ALPHA2, &BETA2, NULL, NULL, &SUM2);
            if (rc)
            {
                fprintf(stderr, "FAILURE MPC_SUM_MTA rc: %d\n", rc);
                exit(EXIT_FAILURE);
            }

            // Calculate the S1 signature component
            rc = MPC_S(HASH_TYPE_SECP256K1, &M, &SIG_R, &K1, &SUM1, &SIG_S1);
            if (rc)
            {
                fprintf(stderr, "FAILURE MPC_S rc: %d\n", rc);
                exit(EXIT_FAILURE);
            }

            // Calculate the S2 signature component
            rc = MPC_S(HASH_TYPE_SECP256K1, &M, &SIG_R, &K2, &SUM2, &SIG_S2);
            if (rc)
            {
                fprintf(stderr, "FAILURE MPC_S rc: %d\n", rc);
                exit(EXIT_FAILURE);
            }

            // Sum S signature component
            rc = MPC_SUM_S(&SIG_S1, &SIG_S2, NULL, &SIG_S);
            if (rc)
            {
                fprintf(stderr, "FAILURE MPC_SUM_S rc: %d\n", rc);
                exit(EXIT_FAILURE);
            }

#ifdef DEBUG
            printf("SIG_S: ");
            OCT_output(&SIG_S);
            printf("\n");
#endif

            // OCT_comp return 1 for equal
            rc = !(OCT_comp(&SIG_S,&SIG_SGOLDEN));
            if(rc != result)
            {
                fprintf(stderr, "FAILURE SIG_S != SIG_SGOLDEN rc: %d\n", rc);
                exit(EXIT_FAILURE);
            }

        }
    }
    fclose(fp);
    printf("SUCCESS TEST R GENERATION PASSED\n");
    exit(EXIT_SUCCESS);
}

