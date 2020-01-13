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
#include <time.h>
#include <amcl/randapi.h>
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

    int rc=0;

    int len=0;
    FILE *fp;

    char line[LINE_LEN]= {0};
    char *linePtr=NULL;

    int applyVector=0;

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

        // Read P
        if (!strncmp(line,Pline, strlen(Pline)))
        {
            len = strlen(Pline);
            linePtr = line + len;
            read_OCTET(&P,linePtr);
#ifdef DEBUG
            printf("P = ");
            OCT_output(&P);
#endif
        }

        // Read Q
        if (!strncmp(line,Qline, strlen(Qline)))
        {
            len = strlen(Qline);
            linePtr = line + len;
            read_OCTET(&Q,linePtr);
#ifdef DEBUG
            printf("Q = ");
            OCT_output(&Q);
#endif
        }

        // Read A
        if (!strncmp(line,Aline, strlen(Aline)))
        {
            len = strlen(Aline);
            linePtr = line + len;
            read_OCTET(&A,linePtr);
#ifdef DEBUG
            printf("A = ");
            OCT_output(&A);
#endif
        }

        // Read B
        if (!strncmp(line,Bline, strlen(Bline)))
        {
            len = strlen(Bline);
            linePtr = line + len;
            read_OCTET(&B,linePtr);
#ifdef DEBUG
            printf("B = ");
            OCT_output(&B);
#endif
        }

        // Read Z
        if (!strncmp(line,Zline, strlen(Zline)))
        {
            len = strlen(Zline);
            linePtr = line + len;
            read_OCTET(&Z,linePtr);
#ifdef DEBUG
            printf("Z = ");
            OCT_output(&Z);
#endif
        }

        // Read R1
        if (!strncmp(line,R1line, strlen(R1line)))
        {
            len = strlen(R1line);
            linePtr = line + len;
            read_OCTET(&R1,linePtr);
#ifdef DEBUG
            printf("R1 = ");
            OCT_output(&R1);
#endif
        }

        // Read R2
        if (!strncmp(line,R2line, strlen(R2line)))
        {
            len = strlen(R2line);
            linePtr = line + len;
            read_OCTET(&R2,linePtr);
#ifdef DEBUG
            printf("R2 = ");
            OCT_output(&R2);
#endif
        }

        // Read CAGOLDEN
        if (!strncmp(line,CAline, strlen(CAline)))
        {
            len = strlen(CAline);
            linePtr = line + len;
            read_OCTET(&CAGOLDEN,linePtr);
#ifdef DEBUG
            printf("CA = ");
            OCT_output(&CAGOLDEN);
#endif
        }

        // Read CBGOLDEN
        if (!strncmp(line,CBline, strlen(CBline)))
        {
            len = strlen(CBline);
            linePtr = line + len;
            read_OCTET(&CBGOLDEN,linePtr);
#ifdef DEBUG
            printf("CB = ");
            OCT_output(&CBGOLDEN);
#endif
        }

        // Read ALPHAGOLDEN
        if (!strncmp(line,ALPHAline, strlen(ALPHAline)))
        {
            len = strlen(ALPHAline);
            linePtr = line + len;
            read_OCTET(&ALPHAGOLDEN,linePtr);
#ifdef DEBUG
            printf("ALPHA = ");
            OCT_output(&ALPHAGOLDEN);
#endif
        }

        // Read BETAGOLDEN
        if (!strncmp(line,BETAline, strlen(BETAline)))
        {
            len = strlen(BETAline);
            linePtr = line + len;
            read_OCTET(&BETAGOLDEN,linePtr);
#ifdef DEBUG
            printf("BETA = ");
            OCT_output(&BETAGOLDEN);
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

            //  Paillier key pair
            PAILLIER_KEY_PAIR(NULL, &P, &Q, &PUB, &PRIV);

            MPC_MTA_CLIENT1(NULL, &PUB, &A, &CA, &R1);

#ifdef DEBUG
            printf("CA: ");
            OCT_output(&CA);
            printf("\n");
#endif

            // OCT_comp return 1 for equal
            rc = !(OCT_comp(&CA,&CAGOLDEN));
            if(rc != result)
            {
                fprintf(stderr, "FAILURE Test %d CA != CAGOLDEN \n", testNo);
                fclose(fp);
                exit(EXIT_FAILURE);
            }

            MPC_MTA_SERVER(NULL, &PUB, &B, &CA, &Z, &R2, &CB, &BETA);

#ifdef DEBUG
            printf("CB: ");
            OCT_output(&CB);
            printf("\n");
            printf("BETA: ");
            OCT_output(&BETA);
            printf("\n");
#endif

            // OCT_comp return 1 for equal
            rc = !(OCT_comp(&CB,&CBGOLDEN));
            if(rc != result)
            {
                fprintf(stderr, "FAILURE Test %d CB != CBGOLDEN \n", testNo);
                fclose(fp);
                exit(EXIT_FAILURE);
            }

            // OCT_comp return 1 for equal
            rc = !(OCT_comp(&BETA,&BETAGOLDEN));
            if(rc != result)
            {
                fprintf(stderr, "FAILURE Test %d BETA != BETAGOLDEN \n", testNo);
                fclose(fp);
                exit(EXIT_FAILURE);
            }

            MPC_MTA_CLIENT2(&PRIV, &CB, &ALPHA);

#ifdef DEBUG
            printf("ALPHA: ");
            OCT_output(&ALPHA);
            printf("\n");
#endif

            // OCT_comp return 1 for equal
            rc = !(OCT_comp(&ALPHA,&ALPHAGOLDEN));
            if(rc != result)
            {
                fprintf(stderr, "FAILURE Test %d ALPHA != ALPHAGOLDEN \n", testNo);
                fclose(fp);
                exit(EXIT_FAILURE);
            }

        }
    }
    fclose(fp);
    printf("SUCCESS TEST MTA PASSED\n");
    exit(EXIT_SUCCESS);
}

