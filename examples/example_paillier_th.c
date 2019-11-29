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

/*
   Example of Paillier crypto system.

   Homomorphic addition of plaintext where the plaintext is an integer

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <amcl/randapi.h>
#include <amcl/paillier.h>

#define NTHREADS 4

int test(csprng *RNG)
{
    int rc;
    char p[FS_2048];
    octet P = {0,sizeof(p),p};
    char q[FS_2048];
    octet Q = {0,sizeof(q),q};

    char n[FS_2048] = {0};
    octet N = {0,sizeof(n),n};
    char g[FS_2048];
    octet G = {0,sizeof(g),g};

    char l[FS_2048] = {0};
    octet L = {0,sizeof(l),l};

    char m[FS_2048] = {0};
    octet M = {0,sizeof(m),m};

    // Plaintext to encrypt
    char ptin[NTHREADS][FS_2048];
    octet PTIN[NTHREADS];
    char ptout[NTHREADS][FS_2048];
    octet PTOUT[NTHREADS];

    // Encrypted PTIN values
    char cto[NTHREADS][FS_4096];
    octet CT[NTHREADS];

    // Homomorphic addition of plaintexts
    char cta[NTHREADS/2][FS_4096];
    octet CTA[NTHREADS/2];
    char cto3[FS_4096] = {0};
    octet CT3 = {0,sizeof(cto3),cto3};

    // output plaintext
    char pto3[FS_2048] = {0};
    octet PT3 = {sizeof(pto3),sizeof(pto3),pto3};

    // Expected ouput is Ox0a
    int values[NTHREADS] = {1,3,4,2};

    // Initialize octets
    for(int i=0; i<NTHREADS; i++)
    {
        memset(ptin[i], 0, FS_2048*sizeof(ptin[i][0]));
        PTIN[i].max = FS_2048;
        PTIN[i].len = 0;
        PTIN[i].val = ptin[i];

        memset(ptout[i], 0, FS_2048*sizeof(ptout[i][0]));
        PTOUT[i].max = FS_2048;
        PTOUT[i].len = 0;
        PTOUT[i].val = ptout[i];

        memset(cto[i], 0, FS_4096*sizeof(cto[i][0]));
        CT[i].max = FS_4096;
        CT[i].len = 0;
        CT[i].val = cto[i];
    }

    for(int i=0; i<NTHREADS/2; i++)
    {
        memset(cta[i], 0, FS_4096*sizeof(cta[i][0]));
        CTA[i].max = FS_4096;
        CTA[i].len = 0;
        CTA[i].val = cta[i];
    }

    printf("Generating public/private key pair\n");
    rc = PAILLIER_KEY_PAIR(RNG, &P, &Q, &N, &G, &L, &M);
    if (rc)
    {
        fprintf(stderr, "ERROR PAILLIER_KEY_PAIR rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("P: ");
    OCT_output(&P);
    printf("\n");
    printf("Q: ");
    OCT_output(&Q);
    printf("\n");

    printf("Public Key \n");
    printf("N: ");
    OCT_output(&N);
    printf("\n");
    printf("G: ");
    OCT_output(&G);
    printf("\n");

    printf("Secret Key \n");
    printf("L: ");
    OCT_output(&L);
    printf("\n");
    printf("M: ");
    OCT_output(&M);
    printf("\n");

    #pragma omp parallel for
    for(int i=0; i<NTHREADS; i++)
    {
        BIG_1024_58 pt[FFLEN_2048];
        FF_2048_init(pt, values[i],FFLEN_2048);
        FF_2048_toOctet(&PTIN[i], pt, FFLEN_2048);
#ifdef DEBUG
        printf("pt ");
        FF_2048_output(pt,FFLEN_2048);
        printf("\n");
#endif
    }

    for(int i=0; i<NTHREADS; i++)
    {
        printf("PTIN[%d] ", i);
        OCT_output(&PTIN[i]);
        printf("\n");
    }

    #pragma omp parallel for
    for(int i=0; i<NTHREADS; i++)
    {
        rc = PAILLIER_ENCRYPT(RNG, &N, &G, &PTIN[i], &CT[i], NULL);
        if (rc)
        {
            fprintf(stderr, "ERROR PAILLIER_ENCRYPT rc: %d\n", rc);
            exit(EXIT_FAILURE);
        }
    }

    for(int i=0; i<NTHREADS; i++)
    {
        printf("CT[%d] ", i);
        OCT_output(&CT[i]);
        printf("\n");
    }

    #pragma omp parallel for
    for(int i=0; i<NTHREADS; i++)
    {
        rc = PAILLIER_DECRYPT(&N, &L, &M, &CT[i], &PTOUT[i]);
        if (rc)
        {
            fprintf(stderr, "ERROR PAILLIER_DECRYPT rc: %d\n", rc);
            exit(EXIT_FAILURE);
        }
    }

    for(int i=0; i<NTHREADS; i++)
    {
        printf("PTOUT[%d] ", i);
        OCT_output(&PTOUT[i]);
        printf("\n");
    }

    #pragma omp parallel for
    for(int i=0; i<NTHREADS/2; i++)
    {
        rc = PAILLIER_ADD(&N, &CT[i*2], &CT[i*2+1], &CTA[i]);
        if (rc)
        {
            fprintf(stderr, "ERROR PAILLIER_ADD rc: %d\n", rc);
            exit(EXIT_FAILURE);
        }
    }

    rc = PAILLIER_ADD(&N, &CTA[0], &CTA[1], &CT3);
    if (rc)
    {
        fprintf(stderr, "ERROR PAILLIER_ADD rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    for(int i=0; i<NTHREADS/2; i++)
    {
        printf("CTA[%d] ", i);
        OCT_output(&CTA[i]);
        printf("\n");
    }
    printf("CT3: ");
    OCT_output(&CT3);
    printf("\n");


    rc = PAILLIER_DECRYPT(&N, &L, &M, &CT3, &PT3);
    if (rc)
    {
        fprintf(stderr, "ERROR PAILLIER_DECRYPT rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("PT3: ");
    OCT_output(&PT3);
    printf("\n");

    OCT_clear(&P);
    OCT_clear(&Q);
    OCT_clear(&N);
    OCT_clear(&G);
    OCT_clear(&L);
    OCT_clear(&M);
    OCT_clear(&CT3);
    OCT_clear(&PT3);
    for(int i=0; i<NTHREADS; i++)
    {
        OCT_clear(&PTIN[i]);
        OCT_clear(&PTOUT[i]);
        OCT_clear(&CT[i]);
    }
    for(int i=0; i<NTHREADS/2; i++)
    {
        OCT_clear(&CTA[i]);
    }
    return 0;
}

int main()
{
    char* seedHex = "78d0fb6705ce77dee47d03eb5b9c5d30";
    char seed[16] = {0};
    octet SEED = {sizeof(seed),sizeof(seed),seed};

    // CSPRNG
    csprng RNG;

    // fake random source
    OCT_fromHex(&SEED,seedHex);
    printf("SEED: ");
    OCT_output(&SEED);

    // initialise strong RNG
    CREATE_CSPRNG(&RNG,&SEED);

    printf("\nPaillier example\n");
    test(&RNG);

    KILL_CSPRNG(&RNG);
}



