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
 * Test utilities definitions.
 */

#include <string.h>
#include "test.h"

// #define DEBUG

/* TV reading Utilities */

void read_OCTET(FILE *fp, octet *OCT, char *string)
{
    int len = strlen(string);
    char buff[len];
    memcpy(buff, string, len);
    char *end = strchr(buff, ',');
    if (end == NULL)
    {
        fclose(fp);

        printf("ERROR unexpected test vector %s\n", string);
        exit(EXIT_FAILURE);
    }
    end[0] = '\0';
    OCT_fromHex(OCT, buff);
}

void read_FF_2048(FILE *fp, BIG_1024_58 *x, char *string, int n)
{
    int len = strlen(string);
    char oct[len / 2];
    octet OCT = {0, sizeof(oct), oct};

    read_OCTET(fp, &OCT, string);
    FF_2048_fromOctet(x, &OCT, n);
}

void read_FF_4096(FILE *fp, BIG_512_60 *x, char *string, int n)
{
    int len = strlen(string);
    char oct[len / 2];
    octet OCT = {0, sizeof(oct), oct};

    read_OCTET(fp, &OCT, string);
    FF_4096_fromOctet(x, &OCT, n);
}

void read_ECP_SECP256K1(FILE *fp, ECP_SECP256K1 *P, char *string)
{
    int len = strlen(string);
    char oct[len /2];
    octet OCT = {0, sizeof(oct), oct};

    read_OCTET(fp, &OCT, string);

    if (!ECP_SECP256K1_fromOctet(P, &OCT))
    {
        fclose(fp);

        printf("ERROR invalid test vector ECP %s\n", string);
        exit(EXIT_FAILURE);
    }
}

void scan_int(int *v, char *line, const char *prefix)
{
    if (!strncmp(line, prefix, strlen(prefix)))
    {
        line+=strlen(prefix);
        sscanf(line, "%d\n", v);
    }
}

void scan_OCTET(FILE *fp, octet *OCT, char *line, const char *prefix)
{
    if (!strncmp(line, prefix, strlen(prefix)))
    {
        line+=strlen(prefix);
        read_OCTET(fp, OCT, line);

#ifdef DEBUG
        printf("%s", prefix);
        OCT_output(OCT);
#endif
    }
}

void scan_FF_2048(FILE *fp, BIG_1024_58 *x, char *line, const char *prefix, int n)
{
    if (!strncmp(line, prefix, strlen(prefix)))
    {
        line+=strlen(prefix);
        read_FF_2048(fp, x, line, n);

#ifdef DEBUG
        printf("%s", prefix);
        FF_2048_output(x, n);
        printf("\n");
#endif
    }
}

void scan_FF_4096(FILE *fp, BIG_512_60 *x, char *line, const char *prefix, int n)
{
    if (!strncmp(line, prefix, strlen(prefix)))
    {
        line+=strlen(prefix);
        read_FF_4096(fp, x, line, n);

#ifdef DEBUG
        printf("%s", prefix);
        FF_4096_output(x, n);
        printf("\n");
#endif
    }
}

void scan_ECP_SECP256K1(FILE *fp, ECP_SECP256K1 *P, char *line, const char *prefix)
{
    if (!strncmp(line, prefix, strlen(prefix)))
    {

        line+=strlen(prefix);
        read_ECP_SECP256K1(fp, P, line);

#ifdef DEBUG
        printf("%s", prefix);
        ECP_SECP256K1_output(P);
#endif
    }
}

/* Assertion utilities */

void compare_OCT(FILE* fp, int testNo, char *name, octet *X, octet *Y)
{
    if (!OCT_comp(X, Y))
    {
        if (fp != NULL)
        {
            fclose(fp);
        }

#ifdef DEBUG
        printf("X = ");
        OCT_output(X);
        printf("Y = ");
        OCT_output(Y);
#endif

        printf("FAILURE %s. Test %d\n", name, testNo);

#ifdef DEBUG
        printf("X = ");
        OCT_output(X);
        printf("Y = ");
        OCT_output(Y);
#endif

        exit(EXIT_FAILURE);
    }
}

void compare_FF_2048(FILE* fp, int testNo, char* name, BIG_1024_58 *x, BIG_1024_58 *y, int n)
{
    if(FF_2048_comp(x, y, n))
    {
        if (fp != NULL)
        {
            fclose(fp);
        }

        fprintf(stderr, "FAILURE %s. Test %d\n", name, testNo);

#ifdef DEBUG
        printf("x = ");
        FF_2048_output(x, n);
        printf("\ny = ");
        FF_2048_output(y,n);
        printf("\n");
#endif

        exit(EXIT_FAILURE);
    }
}

void compare_FF_4096(FILE* fp, int testNo, char* name, BIG_512_60 *x, BIG_512_60 *y, int n)
{
    if(FF_4096_comp(x, y, n))
    {
        if (fp != NULL)
        {
            fclose(fp);
        }

        fprintf(stderr, "FAILURE %s. Test %d\n", name, testNo);

#ifdef DEBUG
        printf("x = ");
        FF_4096_output(x, n);
        printf("\ny = ");
        FF_4096_output(y,n);
        printf("\n");
#endif

        exit(EXIT_FAILURE);
    }
}

void compare_ECP_SECP256K1(FILE *fp, int testNo, char *name, ECP_SECP256K1 *P, ECP_SECP256K1 *Q)
{
    if (!ECP_SECP256K1_equals(P, Q))
    {
        if (fp != NULL)
        {
            fclose(fp);
        }

        fprintf(stderr, "FAILURE %s. Test %d\n", name, testNo);

#ifdef DEBUG
        printf("P = ");
        ECP_SECP256K1_output(P);
        printf("Q = ");
        ECP_SECP256K1_output(Q);
#endif

        exit(EXIT_FAILURE);
    }
}

void assert(FILE *fp, char *msg, int statement)
{
    if (!statement)
    {
        if (fp != NULL)
        {
            fclose(fp);
        }

        fprintf(stderr, "FAILURE %s\n", msg);
        exit(EXIT_FAILURE);
    }
}

void assert_tv(FILE *fp, int testNo, char* name, int statement)
{
    char msg[32 + strlen(name)];
    sprintf(msg, "%s. Test %d", name, testNo);

    assert(fp, msg, statement);
}
