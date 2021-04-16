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

/* GMR ZKP of Square Freeness verification unit test */

#include <string.h>
#include "test.h"
#include "amcl/gmr.h"

#define LINE_LEN 65555
#define IDLEN 16
#define ADLEN 16

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_gmr_verify [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;
    int rc;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    char n[FS_2048];
    octet N = {0, sizeof(n), n};
    const char *Nline = "N = ";

    char id[IDLEN];
    octet ID = {0, sizeof(id), id};
    const char *IDline = "ID = ";

    char ad[ADLEN];
    octet AD = {0, sizeof(ad), ad};
    octet *AD_ptr = NULL;
    const char *ADline = "AD = ";

    GMR_proof Y;
    char yoct[GMR_PROOF_SIZE];
    octet YOCT = {0, sizeof(yoct), yoct};
    const char *Yline = "Y = ";

    // Line terminating a test vector
    const char *last_line = Yline;

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        scan_int(&testNo, line, TESTline);

        // Read ID and AD
        scan_OCTET(fp, &ID, line, IDline);
        scan_OCTET(fp, &AD, line, ADline);

        // Read modulus
        scan_OCTET(fp, &N, line, Nline);

        // Read proof
        scan_OCTET(fp, &YOCT, line, Yline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            // Also input AD if it is not empty
            if (AD.len > 0)
            {
                AD_ptr = &AD;
            }

            rc = GMR_proof_fromOctet(Y, &YOCT);
            assert_tv(fp, testNo, "Error reading Y from TV", rc == GMR_OK);

            rc = GMR_verify(&N, Y, &ID, AD_ptr);
            assert_tv(fp, testNo, "GMR verify", rc == GMR_OK);

            // Mark that at least one test vector was executed
            test_run = 1;

            // Restore AD_ptr
            AD_ptr = NULL;
        }
    }

    fclose(fp);

    if (test_run == 0)
    {
        printf("ERROR no test vector was executed\n");
        exit(EXIT_FAILURE);
    }

    /* Test unhappy path */

    // Invalid Proof
    FF_2048_inc(Y[0], 1, FFLEN_2048);

    rc = GMR_verify(&N, Y, &ID, AD_ptr);
    assert_tv(fp, testNo, "GMR verify invalid proof", rc == GMR_FAIL);

    FF_2048_dec(Y[0], 1, FFLEN_2048);

    // N even
    N.val[N.len-1] = '2';

    rc = GMR_verify(&N, Y, &ID, AD_ptr);
    assert_tv(fp, testNo, "GMR verify N is even", rc == GMR_FAIL);

    // N has small factor (809 * 907)
    OCT_fromHex(&N, "b3243");
    OCT_pad(&N, FS_2048);

    rc = GMR_verify(&N, Y, &ID, AD_ptr);
    assert_tv(fp, testNo, "GMR verify N has small factor", rc == GMR_FAIL);

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
