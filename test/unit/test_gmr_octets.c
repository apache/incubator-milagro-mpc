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

/* GMR ZKP of Square Freeness octet functions unit test */

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
        printf("usage: ./test_gmr_octets [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int test_run = 0;
    int rc;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    GMR_proof Y;

    char yoct[GMR_PROOF_SIZE];
    char yoct_golden[GMR_PROOF_SIZE];
    octet YOCT = {0, sizeof(yoct), yoct};
    octet YOCT_GOLDEN = {0, sizeof(yoct_golden), yoct_golden};
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

        // Read proof
        scan_OCTET(fp, &YOCT_GOLDEN, line, Yline);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            rc = GMR_proof_fromOctet(Y, &YOCT_GOLDEN);
            assert_tv(fp, testNo, "Error reading Y from TV", rc == GMR_OK);

            GMR_proof_toOctet(&YOCT, Y);

            compare_OCT(fp, testNo, "GMR octets consistency", &YOCT, &YOCT_GOLDEN);

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

    /* Test unhappy path */

    // Invalid Proof Format
    YOCT.len--;

    rc = GMR_proof_fromOctet(Y, &YOCT);
    assert_tv(fp, testNo, "GMR proof_fromOctet invalid format", rc == GMR_INVALID_PROOF);

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
