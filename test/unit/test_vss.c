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
#include "amcl/shamir.h"

/*
 * Test VSS interoperability and error codes
 */

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
#include "amcl/shamir.h"

/*
 * Test Verifiable Secret Sharing verification
 */

#define LINE_LEN      1024
#define OCT_ARRAY_LEN 16

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_vss [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int i;
    int rc;
    int test_run = 0;

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    const char *Kline = "K = ";
    int k;

    const char *Nline = "N = ";
    int n;

    const char *Xline = "X = ";
    char x[OCT_ARRAY_LEN][SGS_SECP256K1];
    octet X[OCT_ARRAY_LEN];

    const char *Yline = "Y = ";
    char y[OCT_ARRAY_LEN][SGS_SECP256K1];
    octet Y[OCT_ARRAY_LEN];

    const char *CHECKSline = "CHECKS = ";
    char checks[OCT_ARRAY_LEN][1 + SGS_SECP256K1];
    octet CHECKS[OCT_ARRAY_LEN];

    for (i = 0; i < OCT_ARRAY_LEN; i++)
    {
        X[i].val = x[i];
        X[i].len = 0;
        X[i].max = sizeof(x[i]);

        Y[i].val = y[i];
        Y[i].len = 0;
        Y[i].max = sizeof(y[i]);

        CHECKS[i].val = checks[i];
        CHECKS[i].len = 0;
        CHECKS[i].max = sizeof(checks[i]);
    }

    // Line terminating a test vector
    const char *last_line = CHECKSline;

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    /* Test happy path with test vectors */
    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        scan_int(&testNo, line, TESTline);

        scan_int(&k, line, Kline);
        scan_int(&n, line, Nline);

        scan_OCTET_ARRAY(fp, X,      line, Xline,      n);
        scan_OCTET_ARRAY(fp, Y,      line, Yline,      n);
        scan_OCTET_ARRAY(fp, CHECKS, line, CHECKSline, k);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            for (i = 0; i < n; i++)
            {
                rc = VSS_verify_shares(k, X+i, Y+i, CHECKS);

                assert_tv(fp, testNo, "VSS_verify_shares", rc == VSS_OK);
            }

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

    // Test Inconsistent shares
    rc = VSS_verify_shares(k, X, Y+1, CHECKS);
    assert(NULL, "VSS_verify_shares inconsistent share", rc == VSS_INVALID_SHARES);

    // Test Invalid Free term in the exponent
    CHECKS[0].val = x[0];
    rc = VSS_verify_shares(k, X, Y, CHECKS);
    assert(NULL, "VSS_verify_checks invalid free term in the exponent", rc == VSS_INVALID_CHECKS);
    CHECKS[0].val = checks[0];

    // Test invalid Generic Check
    CHECKS[1].val = x[0];
    rc = VSS_verify_shares(k, X, Y, CHECKS);
    assert(NULL, "VSS_verify_checks invalid generic check", rc == VSS_INVALID_CHECKS);
    CHECKS[0].val = checks[0];

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}

