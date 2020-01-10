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
 * NM Commitment Scheme usage examples
 */

#include <stdio.h>
#include "amcl/commitments.h"

int main()
{
    int rc;

    char x[32];
    octet X = {0, sizeof(x), x};

    char r[SHA256];
    octet R = {0, sizeof(r), r};

    char c[SHA256];
    octet C = {0, sizeof(c), c};

    // Deterministic RNG for testing
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    OCT_rand(&X, &RNG, X.max);
    printf("\nCommit to value X = ");
    OCT_output(&X);

    printf("\nCompute commitment value C and decommitment value R.\n");
    COMMITMENTS_NM_commit(&RNG, &X, &R, &C);

    printf("\tR = ");
    OCT_output(&R);
    printf("\tC = ");
    OCT_output(&C);

    printf("\nTransmit C to commit to the value X.\n");

    printf("\nTransmit R, X to decommit the value.\n");
    rc = COMMITMENTS_NM_decommit(&X, &R, &C);
    if (!rc)
    {
        fprintf(stderr, "FAILURE COMMITMENTS_NM_decommit: %d\n", rc);
        exit(EXIT_FAILURE);
    }
    printf("\tDecommitment successful.\n\n");
}