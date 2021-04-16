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
   Benchmark NM Commitment.
 */

#include "bench.h"
#include "amcl/nm_commitment.h"

#define MIN_TIME    5.0
#define MIN_ITERS   10

char *R_hex = "fc33060a9804e80a36c4421a8fd0ead332aa89aeee91b425cca93635829966a6";
char *X_hex = "cc39908d5a7133e500d729b7458196a6f9bd8a7f501b88f020994936f7cae37c";

int main()
{
    int rc;

    int iterations;
    clock_t start;
    double elapsed;

    char x[32] = {0};
    octet X = {0, sizeof(x), x};

    char r[SHA256] = {0};
    octet R = {0, sizeof(r), r};

    char c[SHA256] = {0};
    octet C = {0, sizeof(c), c};

    // Load values
    OCT_fromHex(&X, X_hex);
    OCT_fromHex(&R, R_hex);

    print_system_info();

    printf("Timing info\n");
    printf("===========\n");

    iterations=0;
    start=clock();
    do
    {
        NM_COMMITMENT_commit(NULL, &X, &R, &C);
        iterations++;
        elapsed=(clock()-start)/(double)CLOCKS_PER_SEC;
    }
    while (elapsed<MIN_TIME || iterations<MIN_ITERS);

    elapsed= MICROSECOND * elapsed / iterations;
    printf("\tNM_COMMITMENT_commit\t%8d iterations\t",iterations);
    printf("%8.2lf us per iteration\n",elapsed);

    iterations = 0;
    start = clock();
    do
    {
        rc = NM_COMMITMENT_decommit(&X, &R, &C);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    if (rc != NM_COMMITMENT_OK)
    {
        printf("FAILURE NM_COMMITMENT_decommit: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    elapsed = MICROSECOND * elapsed / iterations;
    printf("\tNM_COMMITMENT_decommit\t%8d iterations\t", iterations);
    printf("%8.2lf us per iteration\n", elapsed);

    exit(EXIT_SUCCESS);
}
