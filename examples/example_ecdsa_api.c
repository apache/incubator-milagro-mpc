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

// MPC ECDSA calculation

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <amcl/randapi.h>
#include <amcl/utils.h>
#include <amcl/ecdh_SECP256K1.h>
#include <amcl/ecdh_support.h>
#include <amcl/paillier.h>
#include <amcl/mpc.h>
#include <amcl/mpc_api.h>

int main()
{
    int rc=0;

    // Seed value for CSPRNG (use /dev/urandom in production)
    char seed[12][16];

    // Initialise seed
    for(int i=0; i<12; i++)
    {
        for(int j=0; j<16; j++)
        {
            seed[i][j] = i;
        }
    }

    for(int i=0; i<12; i++)
    {
        printf("seed[%d]: ", i);
        amcl_print_hex(seed[i], sizeof(seed[i]));
    }

    // ECDSA Keys
    char w1[EGS_SECP256K1] = {0};
    char pk1[2*EFS_SECP256K1+1] = {0};
    char w2[EGS_SECP256K1] = {0};
    char pk2[2*EFS_SECP256K1+1] = {0};

    printf("Generating ECDSA key pair one\n");
    rc = mpc_api_ecdsa_keys(seed[0], w1, pk1);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR mpc_api_ecdsa_keys rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("Generating ECDSA key pair two\n");
    rc = mpc_api_ecdsa_keys(seed[1], w2, pk2);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR mpc_api_ecdsa_keys rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    // GAMMA values
    char gamma1[EGS_SECP256K1] = {0};
    char gammapt1[2*EFS_SECP256K1+1] = {0};
    char gamma2[EGS_SECP256K1] = {0};
    char gammapt2[2*EFS_SECP256K1+1] = {0};

    printf("Generating GAMMA pair one\n");
    rc = mpc_api_ecdsa_keys(seed[2], gamma1, gammapt1);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR mpc_api_ecdsa_keys rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("Generating GAMMA pair two\n");
    rc = mpc_api_ecdsa_keys(seed[3], gamma2, gammapt2);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR mpc_api_ecdsa_keys rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    // K values
    char k1[EGS_SECP256K1] = {0};
    char kpt1[2*EFS_SECP256K1+1] = {0}; // not used
    char k2[EGS_SECP256K1] = {0};
    char kpt2[2*EFS_SECP256K1+1] = {0}; // not used

    printf("Generating K pair one\n");
    rc = mpc_api_ecdsa_keys(seed[4], k1, kpt1);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR mpc_api_ecdsa_keys rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("Generating K pair two\n");
    rc = mpc_api_ecdsa_keys(seed[5], k2, kpt2);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR mpc_api_ecdsa_keys rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    // Paillier key pairs
    char p1[FS_2048] = {0};
    char q1[FS_2048] = {0};
    char n1[FS_2048] = {0};
    char g1[FS_2048] = {0};
    char l1[FS_2048] = {0};
    char m1[FS_2048] = {0};
    char p2[FS_2048] = {0};
    char q2[FS_2048] = {0};
    char n2[FS_2048] = {0};
    char g2[FS_2048] = {0};
    char l2[FS_2048] = {0};
    char m2[FS_2048] = {0};

    printf("Generating Paillier key pair one\n");
    rc = mpc_api_paillier_keys(seed[6], p1, q1, n1, g1, l1, m1);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR mpc_api_paillier_keys rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("Generating Paillier key pair two\n");
    rc = mpc_api_paillier_keys(seed[7], p2, q2, n2, g2, l2, m2);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR mpc_api_paillier_keys rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }


    printf("ALPHA1 + BETA2 = K1 * GAMMA2\n");

    char ca11[FS_4096];
    char cb12[FS_4096];
    char r11[FS_2048];
    char r12[FS_2048];
    char z12[EGS_SECP256K1];
    char beta2[EGS_SECP256K1];
    char alpha1[EGS_SECP256K1];

    rc = mpc_api_mta_client1(seed[8], n1, g1, k1, ca11, r11);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR mpc_api_mta_client1 rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    rc = mpc_api_mta_server(seed[9], n1, g1, gamma2, ca11, z12, r12, cb12, beta2);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR mpc_api_mta_server rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    rc = mpc_api_mta_client2(n1, l1, m1, cb12, alpha1);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR mpc_api_mta_client1 rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("k1: ");
    amcl_print_hex(k1, sizeof(k1));
    printf("gamma2: ");
    amcl_print_hex(gamma2, sizeof(gamma2));
    printf("alpha1: ");
    amcl_print_hex(alpha1, sizeof(alpha1));
    printf("beta2: ");
    amcl_print_hex(beta2, sizeof(beta2));



    printf("ALPHA1 + BETA2 = K2 * GAMMA1\n");

    char ca22[FS_4096];
    char cb21[FS_4096];
    char r22[FS_2048];
    char r21[FS_2048];
    char z21[EGS_SECP256K1];
    char beta1[EGS_SECP256K1];
    char alpha2[EGS_SECP256K1];

    rc = mpc_api_mta_client1(seed[8], n2, g2, k2, ca22, r22);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR mpc_api_mta_client1 rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    rc = mpc_api_mta_server(seed[9], n2, g2, gamma1, ca22, z21, r21, cb21, beta1);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR mpc_api_mta_server rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    rc = mpc_api_mta_client2(n2, l2, m2, cb21, alpha2);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR mpc_api_mta_client1 rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("k2: ");
    amcl_print_hex(k2, sizeof(k2));
    printf("gamma1: ");
    amcl_print_hex(gamma1, sizeof(gamma1));
    printf("alpha2: ");
    amcl_print_hex(alpha2, sizeof(alpha2));
    printf("beta1: ");
    amcl_print_hex(beta1, sizeof(beta1));

    // sum = K1.GAMMA1 + alpha1  + beta1

    char sum1[EGS_SECP256K1];

    rc = mpc_api_sum_mta(k1, gamma1, alpha1, beta1, NULL, NULL, sum1);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR mpc_api_sum_mta rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("sum1: ");
    amcl_print_hex(sum1, sizeof(sum1));

}
