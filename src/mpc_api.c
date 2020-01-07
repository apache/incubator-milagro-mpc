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

/* MPC definitions */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <amcl/ecdh_SECP256K1.h>
#include <amcl/ecdh_support.h>
#include <amcl/randapi.h>
#include <amcl/paillier.h>
#include <amcl/mpc.h>
#include <amcl/mpc_api.h>

//  Generate ECDSA public and private key
int mpc_api_ecdsa_keys(char* seed, char* sk, char* pk)
{
    int rc;

    octet PK = {0,2*EFS_SECP256K1+1,pk};
    octet SK = {0,EGS_SECP256K1,sk};

    if (seed==NULL)
    {
        rc = ECP_SECP256K1_KEY_PAIR_GENERATE(NULL,&SK,&PK);
    }
    else
    {
        octet SEED = {SEEDLEN,SEEDLEN,seed};

        // CSPRNG
        csprng RNG;

        // initialise strong RNG
        CREATE_CSPRNG(&RNG,&SEED);

        // Generate key pair
        rc = ECP_SECP256K1_KEY_PAIR_GENERATE(&RNG,&SK,&PK);
    }

    if (rc)
    {
        return rc;
    }

#ifdef DEBUG
    printf("mpc_api_ecdsa_keys: PK.len %d PK.val ", PK.len);
    OCT_output(&PK);
    printf("mpc_api_ecdsa_keys: SK.len %d SK.val ", SK.len);
    OCT_output(&SK);
#endif

    return 0;
}

//  Generate PAILLIER public and private key
int mpc_api_paillier_keys(char* seed, char* p, char* q, char* n, char* g, char* l, char* m)
{
    int rc;

    octet P = {0,FS_2048,p};
    octet Q = {0,FS_2048,q};
    octet N = {0,FS_2048,n};
    octet G = {0,FS_2048,g};
    octet L = {0,FS_2048,l};
    octet M = {0,FS_2048,m};

    if (seed==NULL)
    {
        rc = PAILLIER_KEY_PAIR(NULL, &P, &Q, &N, &G, &L, &M);
    }
    else
    {
        octet SEED = {SEEDLEN,SEEDLEN,seed};

        // CSPRNG
        csprng RNG;

        // initialise strong RNG
        CREATE_CSPRNG(&RNG,&SEED);

        // Generate key pair
        rc = PAILLIER_KEY_PAIR(&RNG, &P, &Q, &N, &G, &L, &M);
    }

    if (rc)
    {
        return rc;
    }

#ifdef DEBUG
    printf("mpc_api_paillier_keys: P.len %d P.val ", P.len);
    OCT_output(&P);
    printf("mpc_api_paillier_keys: Q.len %d Q.val ", Q.len);
    OCT_output(&Q);
    printf("mpc_api_paillier_keys: N.len %d N.val ", N.len);
    OCT_output(&N);
    printf("mpc_api_paillier_keys: G.len %d G.val ", G.len);
    OCT_output(&G);
    printf("mpc_api_paillier_keys: L.len %d L.val ", L.len);
    OCT_output(&L);
    printf("mpc_api_paillier_keys: M.len %d M.val ", M.len);
    OCT_output(&M);
#endif

    return 0;
}

//  Client MTA first pass
int mpc_api_mta_client1(char* seed, char* n, char* g, char* a, char* ca, char* r)
{
    int rc;

    octet N = {FS_2048,FS_2048,n};
    octet G = {FS_2048,FS_2048,g};
    octet A = {EGS_SECP256K1,EGS_SECP256K1,a};
    octet CA = {0,FS_4096,ca};
    octet R = {0,FS_2048,r};

    if (seed==NULL)
    {
        rc = MPC_MTA_CLIENT1(NULL, &N, &G, &A, &CA, &R);
    }
    else
    {
        octet SEED = {SEEDLEN,SEEDLEN,seed};

        // CSPRNG
        csprng RNG;

        // initialise strong RNG
        CREATE_CSPRNG(&RNG,&SEED);

        rc = MPC_MTA_CLIENT1(&RNG, &N, &G, &A, &CA, &R);
    }

    if (rc)
    {
        return rc;
    }

#ifdef DEBUG
    printf("mpc_api_mta_client1: N.len %d N.val ", N.len);
    OCT_output(&N);
    printf("mpc_api_mta_client1: G.len %d G.val ", G.len);
    OCT_output(&G);
    printf("mpc_api_mta_client1: A.len %d A.val ", A.len);
    OCT_output(&A);
    printf("mpc_api_mta_client1: CA.len %d CA.val ", CA.len);
    OCT_output(&CA);
    printf("mpc_api_mta_client1: R.len %d R.val ", R.len);
    OCT_output(&R);
#endif

    return 0;
}

//  Server MtA
int mpc_api_mta_server(char* seed, char* n, char* g, char* b, char* ca, char* z, char* r, char* cb, char* beta)
{
    int rc;

    octet N = {FS_2048,FS_2048,n};
    octet G = {FS_2048,FS_2048,g};
    octet B = {EGS_SECP256K1,EGS_SECP256K1,b};
    octet CA = {FS_4096,FS_4096,ca};
    octet Z = {0,EGS_SECP256K1,z};
    octet R = {0,FS_2048,r};
    octet CB = {0,FS_4096,cb};
    octet BETA = {0,EGS_SECP256K1,beta};

    if (seed==NULL)
    {
        rc = MPC_MTA_SERVER(NULL, &N, &G, &B, &CA, &Z, &R, &CB, &BETA);
    }
    else
    {
        octet SEED = {SEEDLEN,SEEDLEN,seed};

        // CSPRNG
        csprng RNG;

        // initialise strong RNG
        CREATE_CSPRNG(&RNG,&SEED);

        rc = MPC_MTA_SERVER(&RNG, &N, &G, &B, &CA, &Z, &R, &CB, &BETA);
    }

    if (rc)
    {
        return rc;
    }

#ifdef DEBUG
    printf("mpc_api_mta_server: N.len %d N.val ", N.len);
    OCT_output(&N);
    printf("mpc_api_mta_server: G.len %d G.val ", G.len);
    OCT_output(&G);
    printf("mpc_api_mta_server: B.len %d B.val ", B.len);
    OCT_output(&B);
    printf("mpc_api_mta_server: CA.len %d CA.val ", CA.len);
    OCT_output(&CA);
    printf("mpc_api_mta_server: Z.len %d R.val ", Z.len);
    OCT_output(&Z);
    printf("mpc_api_mta_server: R.len %d R.val ", R.len);
    OCT_output(&R);
    printf("mpc_api_mta_server: CB.len %d R.val ", CB.len);
    OCT_output(&CB);
    printf("mpc_api_mta_server: BETA.len %d BETA.val ", BETA.len);
    OCT_output(&BETA);
#endif

    return 0;
}

//  Client MTA second pass
int mpc_api_mta_client2(char* n, char* l, char* m, char* cb, char* alpha)
{
    int rc;

    octet N = {FS_2048,FS_2048,n};
    octet L = {FS_2048,FS_2048,l};
    octet M = {FS_2048,FS_2048,m};
    octet CB = {FS_4096,FS_4096,cb};
    octet ALPHA = {0,EGS_SECP256K1,alpha};

    rc = MPC_MTA_CLIENT2(&N, &L, &M, &CB, &ALPHA);
    if (rc)
    {
        return rc;
    }

#ifdef DEBUG
    printf("mpc_api_mta_client2: N.len %d N.val ", N.len);
    OCT_output(&N);
    printf("mpc_api_mta_client2: L.len %d L.val ", L.len);
    OCT_output(&L);
    printf("mpc_api_mta_client2: M.len %d M.val ", M.len);
    OCT_output(&M);
    printf("mpc_api_mta_client2: CB.len %d CB.val ", CB.len);
    OCT_output(&CB);
    printf("mpc_api_mta_client2: ALPHA.len %d APLHA.val ", ALPHA.len);
    OCT_output(&ALPHA);
#endif

    return 0;
}

// Sum of secret shares generated by multiplicative to additive scheme
int mpc_api_sum_mta(char* a, char* b, char* alpha1, char* beta1, char* alpha2, char* beta2, char* sum)
{
    int rc;

    octet A = {EGS_SECP256K1,EGS_SECP256K1,a};
    octet B = {EGS_SECP256K1,EGS_SECP256K1,b};
    octet ALPHA1 = {EGS_SECP256K1,EGS_SECP256K1,alpha1};
    octet BETA1 = {EGS_SECP256K1,EGS_SECP256K1,beta1};
    octet ALPHA2 = {EGS_SECP256K1,EGS_SECP256K1,alpha2};
    octet BETA2 = {EGS_SECP256K1,EGS_SECP256K1,beta2};
    octet SUM = {0,EGS_SECP256K1,sum};

    if (alpha2==NULL)
    {
        rc = MPC_SUM_MTA(&A, &B, &ALPHA1, &BETA1, NULL, NULL, &SUM);
    }
    else
    {
        rc = MPC_SUM_MTA(&A, &B, &ALPHA1, &BETA1, &ALPHA2, &BETA2, &SUM);
    }

    if (rc)
    {
        return rc;
    }

#ifdef DEBUG
    printf("mpc_api_mta_client2: A.len %d A.val ", A.len);
    OCT_output(&A);
    printf("mpc_api_mta_client2: B.len %d B.val ", B.len);
    OCT_output(&B);
    printf("mpc_api_mta_client2: ALPHA1.len %d ALPHA1.val ", ALPHA1.len);
    OCT_output(&ALPHA1);
    printf("mpc_api_mta_client2: BETA1.len %d BETA1.val ", BETA1.len);
    OCT_output(&BETA1);
#endif

    return 0;
}

