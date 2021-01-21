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

// MPC ECDSA smoke test

#include <amcl/randapi.h>
#include <amcl/ecdh_SECP256K1.h>
#include <amcl/mta.h>
#include <amcl/mpc.h>

int test(csprng *RNG)
{
    int rc;

    // Paillier Keys
    PAILLIER_private_key PRIV1;
    PAILLIER_public_key PUB1;
    PAILLIER_private_key PRIV2;
    PAILLIER_public_key PUB2;

    char k1[EGS_SECP256K1];
    octet K1 = {0,sizeof(k1),k1};

    char w1[EGS_SECP256K1];
    octet W1 = {0,sizeof(w1),w1};

    char gamma2[EGS_SECP256K1];
    octet GAMMA2 = {0,sizeof(gamma2),gamma2};

    char ca11[FS_4096];
    octet CA11 = {0,sizeof(ca11),ca11};

    char r11[FS_2048];
    octet R11 = {0,sizeof(r11),r11};

    char cb12[FS_4096];
    octet CB12 = {0,sizeof(cb12),cb12};

    char r12[FS_2048];
    octet R12 = {0,sizeof(r12),r12};

    char z12[EGS_SECP256K1];
    octet Z12 = {0,sizeof(z12),z12};

    char beta2[EGS_SECP256K1];
    octet BETA2 = {0,sizeof(beta2),beta2};

    char alpha1[EGS_SECP256K1];
    octet ALPHA1 = {0,sizeof(alpha1),alpha1};

    char k2[EGS_SECP256K1];
    octet K2 = {0,sizeof(k2),k2};

    char w2[EGS_SECP256K1];
    octet W2 = {0,sizeof(w2),w2};

    char gamma1[EGS_SECP256K1];
    octet GAMMA1 = {0,sizeof(gamma1),gamma1};

    char ca22[FS_4096];
    octet CA22 = {0,sizeof(ca22),ca22};

    char r22[FS_2048];
    octet R22 = {0,sizeof(r22),r22};

    char cb21[FS_4096];
    octet CB21 = {0,sizeof(cb21),cb21};

    char r21[FS_2048];
    octet R21 = {0,sizeof(r21),r21};

    char z21[EGS_SECP256K1];
    octet Z21 = {0,sizeof(z21),z21};

    char beta1[EGS_SECP256K1];
    octet BETA1 = {0,sizeof(beta1),beta1};

    char alpha2[EGS_SECP256K1];
    octet ALPHA2 = {0,sizeof(alpha2),alpha2};

    char sum1[EGS_SECP256K1];
    octet SUM1 = {0,sizeof(sum1),sum1};

    char sum2[EGS_SECP256K1];
    octet SUM2 = {0,sizeof(sum2),sum2};

    char invkgamma[EGS_SECP256K1];
    octet INVKGAMMA = {0,sizeof(invkgamma),invkgamma};

    char gammapt1[EFS_SECP256K1+1];
    octet GAMMAPT1 = {0,sizeof(gammapt1),gammapt1};

    char gammapt2[EFS_SECP256K1+1];
    octet GAMMAPT2 = {0,sizeof(gammapt2),gammapt2};

    char sig_r[EGS_SECP256K1];
    octet SIG_R = {0,sizeof(sig_r),sig_r};

    char pk1[EFS_SECP256K1+1];
    octet PK1 = {0,sizeof(pk1),pk1};

    char pk2[EFS_SECP256K1+1];
    octet PK2 = {0,sizeof(pk2),pk2};

    char pk[EFS_SECP256K1+1];
    octet PK = {0,sizeof(pk),pk};

    char sig_s1[EGS_SECP256K1];
    octet SIG_S1 = {0,sizeof(sig_s1),sig_s1};

    char sig_s2[EGS_SECP256K1];
    octet SIG_S2 = {0,sizeof(sig_s2),sig_s2};

    char sig_s[EGS_SECP256K1];
    octet SIG_S = {0,sizeof(sig_s),sig_s};

    char m[2000];
    octet M = {0,sizeof(m),m};

    char hm[32];
    octet HM = {0,sizeof(hm),hm};

    printf("Generating Paillier key pair one\n");
    PAILLIER_KEY_PAIR(RNG, NULL, NULL, &PUB1, &PRIV1);

    printf("Generating Paillier key pair two\n");
    PAILLIER_KEY_PAIR(RNG, NULL, NULL, &PUB2, &PRIV2);

    printf("Generating ECDSA key pair one\n");
    MPC_ECDSA_KEY_PAIR_GENERATE(RNG, &W1, &PK1);

    rc = ECP_SECP256K1_PUBLIC_KEY_VALIDATE(&PK1);
    if (rc != 0)
    {
        fprintf(stderr, "ERROR ECP_SECP256K1_PUBLIC_KEY_VALIDATE rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("Generating ECDSA key pair two\n");
    MPC_ECDSA_KEY_PAIR_GENERATE(RNG, &W2, &PK2);

    rc = ECP_SECP256K1_PUBLIC_KEY_VALIDATE(&PK2);
    if (rc != 0)
    {
        fprintf(stderr, "ERROR ECP_SECP256K1_PUBLIC_KEY_VALIDATE rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("Generating GAMMA pair one\n");
    MPC_ECDSA_KEY_PAIR_GENERATE(RNG, &GAMMA1, &GAMMAPT1);

    rc = ECP_SECP256K1_PUBLIC_KEY_VALIDATE(&GAMMAPT1);
    if (rc != 0)
    {
        fprintf(stderr, "ERROR ECP_SECP256K1_PUBLIC_KEY_VALIDATE rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("Generating GAMMA pair two\n");
    MPC_ECDSA_KEY_PAIR_GENERATE(RNG, &GAMMA2, &GAMMAPT2);

    rc = ECP_SECP256K1_PUBLIC_KEY_VALIDATE(&GAMMAPT2);
    if (rc != 0)
    {
        fprintf(stderr, "ERROR ECP_SECP256K1_PUBLIC_KEY_VALIDATE rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("Generating K1\n");
    MPC_K_GENERATE(RNG, &K1);

    printf("Generating K2\n");
    MPC_K_GENERATE(RNG, &K2);

    OCT_jstring(&M,"test message");
    printf("M: ");
    OCT_output(&M);

    // ALPHA1 + BETA2 = K1 * GAMMA2
    MPC_MTA_CLIENT1(RNG, &PUB1, &K1, &CA11, &R11);

    printf("CA11: ");
    OCT_output(&CA11);
    printf("\n");

    MPC_MTA_SERVER(RNG, &PUB1, &GAMMA2, &CA11, &Z12, &R12, &CB12, &BETA2);

    printf("CB12: ");
    OCT_output(&CB12);
    printf("\n");

    printf("BETA2: ");
    OCT_output(&BETA2);
    printf("\n");

    MPC_MTA_CLIENT2(&PRIV1, &CB12, &ALPHA1);

    printf("ALPHA1: ");
    OCT_output(&ALPHA1);
    printf("\n");

    // ALPHA2 + BETA1 = K2 * GAMMA1
    MPC_MTA_CLIENT1(RNG, &PUB2, &K2, &CA22, &R22);

    printf("CA22: ");
    OCT_output(&CA22);
    printf("\n");

    MPC_MTA_SERVER(RNG, &PUB2, &GAMMA1, &CA22, &Z21, &R21, &CB21, &BETA1);

    printf("CB21: ");
    OCT_output(&CB21);
    printf("\n");

    printf("BETA1: ");
    OCT_output(&BETA1);
    printf("\n");

    MPC_MTA_CLIENT2(&PRIV2, &CB21, &ALPHA2);

    printf("ALPHA2: ");
    OCT_output(&ALPHA2);
    printf("\n");

    // sum = K1.GAMMA1 + alpha1  + beta1
    MPC_SUM_MTA(&K1, &GAMMA1, &ALPHA1, &BETA1, &SUM1);

    printf("SUM1: ");
    OCT_output(&SUM1);
    printf("\n");

    // sum = K2.GAMMA2 + alpha2  + beta2
    MPC_SUM_MTA(&K2, &GAMMA2, &ALPHA2, &BETA2, &SUM2);

    printf("SUM2: ");
    OCT_output(&SUM2);
    printf("\n");

    // Calculate the inverse of kgamma
    MPC_INVKGAMMA(&SUM1, &SUM2, &INVKGAMMA);

    printf("INVKGAMMA: ");
    OCT_output(&INVKGAMMA);
    printf("\n");

    // Calculate the R signature component
    rc = MPC_R(&INVKGAMMA, &GAMMAPT1, &GAMMAPT2, &SIG_R, NULL);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_R rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    // ALPHA1 + BETA2 = K1 * W2
    MPC_MTA_CLIENT1(NULL, &PUB1, &K1, &CA11, &R11);

    printf("CA11: ");
    OCT_output(&CA11);
    printf("\n");

    MPC_MTA_SERVER(NULL, &PUB1, &W2, &CA11, &Z12, &R12, &CB12, &BETA2);

    printf("CB12: ");
    OCT_output(&CB12);
    printf("\n");

    printf("BETA2: ");
    OCT_output(&BETA2);
    printf("\n");

    MPC_MTA_CLIENT2(&PRIV1, &CB12, &ALPHA1);

    printf("ALPHA1: ");
    OCT_output(&ALPHA1);
    printf("\n");

    // ALPHA2 + BETA1 = K2 * W1
    MPC_MTA_CLIENT1(NULL, &PUB2, &K2, &CA22, &R22);

    printf("CA22: ");
    OCT_output(&CA22);
    printf("\n");

    MPC_MTA_SERVER(NULL,  &PUB2, &W1, &CA22, &Z21, &R21, &CB21, &BETA1);

    printf("CB21: ");
    OCT_output(&CB21);
    printf("\n");

    printf("BETA1: ");
    OCT_output(&BETA1);
    printf("\n");

    MPC_MTA_CLIENT2(&PRIV2, &CB21, &ALPHA2);

    printf("ALPHA2: ");
    OCT_output(&ALPHA2);
    printf("\n");

    // sum = K1.W1 + alpha1  + beta1
    MPC_SUM_MTA(&K1, &W1, &ALPHA1, &BETA1, &SUM1);

    printf("SUM1: ");
    OCT_output(&SUM1);
    printf("\n");

    // sum = K2.W2 + alpha2  + beta2
    MPC_SUM_MTA(&K2, &W2, &ALPHA2, &BETA2, &SUM2);

    printf("SUM2: ");
    OCT_output(&SUM2);
    printf("\n");

    // Calculate the message hash
    MPC_HASH(HASH_TYPE_SECP256K1, &M, &HM);

    // Calculate the S1 signature component
    rc = MPC_S(&HM, &SIG_R, &K1, &SUM1, &SIG_S1);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_S rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("SIG_S1: ");
    OCT_output(&SIG_S1);
    printf("\n");

    // Calculate the S2 signature component
    rc = MPC_S(&HM, &SIG_R, &K2, &SUM2, &SIG_S2);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_S rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("SIG_S2: ");
    OCT_output(&SIG_S2);
    printf("\n");

    // Sum S signature component
    MPC_SUM_S(&SIG_S1, &SIG_S2, &SIG_S);

    printf("SIG_R: ");
    OCT_output(&SIG_R);
    printf("\n");

    printf("SIG_S: ");
    OCT_output(&SIG_S);
    printf("\n");

    // Sum ECDSA public keys
    rc = MPC_SUM_PK(&PK1, &PK2, &PK);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_SUM_PK rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("PK: ");
    OCT_output(&PK);
    printf("\n");

    rc = MPC_ECDSA_VERIFY(&HM,&PK,&SIG_R,&SIG_S);
    if (rc!=0)
    {
        fprintf(stderr, "FAILURE ECP_SECP256K1_VP_DSA rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("ECDSA succeeded\n");
    }

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
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

    // initialise strong RNG
    CREATE_CSPRNG(&RNG,&SEED);

    printf("ECDSA MPC example\n");
    test(&RNG);

    KILL_CSPRNG(&RNG);
}
