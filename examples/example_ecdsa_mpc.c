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

/* ECDSA example */

#include <amcl/ecdh_SECP256K1.h>
#include <amcl/mta.h>
#include <amcl/mpc.h>

int main()
{
    int rc;

    char sk[EGS_SECP256K1];
    octet SK = {0,sizeof(sk),sk};

    char pk[EFS_SECP256K1+1];
    octet PK = {0,sizeof(pk),pk};

    char k[EGS_SECP256K1];
    octet K = {0,sizeof(k),k};

    char m[2000];
    octet M = {0,sizeof(m),m};

    char s[EGS_SECP256K1];
    octet S = {0,sizeof(s),s};

    char r[EGS_SECP256K1];
    octet R = {0,sizeof(r),r};

    // Key generation
    char* sk_hex = "2f7b34cc0194179865128b63dc8af0c4062067291693e8043eda653d32a2b2d2";
    OCT_fromHex(&SK,sk_hex);

    MPC_ECDSA_KEY_PAIR_GENERATE(NULL,&SK,&PK);
    rc=ECP_SECP256K1_PUBLIC_KEY_VALIDATE(&PK);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR ECP_SECP256K1_PUBLIC_KEY_VALIDATE rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }
    printf("SK: ");
    OCT_output(&SK);
    printf("PK: ");
    OCT_output(&PK);

    OCT_jstring(&M,"test message");
    printf("M: ");
    OCT_output(&M);

    char* k_hex = "c222a4d114d17be6820ce54807eda995f017aa36b0a6089f25fdffeae821cd4f";
    OCT_fromHex(&K,k_hex);

    rc = MPC_ECDSA_SIGN(HASH_TYPE_SECP256K1,&K,&SK,&M,&R,&S);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR ECP_SECP256K1_SP_DSA rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }
    printf("K: ");
    OCT_output(&K);
    printf("R: ");
    OCT_output(&R);
    printf("S: ");
    OCT_output(&S);

    rc = ECP_SECP256K1_VP_DSA(HASH_TYPE_SECP256K1,&PK,&M,&R,&S);
    if (rc!=0)
    {
        fprintf(stderr, "ERROR ECP_SECP256K1_VP_DSA rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("ECDSA succeeded\n");
    }

    // clear memory
    OCT_clear(&SK);
    OCT_clear(&PK);
    OCT_clear(&S);
    OCT_clear(&R);
    OCT_clear(&M);

    return 0;
}

