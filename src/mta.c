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
#include "amcl/mta.h"

static char* curve_order_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

// Truncates an octet string
void OCT_truncate(octet *y,octet *x)
{
    /* y < x */
    int i=0;
    int j=0;
    if (x==NULL) return;
    if (y==NULL) return;

    for (i=0; i<y->len; i++)
    {
        j=x->len+i;
        if (i>=y->max)
        {
            y->len=y->max;
            return;
        }
        y->val[i]=x->val[j];
    }
}

// Client MTA first pass
void MPC_MTA_CLIENT1(csprng *RNG,  PAILLIER_public_key *PUB, octet *A, octet *CA, octet *R)
{
    // Read A
    char a1[FS_2048];
    octet A1 = {0,sizeof(a1),a1};
    OCT_clear(&A1);
    A1.len = FS_2048 - EGS_SECP256K1;
    OCT_joctet(&A1,A);

    PAILLIER_ENCRYPT(RNG, PUB, &A1, CA, R);
}

// Client MtA second pass
void MPC_MTA_CLIENT2(PAILLIER_private_key *PRIV, octet *CB, octet *ALPHA)
{
    BIG_512_60 q[FFLEN_4096];
    BIG_512_60 alpha[FFLEN_4096];

    char co[EGS_SECP256K1];
    octet CO = {0,sizeof(co),co};

    char t[FS_2048];
    octet T = {0,sizeof(t),t};

    // Curve order
    OCT_fromHex(&CO,curve_order_hex);
    FF_4096_zero(q, FFLEN_4096);
    BIG_512_60_fromBytesLen(q[0],CO.val,CO.len);

    PAILLIER_DECRYPT(PRIV, CB, &T);

    FF_4096_zero(alpha, FFLEN_4096);
    FF_4096_fromOctet(alpha,&T,HFLEN_4096);

    // alpha = alpha mod q
    FF_4096_mod(alpha, q, FFLEN_4096);

    // Output alpha
    char alpha1[FS_4096];
    octet ALPHA1 = {0,sizeof(alpha1),alpha1};
    FF_4096_toOctet(&ALPHA1, alpha, FFLEN_4096);
    OCT_clear(ALPHA);
    ALPHA->len = EGS_SECP256K1;
    ALPHA1.len = FS_4096 - EGS_SECP256K1;
    OCT_truncate(ALPHA,&ALPHA1);
}

// MtA server
void MPC_MTA_SERVER(csprng *RNG, PAILLIER_public_key *PUB, octet *B, octet *CA, octet *ZO, octet *R, octet *CB, octet *BETA)
{
    BIG_512_60 q[FFLEN_4096];
    BIG_512_60 z[FFLEN_4096];
    BIG_512_60 beta[FFLEN_4096];

    char co[EGS_SECP256K1];
    octet CO = {0,sizeof(co),co};

    char zb[FS_2048];
    octet Z = {0,sizeof(zb),zb};

    char cz[FS_4096];
    octet CZ = {0,sizeof(cz),cz};

    char ct[FS_4096];
    octet CT = {0,sizeof(ct),ct};

    char b1[FS_2048];
    octet B1 = {0,sizeof(b1),b1};

    // Curve order
    OCT_fromHex(&CO,curve_order_hex);
    FF_4096_zero(q, FFLEN_4096);
    BIG_512_60_fromBytesLen(q[0],CO.val,CO.len);

    // Read B
    OCT_clear(&B1);
    B1.len = FS_2048 - EGS_SECP256K1;
    OCT_joctet(&B1,B);

    // Random z value
    if (RNG!=NULL)
    {
        FF_4096_random(z,RNG,FFLEN_4096);
        FF_4096_mod(z,q,FFLEN_4096);
    }
    else
    {
        char z1[FS_4096];
        octet Z1 = {0,sizeof(z1),z1};
        OCT_clear(&Z1);
        Z1.len = FS_4096 - EGS_SECP256K1;
        ZO->len = EGS_SECP256K1;
        OCT_joctet(&Z1,ZO);
        FF_4096_zero(z, FFLEN_4096);
        FF_4096_fromOctet(z,&Z1,FFLEN_4096);
    }
    FF_4096_toOctet(&Z, z, HFLEN_4096);

    // beta = -z mod q
    FF_4096_sub(beta, q, z, FFLEN_4096);

    // CT = E_A(a.b)
    PAILLIER_MULT(PUB, CA, &B1, &CT);

    // CZ = E_A(z)
    PAILLIER_ENCRYPT(RNG, PUB, &Z, &CZ, R);

    // CB = E_A(a.b + z)
    PAILLIER_ADD(PUB, &CT, &CZ, CB);

    // Output Z for Debug
    if (ZO!=NULL)
    {
        char z1[FS_4096];
        octet Z1 = {0,sizeof(z1),z1};
        FF_4096_toOctet(&Z1, z, FFLEN_4096);
        OCT_clear(ZO);
        ZO->len = EGS_SECP256K1;
        Z1.len = FS_4096 - EGS_SECP256K1;
        OCT_truncate(ZO,&Z1);
    }

    // Output beta
    char beta1[FS_4096];
    octet BETA1 = {0,sizeof(beta1),beta1};
    FF_4096_toOctet(&BETA1, beta, FFLEN_4096);
    OCT_clear(BETA);
    BETA->len = EGS_SECP256K1;
    BETA1.len = FS_4096 - EGS_SECP256K1;
    OCT_truncate(BETA,&BETA1);
}

/* sum = a1.b1 + alpha + beta  */
void MPC_SUM_MTA(octet *A, octet *B, octet *ALPHA, octet *BETA,  octet *SUM)
{
    BIG_256_56 a;
    BIG_256_56 b;
    BIG_256_56 alpha;
    BIG_256_56 beta;
    BIG_256_56 sum;
    BIG_256_56 q;

    // Curve order
    BIG_256_56_rcopy(q,CURVE_Order_SECP256K1);

    // Load values
    BIG_256_56_fromBytes(a,A->val);
    BIG_256_56_fromBytes(b,B->val);
    BIG_256_56_fromBytes(alpha,ALPHA->val);
    BIG_256_56_fromBytes(beta,BETA->val);

    // sum = a.b mod q
    BIG_256_56_modmul(sum,a,b,q);

    // sum = sum + alpha  + beta
    BIG_256_56_add(sum,sum,alpha);
    BIG_256_56_add(sum,sum,beta);

    // sum = sum mod q
    BIG_256_56_mod(sum,q);

    // Output result
    SUM->len=EGS_SECP256K1;
    BIG_256_56_toBytes(SUM->val,sum);
}
