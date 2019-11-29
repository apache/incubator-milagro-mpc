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

static char* curve_order_hex = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";


/* ECDSA Signature, R and S are the signature on M using private key SK */
int MPC_ECDSA_SIGN(int sha, octet *K, octet *SK, octet *M, octet *R, octet *S)
{
    char h[128];
    octet H = {0,sizeof(h),h};

    BIG_256_56 q;
    BIG_256_56 r;
    BIG_256_56 s;
    BIG_256_56 sk;
    BIG_256_56 z;
    BIG_256_56 k;
    BIG_256_56 invk;
    BIG_256_56 rx;

    ECP_SECP256K1 G;
    ECP_SECP256K1 RP;

    // Curve generator point
    ECP_SECP256K1_generator(&G);

    // Curve order
    BIG_256_56_rcopy(q,CURVE_Order_SECP256K1);

    // Secret key
    BIG_256_56_fromBytes(sk,SK->val);

    // Hash message. z = hash(M)
    ehashit(sha,M,-1,NULL,&H,sha);
    int hlen=H.len;
    if (H.len>MODBYTES_256_56) hlen=MODBYTES_256_56;
    BIG_256_56_fromBytesLen(z,H.val,hlen);

    // Nonce k
    BIG_256_56_fromBytes(k,K->val);
    BIG_256_56_mod(k,q);

    // k^{-1}
    BIG_256_56_invmodp(invk,k,q);

    // rx, ry = k^{-1}.G
    ECP_SECP256K1_copy(&RP,&G);
    ECP_SECP256K1_mul(&RP,invk);
    ECP_SECP256K1_get(rx,rx,&RP);

    // r = rx mod q
    BIG_256_56_copy(r,rx);
    BIG_256_56_mod(r,q);
    if (BIG_256_56_iszilch(r))
    {
        return ECDH_ERROR;
    }

    // s = r.sk mod q
    BIG_256_56_modmul(s,sk,r,q);

    // s = z + r.sk mod q
    BIG_256_56_add(s,z,s);

    // s = k(z + r.sk) mod q
    BIG_256_56_modmul(s,k,s,q);
    if (BIG_256_56_iszilch(s))
    {
        return ECDH_ERROR;
    }

    // Output result
    R->len=EGS_SECP256K1;
    S->len=EGS_SECP256K1;
    BIG_256_56_toBytes(R->val,r);
    BIG_256_56_toBytes(S->val,s);

    return 0;
}

// Client MTA first pass
int MPC_MTA_CLIENT1(csprng *RNG, octet* N, octet* G, octet* A, octet* CA, octet* R)
{
    int rc;
    rc = PAILLIER_ENCRYPT(RNG, N, G, A, CA, R);
    return rc;
}

// Client MtA second pass
int MPC_MTA_CLIENT2(octet* N, octet* L, octet* M, octet* CB, octet* ALPHA)
{
    int rc;
    rc = PAILLIER_DECRYPT(N, L, M, CB, ALPHA);
    return rc;
}

// MtA server
int MPC_MTA_SERVER(csprng *RNG, octet* N, octet* G, octet* B, octet* CA, octet* ZO, octet* R, octet* CB, octet* BETA)
{
    int rc;
    BIG_512_60 q[FFLEN_4096];
    BIG_512_60 z[FFLEN_4096];
    BIG_512_60 beta[FFLEN_4096];

    char co[FS_4096];
    octet CO = {0,sizeof(co),co};

    char zb[FS_2048];
    octet Z = {0,sizeof(zb),zb};

    char cz[FS_4096];
    octet CZ = {0,sizeof(cz),cz};

    char ct[FS_4096];
    octet CT = {0,sizeof(ct),ct};

    // Curve order
    OCT_fromHex(&CO,curve_order_hex);
    FF_4096_zero(q, FFLEN_4096);
    FF_4096_fromOctet(q,&CO,HFLEN_4096);

    // Random z value
    if (RNG!=NULL)
    {
        FF_4096_randomnum(z,q,RNG,FFLEN_4096);
    }
    else
    {
        FF_4096_zero(z, FFLEN_4096);
        FF_4096_fromOctet(z,ZO,HFLEN_4096);
    }
    FF_4096_toOctet(&Z, z, HFLEN_4096);

    // beta = -z mod q
    FF_4096_sub(beta, q, z, FFLEN_4096);

    // CT = E_A(a.b)
    rc = PAILLIER_MULT(N, CA, B, &CT);
    if (rc)
    {
        return rc;
    }

    // CZ = E_A(z)
    rc = PAILLIER_ENCRYPT(RNG, N, G, &Z, &CZ, R);
    if (rc)
    {
        return rc;
    }

    // CB = E_A(a.b + z)
    rc = PAILLIER_ADD(N, &CT, &CZ, CB);

    // Output Z for Debug
    if (ZO!=NULL)
    {
        FF_4096_toOctet(ZO, z, HFLEN_4096);
    }

    FF_4096_toOctet(BETA, beta, HFLEN_4096);

    return rc;
}
