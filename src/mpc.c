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

#include <amcl/ecdh_SECP256K1.h>
#include <amcl/ecdh_support.h>
#include <amcl/mpc.h>

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

    // invk = k^{-1}
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
    //BIG_256_56_mod(s,q);

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


/* IEEE1363 ECDSA Signature Verification. Signature R and S on M is verified using public key, PK */
int MPC_ECDSA_VERIFY(octet *HM, octet *PK, octet *R,octet *S)
{
    int res=0;
    BIG_256_56 q;
    BIG_256_56 z;
    BIG_256_56 c;
    BIG_256_56 d;
    BIG_256_56 h2;

    ECP_SECP256K1 G;
    ECP_SECP256K1 WP;
    int valid;

    // Curve order
    BIG_256_56_rcopy(q,CURVE_Order_SECP256K1);

    ECP_SECP256K1_generator(&G);

    // Load values
    OCT_shl(R,R->len-MODBYTES_256_56);
    OCT_shl(S,S->len-MODBYTES_256_56);
    BIG_256_56_fromBytes(c,R->val);
    BIG_256_56_fromBytes(d,S->val);
    BIG_256_56_fromBytes(z,HM->val);

    if (BIG_256_56_iszilch(c) || BIG_256_56_comp(c,q)>=0 || BIG_256_56_iszilch(d) || BIG_256_56_comp(d,q)>=0)
    {
        res=ECDH_INVALID;
    }

    if (res==0)
    {
        BIG_256_56_invmodp(d,d,q);
        BIG_256_56_modmul(z,z,d,q);
        BIG_256_56_modmul(h2,c,d,q);

        valid=ECP_SECP256K1_fromOctet(&WP,PK);

        if (!valid) res=ECDH_ERROR;
        else
        {
            ECP_SECP256K1_mul2(&WP,&G,h2,z);

            if (ECP_SECP256K1_isinf(&WP)) res=ECDH_INVALID;
            else
            {
                ECP_SECP256K1_get(d,d,&WP);
                BIG_256_56_mod(d,q);
                if (BIG_256_56_comp(d,c)!=0) res=ECDH_INVALID;
            }
        }
    }

    return res;
}

/* Calculate the inverse of kgamma */
void MPC_INVKGAMMA(octet *KGAMMA1, octet *KGAMMA2, octet *INVKGAMMA)
{
    BIG_256_56 kgamma1;
    BIG_256_56 kgamma2;
    BIG_256_56 kgamma;
    BIG_256_56 invkgamma;
    BIG_256_56 q;

    // Curve order
    BIG_256_56_rcopy(q,CURVE_Order_SECP256K1);

    // Load values
    BIG_256_56_fromBytes(kgamma1,KGAMMA1->val);
    BIG_256_56_fromBytes(kgamma2,KGAMMA2->val);

    // kgamma = kgamma1  + kgamma2
    BIG_256_56_add(kgamma,kgamma1,kgamma2);

    // kgamma = kgamma mod q
    BIG_256_56_mod(kgamma,q);

    // invkgamma = kgamma^{-1}
    BIG_256_56_invmodp(invkgamma,kgamma,q);

    // Output result
    INVKGAMMA->len=EGS_SECP256K1;
    BIG_256_56_toBytes(INVKGAMMA->val,invkgamma);
}


/* Calculate the r component of the signature */
int MPC_R(octet *INVKGAMMA, octet *GAMMAPT1, octet *GAMMAPT2, octet *R)
{
    BIG_256_56 invkgamma;
    BIG_256_56 q;
    BIG_256_56 rx;
    BIG_256_56 r;

    ECP_SECP256K1 gammapt1;
    ECP_SECP256K1 gammapt2;

    // Curve order
    BIG_256_56_rcopy(q,CURVE_Order_SECP256K1);

    // Load values
    BIG_256_56_fromBytes(invkgamma,INVKGAMMA->val);
    if (!ECP_SECP256K1_fromOctet(&gammapt1,GAMMAPT1))
    {
        return 1;
    }
    if (!ECP_SECP256K1_fromOctet(&gammapt2,GAMMAPT2))
    {
        return 1;
    }

    // gammapt1 + gammapt2
    ECP_SECP256K1_add(&gammapt1,&gammapt2);

    // rx, ry = k^{-1}.G
    ECP_SECP256K1_mul(&gammapt1,invkgamma);
    ECP_SECP256K1_get(rx,rx,&gammapt1);

    // r = rx mod q
    BIG_256_56_copy(r,rx);
    BIG_256_56_mod(r,q);
    if (BIG_256_56_iszilch(r))
    {
        return 1;
    }

    // Output result
    R->len=EGS_SECP256K1;
    BIG_256_56_toBytes(R->val,r);

    return 0;
}

// Hash the message
void MPC_HASH(int sha, octet *M, octet *HM)
{
    char h[128];
    octet H = {0,sizeof(h),h};

    BIG_256_56 z;

    // z = hash(M)
    ehashit(sha,M,-1,NULL,&H,sha);
    int hlen=H.len;
    if (H.len>MODBYTES_256_56) hlen=MODBYTES_256_56;
    BIG_256_56_fromBytesLen(z,H.val,hlen);

    // Output result
    HM->len=MODBYTES_256_56;
    BIG_256_56_toBytes(HM->val,z);
}

// Calculate the s component of the signature
int MPC_S(octet *HM, octet *R, octet *K, octet *SIGMA, octet *S)
{
    BIG_256_56 q;
    BIG_256_56 k;
    BIG_256_56 z;
    BIG_256_56 sigma;
    BIG_256_56 r;
    BIG_256_56 kz;
    BIG_256_56 rsigma;
    BIG_256_56 s;

    // Curve order
    BIG_256_56_rcopy(q,CURVE_Order_SECP256K1);

    // Load values
    BIG_256_56_fromBytes(z,HM->val);
    BIG_256_56_fromBytes(r,R->val);
    BIG_256_56_fromBytes(k,K->val);
    BIG_256_56_fromBytes(sigma,SIGMA->val);

    // kz = k.z mod q
    BIG_256_56_modmul(kz,k,z,q);

    // rsigma = r.sigma mod q
    BIG_256_56_modmul(rsigma,r,sigma,q);

    // s = kz + rsigma  mod q
    BIG_256_56_add(s,kz,rsigma);
    BIG_256_56_mod(s,q);
    if (BIG_256_56_iszilch(s))
    {
        return 1;
    }

    // Output result
    S->len=EGS_SECP256K1;
    BIG_256_56_toBytes(S->val,s);

    return 0;
}

/* Calculate sum of s components of signature  */
void MPC_SUM_S(octet *S1, octet *S2, octet *S)
{
    BIG_256_56 s1;
    BIG_256_56 s2;
    BIG_256_56 s;
    BIG_256_56 q;

    // Curve order
    BIG_256_56_rcopy(q,CURVE_Order_SECP256K1);

    // Load values
    BIG_256_56_fromBytes(s1,S1->val);
    BIG_256_56_fromBytes(s2,S2->val);

    // s = s1 + s2
    BIG_256_56_add(s,s1,s2);

    // s = s mod q
    BIG_256_56_mod(s,q);

    // Output result
    S->len=EGS_SECP256K1;
    BIG_256_56_toBytes(S->val,s);
}

// Add the ECDSA public keys shares
int MPC_SUM_PK(octet *PK1, octet *PK2, octet *PK)
{
    ECP_SECP256K1 pk1;
    ECP_SECP256K1 pk2;

    // Load values
    if (!ECP_SECP256K1_fromOctet(&pk1,PK1))
    {
        return 1;
    }
    if (!ECP_SECP256K1_fromOctet(&pk2,PK2))
    {
        return 1;
    }

    // pk1 + pk2
    ECP_SECP256K1_add(&pk1,&pk2);

    // Output result
    ECP_SECP256K1_toOctet(PK,&pk1,false);

    return 0;
}

// Write Paillier public key to octets
void MPC_DUMP_PAILLIER_PK(PAILLIER_public_key *PUB, octet *N, octet *G, octet *N2)
{
    FF_4096_toOctet(N, PUB->n, FFLEN_4096);
    FF_4096_toOctet(G, PUB->g, FFLEN_4096);
    FF_4096_toOctet(N2, PUB->n2, FFLEN_4096);
}

// Load Paillier public key from octets
void MPC_LOAD_PAILLIER_PK(PAILLIER_public_key *PUB, octet *N, octet *G, octet *N2)
{
    FF_4096_fromOctet(PUB->n, N, FFLEN_4096);
    FF_4096_fromOctet(PUB->g, G, FFLEN_4096);
    FF_4096_fromOctet(PUB->n2, N2, FFLEN_4096);
}

// Write Paillier secret key to octets
void MPC_DUMP_PAILLIER_SK(PAILLIER_private_key *PRIV, octet *P, octet *Q, octet *LP, octet *LQ, octet *INVP, octet *INVQ, octet *P2, octet *Q2, octet *MP, octet *MQ)
{
    FF_2048_toOctet(P, PRIV->p, HFLEN_2048);
    FF_2048_toOctet(Q, PRIV->q, HFLEN_2048);

    FF_2048_toOctet(LP, PRIV->lp, HFLEN_2048);
    FF_2048_toOctet(LQ, PRIV->lq, HFLEN_2048);

    FF_2048_toOctet(INVP, PRIV->invp, FFLEN_2048);
    FF_2048_toOctet(INVQ, PRIV->invq, FFLEN_2048);

    FF_2048_toOctet(P2, PRIV->p2, FFLEN_2048);
    FF_2048_toOctet(Q2, PRIV->q2, FFLEN_2048);

    FF_2048_toOctet(MP, PRIV->mp, HFLEN_2048);
    FF_2048_toOctet(MQ, PRIV->mq, HFLEN_2048);
}

// Load Paillier secret key from octets
void MPC_LOAD_PAILLIER_SK(PAILLIER_private_key *PRIV, octet *P, octet *Q, octet *LP, octet *LQ, octet *INVP, octet *INVQ, octet *P2, octet *Q2, octet *MP, octet *MQ)
{
    FF_2048_fromOctet(PRIV->p, P, HFLEN_2048);
    FF_2048_fromOctet(PRIV->q, Q, HFLEN_2048);

    FF_2048_fromOctet(PRIV->lp, LP, HFLEN_2048);
    FF_2048_fromOctet(PRIV->lq, LQ, HFLEN_2048);

    FF_2048_fromOctet(PRIV->invp, INVP, FFLEN_2048);
    FF_2048_fromOctet(PRIV->invq, INVQ, FFLEN_2048);

    FF_2048_fromOctet(PRIV->p2, P2, FFLEN_2048);
    FF_2048_fromOctet(PRIV->q2, Q2, FFLEN_2048);

    FF_2048_fromOctet(PRIV->mp, MP, HFLEN_2048);
    FF_2048_fromOctet(PRIV->mq, MQ, HFLEN_2048);
}
