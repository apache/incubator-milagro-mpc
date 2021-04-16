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
#include <amcl/gg20_zkp.h>
#include <amcl/mpc.h>

/* Generate ECDSA key pair */
void MPC_ECDSA_KEY_PAIR_GENERATE(csprng *RNG, octet* S, octet *W)
{
    BIG_256_56 s;
    BIG_256_56 q;

    ECP_SECP256K1 G;

    ECP_SECP256K1_generator(&G);
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    if (RNG!=NULL)
    {
        BIG_256_56_randomnum(s, q, RNG);

        S->len=EGS_SECP256K1;
        BIG_256_56_toBytes(S->val,s);
    }
    else
    {
        BIG_256_56_fromBytesLen(s, S->val, S->len);
    }

    ECP_SECP256K1_mul(&G, s);
    ECP_SECP256K1_toOctet(W, &G, true);

    BIG_256_56_zero(s);
}

/* ECDSA Signature, R and S are the signature on M using private key SK */
int MPC_ECDSA_SIGN(int sha, const octet *K, const octet *SK, octet *M, octet *R, octet *S)
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
int MPC_ECDSA_VERIFY(const octet *HM, octet *PK, octet *R,octet *S)
{
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
        return ECDH_INVALID;
    }

    BIG_256_56_invmodp(d,d,q);
    BIG_256_56_modmul(z,z,d,q);
    BIG_256_56_modmul(h2,c,d,q);

    valid=ECP_SECP256K1_fromOctet(&WP,PK);
    if (!valid)
    {
        return ECDH_ERROR;
    }

    ECP_SECP256K1_mul2(&WP,&G,h2,z);

    if (ECP_SECP256K1_isinf(&WP))
    {
        return ECDH_INVALID;
    }

    ECP_SECP256K1_get(d,d,&WP);
    BIG_256_56_mod(d,q);
    if (BIG_256_56_comp(d,c)!=0)
    {
        return ECDH_INVALID;
    }

    return 0;
}

void MPC_K_GENERATE(csprng *RNG, octet *K)
{
    BIG_256_56 s;
    BIG_256_56 q;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    BIG_256_56_randomnum(s, q, RNG);

    K->len=EGS_SECP256K1;
    BIG_256_56_toBytes(K->val, s);

    BIG_256_56_zero(s);
}

/* Calculate the inverse of kgamma */
void MPC_INVKGAMMA(const octet *KGAMMA, octet *INVKGAMMA, int n)
{
    int i;

    BIG_256_56 accum;
    BIG_256_56 kgamma;
    BIG_256_56 q;

    // Curve order
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    // accum = kgamma1 + ... + kgamman mod q
    BIG_256_56_fromBytesLen(accum, KGAMMA[0].val, KGAMMA[0].len);

    for (i = 1; i < n; i++)
    {
        BIG_256_56_fromBytesLen(kgamma, KGAMMA[i].val, KGAMMA[i].len);

        BIG_256_56_add(accum, accum, kgamma);
        BIG_256_56_mod(accum, q);
    }

    // invkgamma = accum^{-1}
    BIG_256_56_invmodp(accum, accum, q);

    // Output result
    INVKGAMMA->len = EGS_SECP256K1;
    BIG_256_56_toBytes(INVKGAMMA->val, accum);
}

/* Calculate the r component of the signature */
int MPC_R(const octet *INVKGAMMA, octet *GAMMAPT, octet *R, octet *RP, int n)
{
    int i;

    BIG_256_56 w;
    BIG_256_56 q;

    ECP_SECP256K1 accum;
    ECP_SECP256K1 gammapt;

    // Curve order
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    // accum = gammapt1 + ... + gammaptn
    if (!ECP_SECP256K1_fromOctet(&accum, GAMMAPT))
    {
        return MPC_INVALID_ECP;
    }

    for (i = 1; i < n; i++)
    {
        if (!ECP_SECP256K1_fromOctet(&gammapt, GAMMAPT+i))
        {
            return MPC_INVALID_ECP;
        }

        ECP_SECP256K1_add(&accum, &gammapt);
    }

    // Load invkgamma
    BIG_256_56_fromBytesLen(w, INVKGAMMA->val, INVKGAMMA->len);

    // rx, ry = k^{-1}.G
    ECP_SECP256K1_mul(&accum, w);
    ECP_SECP256K1_get(w, w, &accum);

    // r = rx mod q
    BIG_256_56_mod(w, q);
    if (BIG_256_56_iszilch(w))
    {
        return MPC_FAIL;
    }

    // Output result
    R->len = EGS_SECP256K1;
    BIG_256_56_toBytes(R->val, w);

    if (RP != NULL)
    {
        ECP_SECP256K1_toOctet(RP, &accum, true);
    }

    return MPC_OK;
}

// Hash the message
void MPC_HASH(int sha, octet *M, octet *HM)
{
    ehashit(sha, M, -1, NULL, HM, MODBYTES_256_56);
}

// Calculate the s component of the signature
int MPC_S(const octet *HM, const octet *R, const octet *K, const octet *SIGMA, octet *S)
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
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    // Load values
    BIG_256_56_fromBytes(z, HM->val);
    BIG_256_56_fromBytes(r, R->val);
    BIG_256_56_fromBytes(k, K->val);
    BIG_256_56_fromBytes(sigma, SIGMA->val);

    // kz = k.z mod q
    BIG_256_56_modmul(kz, k, z, q);

    // rsigma = r.sigma mod q
    BIG_256_56_modmul(rsigma, r, sigma, q);

    // s = kz + rsigma  mod q
    BIG_256_56_add(s, kz, rsigma);
    BIG_256_56_mod(s, q);
    if (BIG_256_56_iszilch(s))
    {
        return MPC_FAIL;
    }

    // Output result
    S->len = EGS_SECP256K1;
    BIG_256_56_toBytes(S->val, s);

    return MPC_OK;
}

// Calculate sum of BIGs in the EC gorup
void MPC_SUM_BIGS(octet *OUT, const octet *SHARES, int n)
{
    int i;

    BIG_256_56 accum;
    BIG_256_56 s;
    BIG_256_56 q;

    // Curve order
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    // accum = s1 + ... + sn mod q
    BIG_256_56_fromBytesLen(accum, SHARES->val, SHARES->len);

    for (i = 1; i < n; i++)
    {
        BIG_256_56_fromBytesLen(s, (SHARES+i)->val, (SHARES+i)->len);

        BIG_256_56_add(accum, accum, s);
        BIG_256_56_mod(accum, q);
    }

    // Output result
    OUT->len = EGS_SECP256K1;
    BIG_256_56_toBytes(OUT->val, accum);
}

// Calculate sum of ECPs
int MPC_SUM_ECPS(octet *OUT, octet *SHARES, int n)
{
    int i;

    ECP_SECP256K1 accum;
    ECP_SECP256K1 s;

    // accum = s1 + ... + sn
    if (!ECP_SECP256K1_fromOctet(&accum, SHARES))
    {
        return MPC_INVALID_ECP;
    }

    for (i = 1; i < n; i++)
    {
        if (!ECP_SECP256K1_fromOctet(&s, SHARES+i))
        {
            return MPC_INVALID_ECP;
        }

        ECP_SECP256K1_add(&accum, &s);
    }

    // Output result
    ECP_SECP256K1_toOctet(OUT, &accum, true);

    return MPC_OK;
}

// Compute Phase3 T
void MPC_PHASE3_T(csprng *RNG, octet *SIGMA, octet *L, octet *T)
{
    BIG_256_56 q;
    BIG_256_56 l;
    BIG_256_56 sigma;

    ECP_SECP256K1 G;
    ECP_SECP256K1 H;

    ECP_SECP256K1_generator(&G);
    GG20_ZKP_generator_2(&H);

    BIG_256_56_fromBytesLen(sigma, SIGMA->val, SIGMA->len);

    if (RNG != NULL)
    {
        BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
        BIG_256_56_randomnum(l, q, RNG);

        BIG_256_56_toBytes(L->val, l);
        L->len = EGS_SECP256K1;
    }
    else
    {
        BIG_256_56_fromBytesLen(l, L->val, L->len);
    }

    // T = sigma.G + l.H
    ECP_SECP256K1_mul2(&G, &H, sigma, l);

    ECP_SECP256K1_toOctet(T, &G, true);

    // Clean memory
    BIG_256_56_zero(sigma);
    BIG_256_56_zero(l);
}

// Compute Rt = x.R
extern int MPC_ECP_GENERATE_CHECK(octet *R, octet *X, octet *RT)
{
    BIG_256_56 x;
    ECP_SECP256K1 ECPR;

    BIG_256_56_fromBytesLen(x, X->val, X->len);
    if (!ECP_SECP256K1_fromOctet(&ECPR, R))
    {
        return MPC_INVALID_ECP;
    }

    ECP_SECP256K1_mul(&ECPR, x);
    ECP_SECP256K1_toOctet(RT, &ECPR, true);

    BIG_256_56_zero(x);

    return MPC_OK;
}

int MPC_ECP_VERIFY(octet *RT, octet *G, int n)
{
    int i;

    ECP_SECP256K1 ECP;
    ECP_SECP256K1 ECPG;

    ECP_SECP256K1_inf(&ECP);

    // Combine RTs
    for(i = 0; i < n; i++)
    {
        if(!ECP_SECP256K1_fromOctet(&ECPG, RT+i))
        {
            return MPC_INVALID_ECP;
        }

        ECP_SECP256K1_add(&ECP, &ECPG);
    }

    // Compare to ground truth
    if (G == NULL)
        ECP_SECP256K1_generator(&ECPG);
    else
    {
        if (!ECP_SECP256K1_fromOctet(&ECPG, G))
        {
            return MPC_INVALID_ECP;
        }
    }

    if (!ECP_SECP256K1_equals(&ECP, &ECPG))
    {
        return MPC_FAIL;
    }

    return MPC_OK;
}

// Write Paillier keys to octets
void MPC_DUMP_PAILLIER_SK(PAILLIER_private_key *PRIV, octet *P, octet *Q)
{
    FF_2048_toOctet(P, PRIV->p, HFLEN_2048);
    FF_2048_toOctet(Q, PRIV->q, HFLEN_2048);
}
