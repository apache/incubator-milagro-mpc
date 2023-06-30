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

#include "amcl/cg21/cg21.h"

int CG21_SIGN_ROUND1(octet *msg,
                     const CG21_PRESIGN_ROUND4_STORE_2 *pre,
                     CG21_SIGN_ROUND1_STORE *store,
                     CG21_SIGN_ROUND1_OUTPUT *out){

    /* ---------STEP 1: obtain R_x ----------
    * r:          get x component of R
    */


    ECP_SECP256K1 R;
    BIG_256_56 q;
    BIG_256_56 x;
    BIG_256_56 y;

    // Curve order
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    if (!ECP_SECP256K1_fromOctet(&R, pre->R))
    {
        return CG21_INVALID_ECP;
    }

    // get rx, ry of R
    ECP_SECP256K1_get(x, y, &R);

    // r = rx mod q
    BIG_256_56_mod(x, q);
    if (BIG_256_56_iszilch(x))
    {
        return CG21_SIGN_r_IS_ZERO;
    }

    // store r component of signature
    store->r->len=EGS_SECP256K1;
    BIG_256_56_toBytes(store->r->val,x);
    BIG_256_56_zero(x);
    BIG_256_56_zero(y);


    /* ---------STEP 2: compute sigma ----------
    * sigma:            km + r\chi mod q
    */

    char hm[SHA256_HASH_SIZE];
    octet HM = {0,sizeof(hm),hm};

    // hash message and store it in HM
    ehashit(HASH_TYPE_SECP256K1, msg, -1, NULL, &HM, MODBYTES_256_56);

    BIG_256_56 m;
    BIG_256_56 r;
    BIG_256_56 k;
    BIG_256_56 chi;
    BIG_256_56 km;
    BIG_256_56 rchi;
    BIG_256_56 sigma;

    // Load values
    BIG_256_56_fromBytes(m, HM.val);
    BIG_256_56_fromBytes(r, store->r->val);
    BIG_256_56_fromBytes(k, pre->k->val);
    BIG_256_56_fromBytes(chi, pre->chi->val);


    // km = k.m mod q
    BIG_256_56_modmul(km, k, m, q);

    // rchi = r.chi mod q
    BIG_256_56_modmul(rchi, r, chi, q);

    // s = km + rchi  mod q
    BIG_256_56_add(sigma, km, rchi);
    BIG_256_56_mod(sigma, q);
    if (BIG_256_56_iszilch(sigma))
    {
        // clean memory
        BIG_256_56_zero(r);
        BIG_256_56_zero(k);
        BIG_256_56_zero(chi);
        BIG_256_56_zero(km);
        BIG_256_56_zero(rchi);

        return CG21_SIGN_SIGMA_IS_ZERO;
    }

    // store and output result
    store->i = pre->i;
    out->i = pre->i;

    store->sigma->len = EGS_SECP256K1;
    BIG_256_56_toBytes(store->sigma->val, sigma);

    OCT_copy(out->sigma, store->sigma);

    BIG_256_56_zero(r);
    BIG_256_56_zero(k);
    BIG_256_56_zero(chi);
    BIG_256_56_zero(km);
    BIG_256_56_zero(rchi);
    BIG_256_56_zero(sigma);

    return CG21_OK;
}

int CG21_SIGN_ROUND2(const CG21_SIGN_ROUND1_STORE *mystore,
                     const CG21_SIGN_ROUND1_OUTPUT *hisout,
                     CG21_SIGN_ROUND2_OUTPUT *out,
                     int status){
    /*
     * status = 0      first call
     * status = 1      neither first call, nor last call
     * status = 2      last call
     * status = 3      first and last call (t=2)
     */


    /* ---------STEP 1: generate sigma ----------
    * sigma:          \sum sigma_j
    */

    BIG_256_56 q;
    BIG_256_56 s;
    BIG_256_56 accum;

    // Curve order
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    if (status==0 || status ==3){
        OCT_copy(out->sigma, mystore->sigma);

    }

    BIG_256_56_fromBytesLen(accum, out->sigma->val, out->sigma->len);
    BIG_256_56_fromBytesLen(s, hisout->sigma->val, hisout->sigma->len);

    BIG_256_56_add(accum, accum, s);
    BIG_256_56_mod(accum, q);

    out->sigma->len = EGS_SECP256K1;
    BIG_256_56_toBytes(out->sigma->val, accum);

    if (status==2 || status ==3){
        OCT_copy(out->r, mystore->r);
    }

    // clean memory
    BIG_256_56_zero(accum);
    BIG_256_56_zero(s);

    return CG21_OK;
}

int CG21_SIGN_VALIDATE(const octet *msg,
                       CG21_SIGN_ROUND2_OUTPUT *out,
                       octet *PK){

    BIG_256_56 q;
    BIG_256_56 a;
    BIG_256_56 r;
    BIG_256_56 s;
    BIG_256_56 b;
    BIG_256_56 x;
    BIG_256_56 y;

    ECP_SECP256K1 G;
    ECP_SECP256K1 c;
    int valid;

    char hm[SHA256_HASH_SIZE];
    octet HM = {0,sizeof(hm),hm};

    // hash message and store it in HM
    ehashit(HASH_TYPE_SECP256K1, msg, -1, NULL, &HM, MODBYTES_256_56);

    // Curve order
    BIG_256_56_rcopy(q,CURVE_Order_SECP256K1);
    ECP_SECP256K1_generator(&G);

    // Load values
    OCT_shl(out->r,out->r->len-MODBYTES_256_56);
    OCT_shl(out->sigma,out->sigma->len-MODBYTES_256_56);
    BIG_256_56_fromBytes(r,out->r->val);
    BIG_256_56_fromBytes(s,out->sigma->val);
    BIG_256_56_fromBytes(a,HM.val);

    if (BIG_256_56_iszilch(r) || BIG_256_56_comp(r,q)>=0 || BIG_256_56_iszilch(s) || BIG_256_56_comp(s,q)>=0)
    {
        return CG21_SIGN_SIGNATURE_IS_INVALID;
    }

    /* ---------STEP 1: generate sigma ----------
    * compute a = ms^{-1} mod q
    * compute b = rs^{-1} mod q
    * compute c = a*G + b*PK
    * check c_x == r
    */

    // s = s^-1 mod q
    BIG_256_56_invmodp(s,s,q);

    // a = ms^{-1} mod q
    BIG_256_56_modmul(a,a,s,q);

    // b = rs^{-1} mod q
    BIG_256_56_modmul(b,r,s,q);

    valid=ECP_SECP256K1_fromOctet(&c,PK);
    if (!valid)
    {
        return CG21_INVALID_ECP;
    }

    // c = a*G + b*PK
    ECP_SECP256K1_mul2(&c,&G,b,a);

    if (ECP_SECP256K1_isinf(&c))
    {
        return CG21_INVALID_ECP;
    }

    // get x component of point c
    ECP_SECP256K1_get(x,y,&c);
    BIG_256_56_mod(x,q);

    //check c_x == r
    if (BIG_256_56_comp(x,r)!=0)
    {
        return CG21_SIGN_SIGNATURE_IS_INVALID;
    }

    return CG21_OK;
}