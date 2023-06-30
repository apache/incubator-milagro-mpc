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

#include "amcl/cg21/cg21_pi_mod.h"
#include <amcl/big_256_56.h>
#include <amcl/paillier.h>
#include "amcl/hash_utils.h"
#include "amcl/ff_4096.h"
#include "amcl/ff_2048.h"

static void CG21_PI_MOD_GET_W(csprng *RNG, BIG_512_60 n[HFLEN_4096], BIG_512_60 ws1[HFLEN_4096]){
    while(1){
        FF_4096_randomnum(ws1, n, RNG,HFLEN_4096);
        int rc = FF_4096_jacobi(ws1,n);
        if (rc==-1) {
            break;
        }
    }
}

/**	@brief Generate m number of challenges, y_i
*
* Note: m is defined as CG21_PAILLIER_PROOF_ITERS
*
*  @param N             Paillier N
*  @param w             random obtained from CG21_PI_MOD_GET_W()
*  @param ssid          system-wide session-ID, refers to the same notation as in CG21
*  @param yi            generated challenges
*  @param n             size of packed elements in SSID
*/
static int CG21_PI_MOD_CHALLENGE(BIG_1024_58 *N, octet w, const CG21_SSID *ssid,
                          BIG_1024_58 yi[CG21_PAILLIER_PROOF_ITERS][FFLEN_2048], int n){
    hash256 sha;
    hash256 sha_k;
    HASH256_init(&sha);

    char n_[FS_2048];
    octet N_Oct = {0, sizeof(n_), n_};

    char o[SFS_SECP256K1 + 1];
    octet G_oct = {0, sizeof(o), o};

    char qq[EGS_SECP256K1];
    octet q_oct = {0, sizeof(qq), qq};

    FF_2048_toOctet(&N_Oct, N, FFLEN_2048);
    HASH_UTILS_hash_oct(&sha, &N_Oct);
    HASH_UTILS_hash_oct(&sha, ssid->rid);
    HASH_UTILS_hash_oct(&sha, ssid->rho);
    HASH_UTILS_hash_oct(&sha, &w);

    CG21_get_G(&G_oct);
    CG21_get_q(&q_oct);

    HASH_UTILS_hash_oct(&sha, &G_oct);
    HASH_UTILS_hash_oct(&sha, &q_oct);

    // sort partial X[i] based on j_packed and process them into sha
    int rc = CG21_hash_set_X(&sha, ssid->X_set_packed, ssid->j_set_packed, n, EFS_SECP256K1 + 1);
    if (rc!=CG21_OK){
        return rc;
    }

    for (int i=0;i<CG21_PAILLIER_PROOF_ITERS;i++){
        HASH_UTILS_hash_copy(&sha_k, &sha);
        HASH_UTILS_hash_i2osp4(&sha_k, i);
        HASH_UTILS_sample_mod_FF(&sha_k, N, yi[i]);
    }

    return CG21_OK;
}

static void CG21_PI_MOD_GEN_Xi(CG21_PIMOD_PROOF *pimodProof, CG21_PAILLIER_KEYS paillierKeys){
    bool ab_[4][2]={{0,0},{0,1},{1,0},{1,1}};
    BIG_512_60 yi_[HFLEN_4096];
    BIG_512_60 yMULw[FFLEN_4096];
    BIG_512_60 n_[FFLEN_4096];
    BIG_1024_58 r1[FFLEN_2048];
    BIG_1024_58 r2[FFLEN_2048];
    BIG_1024_58 r11[FFLEN_2048];
    BIG_1024_58 r22[FFLEN_2048];
    BIG_1024_58 yi_2048[FFLEN_2048];
    BIG_1024_58 n_2048[FFLEN_2048];

    char oct[2*FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    FF_4096_zero(n_,FFLEN_4096);
    FF_4096_copy(n_,paillierKeys.paillier_pk.n,HFLEN_4096);

    // convert paillier_pk.n from BIG_512_60[HFLEN_4096] to BIG_1024_58[FFLEN_2048]
    FF_4096_toOctet(&OCT, paillierKeys.paillier_pk.n, HFLEN_4096);
    FF_2048_fromOctet(n_2048, &OCT, FFLEN_2048);

    // for each yi[i] we need to choose (ai,bi) from ab_ such that y'i has 4th root
    for (int i=0;i<CG21_PAILLIER_PROOF_ITERS;i++){

        // convert yi from BIG_1024_58[FFLEN_2048] to y_oct
        char oct2[2 * FS_2048];
        octet y_oct = {0, sizeof(oct2), oct2};
        FF_2048_toOctet(&y_oct, pimodProof->yi[i], FFLEN_2048);

        for (int j=0;j<4;j++){

            // convert y_oct to BIG_512_60[HFLEN_4096]
            FF_4096_zero(yi_, HFLEN_4096);
            FF_4096_fromOctet(yi_, &y_oct, HFLEN_4096);

            // if ai=1 -> (-1)^{ai} becomes -1 -> we compute -yi mod N = N - yi
            // note: if ai=0 -> (-1)^{ai} becomes 0 -> we don't need to do anything
            if (ab_[j][0]) {
                FF_4096_sub(yi_, paillierKeys.paillier_pk.n, yi_, HFLEN_4096);
                FF_4096_norm(yi_, HFLEN_4096);
            }

            // if bi=1 -> we compute yi = w * yi
            if (ab_[j][1]) {
                FF_4096_zero(yMULw, FFLEN_4096);
                FF_4096_mul(yMULw, yi_, pimodProof->w, HFLEN_4096);
                FF_4096_mod(yMULw, n_, FFLEN_4096);
                FF_4096_copy(yi_, yMULw, HFLEN_4096);
            }

            // convert yi_ from BIG_512_60[HFLEN_4096] to BIG_1024_58[FFLEN_2048]
            FF_4096_toOctet(&OCT, yi_, HFLEN_4096);
            FF_2048_fromOctet(yi_2048, &OCT, FFLEN_2048);

            // check whether yi_2048 has any square root in mod p and q
            bool rc1 = CG21_check_sqrt_exist(yi_2048, paillierKeys.paillier_sk.p);
            bool rc2 = CG21_check_sqrt_exist(yi_2048, paillierKeys.paillier_sk.q);

            if (rc1 && rc2){

                // 4th root of yi_2048 mod p
                CG21_sqrt(r1,yi_2048,paillierKeys.paillier_sk.p);
                CG21_sqrt(r11,r1,paillierKeys.paillier_sk.p);

                // 4th root of yi_2048 mod q
                CG21_sqrt(r2,yi_2048,paillierKeys.paillier_sk.q);
                CG21_sqrt(r22,r2,paillierKeys.paillier_sk.q);

                // combine r11 and r22 using CRT to get the final result xi
                FF_2048_crt(pimodProof->xi[i], r11, r22, paillierKeys.paillier_sk.p, paillierKeys.paillier_sk.invpq, n_2048, HFLEN_2048);

                // stores ai and bi values, verifier needs these values
                pimodProof->ab[i][0] = ab_[j][0];
                pimodProof->ab[i][1] = ab_[j][1];

                // don't need to check the other combinations of ai and bi
                break;
            }
        }
    }

    // clean up
    FF_4096_zero(yi_, HFLEN_4096);
    FF_4096_zero(yMULw, FFLEN_4096);
    FF_4096_zero(n_, FFLEN_4096);

    FF_2048_zero(r1, FFLEN_2048);
    FF_2048_zero(r2, HFLEN_2048);
    FF_2048_zero(r11, FFLEN_2048);
    FF_2048_zero(r22, HFLEN_2048);
    FF_2048_zero(yi_2048, FFLEN_2048);
    FF_2048_zero(n_2048, FFLEN_2048);

    OCT_clear(&OCT);
}

static void CG21_PI_MOD_GEN_Zi(CG21_PIMOD_PROOF *pimodProof, CG21_PAILLIER_KEYS paillierKeys){

    BIG_1024_58 Mp[HFLEN_2048];
    BIG_1024_58 Mq[HFLEN_2048];
    BIG_1024_58 Xp[HFLEN_2048];
    BIG_1024_58 Xq[HFLEN_2048];
    BIG_1024_58 ws[FFLEN_2048];
    BIG_1024_58 n_2048[FFLEN_2048];

    char oct[2*FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    /* Compute Mp, Mq s.t.
     *
     *   T ← PQ^(-1) mod (P-1)(Q-1)
     *   zi ← yi^T mod PQ, for i ∈ [1 ... m]
     *
     * i.e.
     *   Mp = Q^(-1) mod P-1
     *   Mq = P^(-1) mod Q-1
     */

    // Compute Mp

    // Since P is odd P>>1 = (P-1)/2
    FF_2048_copy(ws, paillierKeys.paillier_sk.p, HFLEN_2048);
    FF_2048_shr(ws, HFLEN_2048);

    // Compute inverse mod (P-1)/2
    FF_2048_invmodp(Mp, paillierKeys.paillier_sk.q, ws, HFLEN_2048);

    // Apply correction to obtain inverse mod P-1
    if (!FF_2048_parity(Mp))
    {
        FF_2048_add(Mp, ws, Mp, HFLEN_2048);
        FF_2048_norm(Mp, HFLEN_2048);
    }

    // Compute Mq

    // Since Q is odd Q>>1 = (Q-1)/2
    FF_2048_copy(ws, paillierKeys.paillier_sk.q, HFLEN_2048);
    FF_2048_shr(ws, HFLEN_2048);

    // Compute inverse mod (Q-1)/2
    FF_2048_invmodp(Mq, paillierKeys.paillier_sk.p, ws, HFLEN_2048);

    // Apply correction to obtain inverse mod Q-1
    if (!FF_2048_parity(Mq))
    {
        FF_2048_add(Mq, ws, Mq, HFLEN_2048);
        FF_2048_norm(Mq, HFLEN_2048);
    }

    // convert paillier_pk.n from BIG_512_60[HFLEN_4096] to BIG_1024_58[FFLEN_2048]
    FF_4096_toOctet(&OCT, paillierKeys.paillier_pk.n, HFLEN_4096);
    FF_2048_fromOctet(n_2048, &OCT, FFLEN_2048);

    for (int i=0; i<CG21_PAILLIER_PROOF_ITERS;i++){

        // Xp = yi % p
        FF_2048_dmod(Xp, pimodProof->yi[i], paillierKeys.paillier_sk.p, HFLEN_2048);

        // Xq = yi % q
        FF_2048_dmod(Xq, pimodProof->yi[i], paillierKeys.paillier_sk.q, HFLEN_2048);

        // Compute zi^M using Mp, Mq and CRT
        FF_2048_ct_pow(Xp, Xp, Mp, paillierKeys.paillier_sk.p, HFLEN_2048, HFLEN_2048);
        FF_2048_ct_pow(Xq, Xq, Mq, paillierKeys.paillier_sk.q, HFLEN_2048, HFLEN_2048);

        // zi ← yi^T mod PQ, for i ∈ [1 ... m]
        FF_2048_crt(pimodProof->zi[i], Xp, Xq, paillierKeys.paillier_sk.p, paillierKeys.paillier_sk.invpq, n_2048, HFLEN_2048);
    }

    // clean up
    FF_2048_zero(Mp,HFLEN_2048);
    FF_2048_zero(Mq,HFLEN_2048);
    FF_2048_zero(Xp,HFLEN_2048);
    FF_2048_zero(Xq,FFLEN_2048);
    FF_2048_zero(ws,FFLEN_2048);
}

static void boolToChar(const bool arr[][2], char* result) {
    for(int i=0; i<CG21_PAILLIER_PROOF_ITERS; i++) {
        result[i*2] = arr[i][0] ? '1' : '0';
        result[i*2+1] = arr[i][1] ? '1' : '0';
    }
}

static void charToBool(const char* str, bool arr[][2]) {
    for(int i=0; i<CG21_PAILLIER_PROOF_ITERS; i++) {
        arr[i][0] = (str[i*2] == '1') ? true : false;
        arr[i][1] = (str[i*2+1] == '1') ? true : false;
    }
}

static int CG21_PI_MOD_proof_fromOCTET(CG21_PIMOD_PROOF_OCT *paillierProof, CG21_PIMOD_PROOF *pimodProof){
    char result2[CG21_PAILLIER_PROOF_ITERS*2+1];

    char w[FS_2048];
    octet W = {0, sizeof(w), w};

    if (paillierProof->x->len != CG21_PAILLIER_PROOF_SIZE || paillierProof->z->len != CG21_PAILLIER_PROOF_SIZE)
    {
        return CG21_PAILLIER_PROOF_INVALID;
    }

    // load xi, yi and zi values from octets
    for (int i = CG21_PAILLIER_PROOF_ITERS - 1; i >= 0; i--)
    {
        OCT_chop(paillierProof->x, &W, paillierProof->x->len - FS_2048);
        FF_2048_fromOctet(pimodProof->xi[i], &W, FFLEN_2048);

        OCT_chop(paillierProof->z, &W, paillierProof->z->len - FS_2048);
        FF_2048_fromOctet(pimodProof->zi[i], &W, FFLEN_2048);
    }

    // Restore length of the proofs
    paillierProof->x->len = CG21_PAILLIER_PROOF_SIZE;
    paillierProof->z->len = CG21_PAILLIER_PROOF_SIZE;

    // Convert w from octet to BIG_512_60 w[HFLEN_4096]
    FF_4096_zero(pimodProof->w, HFLEN_4096);
    FF_4096_fromOctet(pimodProof->w, paillierProof->w, HFLEN_4096);

    // convert ab from octet to ab[CG21_PAILLIER_PROOF_ITERS][2]
    OCT_toStr(paillierProof->ab, result2);
    charToBool(result2, pimodProof->ab);

    return CG21_OK;
}

static void CG21_PI_MOD_proof_toOctet(CG21_PIMOD_PROOF_OCT *paillierProof, CG21_PIMOD_PROOF pimodProof)
{
    char w[FS_2048];
    octet W = {0, sizeof(w), w};

    OCT_clear(paillierProof->x);
    OCT_clear(paillierProof->z);

    // concatenate xi, yi and zi values as octet
    for (int i = 0; i < CG21_PAILLIER_PROOF_ITERS; i++)
    {
        FF_2048_toOctet(&W, pimodProof.xi[i], FFLEN_2048);
        OCT_joctet(paillierProof->x, &W);

        FF_2048_toOctet(&W, pimodProof.zi[i], FFLEN_2048);
        OCT_joctet(paillierProof->z, &W);
    }

    char result[CG21_PAILLIER_PROOF_ITERS*2+1];
    boolToChar(pimodProof.ab, result);
    result[CG21_PAILLIER_PROOF_ITERS*2] = '\0';  // add null terminator to result string

    OCT_clear(paillierProof->ab);
    OCT_jstring(paillierProof->ab,result);
}

int CG21_PI_MOD_PROVE(csprng *RNG, CG21_PAILLIER_KEYS paillierKeys,
                      const CG21_SSID *ssid, CG21_PIMOD_PROOF_OCT *paillierProof, int n){

    CG21_PIMOD_PROOF pimodProof;
    BIG_1024_58 n_[FFLEN_2048];

    char oct1[FS_2048];
    octet OCT = {0, sizeof(oct1), oct1};

    // choose random w ← ZN of Jacobi symbol −1
    CG21_PI_MOD_GET_W(RNG, paillierKeys.paillier_pk.n, pimodProof.w);
    FF_4096_toOctet(paillierProof->w, pimodProof.w, HFLEN_4096);

    // change the type of paillier_pk.n from BIG_512_60[HFLEN_4096] to BIG_1024_58[FFLEN_2048]
    FF_4096_toOctet(&OCT, paillierKeys.paillier_pk.n, HFLEN_4096);
    FF_2048_fromOctet(n_, &OCT, FFLEN_2048);

    // generate CG21_PAILLIER_PROOF_ITERS number of the challenges
    int rc = CG21_PI_MOD_CHALLENGE(n_, *paillierProof->w, ssid, pimodProof.yi, n);
    if (rc != CG21_OK){
        return rc;
    }

    // generate (ai,bi,xi)
    CG21_PI_MOD_GEN_Xi(&pimodProof, paillierKeys);

    // generate (zi)
    CG21_PI_MOD_GEN_Zi(&pimodProof, paillierKeys);

    // convert the proofs into octet
    CG21_PI_MOD_proof_toOctet(paillierProof, pimodProof);

    return CG21_OK;
}

int CG21_PI_MOD_VERIFY(CG21_PIMOD_PROOF_OCT *paillierProof, const CG21_SSID *ssid, PAILLIER_public_key pk, int n){

    BIG_512_60 r[HFLEN_4096];
    BIG_512_60 num2[HFLEN_4096];
    BIG_512_60 yi_[HFLEN_4096];
    BIG_512_60 yMULw[FFLEN_4096];
    BIG_512_60 n_[FFLEN_4096];

    BIG_1024_58 ws[FFLEN_2048];
    BIG_1024_58 n_2048[FFLEN_2048];
    BIG_1024_58 yi_2048[FFLEN_2048];

    CG21_PIMOD_PROOF pimodProof;

    char oct[2*FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    FF_4096_zero(n_,FFLEN_4096);
    FF_4096_copy(n_,pk.n,HFLEN_4096);

    // convert paillier_pk.n from BIG_512_60[HFLEN_4096] to BIG_1024_58[FFLEN_2048]
    FF_4096_toOctet(&OCT, pk.n, HFLEN_4096);
    FF_2048_fromOctet(n_2048, &OCT, FFLEN_2048);

    FF_4096_init(num2,2,HFLEN_4096);
    FF_4096_copy(r,pk.n,HFLEN_4096);

    // r = n % 2
    FF_4096_mod(r, num2,HFLEN_4096);

    // n should be an odd composite number
    if (FF_4096_iszilch(r, HFLEN_4096)){
        return CG21_PAILLIER_N_IS_EVEN;
    }

    int rc = CG21_PI_MOD_proof_fromOCTET(paillierProof, &pimodProof);
    if (rc != CG21_OK){
        return rc;
    }

    // generate yi
    rc = CG21_PI_MOD_CHALLENGE(n_2048, *paillierProof->w, ssid, pimodProof.yi, n);
    if (rc != CG21_OK){
        return rc;
    }

    for (int i=0; i<CG21_PAILLIER_PROOF_ITERS;i++){

        FF_2048_nt_pow(ws, pimodProof.zi[i], n_2048, n_2048, FFLEN_2048, FFLEN_2048);

        // These values are all public, so it is ok to terminate early
        if (FF_2048_comp(ws, pimodProof.yi[i], FFLEN_2048) != 0)
        {
            return CG21_PAILLIER_PROVE_FAIL;
        }
    }

    for (int i=0; i<CG21_PAILLIER_PROOF_ITERS;i++){
        char oct2[2 * FS_2048];
        octet y_oct = {0, sizeof(oct2), oct2};
        FF_2048_toOctet(&y_oct, pimodProof.yi[i], FFLEN_2048);

        FF_4096_zero(yi_, HFLEN_4096);
        FF_4096_fromOctet(yi_, &y_oct, HFLEN_4096);
        // if ai=1 -> (-1)^{ai} becomes -1 -> we compute -yi mod N = N - yi
        // note: if ai=0 -> (-1)^{ai} becomes 0 -> we don't need to do anything
        if (pimodProof.ab[i][0]) {
            FF_4096_sub(yi_, pk.n, yi_, HFLEN_4096);
            FF_4096_norm(yi_, HFLEN_4096);
        }

        // if bi=1 -> we compute yi = w * yi
        if (pimodProof.ab[i][1]) {
            FF_4096_zero(yMULw, FFLEN_4096);
            FF_4096_mul(yMULw, yi_, pimodProof.w, HFLEN_4096);
            FF_4096_mod(yMULw, n_, FFLEN_4096);
            FF_4096_copy(yi_, yMULw, HFLEN_4096);
        }

        FF_4096_toOctet(&OCT, yi_, HFLEN_4096);
        FF_2048_fromOctet(yi_2048, &OCT, FFLEN_2048);
        FF_2048_nt_pow_int(ws,pimodProof.xi[i],4,n_2048,FFLEN_2048);

        if (FF_2048_comp(ws, yi_2048, FFLEN_2048) != 0)
        {
            return CG21_PAILLIER_PROVE_FAIL;
        }
    }

    return CG21_OK;
}
