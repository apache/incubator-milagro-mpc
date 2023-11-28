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

#include "amcl/cg21/cg21_pi_factor.h"
#include <amcl/big_256_56.h>
#include <amcl/paillier.h>
#include "amcl/hash_utils.h"
#include "amcl/ff_2048.h"

/**	@brief Compute s^z1 * t^z3 * S^(-e) mod P for verification purpose
*
*  @param verify    partial verification
*  @param b0        s component of Pedersen
*  @param b1        t component of Pedersen
*  @param z1        a component of pi-factor proof
*  @param z3        a component of pi-factor proof
*  @param S         a component of pi-factor commitment
*  @param e         challenge for sigma protocol
*  @param p         a safe prime
*  @param n1        size of z1
*  @param n2        size of z3
*/
static void CG21_PI_FACTOR_PED_verify(BIG_1024_58 *verify, BIG_1024_58 *b0, BIG_1024_58 *b1, BIG_1024_58 *z1,
                               BIG_1024_58 *z3, BIG_1024_58 *S, BIG_1024_58 *e, BIG_1024_58 *p, int n1, int n2)
{
    // ------------ VARIABLE DEFINITION ----------
    BIG_1024_58 hws1[HFLEN_2048];
    BIG_1024_58 hws2[HFLEN_2048];
    BIG_1024_58 hws3[HFLEN_2048];
    BIG_1024_58 hws4[HFLEN_2048];
    BIG_1024_58 eneg[HFLEN_2048];

    // ------------ PEDERSEN COMMITMENT VERIFICATION ----------
    FF_2048_copy(hws1, p, HFLEN_2048);
    FF_2048_dec(hws1, 1, HFLEN_2048);

    //if z3 = k(p-1) + t for t < p-1 => s^{z3} = s^{k(p-1)}*s^t = (s^{p-1})^{t}*s^t = 1 * s^t
    // according to the Fermat's theorem if p is prime then a^{p-1}=1 mod p
    CG21_FF_2048_amod(hws4, z3, n2, hws1, HFLEN_2048);

    //https://math.stackexchange.com/a/3099042
    FF_2048_sub(eneg, hws1, e, HFLEN_2048);
    FF_2048_norm(eneg, HFLEN_2048);

    CG21_FF_2048_amod(hws3, z1, n1, hws1, HFLEN_2048);

    FF_2048_dmod(hws1, b0, p, HFLEN_2048);
    FF_2048_dmod(hws2, b1, p, HFLEN_2048);
    FF_2048_dmod(verify, S, p, HFLEN_2048);

    FF_2048_ct_pow_3(verify, hws1, hws3, hws2, hws4, verify, eneg, p, HFLEN_2048, HFLEN_2048);

    // ------------ CLEAN MEMORY ----------
    FF_2048_zero(hws1, HFLEN_2048);
    FF_2048_zero(hws2, HFLEN_2048);
    FF_2048_zero(hws3, HFLEN_2048);
    FF_2048_zero(hws4, HFLEN_2048);
}


/**	@brief Generate challenge for sigma protocol
*
*
*  @param ssid      system-wide session-ID, refers to the same notation as in CG21
*  @param N1        first RSA modulus
*  @param N2        second RSA modulus
*  @param E         challenge
*  @param n         size of the packages in the components of ssid
*/
static int CG21_PI_FACTOR_CHALLENGE(const CG21_SSID *ssid, BIG_1024_58 *N1, BIG_1024_58 *N2,
                              octet *E, int n){

    hash256 sha;
    HASH256_init(&sha);
    BIG_256_56 q;

    char n_[FS_2048];
    octet N_Oct = {0, sizeof(n_), n_};

    char o[SFS_SECP256K1 + 1];
    octet G_oct = {0, sizeof(o), o};

    char qq[EGS_SECP256K1];
    octet q_oct = {0, sizeof(qq), qq};

    FF_2048_toOctet(&N_Oct, N1, FFLEN_2048);
    HASH_UTILS_hash_oct(&sha, &N_Oct);

    FF_2048_toOctet(&N_Oct, N2, FFLEN_2048);
    HASH_UTILS_hash_oct(&sha, &N_Oct);

    HASH_UTILS_hash_oct(&sha, ssid->rid);
    HASH_UTILS_hash_oct(&sha, ssid->rho);

    CG21_get_G(&G_oct);
    CG21_get_q(&q_oct);

    HASH_UTILS_hash_oct(&sha, &G_oct);
    HASH_UTILS_hash_oct(&sha, &q_oct);

    // sort partial X[i] based on j_packed and process them into sha
    int rc = CG21_hash_set_X(&sha, ssid->X_set_packed, ssid->j_set_packed, n, EFS_SECP256K1 + 1);
    if (rc!=CG21_OK){
        return rc;
    }

    // ------------ OUTPUT ----------
    BIG_256_56 e;
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    HASH_UTILS_rejection_sample_mod_BIG(&sha, q, e);

    BIG_256_56_toBytes(E->val, e);
    E->len = EGS_SECP256K1;

    return CG21_OK;
}

void CG21_PI_FACTOR_COMMIT(csprng *RNG, CG21_PiFACTOR_SECRETS *r1priv, CG21_PiFACTOR_COMMIT *r1pub,
                           PEDERSEN_PUB *pub_com, octet *p1, octet *q1, octet *e, const CG21_SSID *ssid,
                           int pack_size){

    /*
     * Bounds for randomness generation were derived from CG21 as follows:
     * \ell is q-bit long
     * \epsilon is 2q-bit long
     */

    // ------------ VARIABLE DEFINITION ----------
    BIG_1024_58 n[FFLEN_2048];
    BIG_1024_58 n_[2*FFLEN_2048];
    BIG_1024_58 n2[2 * FFLEN_2048];
    BIG_1024_58 q[HFLEN_2048];
    BIG_1024_58 q2[FFLEN_2048];
    BIG_1024_58 q3[FFLEN_2048];
    BIG_1024_58 q4[FFLEN_2048];

    BIG_1024_58 alpha[FFLEN_2048];
    BIG_1024_58 beta[FFLEN_2048];
    BIG_1024_58 mu[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 nu[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 sigma[2*FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 r[2*FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 x[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 y[FFLEN_2048 + HFLEN_2048];

    BIG_1024_58 pF[FFLEN_2048];
    BIG_1024_58 qF[FFLEN_2048];
    BIG_1024_58 t[FFLEN_2048];
    BIG_1024_58 Q[FFLEN_2048];
    BIG_1024_58 t1[FFLEN_2048];
    BIG_1024_58 t2[FFLEN_2048+HFLEN_2048];
    BIG_1024_58 t3[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 t4[3*FFLEN_2048];
    BIG_1024_58 t5[2*FFLEN_2048 + HFLEN_2048];

    char p[FS_2048];
    octet p_ = {0,sizeof(p),p};

    char qq[FS_2048];
    octet q_ = {0,sizeof(qq),qq};

    OCT_copy(&p_, p1);
    OCT_copy(&q_, q1);

    OCT_pad(&p_, FS_2048);
    OCT_pad(&q_, FS_2048);
    FF_2048_fromOctet(pF, &p_, FFLEN_2048);
    FF_2048_fromOctet(qF, &q_, FFLEN_2048);
    FF_2048_mul(n_, pF, qF, FFLEN_2048);
    FF_2048_copy(n, n_, FFLEN_2048);

    // Curve order
    CG21_GET_CURVE_ORDER(q);
    FF_2048_sqr(q2, q, HFLEN_2048);
    FF_2048_mul(q3, q, q2, HFLEN_2048);
    FF_2048_mul(q4, q, q3, HFLEN_2048);

    // Paillier_N * Pedersen_N
    FF_2048_mul(n2, n, pub_com->N, FFLEN_2048);
    FF_2048_norm(n2, 2 * FFLEN_2048);


    /* ------------ RANDOM GENERATION ---------- */

    // t1=2^{4\kappa}
    FF_2048_init(t1,1,FFLEN_2048);
    FF_2048_norm(t1,FFLEN_2048);
    for (int i=0; i<CG21_PI_FACTOR_MAX_N_LENGTH/2;i++)
        FF_2048_shl(t1, FFLEN_2048);

    // t1=2^{4\kappa}-1
    FF_2048_dec(t1,1,FFLEN_2048);
    FF_2048_norm(t1,FFLEN_2048);

    // t1=q^3 * {2^{4\kappa}-1}
    FF_2048_mul(t1, t1, q3,FFLEN_2048);

    // Note: we replace sqrt(N) with 2^{4\kappa}-1 as upper bound
    // Generate alpha in [0, .., q^3*{2^{4\kappa}-1}]
    FF_2048_random(alpha, RNG, FFLEN_2048);             //alpha: 2^{8\kappa}-bit random number
    FF_2048_mod(alpha, t1, FFLEN_2048);                 //alpha: alpha mod t1
    FF_2048_toOctet(r1priv->alpha,alpha,FFLEN_2048);

    // Generate beta in [0, .., q^3*{2^{4\kappa}-1}]
    FF_2048_random(beta, RNG, FFLEN_2048);             //beta: 2^{8\kappa}-bit random number
    FF_2048_mod(beta, t1, FFLEN_2048);                 //beta: beta mod t1
    FF_2048_toOctet(r1priv->beta,beta,FFLEN_2048);

    // Generate mu in [0, .., Pedersen_N * q]
    CG21_FF_2048_amul(t2, q, HFLEN_2048, pub_com->N, FFLEN_2048);
    FF_2048_norm(t2, FFLEN_2048 + HFLEN_2048);
    FF_2048_random(mu, RNG, FFLEN_2048 + HFLEN_2048);
    FF_2048_mod(mu, t2, FFLEN_2048 + HFLEN_2048);
    FF_2048_toOctet(r1priv->mu,mu,FFLEN_2048 + HFLEN_2048);

    // Generate nu in [0, .., Pedersen_N * q]
    FF_2048_random(nu, RNG, FFLEN_2048 + HFLEN_2048);
    FF_2048_mod(nu, t2, FFLEN_2048 + HFLEN_2048);
    FF_2048_toOctet(r1priv->nu,nu,FFLEN_2048 + HFLEN_2048);

    // Generate sigma in [0, .., Paillier_N * Pedersen_N * q]
    CG21_FF_2048_amul(t4, q, HFLEN_2048, n2, 2*FFLEN_2048);
    FF_2048_norm(t4, 2*FFLEN_2048 + HFLEN_2048);
    FF_2048_random(sigma, RNG, 2*FFLEN_2048 + HFLEN_2048);
    FF_2048_mod(sigma, t4, 2*FFLEN_2048 + HFLEN_2048);
    FF_2048_toOctet(r1pub->sigma,sigma,2*FFLEN_2048 + HFLEN_2048);

    // Generate r in [0, .., Paillier_N * Pedersen_N * q^3]
    CG21_FF_2048_amul(t4, q3, HFLEN_2048, n2, 2*FFLEN_2048);
    FF_2048_norm(t4, 2*FFLEN_2048 + HFLEN_2048);
    FF_2048_random(r, RNG, 2*FFLEN_2048 + HFLEN_2048);
    FF_2048_mod(r, t4, 2*FFLEN_2048 + HFLEN_2048);
    FF_2048_toOctet(r1priv->r,r,2*FFLEN_2048 + HFLEN_2048);

    // Generate x in [0, .., Pedersen_N * q^3]
    CG21_FF_2048_amul(t2, q3, HFLEN_2048, pub_com->N, FFLEN_2048);
    FF_2048_norm(t2, FFLEN_2048 + HFLEN_2048);
    FF_2048_random(x, RNG, FFLEN_2048 + HFLEN_2048);
    FF_2048_mod(x, t2, FFLEN_2048 + HFLEN_2048);
    FF_2048_toOctet(r1priv->x,x,FFLEN_2048 + HFLEN_2048);

    // Generate y in [0, .., Pedersen_N * q^3]
    FF_2048_random(y, RNG, FFLEN_2048 + HFLEN_2048);
    FF_2048_mod(y, t2, FFLEN_2048 + HFLEN_2048);
    FF_2048_toOctet(r1priv->y,y,FFLEN_2048 + HFLEN_2048);

    /* ------------ COMMITMENT ---------- */
    // Compute P: b0^p * b1^mu mod hat{N}
    FF_2048_zero(t, FFLEN_2048);
    FF_2048_zero(t3, FFLEN_2048 + HFLEN_2048);
    FF_2048_copy(t3, pF, FFLEN_2048);

    FF_2048_ct_pow_2(t, pub_com->b0, t3, pub_com->b1, mu,pub_com->N,
                     FFLEN_2048, FFLEN_2048 + HFLEN_2048);
    FF_2048_toOctet(r1pub->P,t,FFLEN_2048);

    // Compute Q: b0^q * b1^nu mod hat{N}
    FF_2048_zero(Q, FFLEN_2048);
    FF_2048_zero(t3, FFLEN_2048 + HFLEN_2048);
    FF_2048_copy(t3, qF, FFLEN_2048);
    FF_2048_ct_pow_2(Q, pub_com->b0, t3, pub_com->b1, nu,pub_com->N,
                     FFLEN_2048, FFLEN_2048 + HFLEN_2048);
    FF_2048_toOctet(r1pub->Q,Q,FFLEN_2048);

    // Compute A: b0^alpha * b1^x mod hat{N}
    FF_2048_zero(t, FFLEN_2048);
    FF_2048_zero(t3, FFLEN_2048 + HFLEN_2048);
    FF_2048_copy(t3, alpha, FFLEN_2048);
    FF_2048_ct_pow_2(t, pub_com->b0, t3, pub_com->b1, x,pub_com->N,
                     FFLEN_2048, FFLEN_2048 + HFLEN_2048);
    FF_2048_toOctet(r1pub->A,t,FFLEN_2048);

    // Compute B: b0^beta * b1^y mod hat{N}
    FF_2048_zero(t, FFLEN_2048);
    FF_2048_zero(t3, FFLEN_2048 + HFLEN_2048);
    FF_2048_copy(t3, beta, FFLEN_2048);
    FF_2048_ct_pow_2(t, pub_com->b0, t3, pub_com->b1, y,pub_com->N,
                     FFLEN_2048, FFLEN_2048 + HFLEN_2048);
    FF_2048_toOctet(r1pub->B,t,FFLEN_2048);

    // Compute T:  Q^alpha * b1^r mod hat{N}
    FF_2048_zero(t, FFLEN_2048);
    FF_2048_zero(t5, 2*FFLEN_2048 + HFLEN_2048);
    FF_2048_copy(t5, alpha, FFLEN_2048);
    FF_2048_ct_pow_2(t, Q, t5, pub_com->b1, r,pub_com->N,
                     FFLEN_2048, 2*FFLEN_2048 + HFLEN_2048);
    FF_2048_toOctet(r1pub->T,t,FFLEN_2048);

    // clean up
    FF_2048_zero(alpha,FFLEN_2048);
    FF_2048_zero(beta,FFLEN_2048);
    FF_2048_zero(mu,FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(nu,FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(sigma,2*FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(r,2*FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(x,FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(y,FFLEN_2048 + HFLEN_2048);

    FF_2048_zero(t,FFLEN_2048);
    FF_2048_zero(Q,FFLEN_2048);
    FF_2048_zero(t2,2*FFLEN_2048);
    FF_2048_zero(t3,FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(t4,3*FFLEN_2048);
    FF_2048_zero(t5,2*FFLEN_2048 + HFLEN_2048);

    CG21_PI_FACTOR_CHALLENGE(ssid, pub_com->N, n, e, pack_size);
}

void CG21_PI_FACTOR_PROVE(const CG21_PiFACTOR_SECRETS *r1priv, const CG21_PiFACTOR_COMMIT *r1pub, CG21_PiFACTOR_PROOF *proof,
                          octet *p1, octet *q1, octet *e){

    BIG_1024_58 e_[HFLEN_2048];
    BIG_1024_58 e_2[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 e_3[2*FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 t5[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 t6[3*FFLEN_2048];
    BIG_1024_58 t7[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 t8[2*FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 t9[5*FFLEN_2048];
    BIG_1024_58 t10[2*FFLEN_2048 + HFLEN_2048];

    BIG_1024_58 pF[FFLEN_2048];
    BIG_1024_58 qF[FFLEN_2048];

    char oct[3*FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    char p[FS_2048] = {0};
    octet p_ = {0,sizeof(p),p};

    char qq[FS_2048];
    octet q_ = {0,sizeof(qq),qq};

    OCT_copy(&p_, p1);
    OCT_copy(&q_, q1);

    OCT_pad(&p_, FS_2048);
    OCT_pad(&q_, FS_2048);
    FF_2048_fromOctet(pF, &p_, FFLEN_2048);
    FF_2048_fromOctet(qF, &q_, FFLEN_2048);

    // load e as HFLEN_2048 in e_
    OCT_copy(&OCT, e);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(e_, &OCT, HFLEN_2048);

    // load e as FS_2048+HFS_2048 in e_2
    OCT_copy(&OCT, e);
    OCT_pad(&OCT, FS_2048+HFS_2048);
    FF_2048_fromOctet(e_2, &OCT, FFLEN_2048 + HFLEN_2048);

    // load e as 2*FS_2048+HFS_2048 in e_3
    OCT_copy(&OCT, e);
    OCT_pad(&OCT, 2*FS_2048+HFS_2048);
    FF_2048_fromOctet(e_3, &OCT, 2*FFLEN_2048 + HFLEN_2048);

    /*  z1 = e*p + alpha  */
    // zeroise variables
    FF_2048_zero(t5, FFLEN_2048+HFLEN_2048);
    FF_2048_zero(t7, FFLEN_2048+HFLEN_2048);
    FF_2048_zero(t8, FFLEN_2048+HFLEN_2048);

    OCT_clear(&OCT);
    OCT_copy(&OCT, r1priv->alpha);
    OCT_pad(&OCT, FS_2048+HFS_2048);
    FF_2048_fromOctet(t5, &OCT, FFLEN_2048+HFLEN_2048);

    CG21_FF_2048_amul(t7, e_, HFLEN_2048, pF, FFLEN_2048); // t7 = e*p
    FF_2048_add(t8, t7, t5, FFLEN_2048+HFLEN_2048);                // t3 = e*p + alpha
    FF_2048_norm(t8, FFLEN_2048+HFLEN_2048);
    FF_2048_toOctet(proof->z1,t8,FFLEN_2048+HFLEN_2048);

    /*  z2 = e*q + beta  */
    // zeroise variables
    FF_2048_zero(t5, FFLEN_2048+HFLEN_2048);
    FF_2048_zero(t7, FFLEN_2048+HFLEN_2048);
    FF_2048_zero(t8, FFLEN_2048+HFLEN_2048);

    OCT_clear(&OCT);
    OCT_copy(&OCT, r1priv->beta);
    OCT_pad(&OCT, FS_2048+HFS_2048);
    FF_2048_fromOctet(t5, &OCT, FFLEN_2048+HFLEN_2048);

    CG21_FF_2048_amul(t7, e_, HFLEN_2048, qF, FFLEN_2048); // t7 = e*q
    FF_2048_add(t8, t7, t5, FFLEN_2048+HFLEN_2048);                // t3 = e*q + beta
    FF_2048_norm(t8, FFLEN_2048+HFLEN_2048);
    FF_2048_toOctet(proof->z2,t8,FFLEN_2048+HFLEN_2048);

    /*  w1 = e*mu + x  */
    // zeroise variables
    FF_2048_zero(t5, FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(t6, 3*FFLEN_2048);
    FF_2048_zero(t7, FFLEN_2048 + HFLEN_2048);

    // load mu
    OCT_clear(&OCT);
    OCT_copy(&OCT, r1priv->mu);
    OCT_pad(&OCT, FS_2048+HFS_2048);
    FF_2048_fromOctet(t5, &OCT, FFLEN_2048 + HFLEN_2048);

    CG21_FF_2048_amul(t6, e_, HFLEN_2048, t5, FFLEN_2048 + HFLEN_2048); // t6 = e*mu

    //load x
    OCT_clear(&OCT);
    OCT_copy(&OCT, r1priv->x);
    OCT_pad(&OCT, FS_2048+HFS_2048);
    FF_2048_fromOctet(t5, &OCT, FFLEN_2048 + HFLEN_2048);

    FF_2048_add(t7, t6, t5, FFLEN_2048 + HFLEN_2048);          // t7 = e*mu + x
    FF_2048_norm(t7, FFLEN_2048 + HFLEN_2048);
    FF_2048_toOctet(proof->w1,t7,FFLEN_2048 + HFLEN_2048);

    /*  w2 = e*nu + y  */
    // zeroise variables
    FF_2048_zero(t5, FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(t6, 3*FFLEN_2048);
    FF_2048_zero(t7, FFLEN_2048 + HFLEN_2048);

    // load mu
    OCT_clear(&OCT);
    OCT_copy(&OCT, r1priv->nu);
    OCT_pad(&OCT, FS_2048+HFS_2048);
    FF_2048_fromOctet(t5, &OCT, FFLEN_2048 + HFLEN_2048);

    CG21_FF_2048_amul(t6, e_, HFLEN_2048, t5, FFLEN_2048 + HFLEN_2048); // t6 = e*nu

    //load y
    OCT_clear(&OCT);
    OCT_copy(&OCT, r1priv->y);
    OCT_pad(&OCT, FS_2048+HFS_2048);
    FF_2048_fromOctet(t5, &OCT, FFLEN_2048 + HFLEN_2048);

    FF_2048_add(t7, t6, t5, FFLEN_2048 + HFLEN_2048);          // t7 = e*nu + y
    FF_2048_norm(t7, FFLEN_2048 + HFLEN_2048);
    FF_2048_toOctet(proof->w2,t7,FFLEN_2048 + HFLEN_2048);

    /*  v = e*hat{sigma} + r  */
    // zeroise variables
    FF_2048_zero(t5, FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(t6, 3*FFLEN_2048);
    FF_2048_zero(t7, FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(t8, 2*FFLEN_2048 + HFLEN_2048);
    FF_2048_zero(t9, 5*FFLEN_2048);
    FF_2048_zero(t10, 2*FFLEN_2048 + HFLEN_2048);

    //hat{sigma} = sigma - nu*p
    // load sigma
    OCT_clear(&OCT);
    OCT_copy(&OCT, r1pub->sigma);
    OCT_pad(&OCT, 2*FS_2048+HFS_2048);
    FF_2048_fromOctet(t8, &OCT, 2*FFLEN_2048 + HFLEN_2048); // t8 = sigma

    // load nu
    OCT_clear(&OCT);
    OCT_copy(&OCT, r1priv->nu);
    OCT_pad(&OCT, 2*FS_2048);
    FF_2048_fromOctet(t10, &OCT, 2*FFLEN_2048);   // t10 = nu

    // in amul xlen * k = ylen should hold, that's why we load r1priv->nu as 2*FFLEN_2048
    // and not as FFLEN_2048 + HFLEN_2048
    CG21_FF_2048_amul(t6, pF, FFLEN_2048, t10, 2*FFLEN_2048); // t6 = nu*p
    FF_2048_zero(t10, 2*FFLEN_2048 + HFLEN_2048);
    FF_2048_sub(t10, t8, t6, 2*FFLEN_2048 + HFLEN_2048);          // t10 = hat{sigma} = sigma - nu*p
    FF_2048_norm(t10, 2*FFLEN_2048 + HFLEN_2048);

    CG21_FF_2048_amul(t9, e_, HFLEN_2048, t10, 2*FFLEN_2048 + HFLEN_2048); // t9 = e*hat{sigma}

    // load r
    OCT_clear(&OCT);
    OCT_copy(&OCT, r1priv->r);
    OCT_pad(&OCT, 2*FS_2048+HFS_2048);
    FF_2048_fromOctet(t8, &OCT, 2*FFLEN_2048 + HFLEN_2048);         // t8 = r

    FF_2048_add(t10, t8, t9, 2*FFLEN_2048 + HFLEN_2048);          // t10 = e*hat{sigma} + r
    FF_2048_norm(t10, 2*FFLEN_2048 + HFLEN_2048);
    FF_2048_toOctet(proof->v,t10,2*FFLEN_2048 + HFLEN_2048);


}

void CG21_PI_FACTOR_COMMIT_PROVE(csprng *RNG, const CG21_SSID *ssid, PEDERSEN_PUB *pub_com, CG21_PiFACTOR_COMMIT *commit,
                                 CG21_PiFACTOR_PROOF *proof, octet *p1, octet *q1, int pack_size){

    char t1_[FS_2048];
    octet alpha = {0, sizeof(t1_), t1_};

    char t2_[FS_2048];
    octet beta = {0, sizeof(t2_), t2_};

    char t3[FS_2048+HFS_2048];
    octet mu = {0, sizeof(t3), t3};

    char t4[FS_2048+HFS_2048];
    octet nu = {0, sizeof(t4), t4};

    char t6[2*FS_2048+HFS_2048];
    octet r = {0, sizeof(t6), t6};

    char t7[FS_2048+HFS_2048];
    octet x = {0, sizeof(t7), t7};

    char t8[FS_2048+HFS_2048];
    octet y = {0, sizeof(t8), t8};

    char t19[MODBYTES_256_56];
    octet e = {0, sizeof(t19), t19};

    CG21_PiFACTOR_SECRETS secrets;
    secrets.alpha = &alpha;
    secrets.beta = &beta;
    secrets.mu = &mu;
    secrets.nu = &nu;
    secrets.r = &r;
    secrets.x = &x;
    secrets.y = &y;

    CG21_PI_FACTOR_COMMIT(RNG,&secrets,commit,pub_com,p1,q1,&e,ssid,pack_size);
    CG21_PI_FACTOR_PROVE(&secrets,commit,proof,p1,q1,&e);

}

int CG21_PI_FACTOR_VERIFY(const CG21_PiFACTOR_COMMIT *r1pub, const CG21_PiFACTOR_PROOF *proof, octet *N_oct,
                          PEDERSEN_PRIV *priv_com, const CG21_SSID *ssid, int n){

    char oct[3*FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    char te[MODBYTES_256_56];
    octet e = {0, sizeof(te), te};

    BIG_1024_58 q[HFLEN_2048];
    BIG_1024_58 q2[FFLEN_2048];
    BIG_1024_58 q3[FFLEN_2048];
    BIG_1024_58 q4[FFLEN_2048];
    BIG_1024_58 q7[FFLEN_2048];

    BIG_1024_58 e_[HFLEN_2048];
    BIG_1024_58 z1[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 z2[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 w1[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 w2[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 v[2*FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 P[FFLEN_2048];
    BIG_1024_58 Q[FFLEN_2048];
    BIG_1024_58 A[FFLEN_2048];
    BIG_1024_58 B[FFLEN_2048];
    BIG_1024_58 T[FFLEN_2048];

    BIG_1024_58 p_verify[FFLEN_2048];
    BIG_1024_58 q_verify[FFLEN_2048];
    BIG_1024_58 p_gt[FFLEN_2048];
    BIG_1024_58 q_gt[FFLEN_2048];

    BIG_1024_58 t[FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 R[FFLEN_2048];
    BIG_1024_58 t2[2*FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 t3[2*FFLEN_2048 + HFLEN_2048];
    BIG_1024_58 N[FFLEN_2048];

    PEDERSEN_PUB Pedersen_pub;

    FF_2048_fromOctet(N, N_oct, FFLEN_2048);

    // Curve order
    CG21_GET_CURVE_ORDER(q);
    FF_2048_sqr(q2, q, HFLEN_2048);
    FF_2048_mul(q3, q, q2, HFLEN_2048);
    FF_2048_mul(q4, q, q3, HFLEN_2048);
    FF_2048_mul(q7, q4, q3, HFLEN_2048);
    FF_2048_zero(t, FFLEN_2048 + HFLEN_2048);
    FF_2048_copy(t, q7, FFLEN_2048);        // t = q7
    // get Pedersen public parameters
    Pedersen_get_public_param(&Pedersen_pub, priv_com);

    /* Check both z1 and z2 are in the valid range */
    //  load z1
    OCT_clear(&OCT);
    OCT_copy(&OCT, proof->z1);
    OCT_pad(&OCT, FS_2048+ HFS_2048);
    FF_2048_fromOctet(z1, &OCT, FFLEN_2048 + HFLEN_2048);

    // ------------ CHECK 'z1' IS IN [0, ..., t=q^7] ------------
    if (FF_2048_comp(z1, t, FFLEN_2048 + HFLEN_2048) > 0)
    {
        return CG21_PI_FACTOR_INVALID_RANGE;
    }

    //  load z2
    OCT_clear(&OCT);
    OCT_copy(&OCT, proof->z2);
    OCT_pad(&OCT, FS_2048+ HFS_2048);
    FF_2048_fromOctet(z2, &OCT, FFLEN_2048 + HFLEN_2048);

    // ------------ CHECK 'z2' IS IN [0, ..., t=q^7] ------------
    if (FF_2048_comp(z2, t, FFLEN_2048 + HFLEN_2048) > 0)
    {
        return CG21_PI_FACTOR_INVALID_RANGE;
    }

    //  load w1
    OCT_clear(&OCT);
    OCT_copy(&OCT, proof->w1);
    OCT_pad(&OCT, FS_2048 + HFS_2048);
    FF_2048_fromOctet(w1, &OCT, FFLEN_2048 + HFLEN_2048);

    //  load w2
    OCT_clear(&OCT);
    OCT_copy(&OCT, proof->w2);
    OCT_pad(&OCT, FS_2048 + HFS_2048);
    FF_2048_fromOctet(w2, &OCT, FFLEN_2048 + HFLEN_2048);

    //  load v
    OCT_clear(&OCT);
    OCT_copy(&OCT, proof->v);
    OCT_pad(&OCT, 2*FS_2048 + HFS_2048);
    FF_2048_fromOctet(v, &OCT, 2*FFLEN_2048 + HFLEN_2048);

    //  load A
    OCT_clear(&OCT);
    OCT_copy(&OCT, r1pub->A);
    OCT_pad(&OCT, FS_2048);
    FF_2048_fromOctet(A, &OCT, FFLEN_2048);

    //  load B
    OCT_clear(&OCT);
    OCT_copy(&OCT, r1pub->B);
    OCT_pad(&OCT, FS_2048);
    FF_2048_fromOctet(B, &OCT, FFLEN_2048);

    //  load P
    OCT_clear(&OCT);
    OCT_copy(&OCT, r1pub->P);
    OCT_pad(&OCT, FS_2048);
    FF_2048_fromOctet(P, &OCT, FFLEN_2048);

    //  load Q
    OCT_clear(&OCT);
    OCT_copy(&OCT, r1pub->Q);
    OCT_pad(&OCT, FS_2048);
    FF_2048_fromOctet(Q, &OCT, FFLEN_2048);

    //  load T
    OCT_clear(&OCT);
    OCT_copy(&OCT, r1pub->T);
    OCT_pad(&OCT, FS_2048);
    FF_2048_fromOctet(T, &OCT, FFLEN_2048);

    // generate challenge e
    CG21_PI_FACTOR_CHALLENGE(ssid, Pedersen_pub.N, N, &e, n);

    // load octet e as HFLEN_2048 in e_
    OCT_copy(&OCT, &e);
    OCT_pad(&OCT, HFS_2048);
    FF_2048_fromOctet(e_, &OCT, HFLEN_2048);

    /* Split check s^z1 * t^w1 * P^(-e) == A mod PQ using CRT */
    CG21_PI_FACTOR_PED_verify(p_verify, priv_com->b0, priv_com->b1, z1, w1,
                              P, e_, priv_com->mod.p, FFLEN_2048 + HFLEN_2048, FFLEN_2048 + HFLEN_2048);

    CG21_PI_FACTOR_PED_verify(q_verify, priv_com->b0, priv_com->b1, z1, w1,
                              P, e_, priv_com->mod.q, FFLEN_2048 + HFLEN_2048, FFLEN_2048 + HFLEN_2048);


    FF_2048_dmod(p_gt, A, priv_com->mod.p, HFLEN_2048);
    FF_2048_dmod(q_gt, A, priv_com->mod.q, HFLEN_2048);
    int fail = (FF_2048_comp(p_gt, p_verify, HFLEN_2048) != 0) || (FF_2048_comp(q_gt, q_verify, HFLEN_2048) != 0);
    if (fail)
    {
        // Clean memory
        FF_2048_zero(p_gt, HFLEN_2048);
        FF_2048_zero(q_gt, HFLEN_2048);
        FF_2048_zero(p_verify, HFLEN_2048);
        FF_2048_zero(q_verify, HFLEN_2048);

        return CG21_PI_FACTOR_INVALID_PROOF;
    }

    /* Split check s^z2 * t^w2 * Q^(-e) == B mod PQ using CRT */
    CG21_PI_FACTOR_PED_verify(p_verify, priv_com->b0, priv_com->b1, z2, w2,
                              Q, e_, priv_com->mod.p, FFLEN_2048 + HFLEN_2048, FFLEN_2048 + HFLEN_2048);

    CG21_PI_FACTOR_PED_verify(q_verify, priv_com->b0, priv_com->b1, z2, w2,
                              Q, e_, priv_com->mod.q, FFLEN_2048 + HFLEN_2048, FFLEN_2048 + HFLEN_2048);

    FF_2048_dmod(p_gt, B, priv_com->mod.p, HFLEN_2048);
    FF_2048_dmod(q_gt, B, priv_com->mod.q, HFLEN_2048);
    fail = (FF_2048_comp(p_gt, p_verify, HFLEN_2048) != 0) || (FF_2048_comp(q_gt, q_verify, HFLEN_2048) != 0);
    if (fail)
    {
        // Clean memory
        FF_2048_zero(p_gt, HFLEN_2048);
        FF_2048_zero(q_gt, HFLEN_2048);
        FF_2048_zero(p_verify, HFLEN_2048);
        FF_2048_zero(q_verify, HFLEN_2048);

        return CG21_PI_FACTOR_INVALID_PROOF;
    }

    /* Compute R = s^{pa_N}t^{sigma}*/
    // load sigma
    OCT_clear(&OCT);
    OCT_copy(&OCT, r1pub->sigma);
    OCT_pad(&OCT, 2*FS_2048+HFS_2048);
    FF_2048_fromOctet(t2, &OCT, 2*FFLEN_2048 + HFLEN_2048); // t2 = sigma

    // load Paillier N as 2*FFLEN_2048 + HFLEN_2048
    OCT_clear(&OCT);
    FF_2048_toOctet(&OCT, N, FFLEN_2048);
    OCT_pad(&OCT, 2*FS_2048+HFS_2048);
    FF_2048_fromOctet(t3, &OCT, 2*FFLEN_2048 + HFLEN_2048); // t3 = Paillier N

    // R = s^{pa_N}t^{sigma} mod hat{N}
    FF_2048_ct_pow_2(R, Pedersen_pub.b0, t3, Pedersen_pub.b1, t2,Pedersen_pub.N,
                     FFLEN_2048, 2*FFLEN_2048 + HFLEN_2048);

    /* Q^z1 * t^v * R^(-e) == T mod PQ using CRT */
    CG21_PI_FACTOR_PED_verify(p_verify, Q, priv_com->b1, z1, v,
                              R, e_, priv_com->mod.p, FFLEN_2048 + HFLEN_2048, 2 * FFLEN_2048 + HFLEN_2048);

    CG21_PI_FACTOR_PED_verify(q_verify, Q, priv_com->b1, z1, v,
                              R, e_, priv_com->mod.q, FFLEN_2048 + HFLEN_2048, 2 * FFLEN_2048 + HFLEN_2048);

    FF_2048_dmod(p_gt, T, priv_com->mod.p, HFLEN_2048);
    FF_2048_dmod(q_gt, T, priv_com->mod.q, HFLEN_2048);
    fail = (FF_2048_comp(p_gt, p_verify, HFLEN_2048) != 0) || (FF_2048_comp(q_gt, q_verify, HFLEN_2048) != 0);
    if (fail)
    {
        // Clean memory
        FF_2048_zero(p_gt, HFLEN_2048);
        FF_2048_zero(q_gt, HFLEN_2048);
        FF_2048_zero(p_verify, HFLEN_2048);
        FF_2048_zero(q_verify, HFLEN_2048);

        return CG21_PI_FACTOR_INVALID_PROOF;
    }


    return CG21_OK;
}
