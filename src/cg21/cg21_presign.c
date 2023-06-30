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

// ------------------ PRE-SIGN -----------------------
int CG21_VALIDATE_PARTIAL_PKS(CG21_RESHARE_OUTPUT *reshareOutput){
    int size = reshareOutput->pk.pack_size;

    char cc[size][EFS_SECP256K1 + 1];
    octet CC[size];
    init_octets((char *)cc,   CC,   EFS_SECP256K1 + 1, size);

    char x_[EFS_SECP256K1 + 1];
    octet X = {0, sizeof(x_), x_};

    // unpack partial PKs into array of octets
    int rc = CG21_unpack(reshareOutput->pk.X_set_packed, size, CC, EFS_SECP256K1 + 1);
    if (rc!=CG21_OK){
        return rc;
    }

    // add all the partial PKs
    OCT_copy(&X, &CC[0]);
    for (int j =1; j<size; j++){
        CG21_ADD_TWO_PK(&X, &CC[j]);
    }

    // check whether the sum-of-PKs match the main PK
    rc = OCT_comp(&X, reshareOutput->pk.X);
    if (!rc){
        return CG21_PRESIGN_PARTIAL_PK_NOT_VALID;
    }


    return CG21_OK;
}

void CG21_PRESIGN_GET_SSID(CG21_SSID *ssid, const CG21_RESHARE_OUTPUT *reshareOutput,
                           int n1, int n2,const CG21_AUX_OUTPUT *auxOutput){
    char o[SFS_SECP256K1 + 1];
    octet G_oct = {0, sizeof(o), o};

    char qq[EGS_SECP256K1];
    octet q_oct = {0, sizeof(qq), qq};

    CG21_get_G(&G_oct);
    CG21_get_q(&q_oct);

    // copy curve order to ssid
    OCT_copy(ssid->q, &q_oct);

    // copy curve generator to ssid
    OCT_copy(ssid->g, &G_oct);

    // copy from key re-share output to ssid
    OCT_copy(ssid->X_set_packed, reshareOutput->pk.X_set_packed);
    OCT_copy(ssid->j_set_packed, reshareOutput->pk.j_set_packed);
    OCT_copy(ssid->rid, reshareOutput->rid);
    OCT_copy(ssid->rho, reshareOutput->rho);
    *ssid->n1 = n1;

    // copy from Aux. information output to ssid
    OCT_copy(ssid->j_set_packed2, auxOutput->j);
    OCT_copy(ssid->s_set_packed, auxOutput->s);
    OCT_copy(ssid->t_set_packed, auxOutput->t);
    OCT_copy(ssid->N_set_packed, auxOutput->N);
    *ssid->n2 = n2;
}

int CG21_PRESIGN_ROUND1(csprng *RNG, const CG21_RESHARE_OUTPUT *reshareOutput,
                        CG21_RESHARE_SETTING *setting, CG21_PRESIGN_ROUND1_OUTPUT *output,
                        CG21_PRESIGN_ROUND1_STORE *store, PAILLIER_public_key *keys){

    /* define and initialize variables to form SSID */
    char oct1[FS_2048];
    char oct2[FS_2048];
    char x_[setting->t2 - 1][EGS_SECP256K1];

    octet OCT1 = {0, sizeof(oct1), oct1};
    octet OCT2 = {0, sizeof(oct2), oct2};
    octet X[setting->t2 - 1];
    init_octets((char *) x_, X, EGS_SECP256K1, setting->t2 - 1);

    BIG_512_60 ss[FFLEN_4096];
    BIG_256_56 s;
    BIG_256_56 q;


    /*
     * ---------STEP 1: choosing randoms -----------
     * k:               q bits
     * gamma:           q bits
     * rho:             Z^*_N
     * nu:              Z^*_N
     */

    // sample random k
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);     // get the curve order
    BIG_256_56_randomnum(s, q, RNG);             // sample random mod q
    store->k->len=EGS_SECP256K1;
    BIG_256_56_toBytes(store->k->val, s);           // convert sampled random to octet
    BIG_256_56_zero(s);                               // zeroize s

    // sample random gamma
    BIG_256_56_randomnum(s, q, RNG);
    store->gamma->len=EGS_SECP256K1;
    BIG_256_56_toBytes(store->gamma->val, s);
    BIG_256_56_zero(s);

    // sample rho
    FF_4096_zero(ss, FFLEN_4096);
    FF_4096_randomnum(ss, keys->n, RNG,HFLEN_4096);
    FF_4096_toOctet(store->rho,ss,FFLEN_4096);
    FF_4096_zero(ss, FFLEN_4096);

    // sample nu
    FF_4096_randomnum(ss, keys->n, RNG,HFLEN_4096);
    FF_4096_toOctet(store->nu,ss,FFLEN_4096);
    FF_4096_zero(ss, FFLEN_4096);

    // copy player's ID into different variables to be used later
    store->i = reshareOutput->myID;
    output->i = reshareOutput->myID;


    /*
     * ---------STEP 2: compute G and K -----------
     * G:               Enc(gamma, nu)
     * K:               Enc(k    , rho)
     */

    // copy gamma and k into local variables
    OCT_copy(&OCT1, store->gamma);
    OCT_copy(&OCT2, store->k);

    // PAILLIER_ENCRYPT takes plaintext as a 2048-bit input, so k and gamma should be padded
    OCT_pad(&OCT1, FS_2048);
    OCT_pad(&OCT2, FS_2048);

    PAILLIER_ENCRYPT(NULL, keys, &OCT1, output->G, store->nu); // encrypt(gamma;nu)
    PAILLIER_ENCRYPT(NULL, keys, &OCT2, output->K, store->rho); // encrypt(k;rho)

    /*
     * ---------STEP 3: convert sum-of-the-shares to additive shares -----------
     */
    // packed ID of the players in T2 into one octet X
    CG21_lagrange_index_to_octet(setting->t2, setting->T2, reshareOutput->myID, X);

    // convert SSS shared to additive
    SSS_shamir_to_additive(setting->t2, reshareOutput->shares.X, reshareOutput->shares.Y, X, store->a);

    //clean up
    OCT_clear(&OCT1);
    OCT_clear(&OCT2);

    return CG21_OK;
}

void CG21_MTA_decrypt_reduce_q(octet *T, octet *ALPHA)
{
    BIG_1024_58 q[FFLEN_2048];
    BIG_1024_58 alpha[FFLEN_2048];

    char t[FS_2048];
    octet Q = {0,sizeof(t),t};

    char tt[FS_2048];
    octet TT = {0,sizeof(tt),tt};

    OCT_copy(&TT, T);

    // Curve order
    CG21_get_q(&Q);

    OCT_pad(&Q, FS_2048);
    FF_2048_fromOctet(q, &Q, FFLEN_2048);

    FF_2048_fromOctet(alpha, &TT, FFLEN_2048);

    // alpha = alpha mod q
    FF_2048_mod(alpha, q, FFLEN_2048);

    // Output alpha
    FF_2048_toOctet(&TT, alpha, FFLEN_2048);
    OCT_chop(&TT, ALPHA, FS_2048 - EGS_SECP256K1);

    // Clean memory
    FF_2048_zero(alpha, FFLEN_2048);
    OCT_clear(&TT);
}


int CG21_PRESIGN_ROUND2(csprng *RNG, CG21_PRESIGN_ROUND2_OUTPUT *r2output, CG21_PRESIGN_ROUND2_STORE *r2store,
                        const CG21_PRESIGN_ROUND1_OUTPUT *r1output, const CG21_PRESIGN_ROUND1_STORE *r1store,
                        PAILLIER_public_key *hisPK, PAILLIER_public_key *myPK){


    r2store->i = r1store->i;
    r2output->i = r1store->i;

    r2store->j = r1output->i;
    r2output->j = r1output->i;

    /*
     * ---------STEP 1: compute Gamma = gamma*G -----------
     */

    BIG_256_56 s;
    ECP_SECP256K1 G;

    ECP_SECP256K1_generator(&G);    // get curve generator
    BIG_256_56_fromBytesLen(s, r1store->gamma->val, r1store->gamma->len);   // load gamma into big
    ECP_SECP256K1_mul(&G, s);   // compute gamma*G
    ECP_SECP256K1_toOctet(r2store->Gamma, &G, true); // store gamma*G
    ECP_SECP256K1_toOctet(r2output->Gamma, &G, true); // store gamma*G
    BIG_256_56_zero(s); // zeroize s

    /*
     * ---------STEP 2: choosing randoms (CG21: Fig.7, Round 2) -----------
     * beta:             q^5 bits
     * beta_hat:         q^5 bits
     */

    BIG_1024_58 q[HFLEN_2048];          //curve order
    BIG_1024_58 q2[FFLEN_2048];         //q^2
    BIG_1024_58 q3[FFLEN_2048];         //q^3
    BIG_1024_58 q5[FFLEN_2048];         //q^5
    BIG_1024_58 t[FFLEN_2048];

    char oct1[2 * FS_2048];
    octet OCT = {0, sizeof(oct1), oct1};

    // Curve order
    CG21_get_q(&OCT);   // get curve order
    OCT_pad(&OCT, HFS_2048);    // pad curve order with zeros to become 1024-bit number
    FF_2048_fromOctet(q, &OCT, HFLEN_2048); // store padded curve order in q

    FF_2048_sqr(q2, q, HFLEN_2048);
    FF_2048_mul(q3, q, q2, HFLEN_2048);
    FF_2048_mul(q5, q3, q2, FFLEN_2048);

    // Generate beta in [0, .., q^5]
    FF_2048_random(t, RNG, FFLEN_2048);        //t: a 2048-bit
    FF_2048_mod(t, q5, FFLEN_2048);            //t mod q^5
    FF_2048_toOctet(r2store->beta,t, FFLEN_2048);

    // Generate beta_hat in [0, .., q^5]
    FF_2048_random(t, RNG, FFLEN_2048);     //t: a 2048-bit
    FF_2048_mod(t, q5, FFLEN_2048);         //t mod q^5
    FF_2048_toOctet(r2store->beta_hat,t, FFLEN_2048);
    FF_2048_zero(t, FFLEN_2048);


    /*
     * ---------STEP 3: choosing randoms -----------
     * r:               Z^*_N
     * r_hat:           Z^*_N
     * s:               Z^*_N
     * s_hat:           Z^*_N
     */

    // sample rho and nu
    BIG_512_60 rr[FFLEN_4096];
    BIG_512_60 rr_hat[FFLEN_4096];
    BIG_512_60 ss[FFLEN_4096];
    BIG_512_60 ss_hat[FFLEN_4096];

    FF_4096_zero(rr,FFLEN_4096);
    FF_4096_zero(rr_hat,FFLEN_4096);
    FF_4096_zero(ss,FFLEN_4096);
    FF_4096_zero(ss_hat,FFLEN_4096);

    FF_4096_randomnum(rr, myPK->n, RNG,HFLEN_4096);
    FF_4096_randomnum(rr_hat, myPK->n, RNG,HFLEN_4096);
    FF_4096_randomnum(ss, hisPK->n, RNG,HFLEN_4096);
    FF_4096_randomnum(ss_hat, hisPK->n, RNG,HFLEN_4096);

    FF_4096_toOctet(r2store->r,rr,FFLEN_4096);
    FF_4096_toOctet(r2store->r_hat,rr_hat,FFLEN_4096);
    FF_4096_toOctet(r2store->s,ss,FFLEN_4096);
    FF_4096_toOctet(r2store->s_hat,ss_hat,FFLEN_4096);

    FF_4096_zero(rr,FFLEN_4096);
    FF_4096_zero(rr_hat,FFLEN_4096);
    FF_4096_zero(ss,FFLEN_4096);
    FF_4096_zero(ss_hat,FFLEN_4096);

    /*
     * ---------STEP 4: compute F and F_hat -----------
     * F:                   Enc(Beta, r)
     * F_hat:               Enc(Beta_hat, r_hat)
     */

    PAILLIER_ENCRYPT(NULL, myPK, r2store->beta, r2output->F, r2store->r);
    PAILLIER_ENCRYPT(NULL, myPK, r2store->beta_hat, r2output->F_hat, r2store->r_hat);


    /*
     * ---------STEP 5: compute H and H_hat -----------
     * H:                   Enc(-Beta, s)
     * H_hat:               Enc(-Beta_hat, s_hat)
     */

    BIG_1024_58 t_[FFLEN_2048];

    char H[FS_4096];
    octet H_oct = {0, sizeof(H), H};

    char H_hat[FS_4096];
    octet H_hat_oct = {0, sizeof(H_hat), H_hat};

    char ct[FS_4096];
    octet CT = {0, sizeof(ct), ct};

    // store -Beta
    OCT_pad(r2store->neg_beta, HFS_4096);
    FF_2048_fromOctet(t, r2store->beta,FFLEN_2048);
    FF_2048_sub(t_, q5, t,FFLEN_2048); // t_ = -beta mod q5
    FF_2048_norm(t_, FFLEN_2048);
    FF_2048_toOctet(r2store->neg_beta,t_, FFLEN_2048);

    // Enc(Beta, s)
    PAILLIER_ENCRYPT(NULL, hisPK, r2store->beta, &H_oct, r2store->s);

    // store -Beta_hat
    OCT_pad(r2store->neg_beta_hat, HFS_4096);
    FF_2048_fromOctet(t, r2store->beta_hat,FFLEN_2048);
    FF_2048_sub(t_, q5, t,FFLEN_2048); // -beta_hat mod q5
    FF_2048_norm(t_, FFLEN_2048);
    FF_2048_toOctet(r2store->neg_beta_hat,t_, FFLEN_2048);

    // Enc(Beta_hat, s_hat)
    PAILLIER_ENCRYPT(NULL, hisPK, r2store->beta_hat, &H_hat_oct, r2store->s_hat);

    FF_2048_zero(t, FFLEN_2048);
    FF_2048_zero(t_, FFLEN_2048);

    /*
    * ---------STEP 6: compute D and D_hat -----------
    * D:                   K*gamma + H
    * D_hat:               K*a + H_hat ('a' is the additive share computed in Round1)
    */

    char oct11[FS_2048];
    char oct22[FS_2048];
    octet OCT1 = {0, sizeof(oct11), oct11};
    octet OCT2 = {0, sizeof(oct22), oct22};

    OCT_copy(&OCT1, r1store->gamma);
    OCT_copy(&OCT2, r1store->a);

    // PAILLIER_MULT takes plaintext as BIG_512_60 pt[HFLEN_4096], so we should pad our PTs
    OCT_pad(&OCT1, HFS_4096);
    OCT_pad(&OCT2, HFS_4096);

    // CT = E_A(K.gamma)
    PAILLIER_MULT(hisPK, r1output->K, &OCT1, &CT);

    // D = E_A(K.gamma + H)
    PAILLIER_ADD(hisPK, &CT, &H_oct, r2output->D);

    // CT = E_A(K.a)
    PAILLIER_MULT(hisPK, r1output->K, &OCT2, &CT);

    // D_hat = E_A(K.a + H_hat)
    PAILLIER_ADD(hisPK, &CT, &H_hat_oct, r2output->D_hat);

    OCT_clear(&OCT1);
    OCT_clear(&OCT2);
    OCT_clear(&H_hat_oct);
    OCT_clear(&CT);

    return CG21_OK;
}

int CG21_PRESIGN_ROUND3_2_1(const CG21_PRESIGN_ROUND2_OUTPUT *r2hisOutput, CG21_PRESIGN_ROUND3_STORE_1 *r3Store,
                            const CG21_PRESIGN_ROUND2_STORE *r2Store, const CG21_PRESIGN_ROUND1_STORE *r1Store, int status){


    /*
     * status = 0      first call
     * status = 1      neither first call, nor last call
     * status = 2      last call
     * status = 3      first and last call (t=2)
     */

    /*
    * ---------STEP 1: compute Gamma -----------
    * Gamma:            \prod Gamma_j
    */

    r3Store->i = r2Store->i;
    //r3store is from example file is sending each time a different instance, it should be fixed,
    // for each i, same r3store should be sent to this function
    if (status==0 || status==3){
        OCT_copy(r3Store->Gamma, r2Store->Gamma);
    }

    // add Gamma_j to r3Store->Gamma
    CG21_ADD_TWO_PK(r3Store->Gamma, r2hisOutput->Gamma);

    /*
    * ---------STEP 2: compute Delta -----------
    * Delta:            Gamma^{k}, Gamma refers to the sum of Gamma_j computed in step1, and k sampled in round1Out
    */
    if (status==2 || status==3) { // last call, since in the last call the computation of Gamma in step1 is completed
        ECP_SECP256K1 tt;
        BIG_256_56 exp;

        // convert r1Store->k from octet to BIG_256_56
        BIG_256_56_fromBytesLen(exp, r1Store->k->val, r1Store->k->len);

        // convert r3Store2->Gamma from octet to ECP
        if (!ECP_SECP256K1_fromOctet(&tt, r3Store->Gamma))
        {
            return CG21_INVALID_ECP;
        }

        // computes Gamma^{k}
        ECP_SECP256K1_mul(&tt, exp);

        // convert ECP to octet
        ECP_SECP256K1_toOctet(r3Store->Delta, &tt, true);

        // clean up the variables
        ECP_SECP256K1_inf(&tt);
        BIG_256_56_zero(exp);
    }

    return CG21_OK;
}

/** \brief Set the value for an accumulator from octets
 *
 * Set the accumulator to V1 * V2
 *
 * @param accum               Accumulator to be set
 * @param V1                  First factor for the value to set
 * @param V2                  Second Factor for the value to set
 */
static void CG21_MTA_ACCUMULATOR_SET(BIG_256_56 accum, const octet *V1, const octet *V2)
{
    BIG_256_56 v1;
    BIG_256_56 v2;
    DBIG_256_56 w;

    BIG_256_56_fromBytesLen(v1, V1->val, V1->len);
    BIG_256_56_fromBytesLen(v2, V2->val, V2->len);

    BIG_256_56_mul(w, v1, v2);
    BIG_256_56_rcopy(v1, CURVE_Order_SECP256K1);
    BIG_256_56_dmod(accum, w, v1);

    // Clean memory
    BIG_256_56_zero(v2);
    BIG_256_56_dzero(w);
}

/** \brief Add a value to an accumulator
 *
 * The octet value V is added to the accumulator and
 * reduced modulo the curve order
 *
 * @param accum               Accumulator. This must have a valid value
 * @param V                   Octet value to add
 */
static void CG21_MTA_ACCUMULATOR_ADD(BIG_256_56 accum, const octet *V)
{
    BIG_256_56 v;

    BIG_256_56_fromBytesLen(v, V->val, V->len);

    BIG_256_56_add(accum, accum, v);
    BIG_256_56_rcopy(v, CURVE_Order_SECP256K1);
    BIG_256_56_mod(accum, v);

    // Clean memory
    BIG_256_56_zero(v);
}

int CG21_PRESIGN_ROUND3_2_2(const CG21_PRESIGN_ROUND2_OUTPUT *r2hisOutput,
                            CG21_PRESIGN_ROUND3_OUTPUT *r3Output,
                            const CG21_PRESIGN_ROUND3_STORE_1 *r3Store1,
                            CG21_PRESIGN_ROUND3_STORE_2 *r3Store2,
                            const CG21_PRESIGN_ROUND1_STORE *r1Store,
                            PAILLIER_private_key *myKeys,
                            const CG21_PRESIGN_ROUND2_STORE *r2Store,
                            int status){

    /*
     * status = 0      first call
     * status = 1      neither first call, nor last call
     * status = 2      last call
     * status = 3      first and last call (t=2)
     */

    /*
    * ---------STEP 3: compute alpha and alpha_hat -----------
    * alpha:                Decryption(D), D is received from party j in round2
    * alpha_hat:            Decryption(D_hat)
    */

    char pt1[FS_2048];
    char pt2[FS_2048];
    char tt1[EGS_SECP256K1];
    char tt2[EGS_SECP256K1];
    char beta[EGS_SECP256K1];
    char beta_hat[EGS_SECP256K1];

    octet PT1 = {0, sizeof(pt1), pt1};
    octet PT2 = {0, sizeof(pt2), pt2};
    octet Alpha = {0, sizeof(tt1), tt1};
    octet Alpha_hat = {0, sizeof(tt2), tt2};
    octet Beta = {0, sizeof(beta), beta};
    octet Beta_hat = {0, sizeof(beta_hat), beta_hat};

    OCT_clear(&Alpha);
    OCT_clear(&Alpha_hat);
    OCT_clear(&Beta);
    OCT_clear(&Beta_hat);

    r3Store2->i = r2Store->i;
    r3Output->i = r2Store->i;
    OCT_copy(r3Output->Delta, r3Store1->Delta);

    PAILLIER_DECRYPT(myKeys, r2hisOutput->D, &PT1);
    PAILLIER_DECRYPT(myKeys, r2hisOutput->D_hat, &PT2);

    CG21_MTA_decrypt_reduce_q(&PT1, &Alpha);
    CG21_MTA_decrypt_reduce_q(&PT2, &Alpha_hat);

    CG21_MTA_decrypt_reduce_q(r2Store->neg_beta, &Beta);
    CG21_MTA_decrypt_reduce_q(r2Store->neg_beta_hat, &Beta_hat);


    /*
    * ---------STEP 4: compute delta and chi -----------
    * delta:                gamma*k + \sum alpha + (-beta)
    * chi:                  a*k + \sum alpha_hat + (-beta_hat)
    */

    BIG_256_56 sum1;
    BIG_256_56 sum2;

    if (status==0 || status==3) {
        // sum1 = gamma.k mod q  & sum1 = a.k mod q
        CG21_MTA_ACCUMULATOR_SET(sum1, r1Store->gamma, r1Store->k);
        CG21_MTA_ACCUMULATOR_SET(sum2, r1Store->a, r1Store->k);
    }
    else{
        BIG_256_56_fromBytesLen(sum1, r3Store2->delta->val, r3Store2->delta->len);
        BIG_256_56_fromBytesLen(sum2, r3Store2->chi->val, r3Store2->chi->len);
    }

    // sum1 = sum1 + alpha + beta
    CG21_MTA_ACCUMULATOR_ADD(sum1, &Alpha);
    CG21_MTA_ACCUMULATOR_ADD(sum1, &Beta);

    // sum2 = sum2 + alpha_hat + beta_hat
    CG21_MTA_ACCUMULATOR_ADD(sum2, &Alpha_hat);
    CG21_MTA_ACCUMULATOR_ADD(sum2, &Beta_hat);

    // Output result
    BIG_256_56_toBytes(r3Store2->delta->val, sum1);
    BIG_256_56_toBytes(r3Output->delta->val, sum1);
    BIG_256_56_toBytes(r3Store2->chi->val, sum2);

    r3Store2->delta->len = EGS_SECP256K1;
    r3Output->delta->len = EGS_SECP256K1;
    r3Store2->chi->len = EGS_SECP256K1;

    // Clean memory
    BIG_256_56_zero(sum1);
    BIG_256_56_zero(sum2);
    OCT_clear(&Alpha);
    OCT_clear(&Alpha_hat);
    OCT_clear(&Beta);
    OCT_clear(&Beta_hat);
    OCT_clear(&PT1);
    OCT_clear(&PT2);

    return CG21_OK;
}

int CG21_PRESIGN_OUTPUT_2_1(const CG21_PRESIGN_ROUND3_OUTPUT *r3hisOutput,
                            const CG21_PRESIGN_ROUND3_OUTPUT *r3myOutput,
                            CG21_PRESIGN_ROUND4_STORE_1 *r4Store,
                            int status){

    /*
     * status = 0      first call
     * status = 1      neither first call, nor last call
     * status = 2      last call
     * status = 3      first and last call (t=2)


     * ---------STEP 1: compute delta and Delta ----------
     * delta:           \sum delta_i
     * Delta:           \prod Delta_j
    */
    BIG_256_56 sum;

    if (status==0 || status ==3){
        OCT_copy(r4Store->Delta, r3myOutput->Delta);
        OCT_copy(r4Store->delta, r3myOutput->delta);

    }

    // \prod Delta_j
    CG21_ADD_TWO_PK(r4Store->Delta, r3hisOutput->Delta);
    BIG_256_56_fromBytesLen(sum, r4Store->delta->val, r4Store->delta->len);

    CG21_MTA_ACCUMULATOR_ADD(sum, r3hisOutput->delta);

    BIG_256_56_toBytes(r4Store->delta->val, sum);
    r4Store->delta->len = EGS_SECP256K1;
    BIG_256_56_zero(sum);


    /*
    * ---------STEP 2: check g^\delta == \prod \Delta_j -----------
    */
    if (status==2 || status ==3){
        ECP_SECP256K1 G;
        BIG_256_56 s;

        char tt[EFS_SECP256K1 + 1];
        octet deltaG = {0, sizeof(tt), tt};

        ECP_SECP256K1_generator(&G);
        BIG_256_56_fromBytesLen(s, r4Store->delta->val, r4Store->delta->len);

        ECP_SECP256K1_mul(&G, s);
        ECP_SECP256K1_toOctet(&deltaG, &G, true);

        BIG_256_56_zero(s);
        ECP_SECP256K1_inf(&G);

        int rc = OCT_comp(r4Store->Delta, &deltaG);
        OCT_clear(&deltaG);
        if (rc==0){
            return CG21_PRESIGN_DELTA_NOT_VALID;
        }
    }

    return CG21_OK;
}

int CG21_PRESIGN_OUTPUT_2_2(const CG21_PRESIGN_ROUND1_STORE *r1Store,
                            const CG21_PRESIGN_ROUND3_STORE_1 *r3Store1,
                            const CG21_PRESIGN_ROUND3_STORE_2 *r3Store2,
                            const CG21_PRESIGN_ROUND4_STORE_1 *r4Store1,
                            CG21_PRESIGN_ROUND4_STORE_2 *r4Store2,
                            CG21_PRESIGN_ROUND4_OUTPUT *r4Output){

    /* ---------STEP 1: compute R ----------
    * R:           Gamma ^ {delta^{-1}}
    */

    BIG_256_56 delta;
    BIG_256_56 invdelta;
    BIG_256_56 q;
    ECP_SECP256K1 tt;

    r4Output->i = r3Store1->i;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    BIG_256_56_fromBytesLen(delta, r4Store1->delta->val, r4Store1->delta->len);
    BIG_256_56_invmodp(invdelta, delta, q);


    // convert r3Store2->Gamma from octet to ECP
    if (!ECP_SECP256K1_fromOctet(&tt, r3Store1->Gamma))
    {

        BIG_256_56_zero(delta);
        BIG_256_56_zero(invdelta);

        r4Output->PRESIGN_SUCCESS = CG21_PRESIGN_FAILED;
        return CG21_INVALID_ECP;
    }

    // computes Gamma^{delta{-1}}
    ECP_SECP256K1_mul(&tt, invdelta);

    // convert ECP to octet
    ECP_SECP256K1_toOctet(r4Store2->R, &tt, true);

    // form ROUND3 output and store
    OCT_copy(r4Store2->chi, r3Store2->chi);
    OCT_copy(r4Store2->k, r1Store->k);
    r4Store2->i = r3Store1->i;

    r4Output->PRESIGN_SUCCESS = CG21_OK;

    BIG_256_56_zero(delta);
    BIG_256_56_zero(invdelta);
    ECP_SECP256K1_inf(&tt);

    return CG21_OK;
}