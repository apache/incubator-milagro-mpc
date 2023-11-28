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

void CG21_KEY_RESHARE_GET_RESHARE_SETTING(CG21_RESHARE_SETTING *out, int t1, int n1, int t2, int n2, int *old_t_IDs, int *new_n_IDs){

    out->t1 = t1;
    out->n1 = n1;
    out->t2 = t2;
    out->n2 = n2;

    out->T1 = old_t_IDs;
    out->N2 = new_n_IDs;
}

static int CG21_KEY_RESHARE_GEN_V_T1(const CG21_SSID *ssid, const CG21_RESHARE_ROUND1_STORE_PUB_T1 *storePub,
                              CG21_RESHARE_ROUND1_OUT *pubOut, CG21_RESHARE_SETTING setting){
    hash256 sha;
    HASH256_init(&sha);

    //Process i into sha
    HASH_UTILS_hash_i2osp4(&sha, *pubOut->i);

    // process rho and u into sha
    HASH_UTILS_hash_oct(&sha, storePub->rho);
    HASH_UTILS_hash_oct(&sha, storePub->u);

    // process the curve order and generator into sha
    HASH_UTILS_hash_oct(&sha, ssid->g);
    HASH_UTILS_hash_oct(&sha, ssid->q);

    // process xor-ed rids into sha
    HASH_UTILS_hash_oct(&sha, ssid->rid);

    // sort partial X[i] based on j_packed and process them into sha
    int rc = CG21_hash_set_X(&sha, ssid->X_set_packed, ssid->j_set_packed,
                             setting.n1, EFS_SECP256K1 + 1);
    if (rc!=CG21_OK){
        return rc;
    }

    // process A into sha
    HASH_UTILS_hash_oct(&sha, storePub->A);

    //process VSS checks into sha
    HASH_UTILS_hash_oct(&sha, storePub->checks);
    HASH_UTILS_hash_i2osp4(&sha, storePub->checks->len);

    HASH256_hash(&sha, pubOut->V->val);
    pubOut->V->len = SHA256;

    return CG21_OK;
}

static int CG21_KEY_RESHARE_GEN_V_N2(const CG21_SSID *ssid, const CG21_RESHARE_ROUND1_STORE_PUB_N2 *storePub,
                              CG21_RESHARE_ROUND1_OUT *pubOut, CG21_RESHARE_SETTING setting){
    hash256 sha;
    HASH256_init(&sha);

    //Process i||len(i) into sha
    HASH_UTILS_hash_i2osp4(&sha, *pubOut->i);
    HASH_UTILS_hash_i2osp4(&sha, CG21_calculateBitLength(*pubOut->i));


    // process rho and u into sha
    HASH_UTILS_hash_oct(&sha, storePub->rho);
    HASH_UTILS_hash_oct(&sha, storePub->u);

    // process the curve order and generator into sha
    HASH_UTILS_hash_oct(&sha, ssid->g);
    HASH_UTILS_hash_oct(&sha, ssid->q);

    // process xor-ed rids into sha
    HASH_UTILS_hash_oct(&sha, ssid->rid);

    // sort partial X[i] based on j_packed and process them into sha
    int rc = CG21_hash_set_X(&sha, ssid->X_set_packed, ssid->j_set_packed,
                             setting.n1, EFS_SECP256K1 + 1);
    if (rc!=CG21_OK){
        return rc;
    }

    // process A into sha
    HASH_UTILS_hash_oct(&sha, storePub->A);
    HASH256_hash(&sha, pubOut->V->val);
    pubOut->V->len = SHA256;

    return CG21_OK;
}

int CG21_KEY_RESHARE_ROUND1_T1(csprng *RNG, const CG21_SSID *ssid, int ID, CG21_RESHARE_SETTING setting,
                               const SSS_shares *myShare, CG21_RESHARE_ROUND1_STORE_SECRET_T1 *storeSecret,
                               CG21_RESHARE_ROUND1_STORE_PUB_T1 *storePub, CG21_RESHARE_ROUND1_OUT *pubOut){

    // check ID is in T1 (T1 is the set of t1 players' IDs )
    bool check = false;
    for (int i=0; i<setting.t1; i++){
        if (ID == *(setting.T1 + i)){
            check = true;
        }
    }
    if (check==false){
        return CG21_ID_IS_INVALID;
    }

    if (setting.t1 < 2){
        return CG21_RESHARE_t1_IS_SMALL;
    }

    /* converts SSS shares to additive */
    BIG_256_56 w;
    BIG_256_56 q;
    BIG_256_56 s;
    ECP_SECP256K1 G;

    char x_[setting.t1 - 1][EGS_SECP256K1];
    octet X[setting.t1 - 1];
    init_octets((char *) x_, X, EGS_SECP256K1, setting.t1 - 1);

    // convert array of integers T1 to array of octets X
    CG21_lagrange_index_to_octet(setting.t1, setting.T1, ID, X);

    // convert SSS shared to additive
    SSS_shamir_to_additive(setting.t1, myShare->X, myShare->Y, X, storeSecret->a);

    // computes public Key associated with the additive share
    ECP_SECP256K1_generator(&G);
    BIG_256_56_fromBytesLen(w, storeSecret->a->val, storeSecret->a->len);
    ECP_SECP256K1_mul(&G, w);
    ECP_SECP256K1_toOctet(storePub->Xi, &G, true);
    BIG_256_56_zero(w); // clean up the secret

    char cc[setting.t2][EFS_SECP256K1 + 1];
    octet CC[setting.t2];
    init_octets((char *)cc,   CC,   EFS_SECP256K1 + 1, setting.t2);

    // apply VSS on the additive shares to get shares and the corresponding checks
    VSS_make_shares(setting.t2, setting.n2, RNG, &storeSecret->shares, CC, storeSecret->a);

    // pack the checks into one octet (storePub->checks)
    CG21_pack_vss_checks(CC,setting.t2,storePub->checks);

    // sample rho_i
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    BIG_256_56_randomnum(s, q, RNG);
    storePub->rho->len=EGS_SECP256K1;
    BIG_256_56_toBytes(storePub->rho->val,s);
    BIG_256_56_zero(s);

    // sample u_i
    BIG_256_56_randomnum(s, q, RNG);
    storePub->u->len=EGS_SECP256K1;
    BIG_256_56_toBytes(storePub->u->val,s);
    BIG_256_56_zero(s);

    // i component of (ssid,i,V)
    *pubOut->i = ID;
    *storePub->i = ID;

    // commit to random r
    SCHNORR_commit(RNG, storeSecret->r, storePub->A);

    //compute V_i
    int rc = CG21_KEY_RESHARE_GEN_V_T1(ssid, storePub, pubOut, setting);
    if (rc!=CG21_OK){
        return rc;
    }

    return CG21_OK;
}

int CG21_KEY_RESHARE_ROUND1_N2(csprng *RNG, const CG21_SSID *ssid, int ID, CG21_RESHARE_SETTING setting,
                               CG21_RESHARE_ROUND1_STORE_SECRET_N2 *storeSecret, CG21_RESHARE_ROUND1_STORE_PUB_N2 *storePub,
                               CG21_RESHARE_ROUND1_OUT *pubOut){

    // check ID is in N2, but not in T1
    bool check_T1 = false;
    bool check_N2 = false;
    for (int i=0; i<setting.t1; i++){
        if (ID == *(setting.T1 + i)){
            check_T1 = true;
        }
    }
    for (int i=0; i<setting.n2; i++){
        if (ID == *(setting.N2 + i)){
            check_N2 = true;
        }
    }

    if (check_T1!=false || check_N2!=true){
        return CG21_ID_IS_INVALID;
    }

    BIG_256_56 q;
    BIG_256_56 s;

    // sample rho_i
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    BIG_256_56_randomnum(s, q, RNG);
    storePub->rho->len=EGS_SECP256K1;
    BIG_256_56_toBytes(storePub->rho->val,s);
    BIG_256_56_zero(s);

    // sample u_i
    BIG_256_56_randomnum(s, q, RNG);
    storePub->u->len=EGS_SECP256K1;
    BIG_256_56_toBytes(storePub->u->val,s);
    BIG_256_56_zero(s);

    // i component of (ssid,i,V)
    *pubOut->i = ID;
    *storePub->i = ID;

    // commit to random r
    SCHNORR_commit(RNG, storeSecret->r, storePub->A);

    //compute V_i
    int rc = CG21_KEY_RESHARE_GEN_V_N2(ssid, storePub, pubOut, setting);
    if (rc!=CG21_OK) {
        return rc;
    }

    return CG21_OK;
}

int CG21_KEY_RESHARE_ROUND3_CHECK_V_T1(const CG21_SSID *ssid,
                                       CG21_RESHARE_SETTING setting,
                                       const CG21_RESHARE_ROUND1_STORE_PUB_T1 *ReceiveR3,
                                       CG21_RESHARE_ROUND1_OUT *ReceiveR2){


    // check Party IDs in both messages are the same
    if (*ReceiveR2->i != *ReceiveR3->i){
        return CG21_RESHARE_V_IS_NOT_VALID;
    }

    // ID should be in T1
    bool ID_in_T1=false;
    for (int i=0; i<setting.t1; i++){
        if (*(setting.T1+i) == *ReceiveR2->i){
            ID_in_T1 = true;
        }
    }
    if (!ID_in_T1){
        return CG21_RESHARE_V_IS_NOT_VALID;
    }

    int Vi;

    char v[SHA256];
    octet V = {0, sizeof(v), v};
    CG21_RESHARE_ROUND1_OUT pubOut;
    pubOut.i = &Vi;
    pubOut.V = &V;

    pubOut.i = ReceiveR2->i;

    //compute V_i
    int rc = CG21_KEY_RESHARE_GEN_V_T1(ssid, ReceiveR3, &pubOut, setting);
    if (rc!=CG21_OK)
        return rc;

    int ret = OCT_comp(pubOut.V, ReceiveR2->V);
    if (ret != 1){
        return CG21_RESHARE_V_IS_NOT_VALID;
    }

    return  CG21_OK;
}

int CG21_KEY_RESHARE_ROUND3_CHECK_V_N2(const CG21_SSID *ssid,
                                       CG21_RESHARE_SETTING setting,
                                       const CG21_RESHARE_ROUND1_STORE_PUB_N2 *ReceiveR3,
                                       CG21_RESHARE_ROUND1_OUT *ReceiveR2){


    // check Party IDs in both messages are the same
    if (*ReceiveR2->i != *ReceiveR3->i){
        return CG21_RESHARE_V_IS_NOT_VALID;
    }

    /* ID should not be in T1, but in N2 */
    //check ID is not in T1
    bool ID_in_T1=false;
    for (int i=0; i<setting.t1; i++){
        if (*(setting.T1+i) == *ReceiveR2->i){
            ID_in_T1 = true;
        }
    }
    if (ID_in_T1){
        return CG21_RESHARE_V_IS_NOT_VALID;
    }

    // check ID is in N2
    bool ID_in_N2=false;
    for (int i=0; i<setting.n2; i++){
        if (*(setting.N2+i) == *ReceiveR2->i){
            ID_in_N2 = true;
        }
    }
    if (!ID_in_N2){
        return CG21_RESHARE_V_IS_NOT_VALID;
    }

    int Vi;

    char v[SHA256];
    octet V = {0, sizeof(v), v};
    CG21_RESHARE_ROUND1_OUT pubOut;
    pubOut.i = &Vi;
    pubOut.V = &V;

    pubOut.i = ReceiveR2->i;

    //compute V_i
    int rc = CG21_KEY_RESHARE_GEN_V_N2(ssid, ReceiveR3, &pubOut, setting);
    if (rc!=CG21_OK) {
        return rc;
    }

    int ret = OCT_comp(pubOut.V, ReceiveR2->V);
    if (ret != 1){
        return CG21_RESHARE_V_IS_NOT_VALID;
    }

    return  CG21_OK;
}

static int CG21_CHECK_PARTIAL_PK(CG21_RESHARE_SETTING setting, octet *pack_pk_sum_shares, const octet *myX,
                          const CG21_RESHARE_ROUND1_STORE_PUB_T1 *ReceiveR3){

    int z = setting.n1-1;
    BIG_256_56 hisX;
    BIG_256_56 coeff;

    char cc[z][EFS_SECP256K1 + 1];
    octet CC[z];
    init_octets((char *)cc,   CC,   EFS_SECP256K1 + 1, z);

    char x_[setting.t1-1][EGS_SECP256K1];
    octet X[setting.t1-1];
    init_octets((char *) x_, X, EGS_SECP256K1, setting.t1-1);

    char x2_[EGS_SECP256K1];
    octet X2 = {0, sizeof(x2_), x2_};

    // unpack packed PK of sum-of-the-shares into array of octets
    int rc = CG21_unpack(pack_pk_sum_shares, z, CC, EFS_SECP256K1 + 1);
    if (rc!=CG21_OK){
        return rc;
    }

    /* calculate Lagrangian coefficient for the party ReceiveR3->i */
    CG21_lagrange_index_to_octet(setting.t1, setting.T1, *ReceiveR3->i, X);
    BIG_256_56_zero(hisX);
    BIG_256_56_inc(hisX, *ReceiveR3->i);

    BIG_256_56_toBytes(X2.val, hisX);
    X2.len = SGS_SECP256K1;

    CG21_lagrange_calc_coeff(setting.t1, &X2, X, &coeff);

    // convert big to int
    BIG_256_56 myXBig;
    int myXint=0;
    BIG_256_56_fromBytesLen(myXBig, myX->val, myX->len);

    while(BIG_256_56_iszilch(myXBig)!=1){
        myXint = myXint + 1;
        BIG_256_56_inc(myXBig, -1);
    }

    int index = *(ReceiveR3->i)-1;

    if (*(ReceiveR3->i) > myXint){
        index = *(ReceiveR3->i)-2;
    }

    ECP_SECP256K1 pk_sum_ss;

    rc = ECP_SECP256K1_fromOctet(&pk_sum_ss, &CC[index]);
    if (rc != 1)
    {
        return rc;
    }

    // calculate {g^{sum_of_share}}^{coeff}
    ECP_SECP256K1_mul(&pk_sum_ss, coeff);

    char o[SFS_SECP256K1 + 1];
    octet O = {0, sizeof(o), o};

    // convert ECP point to octet
    ECP_SECP256K1_toOctet(&O, &pk_sum_ss, true);

    // check whether calculated version using VSS checks and received {g^{sum_of_share}}^{coeff} are both equal
    rc = OCT_comp(&O, ReceiveR3->Xi);
    if (rc != 1) {
        return CG21_RESHARE_PARTIAL_PK_NOT_VALID;
    }
    return CG21_OK;
}

int CG21_KEY_RESHARE_CHECK_VSS_T1(CG21_RESHARE_SETTING setting, CG21_RESHARE_ROUND1_STORE_PUB_T1 *ReceiveR3,
                                  const CG21_RESHARE_ROUND1_STORE_PUB_T1 *myR3_T1, const SSS_shares *SS_R3, octet *myX,
                                  octet *PK, octet *X, octet *pack_pk_sum_shares, CG21_RESHARE_ROUND4_STORE *r3Store,
                                  int Xstatus){

    /*
     * Xstatus = 0      first call
     * Xstatus = 1      neither first call, nor last call
     * Xstatus = 2      last call
     * Xstatus = 3      first and last call (t=2)
     */

    // pack vss octets into one octet
    if (Xstatus==0 || Xstatus==3) {
        OCT_joctet(r3Store->pack_all_checks, myR3_T1->checks);
    }
    OCT_joctet(r3Store->pack_all_checks, ReceiveR3->checks);

    // unpack checks
    char cc[setting.t2][EFS_SECP256K1 + 1];
    octet CC[setting.t2];
    init_octets((char *)cc,   CC,   EFS_SECP256K1 + 1, setting.t2);
    int rc = CG21_unpack(ReceiveR3->checks, setting.t2, CC, EFS_SECP256K1 + 1);
    if (rc!=CG21_OK){
        return rc;
    }

    // checks X_j == VSS_j(v_0)
    rc = OCT_comp(&CC[0], ReceiveR3->Xi);

    if (rc==0){
        return CG21_Xs_ARE_NOT_EQUAL;
    }

    // Check that given shared secrets have same x-coord
    rc = OCT_comp(SS_R3->X, myX);
    if (rc==0){
        return CG21_WRONG_SHARE_IS_GIVEN;
    }

    // VSS Verification for the received share
    rc = VSS_verify_shares(setting.t2, SS_R3->X, SS_R3->Y, CC);
    if (rc != VSS_OK)
    {
        return rc;
    }

    // check partial PK is correct based on vss checks from keygen
    rc = CG21_CHECK_PARTIAL_PK(setting, pack_pk_sum_shares, myX, ReceiveR3);
    if (rc!=CG21_OK){
        return rc;
    }

    // first partial PK
    if (Xstatus==0 || Xstatus==3) {
        OCT_copy(X, myR3_T1->Xi);
    }

    CG21_ADD_TWO_PK(X, ReceiveR3->Xi);

    // last partial PK
    if (Xstatus==2 || Xstatus==3){
        rc = OCT_comp(X, PK);
        if (rc==0){
            return CG21_RESHARE_CHECKS_NOT_VALID;
        }
    }

    return CG21_OK;
}

void CG21_KEY_RESHARE_ENCRYPT_SHARES(csprng *RNG, PAILLIER_public_key *pk, int hisID,
                                     CG21_RESHARE_ROUND1_STORE_SECRET_T1 *storeSecret,
                                     CG21_RESHARE_ROUND1_STORE_PUB_T1 storePub,
                                     CG21_RESHARE_ROUND3_OUTPUT *output){

    char oct1[FS_2048];
    octet OCT1 = {0, sizeof(oct1), oct1};

    OCT_copy(&OCT1, storeSecret->shares.Y);
    OCT_pad(&OCT1, FS_2048);

    // encrypt y-coord
    PAILLIER_ENCRYPT(RNG, pk, &OCT1, output->C, NULL);

    // copy x-coord into output->X
    OCT_copy(output->X,storeSecret->shares.X);

    *(output->i) = *storePub.i;
    *(output->j) = hisID;
}


void CG21_KEY_RESHARE_DECRYPT_SHARES(PAILLIER_private_key *sk,
                                     CG21_RESHARE_ROUND3_OUTPUT *r3output,
                                     SSS_shares *share){

    char pt[FS_2048];
    octet PT = {0, sizeof(pt), pt};

    char y[EGS_SECP256K1];
    octet Y = {0, sizeof(y), y};

    // Decrypt C to get y-coord of the received point
    PAILLIER_DECRYPT(sk, r3output->C, &PT);

    // remove the zeros from y-coord
    OCT_chop( &PT, &Y,PT.len - EGS_SECP256K1);

    // form the shared point as SSS_shares
    OCT_copy(share->X, r3output->X );
    OCT_copy(share->Y, &Y );

}


int CG21_KEY_RESHARE_CHECK_VSS_N2(CG21_RESHARE_SETTING setting, CG21_RESHARE_ROUND1_STORE_PUB_T1 *ReceiveR3,
                                  const SSS_shares *SS_R3, const octet *myX, const octet *PK, octet *X, octet *pack_pk_sum_shares,
                                  CG21_RESHARE_ROUND4_STORE *r4Store, int Xstatus){
    // pack vss octets into one octet
    OCT_joctet(r4Store->pack_all_checks, ReceiveR3->checks);

    // unpack checks
    char cc[setting.t2][EFS_SECP256K1 + 1];
    octet CC[setting.t2];
    init_octets((char *)cc,   CC,   EFS_SECP256K1 + 1, setting.t2);
    int rc = CG21_unpack(ReceiveR3->checks, setting.t2, CC, EFS_SECP256K1 + 1);
    if (rc!=CG21_OK){
        return rc;
    }

    // checks X_j == VSS_j(v_0)
    rc = OCT_comp(CC, ReceiveR3->Xi);
    if (rc==0){
        return CG21_Xs_ARE_NOT_EQUAL;
    }

    // Check that given shared secrets have same x-coord
    rc = OCT_comp(SS_R3->X, myX);
    if (rc==0){
        return CG21_WRONG_SHARE_IS_GIVEN;
    }

    // VSS Verification for the received share
    rc = VSS_verify_shares(setting.t2, SS_R3->X, SS_R3->Y, CC);
    if (rc != VSS_OK)
    {
        return rc;
    }

    // check partial PK is correct based on vss checks from keygen
    rc = CG21_CHECK_PARTIAL_PK(setting, pack_pk_sum_shares, myX, ReceiveR3);
    if (rc!=CG21_OK){
        return rc;
    }

    // first partial PK
    if (Xstatus==0) {
        OCT_copy(X, ReceiveR3->Xi);
    }
    else {
        CG21_ADD_TWO_PK(X, ReceiveR3->Xi);
    }

    // last partial PK
    if (Xstatus == 2) {
        rc = OCT_comp(X, PK);
        if (rc == 0) {
            return CG21_RESHARE_CHECKS_NOT_VALID;
        }
    }


    return CG21_OK;
}

void CG21_KEY_RESHARE_SUM_SHARES(const SSS_shares *share, CG21_RESHARE_ROUND4_STORE *r3Store, bool first){

    if (first){
        OCT_copy(r3Store->shares.X, share->X);
        OCT_copy(r3Store->shares.Y, share->Y);
    }else{

        BIG_256_56 accum;
        BIG_256_56 s;
        BIG_256_56 q;

        // curve order
        BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

        // octet to Big
        BIG_256_56_fromBytesLen(accum, r3Store->shares.Y->val, r3Store->shares.Y->len);
        BIG_256_56_fromBytesLen(s, share->Y->val, share->Y->len);

        // add shares mod q
        BIG_256_56_add(accum, accum, s);
        BIG_256_56_mod(accum, q);

        // output result
        r3Store->shares.Y->len = EGS_SECP256K1;
        BIG_256_56_toBytes(r3Store->shares.Y->val, accum);

        // clean up
        BIG_256_56_zero(accum);
        BIG_256_56_zero(s);
    }
}

static int CG21_KEY_RESHARE_GEN_CHALLENGE(int myID, int n, const octet *X, CG21_SSID *ssid,
                                          const octet *rho, octet *out, octet *A){
    hash256 sha;
    BIG_256_56 q;
    BIG_256_56 e;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    HASH256_init(&sha);

    HASH_UTILS_hash_oct(&sha, X);
    HASH_UTILS_hash_oct(&sha, A);
    //Process i||len(i) into sha
    HASH_UTILS_hash_i2osp4(&sha, myID);
    HASH_UTILS_hash_i2osp4(&sha, CG21_calculateBitLength (myID));

    // process rho and u into sha
    HASH_UTILS_hash_oct(&sha, rho);

    // process the curve order and generator into sha
    HASH_UTILS_hash_oct(&sha, ssid->g);
    HASH_UTILS_hash_oct(&sha, ssid->q);

    // process xor-ed rids into sha
    HASH_UTILS_hash_oct(&sha, ssid->rid);

    // sort partial X[i] based on j_packed and process them into sha
    int rc = CG21_hash_set_X(&sha, ssid->X_set_packed, ssid->j_set_packed, n, EFS_SECP256K1 + 1);
    if (rc!=CG21_OK){
        return rc;
    }

    HASH_UTILS_rejection_sample_mod_BIG(&sha, q, e);

    BIG_256_56_toBytes(out->val, e);
    out->len = SGS_SECP256K1;

    return CG21_OK;
}

static int key_reshare_prove_helper(const CG21_RESHARE_ROUND4_STORE *r3Store, CG21_SSID *ssid, int myID, int n,
                             const octet *r, octet *A, octet *rho, CG21_RESHARE_ROUND4_OUTPUT *output){
    BIG_256_56 accum;
    ECP_SECP256K1 G;
    char e2[SGS_SECP256K1];
    char o[SFS_SECP256K1 + 1];

    octet E = {0, sizeof(e2), e2};
    octet X = {0, sizeof(o), o};

    // convert octet to big
    BIG_256_56_fromBytesLen(accum, r3Store->shares.Y->val, r3Store->shares.Y->len);

    // compute sum-of-the-shares * G and convert the result into octet
    ECP_SECP256K1_generator(&G);
    ECP_SECP256K1_mul(&G, accum);
    ECP_SECP256K1_toOctet(&X, &G, true);

    // clean up
    BIG_256_56_zero(accum);

    // compute challenge
    int rc = CG21_KEY_RESHARE_GEN_CHALLENGE(myID, n, &X, ssid, rho, &E, A);
    if (rc!=CG21_OK){
        return rc;
    }

    // prove the knowledge of sum-of-the-shares
    SCHNORR_prove(r, &E, r3Store->shares.Y, output->proof.psi);
    OCT_copy(output->proof.A, A);

    *output->i = myID;

    return CG21_OK;
}

int CG21_KEY_RESHARE_PROVE_T1(CG21_RESHARE_ROUND4_OUTPUT *output, const CG21_RESHARE_ROUND1_STORE_SECRET_T1 *secretT1,
                              const CG21_RESHARE_ROUND1_STORE_PUB_T1 *pubT1, CG21_RESHARE_ROUND4_STORE *r3Store,
                              CG21_SSID *ssid, octet *rho, int myID, int n){

    int rc = key_reshare_prove_helper(r3Store,ssid,myID,n,secretT1->r,pubT1->A, rho, output);
    OCT_copy(r3Store->rho, rho);
    if (rc!=CG21_OK){
        return rc;
    }

    return CG21_OK;
}

int CG21_KEY_RESHARE_PROVE_N2(CG21_RESHARE_ROUND4_OUTPUT *output, const CG21_RESHARE_ROUND1_STORE_SECRET_N2 *secretN2,
                              const CG21_RESHARE_ROUND1_STORE_PUB_N2 *pubN2, CG21_RESHARE_ROUND4_STORE *r3Store, CG21_SSID *ssid,
                              octet *rho, int myID, int n){

    int rc = key_reshare_prove_helper(r3Store,ssid,myID,n,secretN2->r,pubN2->A, rho, output);
    OCT_copy(r3Store->rho, rho);
    if (rc!=CG21_OK){
        return rc;
    }

    return CG21_OK;
}

static int key_reshare_verify_helper(const CG21_RESHARE_ROUND4_OUTPUT *input, CG21_RESHARE_SETTING setting,
                              CG21_RESHARE_ROUND4_STORE *r3Store, CG21_SSID *ssid, int hisID, const octet *A){

    // A received from Round1 is equal to A received from Round3
    int rc = OCT_comp(input->proof.A, A);
    if (rc != 1) {
        return CG21_A_DOES_NOT_MATCH;
    }

    ECP_SECP256K1  V;
    ECP_SECP256K1 Xi;
    BIG_256_56 x;

    char id[SGS_SECP256K1];
    octet X = {0, sizeof(id), id};

    char xi[SFS_SECP256K1 + 1];
    octet Xi_ = {0, sizeof(xi), xi};

    // convert hisID to Big and then to octet
    BIG_256_56_zero(x);
    BIG_256_56_inc(x, hisID);
    BIG_256_56_toBytes(X.val, x);
    X.len = SGS_SECP256K1;

    char round1_checks[setting.t1][setting.t2][EFS_SECP256K1 + 1];    // VSS: checks
    octet CC[(setting.t1)*setting.t2];
    init_octets((char *) round1_checks, CC, EFS_SECP256K1 + 1, (setting.t1)*setting.t2);

    // pack_all_checks is the pack of all the players' VSS checks in one octet
    rc = CG21_double_unpack(r3Store->pack_all_checks, setting.t1, setting.t2, CC);
    if (rc!=CG21_OK){
        return rc;
    }

    // copy the first xi*G
    CG21_CALC_XI(setting.t2, &X, CC , &Xi);

    // this for loop computes g^{sum_of_the_shares} of the other players using their vss checks
    for (int j = 1; j < setting.t1; j++) {
        // this functions calculates g^{x_i}, same x_i used in GG20 section 3.1 (phase 2), based on the VSS checks
        CG21_CALC_XI(setting.t2, &X, CC + j * setting.t2, &V);

        ECP_SECP256K1_add(&Xi, &V);
    }
    ECP_SECP256K1_toOctet(&Xi_, &Xi, true);

    char e2[SGS_SECP256K1];
    octet E = {0, sizeof(e2), e2};
    rc = CG21_KEY_RESHARE_GEN_CHALLENGE(hisID, setting.n1, &Xi_, ssid, r3Store->rho, &E, input->proof.A);

    if (rc!=CG21_OK){
        return rc;
    }

    int rc2 = SCHNORR_verify(&Xi_, input->proof.A, &E, input->proof.psi);
    if (rc2)
    {
        return CG21_SCHNORR_VERIFY_FAILED;
    }

    return CG21_OK;
}

int CG21_KEY_RESHARE_VERIFY_T1(const CG21_RESHARE_ROUND4_OUTPUT *input, const CG21_RESHARE_ROUND1_STORE_PUB_T1 *pubT1,
                               CG21_RESHARE_SETTING setting, CG21_RESHARE_ROUND4_STORE *r3Store,
                               CG21_SSID *ssid, int hisID){

    int rc = key_reshare_verify_helper(input,setting,r3Store,ssid,hisID,pubT1->A);
    if (rc!=CG21_OK)
    {
        return rc;
    }

    return CG21_OK;
}

int CG21_KEY_RESHARE_VERIFY_N2(const CG21_RESHARE_ROUND4_OUTPUT *input, const CG21_RESHARE_ROUND1_STORE_PUB_N2 *pubN2,
                               CG21_RESHARE_SETTING setting, CG21_RESHARE_ROUND4_STORE *r3Store,
                               CG21_SSID *ssid, int hisID){

    int rc = key_reshare_verify_helper(input,setting,r3Store,ssid,hisID,pubN2->A);
    if (rc!=CG21_OK)
    {
        return rc;
    }

    return CG21_OK;
}

void CG21_KEY_RESHARE_OUTPUT(CG21_RESHARE_OUTPUT *output, const CG21_RESHARE_ROUND4_STORE *r3Store,
                             const CG21_RESHARE_ROUND1_STORE_PUB_T1 *r3Receive, octet *PK,
                             CG21_RESHARE_SETTING setting, octet *rid, int j, bool first){
    if (first){
        output->n =  setting.n2;
        output->t =  setting.t2;

        OCT_copy(output->pk.X, PK);
        OCT_copy(output->rho, r3Store->rho);
        OCT_copy(output->rid, rid);
        OCT_copy(output->shares.X, r3Store->shares.X);
        OCT_copy(output->shares.Y, r3Store->shares.Y);
        output->pk.pack_size = setting.t1;
    }

    // pack partial ECDSA PKs into one octet
    CG21_PACK_PARTIAL_PK(&output->pk, r3Receive->Xi, j, first);

}
