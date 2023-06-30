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

/*  ------------- PHASE 2: Auxiliary Info ----------------  */


void CG21_AUX_FORM_SSID(CG21_SSID *ssid, octet *rid, octet *X_packed, octet *j_packed, const int n){

    char o[SFS_SECP256K1 + 1];
    octet G_oct = {0, sizeof(o), o};

    char qq[EGS_SECP256K1];
    octet q_oct = {0, sizeof(qq), qq};

    char rho[EGS_SECP256K1]={0};
    octet rho_oct = {EGS_SECP256K1, sizeof(rho), rho};

    CG21_get_G(&G_oct);
    CG21_get_q(&q_oct);

    // copy curve order to ssid
    OCT_copy(ssid->q, &q_oct);

    // copy curve generator to ssid
    OCT_copy(ssid->g, &G_oct);

    // copy from inputs to ssid
    OCT_copy(ssid->X_set_packed, X_packed);
    OCT_copy(ssid->j_set_packed, j_packed);
    OCT_copy(ssid->rid, rid);

    // copy q-bit zero into ssid->rho
    OCT_copy(ssid->rho, &rho_oct);
    *ssid->n1 = n;
}

int CG21_AUX_ROUND1_GEN_V(csprng *RNG, CG21_AUX_ROUND1_STORE_PUB *round1StorePub,
                          CG21_AUX_ROUND1_STORE_PRIV *round1storePriv,
                          CG21_AUX_ROUND1_OUT *round1Out,
                          CG21_PAILLIER_KEYS *paillier,
                          const CG21_SSID *ssid,
                          CG21_PEDERSEN_KEYS *pedersen,
                          int id, int n){

    BIG_256_56 s;
    BIG_256_56 q;



    hash256 sha;
    char w[SHA256];

    // get curve order
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    // choose random rho
    BIG_256_56_randomnum(s, q, RNG);
    round1StorePub->rho->len=EGS_SECP256K1;
    BIG_256_56_toBytes(round1StorePub->rho->val,s);

    // choose random u
    BIG_256_56_zero(s);
    BIG_256_56_randomnum(s, q, RNG);
    round1StorePub->u->len=EGS_SECP256K1;
    BIG_256_56_toBytes(round1StorePub->u->val,s);
    BIG_256_56_zero(s);

    // store player ID
    round1StorePub->i = id;
    round1storePriv->i = id;
    round1Out->i = id;
    round1StorePub->t=n;

    HASH256_init(&sha);

    //Process i into sha
    HASH_UTILS_hash_i2osp4(&sha, id);
    HASH_UTILS_hash_i2osp4(&sha, sizeof(id));

    // process rho and u into sha
    HASH_UTILS_hash_oct(&sha, round1StorePub->rho);
    HASH_UTILS_hash_oct(&sha, round1StorePub->u);

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

    // pack b0, b1, N into one octet
    CG21_PedersenPub_to_octet(&pedersen->pedersenPub, round1StorePub->PedPub);

    // pack N and N^2 into one octet
    CG21_PaillierPub_to_octet(&paillier->paillier_pk, round1StorePub->PaiPub);

    // pack Pedersen private params
    CG21_PedersenPriv_to_octet(&pedersen->pedersenPriv, round1storePriv->PEDERSEN_PRIV);

    // pack Paillier primes
    CG21_PaillierPriv_to_octet(&paillier->paillier_sk, round1storePriv->Paillier_PRIV);

    // we can skip hashing Paillier public key, since both Pedersen and Paillier are sharing the same N.
    // however, to keep this part generic we hash both Paillier and Pedersen N values
    HASH_UTILS_hash_oct(&sha, round1StorePub->PedPub);
    HASH_UTILS_hash_oct(&sha, round1StorePub->PaiPub);

    // PiMod and PiPRM: prove
    rc = CG21_PI_PRM_PROVE_HELPER(RNG,round1storePriv,ssid,round1StorePub);
    if (rc != CG21_OK){
        exit(rc);
    }

    HASH_UTILS_hash_oct(&sha, round1StorePub->pedersenProof.rho);
    HASH_UTILS_hash_oct(&sha, round1StorePub->pedersenProof.irho);
    HASH_UTILS_hash_oct(&sha, round1StorePub->pedersenProof.t);
    HASH_UTILS_hash_oct(&sha, round1StorePub->pedersenProof.it);

    /* Output */
    HASH256_hash(&sha, w);
    for (int j=0; j<SHA256; j++){
        round1Out->V->val[j] = w[j];
    }
    round1Out->V->len = SHA256;

    return CG21_OK;
}

int CG21_AUX_ROUND3_CHECK_SSID(CG21_SSID *his_ssid, octet *my_rid, octet *my_rho,
                               CG21_SSID *my_ssid, int n, bool rho){

    int ret;

    char o[SFS_SECP256K1 + 1];
    octet G_oct = {0, sizeof(o), o};

    char qq[EGS_SECP256K1];
    octet q_oct = {0, sizeof(qq), qq};

    // check whether given X_set and j_set are valid
    ret = CG21_set_comp(his_ssid->X_set_packed, his_ssid->j_set_packed,
                        my_ssid->X_set_packed,
                        my_ssid->j_set_packed, n, EFS_SECP256K1 + 1);
    if (ret != 1){
        return CG21_UNKNOWN_SSID;
    }

    // check the given rid
    ret = OCT_comp(his_ssid->rid, my_rid);
    if (ret != 1){
        return CG21_UNKNOWN_SSID;
    }

    // check the given curve generator
    CG21_get_G(&G_oct);
    ret = OCT_comp(his_ssid->g, &G_oct);
    if (ret != 1){
        return CG21_UNKNOWN_SSID;
    }

    // check the given curve order
    CG21_get_q(&q_oct);
    ret = OCT_comp(his_ssid->q, &q_oct);
    if (ret != 1){
        return CG21_UNKNOWN_SSID;
    }

    if (rho){
        ret = OCT_comp(his_ssid->rho, my_rho);
        if (ret != 1){
            return CG21_UNKNOWN_SSID;
        }
    }

    return CG21_OK;
}

int CG21_AUX_ROUND3_CHECK_V_N(CG21_SSID *ssid,
                              CG21_AUX_ROUND1_STORE_PUB round1Pub,
                              const CG21_AUX_ROUND1_OUT *round1Out){

    BIG_512_60 min_n[HFLEN_4096];
    hash256 sha;

    char v[SHA256];
    octet V_r3 = {0, sizeof(v), v};

    HASH256_init(&sha);

    //Process i into sha
    HASH_UTILS_hash_i2osp4(&sha, round1Pub.i);
    HASH_UTILS_hash_i2osp4(&sha, sizeof(round1Pub.i));

    // process rho and u into sha
    HASH_UTILS_hash_oct(&sha, round1Pub.rho);
    HASH_UTILS_hash_oct(&sha, round1Pub.u);

    // process the curve order and generator into sha
    HASH_UTILS_hash_oct(&sha, ssid->g);
    HASH_UTILS_hash_oct(&sha, ssid->q);

    // process xor-ed rids into sha
    HASH_UTILS_hash_oct(&sha, ssid->rid);

    // sort partial X[i] based on j_packed and process them into sha
    int rc = CG21_hash_set_X(&sha, ssid->X_set_packed, ssid->j_set_packed, round1Pub.t, EFS_SECP256K1 + 1);
    if (rc!=CG21_OK){
        return rc;
    }

    HASH_UTILS_hash_oct(&sha, round1Pub.PedPub);
    HASH_UTILS_hash_oct(&sha, round1Pub.PaiPub);

    HASH_UTILS_hash_oct(&sha, round1Pub.pedersenProof.rho);
    HASH_UTILS_hash_oct(&sha, round1Pub.pedersenProof.irho);
    HASH_UTILS_hash_oct(&sha, round1Pub.pedersenProof.t);
    HASH_UTILS_hash_oct(&sha, round1Pub.pedersenProof.it);

    // generates V' from given element from Round2
    HASH256_hash(&sha,  V_r3.val);
    V_r3.len = SHA256;

    // compare V' against given V from Round1
    int ret = OCT_comp(&V_r3,round1Out->V);
    if (ret != 1){
        return CG21_AUX_V_IS_NOT_VALID;
    }

    // compute 2^{8\kappa-1}
    FF_4096_init(min_n,1,HFLEN_4096);
    FF_4096_norm(min_n,HFLEN_4096);
    for (int ii=0; ii<CG21_MINIMUM_N_LENGTH;ii++)
        FF_4096_shl(min_n, HFLEN_4096);

    // load Paillier public keys
    PAILLIER_public_key paillierPub2;
    rc = CG21_PaillierPub_from_octet(&paillierPub2, round1Pub.PaiPub);
    if (rc!=CG21_OK){
        return CG21_UTILITIES_WRONG_PACKED_SIZE;
    }

    // check Paillier N >= 2^{8\kappa-1}
    rc = FF_4096_comp(paillierPub2.n,min_n,HFLEN_4096);
    if (rc==-1){
        return CG21_PAILLIER_INVALID_N_LENGTH;
    }

    return CG21_OK;
}

void CG21_AUX_ROUND3_XOR_RHO(const CG21_AUX_ROUND1_STORE_PUB *rn1SP,CG21_AUX_ROUND3 *rn3, bool myrho){
    if (myrho) {
        OCT_pad(rn3->rho, EGS_SECP256K1);
        rn3->i = rn1SP->i;
        rn3->t = rn1SP->t;
    }

    OCT_xor(rn3->rho, rn1SP->rho);
}

int CG21_PI_MOD_PROVE_HELPER(csprng *RNG, CG21_AUX_ROUND1_STORE_PRIV *rnd1Priv, const CG21_SSID *ssid,
                                 CG21_AUX_ROUND3 *rnd3){

    CG21_PAILLIER_KEYS paillier;

    // recover Paillier private parameters from packed octet
    int rc = CG21_PaillierKeys_from_octet(&paillier, rnd1Priv->Paillier_PRIV);
    if (rc!=CG21_OK){

        // clean up
        PAILLIER_PRIVATE_KEY_KILL(&paillier.paillier_sk);

        return rc;
    }

    // generate ZKP for Paillier parameters
    rc = CG21_PI_MOD_PROVE(RNG, paillier, ssid, &rnd3->paillierProof, rnd3->t);

    // clean up
    PAILLIER_PRIVATE_KEY_KILL(&paillier.paillier_sk);

    return rc;
}

int CG21_PI_PRM_PROVE_HELPER(csprng *RNG, CG21_AUX_ROUND1_STORE_PRIV *rnd1Priv, const CG21_SSID *ssid,
                             CG21_AUX_ROUND1_STORE_PUB *rnd1StorePub){

    PEDERSEN_PRIV pedersenPriv;

    // recover Pedersen private parameters from packed octet
    int rc = CG21_PedersenPriv_from_octet(&pedersenPriv, rnd1Priv->PEDERSEN_PRIV);
    if (rc!=CG21_OK){

        // clean up
        CG21_Pedersen_Private_Kill(&pedersenPriv);

        return rc;
    }

    // generate ZKP for Pedersen parameters
    rc = CG21_PI_PRM_PROVE(RNG, &pedersenPriv, ssid, &rnd1StorePub->pedersenProof);

    // clean up
    CG21_Pedersen_Private_Kill(&pedersenPriv);

    return rc;
}

int CG21_PI_MOD_VERIFY_HELPER(CG21_AUX_ROUND1_STORE_PUB *rnd1Pub, const CG21_SSID *ssid,
                                  CG21_AUX_ROUND3 *rnd3){

    PAILLIER_public_key PaiPub;

    // recover Paillier public parameters from packed octet
    int rc = CG21_PaillierPub_from_octet(&PaiPub, rnd1Pub->PaiPub);
    if (rc!=CG21_OK){
        return rc;
    }

    // verify the ZKP for Paillier parameters
    rc = CG21_PI_MOD_VERIFY(&rnd3->paillierProof, ssid, PaiPub,rnd1Pub->t);

    return rc;
}

int CG21_PI_PRM_VERIFY_HELPER(CG21_AUX_ROUND1_STORE_PUB *rnd1Pub, const CG21_SSID *ssid){

    PEDERSEN_PUB PedPub;

    // recover Pedersen public parameters from packed octet
    int rc = CG21_PedersenPub_from_octet(&PedPub, rnd1Pub->PedPub);
    if (rc!=CG21_OK){
        return rc;
    }

    // verify ZKP for Pedersen parameters
    rc = CG21_PI_PRM_VERIFY(&PedPub, ssid, &rnd1Pub->pedersenProof, rnd1Pub->t);

    return rc;
}

int CG21_PI_FACTOR_PROVE_HELPER(csprng *RNG, const CG21_SSID *ssid, CG21_AUX_ROUND1_STORE_PUB *rnd1Pub,
                                CG21_AUX_ROUND3 *rnd3pub, CG21_AUX_ROUND1_STORE_PRIV *rnd1Priv){

    char t1[HFS_2048];
    octet P = {0, sizeof(t1), t1};

    char t2[HFS_2048];
    octet Q = {0, sizeof(t2), t2};

    PEDERSEN_PUB verifierPedPub;
    // recover Pedersen public parameters from packed octet
    int rc = CG21_PedersenPub_from_octet(&verifierPedPub, rnd1Pub->PedPub);
    if (rc!=CG21_OK){
        return rc;
    }

    // recover Paillier private parameters from packed octet
    CG21_PAILLIER_KEYS paillier;
    rc = CG21_PaillierKeys_from_octet(&paillier, rnd1Priv->Paillier_PRIV);
    if (rc!=CG21_OK){

        // clean up
        PAILLIER_PRIVATE_KEY_KILL(&paillier.paillier_sk);

        return rc;
    }

    FF_2048_toOctet(&P,paillier.paillier_sk.p,HFLEN_2048);
    FF_2048_toOctet(&Q,paillier.paillier_sk.q,HFLEN_2048);

    CG21_PI_FACTOR_COMMIT_PROVE(RNG, ssid,&verifierPedPub,&rnd3pub->factorCommits,
                                &rnd3pub->factorProof,&P,&Q,rnd1Pub->t);

    // clean up
    PAILLIER_PRIVATE_KEY_KILL(&paillier.paillier_sk);
    OCT_clear(&P);
    OCT_clear(&Q);

    return CG21_OK;
}

int CG21_PI_FACTOR_VERIFY_HELPER(const CG21_SSID *ssid, CG21_AUX_ROUND3 *rnd3pub, CG21_AUX_ROUND1_STORE_PUB *rnd1Pub,
                                 CG21_AUX_ROUND1_STORE_PRIV *rnd1Priv){

    char t1[HFS_4096];
    octet N = {0, sizeof(t1), t1};

    PEDERSEN_PRIV PedPriv;
    // recover Pedersen public parameters from packed octet
    int rc = CG21_PedersenPriv_from_octet(&PedPriv, rnd1Priv->PEDERSEN_PRIV);
    if (rc!=CG21_OK){
        return rc;
    }

    PAILLIER_public_key pk;
    rc = CG21_PaillierPub_from_octet(&pk,rnd1Pub->PaiPub);
    if (rc!=CG21_OK){

        CG21_Pedersen_Private_Kill(&PedPriv); // clean up
        return rc;
    }

    FF_4096_toOctet(&N, pk.n, HFLEN_4096); // convert N to octet
    rc = CG21_PI_FACTOR_VERIFY(&rnd3pub->factorCommits,&rnd3pub->factorProof,&N,
                               &PedPriv,ssid, rnd1Pub->t);

    // clean up
    CG21_Pedersen_Private_Kill(&PedPriv);

    if (rc != CG21_OK){
        return rc;
    }

    return CG21_OK;
}

void CG21_AUX_PACK_OUTPUT(CG21_AUX_OUTPUT *output, CG21_AUX_ROUND1_STORE_PUB rnd1Pub, bool first_entry){
    char hex_string[5];

    char hex_j[5];
    octet OCT_j = {0, sizeof(hex_j), hex_j};

    char n[FS_2048];
    octet N = {0, sizeof(n), n};

    char s[FS_2048];
    octet S = {0, sizeof(s), s};

    char t[FS_2048];
    octet T = {0, sizeof(t), t};

    if (first_entry){
        OCT_clear(output->N);
        OCT_clear(output->s);
        OCT_clear(output->t);
        OCT_clear(output->j);
    }

    PEDERSEN_PUB pedersenPub2;

    // recover Pedersen public parameters from packed octet
    CG21_PedersenPub_from_octet(&pedersenPub2, rnd1Pub.PedPub);

    // convert Paillier/Pedersen N to octet
    FF_2048_toOctet(&N, pedersenPub2.N, FFLEN_2048);

    // convert s,t to octet
    FF_2048_toOctet(&S, pedersenPub2.b0, FFLEN_2048);
    FF_2048_toOctet(&T, pedersenPub2.b1, FFLEN_2048);

    // join Ni to the end of N_set_packed
    OCT_joctet(output->N, &N);

    // join s,t to the end of s/t_set_packed
    OCT_joctet(output->s, &S);
    OCT_joctet(output->t, &T);

    // convert integer to hex
    sprintf(&hex_string[0], "%04X", rnd1Pub.i);

    // convert hex_string to octet
    OCT_fromHex(&OCT_j,hex_string);

    // join OCT_j to the end of j_set_packed
    OCT_joctet(output->j, &OCT_j);

}
