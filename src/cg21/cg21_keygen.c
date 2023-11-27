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

static void CG21_GENERATE_CHALLENGE(const octet *X, int i, octet rid, const CG21_KEYGEN_SID *sid, octet *E, octet *A){

    hash256 sha;

    BIG_256_56 e;
    BIG_256_56 q;

    // get curve order
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);



    // e = H(G,A,X,sid,i,rid) mod q
    HASH256_init(&sha);

    HASH_UTILS_hash_oct(&sha, sid->g);
    HASH_UTILS_hash_oct(&sha, sid->q);
    HASH_UTILS_hash_oct(&sha, sid->P);

    HASH_UTILS_hash_i2osp4(&sha, sid->uid->len);
    HASH_UTILS_hash_oct(&sha, sid->uid);

    HASH_UTILS_hash_oct(&sha, X);
    HASH_UTILS_hash_oct(&sha, A);
    HASH_UTILS_hash_i2osp4(&sha, i);
    HASH_UTILS_hash_i2osp4(&sha, sizeof(i));

    HASH_UTILS_hash_oct(&sha, &rid);

    // interpret sha output as an int mod q
    HASH_UTILS_rejection_sample_mod_BIG(&sha, q, e);

    BIG_256_56_toBytes(E->val, e);
    E->len = SGS_SECP256K1;

}
void CG21_KEYGEN_ROUND1_GEN_V(const CG21_KEYGEN_ROUND1_STORE_PUB *store, const CG21_KEYGEN_SID *sid, octet *V){
    hash256 sha;
    HASH256_init(&sha);

    HASH_UTILS_hash_oct(&sha, sid->g);
    HASH_UTILS_hash_oct(&sha, sid->q);
    HASH_UTILS_hash_oct(&sha, sid->P);

    HASH_UTILS_hash_i2osp4(&sha, sid->uid->len);
    HASH_UTILS_hash_oct(&sha, sid->uid);

    HASH_UTILS_hash_i2osp4(&sha, store->i);
    HASH_UTILS_hash_i2osp4(&sha, sizeof(store->i));

    HASH_UTILS_hash_oct(&sha, store->rid);
    HASH_UTILS_hash_oct(&sha, store->X);
    HASH_UTILS_hash_oct(&sha, store->A);
    HASH_UTILS_hash_oct(&sha, store->A2);
    HASH_UTILS_hash_oct(&sha, store->u);
    HASH_UTILS_hash_oct(&sha, store->packed_checks);
    HASH_UTILS_hash_i2osp4(&sha, store->packed_checks->len);    // prevent length extension attack

    /* Output */
    HASH256_hash(&sha, V->val);
    V->len = SHA256;
}

void CG21_KEY_GENERATE_GET_SID(CG21_KEYGEN_SID *sid, octet *P){

    char o[SFS_SECP256K1 + 1];
    octet G_oct = {0, sizeof(o), o};

    char qq[EGS_SECP256K1];
    octet q_oct = {0, sizeof(qq), qq};

    CG21_get_G(&G_oct);
    CG21_get_q(&q_oct);

    // copy curve order to ssid
    OCT_copy(sid->q, &q_oct);

    // copy curve generator to ssid
    OCT_copy(sid->g, &G_oct);

    // copy parties' IDs
    OCT_copy(sid->P, P);

}

int CG21_KEY_GENERATE_ROUND1(csprng *RNG,
                             CG21_KEYGEN_ROUND1_STORE_PRIV *priv,
                             CG21_KEYGEN_ROUND1_STORE_PUB *pub,
                             CG21_KEYGEN_ROUND1_output *output,
                             CG21_KEYGEN_SID *sid,
                             int myID, int n, int t, octet *P)
{

    BIG_256_56 s;
    BIG_256_56 q;
    ECP_SECP256K1 G;

    char v[SHA256];
    octet V = {0, sizeof(v), v};

    // get curve generator
    ECP_SECP256K1_generator(&G);

    // get curve order
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    // choose a random x_i (partial secret)
    BIG_256_56_randomnum(s, q, RNG);

    priv->x->len=EGS_SECP256K1;
    BIG_256_56_toBytes(priv->x->val, s);

    char cc[t][EFS_SECP256K1 + 1];
    octet CC[t];
    init_octets((char *)cc,   CC,   EFS_SECP256K1 + 1, t);

    // run VSS on partial secret to get shares(priv->shares) and checks(CC)
    VSS_make_shares(t, n, RNG, &priv->shares, CC, priv->x);

    // pack VSS checks(CC) into one octet(pub->packed_checks)
    CG21_pack_vss_checks(CC, t, pub->packed_checks);

    // compute partial ECDSA PK(G)
    ECP_SECP256K1_mul(&G, s);
    BIG_256_56_zero(s);

    // convert partial ECDSA PK from ECP to octet
    ECP_SECP256K1_toOctet(pub->X, &G, true);

    // validate the correctness of the partial ECDSA PK
    int rc = ECP_SECP256K1_PUBLIC_KEY_VALIDATE(pub->X);
    if (rc != 0)
    {
        return CG21_KEY_ERROR;
    }

    // commit to random tau and tau2
    SCHNORR_commit(RNG, priv->tau, pub->A);
    SCHNORR_commit(RNG, priv->tau2, pub->A2);

    // choose random rid
    BIG_256_56_randomnum(s, q, RNG);
    pub->rid->len=EGS_SECP256K1;
    BIG_256_56_toBytes(pub->rid->val, s);

    // choose random u
    BIG_256_56_zero(s);
    BIG_256_56_randomnum(s, q, RNG);
    pub->u->len=EGS_SECP256K1;
    BIG_256_56_toBytes(pub->u->val, s);

    // get SID
    CG21_KEY_GENERATE_GET_SID(sid,P);

    // store ID
    priv->i= myID;
    output->i = myID;
    pub->i = myID;

    // store threshold setting
    priv->t = t;
    priv->n = n;

    // compute V
    CG21_KEYGEN_ROUND1_GEN_V(pub, sid, &V);
    OCT_copy(output->V, &V);

    // clean up
    BIG_256_56_zero(s);

    return CG21_OK;
}

int CG21_KEY_GENERATE_ROUND3_1(const CG21_KEYGEN_ROUND1_output *r1_out,
                               CG21_KEYGEN_ROUND1_STORE_PUB *r2_out,
                               const CG21_KEYGEN_ROUND1_STORE_PRIV *myPriv,
                               const SSS_shares *r2_share,
                               const CG21_KEYGEN_SID *sid,
                               CG21_KEYGEN_ROUND3_STORE *r3){

    char v[SHA256];
    octet V = {0, sizeof(v), v};

    char cc[myPriv->t][EFS_SECP256K1 + 1];
    octet CC[myPriv->t];
    init_octets((char *)cc,   CC,   EFS_SECP256K1 + 1, myPriv->t);

    int rc;

    // compute V
    CG21_KEYGEN_ROUND1_GEN_V(r2_out, sid, &V);

    // check whether V is given from round 1 is equal to the computed version
    rc = OCT_comp(&V, r1_out->V);
    if (rc==0){
        return CG21_V_IS_NOT_VERIFIED;
    }

    // unpack VSS checks from r2_out->packed_checks into CC
    rc = CG21_unpack(r2_out->packed_checks, myPriv->t, CC, EFS_SECP256K1 + 1);
    if (rc!=CG21_OK){
        return rc;
    }

    // check whether the given partial PK is equal to the free term in the exponent
    rc = OCT_comp(&CC[0], r2_out->X);
    if (rc==0){
        return CG21_Xs_ARE_NOT_EQUAL;
    }

    // Check that given shared secrets have same x-coord
    // myPriv->i refers to the ID of the player running this script, but this ID is stored in the index myPriv->i-1
    // since IDs start from 1, but indices start from 0
    rc = OCT_comp(r2_share->X, myPriv->shares.X+(myPriv->i-1));
    if (rc==0){
        return CG21_WRONG_SHARE_IS_GIVEN;
    }

    // VSS Verification for the received share
    rc = VSS_verify_shares(myPriv->t, r2_share->X, r2_share->Y, CC);
    if (rc != VSS_OK)
    {
        return rc;
    }

    // pack packed-vss octets into one octet
    OCT_joctet(r3->packed_all_checks, r2_out->packed_checks);

    //pack received Y from point(X,Y) into one octet
    OCT_joctet(r3->packed_share_Y, r2_share->Y);

    r3->n = myPriv->n;
    r3->t = myPriv->t;

    return CG21_OK;
}

int CG21_KEY_GENERATE_ROUND3_2_1(const CG21_KEYGEN_ROUND1_STORE_PUB *pub,
                                  CG21_KEYGEN_ROUND3_STORE *r3,
                                  bool myrid) {

    if (myrid) {
        OCT_pad(r3->xor_rid, EGS_SECP256K1);
    }

    OCT_xor(r3->xor_rid, pub->rid);

    return CG21_OK;
}

int CG21_KEY_GENERATE_ROUND3_2_2(const CG21_KEYGEN_ROUND1_STORE_PRIV *myPriv,
                                  const CG21_KEYGEN_ROUND1_STORE_PUB *r2,
                                  const CG21_KEYGEN_ROUND3_STORE *r3,
                                  const CG21_KEYGEN_SID *sid,
                                  CG21_KEYGEN_ROUND3_OUTPUT *r3Out){

    char e2[SGS_SECP256K1];
    octet E = {0, sizeof(e2), e2};

    r3Out->i = myPriv->i;

    // generate challenge e for Schnorr proof
    CG21_GENERATE_CHALLENGE(r2->X,myPriv->i,*r3->xor_rid,sid, &E, r2->A);

    // Schnorr prove for having access to partial x
    SCHNORR_prove(myPriv->tau, &E, myPriv->x, r3Out->ui_proof.psi);
    OCT_copy(r3Out->ui_proof.A, r2->A);

    return CG21_OK;
}

int CG21_KEY_GENERATE_ROUND3_2_3(const CG21_KEYGEN_ROUND1_STORE_PRIV *myPriv,
                                  const CG21_KEYGEN_ROUND1_STORE_PUB *pub,
                                  CG21_KEYGEN_ROUND3_STORE *r3,
                                  const CG21_KEYGEN_SID *sid,
                                  CG21_KEYGEN_ROUND3_OUTPUT *r3Output){

    BIG_256_56 accum;
    BIG_256_56 s;
    BIG_256_56 q;
    ECP_SECP256K1 G;

    char e2[SGS_SECP256K1];
    octet E = {0, sizeof(e2), e2};

    char o[SFS_SECP256K1 + 1];
    octet X = {0, sizeof(o), o};

    // Curve order
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    // Curve generator
    ECP_SECP256K1_generator(&G);

    char y[myPriv->n-1][EGS_SECP256K1];
    octet Y[myPriv->n-1];
    init_octets((char *)y,   Y,   EGS_SECP256K1, myPriv->n-1);

    // unpack Y component of the received SSS points
    int rc = CG21_unpack(r3->packed_share_Y, myPriv->n-1, Y, EGS_SECP256K1);
    if (rc!=CG21_OK){
        return rc;
    }

    int t =  myPriv->i - 1;
    BIG_256_56_fromBytesLen(accum, (myPriv->shares.Y + t)->val, (myPriv->shares.Y + t)->len);

    // compute sum-of-the-shares
    for (int i=0; i<myPriv->n-1; i++){
        BIG_256_56_fromBytesLen(s, Y[i].val, Y[i].len);
        BIG_256_56_add(accum, accum, s);
        BIG_256_56_mod(accum, q);
    }

    // convert sum-of-the-shares to octet
    r3->xi.Y->len = EGS_SECP256K1;
    BIG_256_56_toBytes(r3->xi.Y->val, accum);

    OCT_copy(r3->xi.X,myPriv->shares.X + t);

    // computes (sum-of-the-shares)*G
    ECP_SECP256K1_mul(&G, accum);

    // convert (sum-of-the-shares)*G to octet
    ECP_SECP256K1_toOctet(&X, &G, true);

    // generate challenge e for Schnorr proof
    CG21_GENERATE_CHALLENGE(&X, myPriv->i, *r3->xor_rid, sid, &E, pub->A2);

    // Schnorr proof for the knowledge of sum-of-the-shares
    SCHNORR_prove(myPriv->tau2, &E, r3->xi.Y, r3Output->xi_proof.psi);
    OCT_copy(r3Output->xi_proof.A, pub->A2);

    // clean up
    BIG_256_56_zero(accum);
    BIG_256_56_zero(s);

    for (int i=0; i<myPriv->n-1; i++){
        OCT_clear(&Y[i]);
    }

    return CG21_OK;
}

int CG21_KEY_GENERATE_OUTPUT_1_1(const CG21_KEYGEN_ROUND3_OUTPUT *r3Out,
                                 const CG21_KEYGEN_ROUND1_STORE_PUB *r3,
                                 const CG21_KEYGEN_SID *sid,
                                 const CG21_KEYGEN_ROUND3_STORE *r3Store){

    if (!OCT_comp(r3Out->ui_proof.A, r3->A)){
        return CG21_A_DOES_NOT_MATCH;
    }

    char e2[SGS_SECP256K1];
    octet E = {0, sizeof(e2), e2};

    // generate challenge e
    CG21_GENERATE_CHALLENGE((r3->X),r3->i,*r3Store->xor_rid, sid, &E, r3->A);

    // verify Schnorr proof for partial secret, x_i, using the challenge e
    int rc = SCHNORR_verify(r3->X, r3->A, &E, r3Out->ui_proof.psi);
    if (rc)
    {
        return CG21_SCHNORR_VERIFY_FAILED;
    }

    return CG21_OK;
}


int CG21_KEY_GENERATE_OUTPUT_1_2(CG21_KEYGEN_OUTPUT *output,
                                 const CG21_KEYGEN_ROUND3_OUTPUT *r3Out,
                                 CG21_KEYGEN_ROUND3_STORE *r3Store,
                                 CG21_KEYGEN_ROUND1_STORE_PRIV *myPriv,
                                 const CG21_KEYGEN_SID *sid,
                                 const CG21_KEYGEN_ROUND1_STORE_PUB *r1Pub){

    ECP_SECP256K1 V;
    ECP_SECP256K1 Xi;
    BIG_256_56 T;

    char e[SGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    char xi[SFS_SECP256K1 + 1];
    octet Xi_ = {0, sizeof(xi), xi};

    // converts party ID to array index
    int ind = r3Out->i - 1;

    int n = r3Store->n;
    int t = r3Store->t;

    // we only retrieve n-1 packed_checks that belong to other parties
    char round1_checks[n-1][t][EFS_SECP256K1 + 1];    // VSS: checks
    octet CC[(n-1)*t];
    init_octets((char *) round1_checks, CC, EFS_SECP256K1 + 1, (n-1)*t);

    // all players' vss checked are packed into one single octet
    // the following function first split each players' packed VSS checks from the main octet
    // then unpack each packed VSS checks
    // at the end, we will have (n-1)*t VSS checks
    int rc = CG21_double_unpack(r3Store->packed_all_checks, n-1, t, CC);
    if (rc!=CG21_OK){
        return rc;
    }

    // initialize Xi with (myPriv->shares.Y + ind)*G
    BIG_256_56_fromBytesLen(T, (myPriv->shares.Y + ind)->val, (myPriv->shares.Y + ind)->len);
    ECP_SECP256K1_generator(&Xi);
    ECP_SECP256K1_mul(&Xi, T);

    for (int j=0; j<n-1; j++) {
        // this functions calculates g^{x_i}, same x_i used in GG20 section 3.1 (phase 2), based on the VSS checks
        // CC+j*t refers to the beginning of each parties' octet and +t means we don't want to include the first checks
        // that belongs to the verifier in calculation of XI
        CG21_CALC_XI(t, myPriv->shares.X + ind, CC + j * t, &V);
        ECP_SECP256K1_add(&Xi, &V);
    }
    ECP_SECP256K1_toOctet(&Xi_, &Xi, true);

    // store all the other players (sum_of_share)*G to be used in key re-sharing protocol
    OCT_joctet(output->pk_ss_sum_pack, &Xi_);

    CG21_GENERATE_CHALLENGE(&Xi_, r3Out->i, *r3Store->xor_rid, sid, &E, r1Pub->A2);

    int rc2 = SCHNORR_verify(&Xi_, r1Pub->A2, &E, r3Out->xi_proof.psi);

    // clean up
    BIG_256_56_zero(T);
    ECP_SECP256K1_inf(&Xi);

    if (rc2)
    {
        return CG21_SCHNORR_VERIFY_FAILED;
    }

    return CG21_OK;
}

void CG21_PACK_PARTIAL_PK(CG21_KEYGEN_OUTPUT *output, octet *X, int i, bool first_entry){

    char hex_i[5];
    char hex_string[5];
    octet OCT_i = {0, sizeof(hex_i), hex_i};

    if (first_entry){
        OCT_clear(output->X_set_packed);
        OCT_clear(output->j_set_packed);
    }
    // join r1Pub to the end of X_set_packed
    OCT_joctet(output->X_set_packed, X);

    // convert integer to hex
    sprintf(&hex_string[0], "%04X", i);

    // convert hex_string to octet
    OCT_fromHex(&OCT_i,hex_string);

    // join OCT_i to the end of j_set_packed
    OCT_joctet(output->j_set_packed, &OCT_i);
}

int CG21_KEY_GENERATE_OUTPUT_2(CG21_KEYGEN_OUTPUT *output,
                               CG21_KEYGEN_ROUND1_STORE_PUB *r1Pub,
                               bool first_entry){

    CG21_PACK_PARTIAL_PK(output, r1Pub->X, r1Pub->i, first_entry);

    return CG21_OK;
}

int CG21_KEY_GENERATE_OUTPUT_3(CG21_KEYGEN_OUTPUT *out, int n){


    ECP_SECP256K1 accum;
    ECP_SECP256K1 s;

    char x[EFS_SECP256K1 + 1];
    octet Xoct = {0, sizeof(x), x};

    // checked the length of X_packed
    if (out->X_set_packed->len != n * (EFS_SECP256K1 + 1))
    {
        return CG21_WRONG_PACKED_X_SIZE;
    }

    OCT_clear(&Xoct);

    // extract the last Xi from X_packed
    OCT_chop(out->X_set_packed, &Xoct, out->X_set_packed->len - (EFS_SECP256K1 + 1));

    // convert Xi from octet to point
    if (!ECP_SECP256K1_fromOctet(&accum, &Xoct))
    {
        return CG21_INVALID_ECP;
    }

    for (int i = n - 2; i >= 0; i--)
    {
        OCT_clear(&Xoct);
        OCT_chop(out->X_set_packed, &Xoct, out->X_set_packed->len - (EFS_SECP256K1 + 1));

        if (!ECP_SECP256K1_fromOctet(&s, &Xoct))
        {
            return CG21_INVALID_ECP;
        }

        ECP_SECP256K1_add(&accum, &s);
    }

    // restore length of the packed X
    out->X_set_packed->len = n * (EFS_SECP256K1 + 1);

    // convert X from point to octet
    ECP_SECP256K1_toOctet(out->X, &accum, true);

    return CG21_OK;
}
