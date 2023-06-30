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

#include <stdlib.h>
#include <amcl/amcl.h>
#include <amcl/paillier.h>
#include <amcl/ecdh_SECP256K1.h>
#include <amcl/randapi.h>
#include "amcl/schnorr.h"
#include "amcl/cg21/cg21_utilities.h"
#include "amcl/cg21/cg21.h"

bool Debug = false;

typedef struct
{
    csprng *RNG;
    CG21_RESHARE_SETTING *setting;
    octet *presign_a; // presign additive shares
    octet *PK;
    octet *msg;
    CG21_PRESIGN_ROUND4_STORE_2 *presign;
    CG21_SIGN_ROUND1_STORE *r1store;
    CG21_SIGN_ROUND1_OUTPUT *r1out;
    CG21_SIGN_ROUND2_OUTPUT *r2out;


} CG21_SIGN_SESSION;

void init_octets(char* mem, octet *OCTETS, int max, int n)
{
    for (int i = 0; i < n; i++)
    {
        OCTETS[i].val = mem + (i*max);
        OCTETS[i].len = 0;
        OCTETS[i].max = max;
    }
}

int file_read_tn(CG21_RESHARE_SETTING *setting){
    FILE *file = fopen("cg21_presign.csv", "r");
    if (file == NULL) {
        printf("Error: could not open file.\n");
        return 1;
    }

    char line[2048];
    if (fgets(line, 10, file)==NULL){
        exit(1);
    }

    const char *t1 = strtok(line, ",");
    char *endptr;
    long lnum = strtol(t1, &endptr, 10);
    int t = (int)lnum;

    const char *n1 = strtok(NULL, ",");
    lnum = strtol(n1, &endptr, 10);
    int n = (int)lnum;

    setting->t2 = t;
    setting->n2 = n;

    printf("\n(%d,%d)",t,n);

    fclose(file);

    return 0;
}

int file_read_presign(CG21_SIGN_SESSION *session) {

    FILE *file = fopen("cg21_presign.csv", "r");
    if (file == NULL) {
        printf("Error: could not open file.\n");
        return 1;
    }

    char line[2048];
    if (fgets(line, 2000, file)==NULL){
        exit(1);
    }

    if (fgets(line, 2000, file)==NULL){
        exit(1);
    }

    char *t3 = strtok(line, ",");
    OCT_fromHex(session->PK, t3);

    printf("\nPK=");
    OCT_output(session->PK);

    for (int i=0; i<session->setting->t2; i++) {
        if (fgets(line, 2000, file)==NULL){
            exit(1);
        }

        // read and store user ID
        const char *t2 = strtok(line, ",");
        char *endptr;
        long lnum = strtol(t2, &endptr, 10);
        session->presign[i].i = (int)lnum;
        printf("\ni=%d\n",session->presign[i].i);

        // read and store R component
        t2 = strtok(NULL, ",");
        OCT_fromHex(session->presign[i].R, t2);
        printf("R=");
        OCT_output(session->presign[i].R);

        // read and store k component
        t2 = strtok(NULL, ",");
        OCT_fromHex(session->presign[i].k, t2);
        printf("k=");
        OCT_output(session->presign[i].k);

        // read and store chi component
        t2 = strtok(NULL, ",");
        OCT_fromHex(session->presign[i].chi, t2);
        printf("chi=");
        OCT_output(session->presign[i].chi);

        // read and store additive shares
        t2 = strtok(NULL, ",");
        OCT_fromHex(session->presign_a+i, t2);
        printf("a=");
        OCT_output(session->presign_a+i);

    }
    /* Close the file */
    fclose(file);
    return 0;
}

int cg21_sign_round1(CG21_SIGN_SESSION *session){

    for (int i=0; i< session->setting->t2; i++){
        CG21_SIGN_ROUND1(session->msg,session->presign+i,session->r1store+i,session->r1out+i);
    }

    return 0;
}

int cg21_sign_round2(CG21_SIGN_SESSION *session){
    printf("\n\n----------- VALIDATION (using PK) -----------");

    int t2 = session->setting->t2;
    for (int i=0; i< t2; i++){

        for (int j=0; j<t2; j++) {
            int status = 1;

            if (i == j) {
                continue;
            }

            if (j==0 || (j==1 && i==0)){
                status=0; // first iteration
            }
            if (j==t2-1 || (j==t2-2 && i==t2-1)){
                if (status==0){
                    status=3; // first iteration is the last iteration (t=2)
                }else {
                    status = 2; // last iteration (!= first iteration)
                }
            }

            CG21_SIGN_ROUND2(session->r1store+i,session->r1out+j,session->r2out+i, status);
        }
    }

    for (int i=0; i< t2; i++){
        int rc=CG21_SIGN_VALIDATE(session->msg, session->r2out+i, session->PK);
        if (rc==CG21_OK){
            printf("\nOutput[%d]: Signature is valid", i+1);
        }else{
            printf("\nOutput[%d]: Signature is NOT valid",i+1);
            exit(1);
        }
    }

    return 0;
}

int cg21_sign_validation(const CG21_SIGN_SESSION *session){

    printf("\n\n----------- VALIDATION (using secrets) -----------");
    int t2 = session->setting->t2;
    int rc;

    /*
    * --------- CHECK 1: additive shares -----------
    * check whether the sum of additive shares * G becomes ECDSA PK
    */
    BIG_256_56 s;
    BIG_256_56 q;
    BIG_256_56 suma;
    ECP_SECP256K1 G;

    char pk[EFS_SECP256K1 + 1];
    octet PK = {0, sizeof(pk), pk};

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    ECP_SECP256K1_generator(&G);

    // this for loop sums the additive shares
    for (int i=0; i<t2; i++) {

        if (i==0){
            BIG_256_56_fromBytesLen(suma, (session->presign_a+i)->val, (session->presign_a+i)->len);
        }else {
            BIG_256_56_fromBytesLen(s, (session->presign_a+i)->val, (session->presign_a+i)->len);
            BIG_256_56_add(suma, suma, s);
            BIG_256_56_mod(suma, q);
        }
    }

    // PK = accum * G
    ECP_SECP256K1_mul(&G, suma);
    ECP_SECP256K1_toOctet(&PK, &G, true);

    rc = OCT_comp(&PK, session->PK);
    if (rc==0){
        printf("\nPresign:\tadditive shares are NOT valid!");
        exit(1);
    }else{
        printf("\nPresign:\tadditive shares are valid");
    }
    // --------------- END OF CHECK 1 -----------------


    /*
    * --------- CHECK 2: chi values -----------
     * check whether the addition of chi values becomes \sum\k_i * \sum a_i
    */

    BIG_256_56 sumk;
    BIG_256_56 ka;
    DBIG_256_56 dka;
    BIG_256_56 sumchi;

    // step 1: compute \sum\gamma_i and \sum k_i
    for (int i=0; i<t2; i++) {
        if (i==0){
            BIG_256_56_fromBytesLen(sumk, (session->presign+i)->k->val, (session->presign+i)->k->len);
        }else {

            BIG_256_56_fromBytesLen(s, (session->presign + i)->k->val, (session->presign + i)->k->len);
            BIG_256_56_add(sumk, sumk, s);
            BIG_256_56_mod(sumk, q);
        }
    }

    // step 2: compute kgamma
    BIG_256_56_mul(dka, suma, sumk);
    BIG_256_56_dmod(ka, dka, q);

    // step 2: sume of \chi components
    for (int i=0; i<t2; i++) {
        if (i==0){
            BIG_256_56_fromBytesLen(sumchi, (session->presign+i)->chi->val, (session->presign+i)->chi->len);
        }else {
            BIG_256_56_fromBytesLen(s, (session->presign + i)->chi->val, (session->presign + i)->chi->len);
            BIG_256_56_add(sumchi, sumchi, s);
            BIG_256_56_mod(sumchi, q);
        }
    }

    if (BIG_256_56_comp(ka,sumchi) != 0){
        printf("\nPresign:\tpartial chi components are NOT valid!");
        exit(1);
    }else{
        printf("\nPresign:\tpartial chi components are valid");
    }
    // --------------- END OF CHECK 2 -----------------

    /*
    * --------- CHECK 3: sigma component -----------
     * check whether generated sum of sigma values is equal to \sum{k_i}m+ r\sum{chi}
    */

    BIG_256_56 km;
    BIG_256_56 m;
    BIG_256_56 rchi;
    BIG_256_56 sigma;
    BIG_256_56 x;
    BIG_256_56 y;
    ECP_SECP256K1 R;

    // step1: hash message
    char hm[32];
    octet HM = {0,sizeof(hm),hm};

    // hash message and store it in HM
    ehashit(HASH_TYPE_SECP256K1, session->msg, -1, NULL, &HM, MODBYTES_256_56);

    // step2: get x component of R and reduce it to mod q
    if (!ECP_SECP256K1_fromOctet(&R, session->presign->R))
    {
        printf("\nR component is NOT valid!");
        exit(1);
    }

    // get rx, ry of R
    ECP_SECP256K1_get(x, y, &R);

    // r = rx mod q
    BIG_256_56_mod(x, q);
    if (BIG_256_56_iszilch(x))
    {
        printf("\nRx is NOT valid!");
        exit(1);
    }

    // rchi = r.chi mod q
    BIG_256_56_modmul(rchi, x, sumchi, q);

    // km = k.m mod q
    BIG_256_56_fromBytes(m, HM.val);
    BIG_256_56_modmul(km, sumk, m, q);

    // s = km + rchi  mod q
    BIG_256_56_add(sigma, km, rchi);
    BIG_256_56_mod(sigma, q);
    if (BIG_256_56_iszilch(sigma))
    {
        printf("\nsigma is NOT valid!");
        exit(1);
    }

    BIG_256_56_fromBytesLen(x, session->r2out->sigma->val,session->r2out->sigma->len);

    if (BIG_256_56_comp(sigma,x) != 0){
        printf("\nSign:\t\tSignature is NOT valid!");
        exit(1);
    }else{
        printf("\nSign:\t\tsigma is valid");
    }

    /*
    * --------- CHECK 4: sigma values -----------
     * check whether generated sigma values are similar
    */

    for (int i=1; i<t2-1; i++) {
        rc = OCT_comp((session->r2out+ i)->sigma, (session->r2out+ i+1)->sigma);
        if (rc == 0){
            printf("\nOutput:\t\tsigma values are NOT similar!");
            exit(1);
        }
    }
    printf("\nOutput:\t\tsigma values are similar");

    return 0;
}

int main() {

    // Deterministic RNG for debugging
    const char* seedHex = "78d0fb6705ce77dee47d03eb5b9c5d30";
    char seed[16] = {0};
    octet SEED = {sizeof(seed),sizeof(seed),seed};

    // CSPRNG
    csprng RNG;

    // fake random source
    OCT_fromHex(&SEED,seedHex);
    printf("SEED: ");
    OCT_output(&SEED);

    // initialise strong RNG
    CREATE_CSPRNG(&RNG,&SEED);

    CG21_SIGN_SESSION session;
    session.RNG = &RNG;

    //****** read t,n from file *******
    CG21_RESHARE_SETTING setting;
    file_read_tn(&setting);
    session.setting = &setting;

    int t = setting.t2;

    char presign_R[t][EFS_SECP256K1 + 1];
    char presign_chi[t][EGS_SECP256K1];
    char presign_k[t][EGS_SECP256K1];
    char presign_a[t][EGS_SECP256K1];
    char pk[EFS_SECP256K1 + 1];   // r1Store, final ECDSA PK

    octet PRESIGN_R[t];
    octet PRESIGN_chi[t];
    octet PRESIGN_k[t];
    octet PRESIGN_a[t];
    octet PK = {0, sizeof(pk), pk};

    init_octets((char *)presign_R, PRESIGN_R, EFS_SECP256K1 + 1, t);
    init_octets((char *)presign_chi, PRESIGN_chi, EGS_SECP256K1, t);
    init_octets((char *)presign_k, PRESIGN_k, EGS_SECP256K1, t);
    init_octets((char *)presign_a, PRESIGN_a, EGS_SECP256K1, t);


    CG21_PRESIGN_ROUND4_STORE_2 presign[t];

    for (int i=0; i < t; i++) {
        presign[i].R = PRESIGN_R + i;
        presign[i].chi = PRESIGN_chi + i;
        presign[i].k = PRESIGN_k + i;
    }

    session.presign = presign;
    session.presign_a = PRESIGN_a;
    session.PK = &PK;



    file_read_presign(&session);

    // message to sign
    char m[2000];
    octet MSG = {0,sizeof(m),m};

    OCT_jstring(&MSG,"test message");
    printf("M: ");
    OCT_output(&MSG);

    printf("\nmsg=");
    OCT_output(&MSG);

    session.msg = &MSG;

    char round1_r[t][EGS_SECP256K1];
    char round1_sigma[t][EGS_SECP256K1];
    char round1_sigma_out[t][EGS_SECP256K1];

    octet ROUND1_r[t];
    octet ROUND1_sigma[t];
    octet ROUND1_sigma_out[t];

    init_octets((char *)round1_r, ROUND1_r, EGS_SECP256K1, t);
    init_octets((char *)round1_sigma, ROUND1_sigma, EGS_SECP256K1, t);
    init_octets((char *)round1_sigma_out, ROUND1_sigma_out, EGS_SECP256K1, t);

    CG21_SIGN_ROUND1_STORE r1store[t];
    CG21_SIGN_ROUND1_OUTPUT r1out[t];

    for (int i=0; i < t; i++) {
        r1store[i].sigma = ROUND1_sigma + i;
        r1store[i].r = ROUND1_r + i;

        r1out[i].sigma = ROUND1_sigma_out + i;
    }

    session.r1store = r1store;
    session.r1out = r1out;

    cg21_sign_round1(&session);

    char round2_r[t][EGS_SECP256K1];
    char round2_sigma[t][EGS_SECP256K1];

    octet ROUND2_r[t];
    octet ROUND2_sigma[t];

    init_octets((char *)round2_r, ROUND2_r, EGS_SECP256K1, t);
    init_octets((char *)round2_sigma, ROUND2_sigma, EGS_SECP256K1, t);

    CG21_SIGN_ROUND2_OUTPUT r2out[t];
    for (int i=0; i < t; i++) {
        r2out[i].sigma = ROUND2_sigma + i;
        r2out[i].r = ROUND2_r + i;
    }

    session.r2out = r2out;
    cg21_sign_round2(&session);

    cg21_sign_validation(&session);

    exit(0);
}