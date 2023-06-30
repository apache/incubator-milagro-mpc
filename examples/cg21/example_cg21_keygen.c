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

    This example is for the implementation of CG21:KeyGen.
    Visit https://dl.acm.org/doi/abs/10.1145/3372297.3423367, page:1779, figure:4

    Note: We use SSS to convert original CG21:KeyGen from (n,n) to (t,n) threshold setting

 */

#include <stdlib.h>
#include <amcl/amcl.h>
#include "amcl/cg21/cg21.h"
#include <amcl/ecdh_SECP256K1.h>
#include <amcl/randapi.h>
#include "amcl/schnorr.h"

bool Debug = false;

typedef struct
{
    int t;
    int n;
    octet *P;

} CG21_NETWORK;

typedef struct
{
    octet *ID;
    CG21_NETWORK *party;
    CG21_KEYGEN_ROUND1_STORE_PRIV *round1_store_priv;
    CG21_KEYGEN_ROUND1_STORE_PUB *round1_store_pub;
    CG21_KEYGEN_ROUND1_output *round1_output;
    CG21_KEYGEN_ROUND2 *round2;
    CG21_KEYGEN_ROUND3_STORE *round3Store;
    CG21_KEYGEN_ROUND3_OUTPUT *round3Output;
    CG21_KEYGEN_OUTPUT *output;
    CG21_KEYGEN_SID *sid;

} CG21_KEYGEN_SESSION;

void init_octets(char* mem, octet *OCTETS, int max, int n)
{
    for (int i = 0; i < n; i++)
    {
        OCTETS[i].val = mem + (i*max);
        OCTETS[i].len = 0;
        OCTETS[i].max = max;
    }
}

int key_generation_round1(csprng *RNG, CG21_NETWORK *p, CG21_KEYGEN_SESSION *s) {

    int n;
    n = p->n;

    for (int i = 0; i < n; i++)
    {
        int rc = CG21_KEY_GENERATE_ROUND1(RNG, s->round1_store_priv + i,
                                          s->round1_store_pub + i,
                                          s->round1_output + i,
                                          s->sid+i,
                                          i+1, p->n, p->t, p->P);
        if (rc != CG21_OK)
        {
            return rc;
        }
        printf("\t[Player %d] Generates CG21 KeyGen-Round1: Done\n", i+1);
    }
    return CG21_OK;
}

void print_r3(const CG21_KEYGEN_ROUND1_STORE_PUB *r3, int n){
    printf("******* R3 ***********:\n");
    for (int i=0; i<n-1; i++ ){
        printf("A:");
        OCT_output(r3->A+i);

        printf("u:");
        OCT_output(r3->u+i);

        printf("rid:");
        OCT_output(r3->rid+i);

        printf("X:");
        OCT_output(r3->X+i);

        printf("j:%d",r3->i+i);
    }
}

int key_generation_round3(const CG21_NETWORK *p, CG21_KEYGEN_SESSION *s){
    int n;
    n = p->n;

    if (Debug) {
        for (int i = 0; i < n; i++) {
            printf("checks-R3:\n");
            for (int j = 0; j < n-1; j++) {
                printf("X=");
                OCT_output(&s->round1_store_priv[i].shares.X[j]);
                printf("Y=");
                OCT_output(&s->round1_store_priv[i].shares.Y[j]);
            }
            printf("\n");
        }
    }

    // each node checks X_j == VSS_j(v_0)
    // ... checks the given shares are for him
    // ... verifies H(sid,j,rid_j,X_j,A_j,u_j)=V_j
    for (int i=0; i<n; i++) {
        for (int j = 0; j < n; j++) {

            if (i==j){
                continue;
            }

            // this share is received in a secure way from the party with ID=j
            SSS_shares shares;
            shares.X = s->round1_store_priv[j].shares.X + i;
            shares.Y = s->round1_store_priv[j].shares.Y + i;

            int rc = CG21_KEY_GENERATE_ROUND3_1(s->round1_output + j,
                                                s->round1_store_pub + j,
                                                s->round1_store_priv + i,
                                                &shares,
                                                s->sid+i,
                                                s->round3Store + i);
            if (rc != CG21_OK)
                return rc;
        }

        printf("\n\tPlayer %d verified all V_j", i+1);
    }

    for (int i=0; i<n; i++) {
        CG21_KEY_GENERATE_ROUND3_2_1(s->round1_store_pub + i,
                                     s->round3Store + i,
                                     true);
        for (int j = 0; j < n ; j++) {

            if (i==j){
                continue;
            }
            // Player i xor rid_i
            CG21_KEY_GENERATE_ROUND3_2_1(s->round1_store_pub + j,
                                         s->round3Store + i,
                                         false);
        }

        // generates (psi, A)
        CG21_KEY_GENERATE_ROUND3_2_2(s->round1_store_priv + i,
                                     s->round1_store_pub + i,
                                     s->round3Store + i,
                                     s->sid+i,
                                     s->round3Output + i);

        // generates (psi', A')
        CG21_KEY_GENERATE_ROUND3_2_3(s->round1_store_priv + i,
                                     s->round1_store_pub + i,
                                     s->round3Store + i,
                                     s->sid+i,
                                     s->round3Output + i);

        if (Debug){
            printf("For Player %d\n", i+1);
            printf("\t(SKX, SKY):\n");
            printf("\t\t");
            OCT_output((s->round3Store + i)->xi.X);
            printf("\t\t");
            OCT_output((s->round3Store + i)->xi.Y);

            printf("\n\t⊕rid:");
            OCT_output((s->round3Store + i)->xor_rid);
            printf("\tpsi_ui: ");
            OCT_output((s->round3Output+i)->ui_proof.psi);
            printf("\tA_ui:   ");
            OCT_output((s->round3Output+i)->ui_proof.A);
            printf("\tpsi_xi: ");
            OCT_output((s->round3Output+i)->xi_proof.psi);
            printf("\tA_xi:   ");
            OCT_output((s->round3Output+i)->xi_proof.A);
        }
    }

    return CG21_OK;
}

int key_generation_final(const CG21_NETWORK *p, CG21_KEYGEN_SESSION *s){
    int n;
    n = p->n;

    // each node verifies the Schnorr proofs of the other nodes
    for (int i=0; i<n; i++){
        for (int j=0; j<n; j++) {
            if (i==j){
                continue;
            }
            int rc1 = CG21_KEY_GENERATE_OUTPUT_1_1(s->round3Output + j,
                                                   s->round1_store_pub + j,
                                                   s->sid+i,
                                                   s->round3Store + i);
            if (rc1) {
                printf("CG21_KEY_GENERATE_OUTPUT_1_1 FAILED!, %d\n", rc1);
                exit(EXIT_FAILURE);
            }

            int rc2 = CG21_KEY_GENERATE_OUTPUT_1_2(s->output+i,
                                                   s->round3Output + j,
                                                   s->round3Store + i,
                                                   &s->round1_store_priv[i],
                                                   s->sid+i,
                                                   s->round1_store_pub+j);
            if (rc2){
                printf("CG21_KEY_GENERATE_OUTPUT_1_2 FAILED!, %d\n", rc2);
                exit(EXIT_FAILURE);
            }
        }

        printf("\n\tPlayer %d verified all Schnorr proofs.", i+1);
    }

    // each node stores X = (X1, ... , Xn)
    printf("\n");
    for (int i=0; i<n; i++){
        CG21_KEY_GENERATE_OUTPUT_2(s->output+i, s->round1_store_pub+i,  true);

        for (int j=0; j<n; j++){
            if(i==j){
                continue;
            }
            CG21_KEY_GENERATE_OUTPUT_2(s->output+i, s->round1_store_pub + j, false);
        }

        if (Debug){
            printf("\n packed X=");
            OCT_output((s->output+i)->X_set_packed);

            printf("\n packed j=");
            OCT_output((s->output+i)->j_set_packed);
            printf("\n===========================");
        }
    }

    // computes PK = \prod PK_i
    for (int i=0; i<n; i++){
        int rc = CG21_KEY_GENERATE_OUTPUT_3(s->output+i,n);
        if (rc){
            printf("CG21_KEY_GENERATE_OUTPUT_3 FAILED!, %d\n", rc);
            exit(EXIT_FAILURE);
        }
    }

    printf("\n\tPlayers generated Public Key X\n");
    return CG21_OK;
}

void validation(const CG21_NETWORK *p, const CG21_KEYGEN_SESSION *s){

    printf("\n\n----------- VALIDATION -----------");
    /*
     * 1- First we add up all the x_i to get skx
     */

    int n;
    int t;
    n = p->n;
    t = p->t;

    char x[t][SGS_SECP256K1];
    octet X[t];
    char y[t][SGS_SECP256K1];
    octet Y[t];

    for(int i = 0; i < t; i++)
    {
        Y[i].max = SGS_SECP256K1;
        Y[i].len = SGS_SECP256K1;
        Y[i].val = y[i];

        X[i].max = SGS_SECP256K1;
        X[i].len = SGS_SECP256K1;
        X[i].val = x[i];
    }

    SSS_shares shares = {X, Y};

    BIG_256_56 skx;
    BIG_256_56 h;
    BIG_256_56 q;
    ECP_SECP256K1 G;

    char pk[EFS_SECP256K1 + 1];
    octet Golden_PK = {0, sizeof(pk), pk};

    char ss1[EGS_SECP256K1];
    octet Golden_SK = {0,sizeof(ss1),ss1};

    char ss[EGS_SECP256K1];
    octet S = {0,sizeof(ss),ss};

    ECP_SECP256K1_generator(&G);
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    // skx = sum{x_i}
    BIG_256_56_fromBytesLen(skx, s->round1_store_priv->x->val, s->round1_store_priv->x->len);
    for (int i=1; i<n; i++){
        BIG_256_56_fromBytesLen(h, (s->round1_store_priv + i)->x->val, (s->round1_store_priv + i)->x->len);

        BIG_256_56_add(skx, skx, h);
        BIG_256_56_mod(skx, q);
    }

    // compute PK = skx*G
    ECP_SECP256K1_mul(&G, skx);
    ECP_SECP256K1_toOctet(&Golden_PK, &G, true);


    for (int i=0;i<n;i++){
        int rc = OCT_comp(&Golden_PK, (s->output+i)->X);
        if (rc==0){
            printf("\nECDSA PK:\tINVALID for Player %d!",i+1);
            exit(1);
        }
        else{
            printf("\nECDSA PK:\tvalid for Player %d",i+1);
        }
    }

    printf("\n");

    Golden_SK.len = EGS_SECP256K1;
    BIG_256_56_toBytes(Golden_SK.val, skx);

    for (int j=0;j<n-t+1;j++){
        int c=0;
        for (int i=j;i<j+t;i++){
            OCT_copy(&shares.X[c], (s->round3Store + i)->xi.X);
            OCT_copy(&shares.Y[c], (s->round3Store + i)->xi.Y);
            c++;
        }
        SSS_recover_secret(t, &shares, &S);

        int rc = OCT_comp(&Golden_SK, &S);
        if (rc==0){
            printf("\nECDSA shares:\tINVALID for players (%d, ..., %d)!",j, j+t-1);
            exit(1);
        }
        else{
            printf("\nECDSA shares:\tSK recovered from players (%d, ..., %d) successfully",j, j+t-1);
        }
    }

}

void Store_CSV_OCT_Helper(FILE *fpt, const octet * oct){
    unsigned char ch;
    for (int i=0; i<oct->len; i++)
    {
        ch=oct->val[i];
        fprintf(fpt,"%02x",ch);
    }
}

void Store_CSV(const CG21_NETWORK *p, CG21_KEYGEN_SESSION *s){
    FILE *fpt;
    fpt = fopen("cg21_keygen.csv", "w+");
    fprintf(fpt,"%d,%d", p->t, p->n);
    fprintf(fpt,"\n");
    Store_CSV_OCT_Helper(fpt, (s->output+0)->X);
    fprintf(fpt,",");
    Store_CSV_OCT_Helper(fpt, (s->round3Store)->xor_rid);

    for (int i=0;i<p->n;i++){
        fprintf(fpt,"\n");
        Store_CSV_OCT_Helper(fpt, (s->round3Store + i)->xi.X);
        fprintf(fpt,",");
        Store_CSV_OCT_Helper(fpt, (s->round3Store + i)->xi.Y);
        fprintf(fpt,",");
        Store_CSV_OCT_Helper(fpt, (s->output+i)->X_set_packed);
        fprintf(fpt,",");
        Store_CSV_OCT_Helper(fpt, (s->output+i)->j_set_packed);
        fprintf(fpt,",");
        Store_CSV_OCT_Helper(fpt, (s->output+i)->pk_ss_sum_pack);
    }

    if (fpt){
        fclose(fpt);
    }
}


void usage(char *name)
{
    printf("Usage: %s t n\n", name);
    printf("Run a (t, n) keygen \n");
    printf("\n");
    printf("  t  Threshold for the TSS protocol. t <= n\n");
    printf("  n  Number of participants in the TSS protocol. t <= n, n>1\n");
    printf("\n");
    printf("Example:\n");
    printf("  %s 2 3\n", name);
}

int main(int argc, char *argv[]) {
    int i;
    int t;
    int n;
    int rc;

    /* Read arguments */
    if (argc != 3) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    t = atoi(argv[1]); // t is the threshold
    n = atoi(argv[2]); // n is the total number of the nodes

    if (t < 1 || n < 2 || t > n) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

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

    CG21_KEYGEN_SESSION s;

    printf("CG21:KeyGen example\n\n");

    char m[2000];
    octet P = {0,sizeof(m),m};

    OCT_jstring(&P,"000100020003");
    printf("P: ");
    OCT_output_string(&P);


    // KeyGen Round 1
    printf("\n-----------------------\n");
    printf("ROUND 1:\n");
    char player_uid[n][iLEN];
    char round1_x[n][EGS_SECP256K1];
    char round1_X[n][EFS_SECP256K1 + 1];
    char round1_A[n][SFS_SECP256K1 + 1];
    char round1_tau[n][EGS_SECP256K1];
    char round1_A2[n][SFS_SECP256K1 + 1];
    char round1_tau2[n][EGS_SECP256K1];
    char round1_rid[n][EGS_SECP256K1];
    char round1_u[n][EGS_SECP256K1];
    char round1_V[n][SHA256];
    char round1_shares_x[n][n][EGS_SECP256K1];
    char round1_shares_y[n][n][EGS_SECP256K1];
    char round1_checks[n][t][EFS_SECP256K1 + 1];
    char round1_packed_checks[n][t*(EFS_SECP256K1 + 1)];    // VSS: checks
    char round1_order[n][EFS_SECP256K1];
    char round1_generator[n][EFS_SECP256K1 + 1];
    char round1_P_packed[n][n * 4 + 1];

    octet PLAYER_UID[n];
    octet ROUND1_x[n];
    octet ROUND1_X[n];
    octet ROUND1_A[n];
    octet ROUND1_tau[n];
    octet ROUND1_A2[n];
    octet ROUND1_tau2[n];
    octet ROUND1_rid[n];
    octet ROUND1_u[n];
    octet ROUND1_V[n];
    octet ROUND1_checks[n * t];
    octet ROUND1_packed_checks[n];
    octet ROUND1_shares_X[n * n];
    octet ROUND1_shares_Y[n * n];
    octet ROUND1_ORDER[n];
    octet ROUND1_GENERATOR[n];
    octet ROUND1_P_PACKED[n];

    init_octets((char *) round1_x, ROUND1_x, EGS_SECP256K1, n);
    init_octets((char *) round1_X, ROUND1_X, EFS_SECP256K1 + 1, n);
    init_octets((char *) round1_A, ROUND1_A, SFS_SECP256K1 + 1, n);
    init_octets((char *) round1_tau, ROUND1_tau, EGS_SECP256K1, n);
    init_octets((char *) round1_A2, ROUND1_A2, SFS_SECP256K1 + 1, n);
    init_octets((char *) round1_tau2, ROUND1_tau2, EGS_SECP256K1, n);
    init_octets((char *) round1_rid, ROUND1_rid, EGS_SECP256K1, n);
    init_octets((char *) round1_u, ROUND1_u, EGS_SECP256K1, n);
    init_octets((char *) round1_V, ROUND1_V, SHA256, n);
    init_octets((char *)round1_shares_x, ROUND1_shares_X, EGS_SECP256K1,     n * n);
    init_octets((char *)round1_shares_y, ROUND1_shares_Y, EGS_SECP256K1,     n * n);
    init_octets((char *)round1_checks,   ROUND1_checks,   EFS_SECP256K1 + 1, n * t);
    init_octets((char *)round1_packed_checks,   ROUND1_packed_checks,   t*(EFS_SECP256K1 + 1), n);
    init_octets((char *) round1_order, ROUND1_ORDER, EFS_SECP256K1, n);
    init_octets((char *) round1_generator, ROUND1_GENERATOR, EFS_SECP256K1 + 1, n);
    init_octets((char *) round1_P_packed, ROUND1_P_PACKED, n * 4 + 1, n);
    init_octets((char *) player_uid, PLAYER_UID, iLEN, n);

    CG21_KEYGEN_ROUND1_STORE_PRIV r1_store_priv[n];
    CG21_KEYGEN_ROUND1_STORE_PUB r1_store_pub[n];
    CG21_KEYGEN_ROUND1_output r1_output[n];
    CG21_KEYGEN_SID sid[n];

    char id[iLEN];
    octet ID = {0, sizeof(id), id};
    OCT_rand(&ID, &RNG, iLEN);

    for (i = 0; i < n; i++) {
        r1_store_priv[i].x = ROUND1_x + i;
        r1_store_pub[i].X = ROUND1_X + i;
        r1_store_pub[i].A = ROUND1_A + i;
        r1_store_priv[i].tau = ROUND1_tau + i;
        r1_store_pub[i].A2 = ROUND1_A2 + i;
        r1_store_priv[i].tau2 = ROUND1_tau2 + i;
        r1_store_pub[i].rid = ROUND1_rid + i;
        r1_store_pub[i].u = ROUND1_u + i;
        r1_store_priv[i].shares.X = ROUND1_shares_X + (n * i);
        r1_store_priv[i].shares.Y = ROUND1_shares_Y + (n * i);
        r1_store_pub[i].packed_checks = ROUND1_packed_checks + i;

        r1_output[i].V = ROUND1_V + i;
        sid[i].g = ROUND1_GENERATOR + i;
        sid[i].q = ROUND1_ORDER + i;
        sid[i].P = ROUND1_P_PACKED + i;
        sid[i].uid = PLAYER_UID + i;

        // players should have same session ID for sigma protocols
        OCT_copy(sid[i].uid, &ID);
    }

    s.round1_store_priv = r1_store_priv;
    s.round1_store_pub = r1_store_pub;
    s.round1_output = r1_output;
    s.sid = sid;
    CG21_NETWORK p ;
    p.t = t;
    p.n = n;
    p.P = &P;

    rc = key_generation_round1(&RNG, &p, &s);
    if (rc != CG21_OK) {
        exit(EXIT_FAILURE);
    }
    printf("\n\tNodes broadcast (sid,i,V_i)\n");

    if (Debug){
        for (i = 0; i < n; i++) {
            printf("[Player %d]\n", i);
            printf("\ti%d  : ",s.round1_store_priv[i].i);
            printf("\tV  : ");
            OCT_output(s.round1_output[i].V);
            printf("\tA: ");
            OCT_output(s.round1_store_pub[i].A);
        }
    }

    // KeyGen Round 3
    printf("-----------------------\n");
    printf("ROUND 3:\n");
    char round3_xor_rid[n][EGS_SECP256K1];
    char round3_psi_ui[n][SGS_SECP256K1];
    char round3_A_ui[n][SFS_SECP256K1 + 1];
    char round3_psi_xi[n][SGS_SECP256K1];
    char round3_A_xi[n][SFS_SECP256K1 + 1];
    char round3_shares_packed_y[n][(n-1)*EGS_SECP256K1];
    char round3_double_pack[n][n * t * (EFS_SECP256K1 + 1)];    // VSS: checks

    char round3_sk_x[n][EGS_SECP256K1];
    char round3_sk_y[n][EGS_SECP256K1];

    octet ROUND3_xor_rid[n];
    octet ROUND3_psi_ui[n];
    octet ROUND3_A_ui[n];
    octet ROUND3_psi_xi[n];
    octet ROUND3_A_xi[n];
    octet ROUND3_double_pack[n];
    octet ROUND3_share_packed_Y[n];
    octet ROUND3_sk_X[n];
    octet ROUND3_sk_Y[n];

    init_octets((char *)round3_xor_rid,  ROUND3_xor_rid,  EGS_SECP256K1, n);
    init_octets((char *)round3_psi_ui, ROUND3_psi_ui, SGS_SECP256K1, n);
    init_octets((char *)round3_A_ui, ROUND3_A_ui, SFS_SECP256K1 + 1, n);
    init_octets((char *)round3_psi_xi, ROUND3_psi_xi, SGS_SECP256K1, n);
    init_octets((char *)round3_A_xi, ROUND3_A_xi, SFS_SECP256K1 + 1, n);
    init_octets((char *)round3_shares_packed_y, ROUND3_share_packed_Y, (n-1)*EGS_SECP256K1,     n);

    init_octets((char *)round3_sk_x, ROUND3_sk_X, EGS_SECP256K1, n);
    init_octets((char *)round3_sk_y, ROUND3_sk_Y, EGS_SECP256K1, n);
    init_octets((char *)round3_double_pack, ROUND3_double_pack, n * t * (EFS_SECP256K1 + 1), n);

    CG21_KEYGEN_ROUND3_STORE r3[n];
    CG21_KEYGEN_ROUND3_OUTPUT r3o[n];
    for (i = 0; i < n; i++)
    {

        r3[i].xor_rid = ROUND3_xor_rid + i;
        r3[i].packed_share_Y = ROUND3_share_packed_Y + i;
        r3[i].packed_all_checks = ROUND3_double_pack + i;
        r3[i].xi.X = ROUND3_sk_X + i;
        r3[i].xi.Y = ROUND3_sk_Y + i;

        r3o[i].ui_proof.psi = ROUND3_psi_ui + i;
        r3o[i].ui_proof.A = ROUND3_A_ui + i;
        r3o[i].xi_proof.psi = ROUND3_psi_xi + i;
        r3o[i].xi_proof.A = ROUND3_A_xi + i;
    }
    s.round3Store = r3;
    s.round3Output = r3o;
    rc = key_generation_round3(&p, &s);
    if (rc!=CG21_OK){
        printf("KeyGen R3 Failed: %d", rc);
        return rc;
    }

    if (Debug)
    {
        for (i = 0; i < n; i++) {
            print_r3(s.round1_store_pub + i, n);
        }
    }

    printf("\n\tNodes broadcast (sid,i,psi_i)\n");

    // KeyGen r1_output
    printf("-----------------------\n");
    printf("FINAL ROUND:\n");
    char round4_X[n][EFS_SECP256K1 + 1];
    char round4_i_packed[n][n * 4 + 1];
    char round4_X_set_packed[n][n * (EFS_SECP256K1 + 1)];
    char round4_pk_ss_sum_pack[n][(n - 1)*(SFS_SECP256K1 + 1)];

    octet ROUND4_X[n];
    octet ROUND4_i_PACKED[n];
    octet ROUND4_X_SET_PACKED[n];
    octet ROUND4_PK_SS_SUM_PACK[n];

    init_octets((char *)round4_X,  ROUND4_X,  EFS_SECP256K1 + 1, n);
    init_octets((char *)round4_i_packed, ROUND4_i_PACKED, (n * 4 + 1), n);
    init_octets((char *)round4_X_set_packed, ROUND4_X_SET_PACKED, n * (EFS_SECP256K1 + 1), n);
    init_octets((char *)round4_pk_ss_sum_pack, ROUND4_PK_SS_SUM_PACK, (n - 1)*(SFS_SECP256K1 + 1), n );

    CG21_KEYGEN_OUTPUT output[n];

    for (i = 0; i < n; i++)
    {
        output[i].X = ROUND4_X + i;
        output[i].j_set_packed = ROUND4_i_PACKED + i;
        output[i].X_set_packed = ROUND4_X_SET_PACKED + i;
        output[i].pk_ss_sum_pack = ROUND4_PK_SS_SUM_PACK + i;
    }
    s.output = output;
    key_generation_final(&p, &s);

    // verify parameters (only for testing the code)
    validation(&p, &s);
    Store_CSV(&p, &s);
    printf("\n\nParams are stored successfully!");
    printf("\n\nCG21:KeyGen is done successfully!\n");

    return CG21_OK;
}