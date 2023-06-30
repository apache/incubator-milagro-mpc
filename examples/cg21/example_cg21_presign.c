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
#include "amcl/cg21/cg21_rp_pi_enc.h"
#include "amcl/cg21/cg21_rp_pi_logstar.h"
#include "amcl/cg21/cg21_rp_pi_affg.h"

bool Debug = false;

char *PT_hex[8] = {"f592ad30c88d719fd272095257c90395d16f6c613a3ccf1b556646a99c316275ce6bf0565f1f28e705342158c79e0d5614bcfeec3b02d60eb5bd490b930b04c64103b2b0257d73156715012c77f43872024488297b1f03d521200ffadeb3f85e86378837ed34c366b5f58e8dd042e320381d765a871f963f80fc4ac4bb4c096f",
                   "C6C646679CD5B694841621AAD2FE7840E39B777C0BDEB36597594DA4FA0F07E4FC0B8E719F05203850FF8540A62394A8984E880C3AD0A407736BFE4631D7C501C43EB2463629CDF897BDA60664660FC5209BF73C6A33EF1FD2995C830C8A10339A5ED90EFD0698D470659C244CC927AAB4CD7D1F4D616A135EF250E9BB119673",
                   "c883b3abc4b6dd37e41d7bcf2b326442a58a874089691af7dd5a4a039f30551b2b2c11aa1a0dd0cfdc66d5a1ed311d6e331599faec066af94f65ebbdc7b1c9813da0216de612e340a7381a6b73d692bdb093f307fc904b0a44b63b478a88454c05730ba2ea071006ab4132bdfc3bc94994f8958636e7e7a1564117cc543043bb",
                   "ccb0d6ca8525fe14d283a29b4a673ef0b5dae276ff60dc346cb28a83144b3f2f788f7876e817e58eb2944f51cc4b15a815b30f8dfffacf2cac2ddab94a2ff5ac0e14adc2f56ec6bb9bcb66988c165ecb530bd7abc8c7068be9fbc66d53cbd6f42f07b4accab7019d09ec73286d2406d10748209cc0bb1b2d03da14cc7cb7ebdb",
                   "d4bb5a43bc21ea77eab86aca9636d4e7c0d2596d8bc3a00c1ae26a3e442fa2530fbdb8f93e2fd14fa8e26809e5d27b193cdb092fc1c287aba9d132f54764cd95abc77c6e007cc588022a3ff4910ca54f8ea23e836bf6baaec3b701bb0a1a68a3f2af825971f70f347ea260e6e3bd9cf922229f6c366a4c0e113a4f5f45bfb54f",
                   "E0EA3822BFB63CBB3F13679A76A840D5B8D6215DFC3842B679B0E66DFC86D6C0F0F70017035C4E2E4A155E87C72FF9CB55C38680BF9F9D7A5DCB6F01717CDD37705385D2DD6F1A2EF4E47E8B568787EF2C7589ABBFE5FFF2D9AF66720B5CF31B0E2940B9C2FDECFC703FA55D50F2BB499F51BA92E9A71607FBA7E36F10D57387",
                   "FE67C9CECC8E485BB74D130404526F2018589A079A71D73B04B39C38B157E8CA999BDAB1F191918271BEF937A6DA4BA94F40BC9A6A91FD53E57B2494FE2042798D8D929F95689C181E723C45222A8E18DB9CF05A3BF960FBDE98C9518C08D90D553052DBEF7121E0C8CEEAB9E4F6897AB0BA9A7B47183C6E8B0294B637CE6723",
                   "FE49BB949B4DD772CC62F459370BF5141D44EFFC403C90E5CAA3B0A9ADAB18991E7D653B6D05DA42CAC9A0CC9329951B213977C8576AA711EC1E8F80B49D4ED59404DF46EC04ABE1631E70F4DCCB1A9A01F44969A7845183F705D6395A32FFDFA9BD98E0FF4ECB694C22BBE2A1D58650C9F5A920E5AFA35453F5D71A5CE2CC4F"};



char *QT_hex[8] = {"c49346cef2c4249b7df76b93191e916db4582549697a526a6aa0094c09d83dc71be94598e64fba8e34f3b27c3a40090be0a44e1818b14c5513e0b9d9cdc9bb19398a29725fa851b08addaacb430ebe55128f6c43d611d2a35ddb7e7fba5edae177c9de0271912110709125ce18dd403be71ce96784ec856115e2fc4462ccd5d5",
                   "B6A1CED9AD6A84F36615652BB7794062911DFF67275F58F2F6C64356ABE8C1BBD4DB522C544071F15DC1704D0278731F2519EDD143B6F4065250CCB5625888DF1747470A83E515A7B3CCB71D20E661799C5CA21599EEF104989A5DC4399983FCD6ABD2B27802B1B790EEB0DBB8786167B5B41EB9D1EC65F3B4CE0F8129CC0635",
                   "ff095fd68d025eb5051e4d06c3b581ce23cd599013bdb9485b3775df8f4af936b6b60906269f48380f71fa49eb04970ab15e4d5ed2b1bbcfc1c2b5f8ed1ee5bee8a8d791dbe3e420f672aeb5d830c632ddc02de95b042ea943341ed73bab492ca32f1ba4c0cdace982e8c1c249e5c92a39e272b79eb09caf294fee74a42a330f",
                   "e93b9900d422108975781193a0b52bd466ed584946251148a37d952df2da8d6366869823aff52b7435ade7ac8a21424db364a63fb2a04375361fe145d3f57cf43fa1cc1b6f52f58ad10ec8f0a9de8bf20a4bb4bcdb82a41eb07e2f1265ebb5d0d490e606dff1a2f5c09fbf3aa68ee4bcc1cb7291ddfad691a27ff277e6126c7b",
                   "e15a6a18a7b6bf0893c00526202ea5fcb7cde901f780406ea78ca951459ce3130fd65687badb4a8e41bbe676c672ff7b5914ca983bf0937fe5f423f2e655b144302a3ae17d2a3f1ef9d779baac67939924ba1a0210d37bc2badb90c76d38daa74704eb93cec5588f2452b9829511332cc7e5933e08392839b79a8cd8336948ab",
                   "E139D2FBEEDA6AD968E7423306E001A44DF2EF945E3A6FBA078A8D210C8259C7E5C23BE3B66B335F9332EBB72E72981F6CB82AEE6C2BC0F8667ED1CB7DE10B92148CE23B3A0E516690B600758C1355AD0DB55DD87506A41EEC609CF72FD11B125E47012674CAB2EE0A46E620B70DD69E5E27838442EA0FC547DBB95AD147A9A5",
                   "CD47D116CEB853057CAE356305FED20E2D551A5D91FB0EDA0042137C5099A16518899B7E3969952C8BBC369FBE0E9FD79B03BAE053FC09A13B340D4E894700604470F9B0F013F5B837202083C595A77B7A85CB12FD2AA33148CC209F8102C04F7A79D5630D5DA3B47D9C13DE68BB7F529DB6F550828054211162E84EA45612CD",
                   "D3D77DD5E850B2041AC5EC7B690E220823D295353E93C715ECEA21EB0C9E62D33D40E18353AAFB4DC986C435C33777FE03D81592F61EC7614681EE0A11E30978ECA9AA58F328FD2EEEB6738251BA5BB53F0AFD22E6AE700C2B111DDE4DF6850C6E0F0A44E1FEED3C9FA3347C9D46F0F6181785DF61193F1109D8BB0E385880E9"};


typedef struct
{
    octet *rid;
    octet *i;  // i also represent Xi
    octet *Yi;
    octet *X_packed;
    octet *j_packed;
    octet *PK;

} CG21_KEYGEN_DATA;

typedef struct
{
    csprng *RNG;
    CG21_PRESIGN_ROUND1_STORE *r1Store;
    CG21_PRESIGN_ROUND1_OUTPUT *r1out;
    CG21_PRESIGN_ROUND2_STORE *r2Store;
    CG21_PRESIGN_ROUND2_OUTPUT *r2out;
    CG21_PRESIGN_ROUND3_STORE_1 *r3Store1;
    CG21_PRESIGN_ROUND3_STORE_2 *r3Store2;
    CG21_PRESIGN_ROUND3_OUTPUT *r3out;
    CG21_PRESIGN_ROUND4_STORE_1 *r4Store1;
    CG21_PRESIGN_ROUND4_STORE_2 *r4Store2;
    CG21_PRESIGN_ROUND4_OUTPUT *r4out;
    CG21_RESHARE_OUTPUT *reshareOutput;
    CG21_AUX_OUTPUT *auxOutput;
    CG21_PAILLIER_KEYS *paillierKeys;
    CG21_PEDERSEN_KEYS *pedersenKeys;
    CG21_RESHARE_SETTING *setting;
    CG21_SSID *ssid;

    // Pi-Enc
    PiEnc_COMMITS_OCT *PiEncCommitOct;
    PiEnc_PROOFS_OCT *PiEncProofOct;
    PiEnc_COMMITS *PiEncCommit;
    PiEnc_PROOFS *PiEnc_proof;

    // Pi-LogStar
    PiLogstar_COMMITS_OCT *PiLogCommitOct1;
    PiLogstar_PROOFS_OCT *PiLogProofOct1;
    PiLogstar_COMMITS *PiLogCommit1;
    PiLogstar_PROOFS *PiLogProof1;

    // Pi-LogStar
    PiLogstar_COMMITS_OCT *PiLogCommitOct2;
    PiLogstar_PROOFS_OCT *PiLogProofOct2;
    PiLogstar_COMMITS *PiLogCommit2;
    PiLogstar_PROOFS *PiLogProof2;

    //Pi-AffG-1
    Piaffg_COMMITS *PiAffgCommit1;
    Piaffg_PROOFS *PiAffgProof1;
    Piaffg_PROOFS_OCT *PiAffgProofOct1;
    Piaffg_COMMITS_OCT *PiAffgCommitOct1;

    //Pi-AffG-2
    Piaffg_COMMITS *PiAffgCommit2;
    Piaffg_PROOFS *PiAffgProof2;
    Piaffg_PROOFS_OCT *PiAffgProofOct2;
    Piaffg_COMMITS_OCT *PiAffgCommitOct2;

} CG21_PRESIGN_SESSION;

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
    FILE *file = fopen("cg21_reshare.csv", "r");
    if (file == NULL) {
        printf("Error: could not open file.\n");
        return 1;
    }

    char line[2048];
    if (fgets(line, 10, file)==NULL){
        exit(1);
    }

    const char *t1_ = strtok(line, ",");
    char *endptr;
    long lnum_ = strtol(t1_, &endptr, 10);
    int t_ = (int)lnum_;

    if (fgets(line, 10, file)==NULL){
        exit(1);
    }

    const char *t1 = strtok(line, ",");
    long lnum = strtol(t1, &endptr, 10);
    int t = (int)lnum;

    const char *n1 = strtok(NULL, ",");
    lnum = strtol(n1, &endptr, 10);
    int n = (int)lnum;

    setting->t1 = t_;
    setting->t2 = t;
    setting->n2 = n;

    printf("\n%d, (%d,%d)",setting->t1,setting->t2,setting->n2);

    if (n>7){
        printf("\nn cannot be greater than 7 in this example!");
        exit(1);
    }

    fclose(file);

    return 0;
}

int file_read_keygen_reshare_aux(const CG21_RESHARE_SETTING *setting, CG21_RESHARE_OUTPUT *keyReshareOutput,
                                 CG21_AUX_OUTPUT *AuxOutput){

    // read key re-sharing output
    FILE *file = fopen("cg21_reshare.csv", "r");
    if (file == NULL) {
        printf("Error: could not open file.\n");
        return 1;
    }

    // skip the first th line
    char line[2048];
    if (fgets(line, 10, file)==NULL){
        exit(1);
    }

    if (fgets(line, 10, file)==NULL){
        exit(1);
    }

    if (fgets(line, 2000, file)==NULL){
        exit(1);
    }

    const char *t3 = strtok(line, ",");
    const char *t3_1 = strtok(NULL, ",");
    const char *t3_2 = strtok(NULL, ",");

    for (int i=0; i<setting->n2; i++) {
        OCT_fromHex(keyReshareOutput[i].pk.X, t3);
        OCT_fromHex(keyReshareOutput[i].rid, t3_1);
        OCT_fromHex(keyReshareOutput[i].rho, t3_2);

        keyReshareOutput[i].n = setting->n2;
        keyReshareOutput[i].t = setting->t2;
        keyReshareOutput[i].myID = i+1;
        keyReshareOutput[i].pk.pack_size = setting->t1;
    }

    for (int i=0; i<setting->n2; i++) {
        if (fgets(line, 2000, file)==NULL){
            exit(1);
        }

        const char *t2 = strtok(line, ",");
        OCT_fromHex(keyReshareOutput[i].shares.X, t2);

        // skip the next parameter in the file
        t2 = strtok(NULL, ",");
        OCT_fromHex(keyReshareOutput[i].shares.Y, t2);

        // load packed set of Xi
        t2 = strtok(NULL, ",");

        // convert packed set of Xi to octet
        OCT_fromHex(keyReshareOutput[i].pk.X_set_packed, t2);

        // load packed j values
        t2 = strtok(NULL, ",");

        // convert the packed j values to octet
        OCT_fromHex(keyReshareOutput[i].pk.j_set_packed, t2);
        keyReshareOutput[i].pk.j_set_packed->len = setting->t2*2;

    }

    char line2[10000];
    // read key Aux. information output
    file = fopen("cg21_aux.csv", "r");
    if (file == NULL) {
        printf("Error: could not open file.\n");
        return 1;
    }
    // skip the first line
    if (fgets(line2, 10, file)==NULL){
        exit(1);
    }

    for (int i=0; i<setting->n2; i++) {
        if (fgets(line2, 10000, file)==NULL){
            exit(1);
        }

        const char *t2 = strtok(line2, ",");
        OCT_fromHex(AuxOutput[i].j, t2);
        AuxOutput[i].j->len = setting->n2*2;

        // skip the next parameter in the file
        t2 = strtok(NULL, ",");
        OCT_fromHex(AuxOutput[i].N, t2);
        AuxOutput[i].N->len = setting->n2*FS_2048;

        // load packed set of Xi
        t2 = strtok(NULL, ",");

        // convert packed set of Xi to octet
        OCT_fromHex(AuxOutput[i].s, t2);
        AuxOutput[i].s->len = setting->n2*FS_2048;

        // load packed j values
        t2 = strtok(NULL, ",");

        // convert the packed j values to octet
        OCT_fromHex(AuxOutput[i].t, t2);
        AuxOutput[i].t->len = setting->n2*FS_2048;

    }

    /* Close the file */
    fclose(file);

    return 0;
}

void CG21_validate_partial_pk_reshare_output(CG21_PRESIGN_SESSION *session){

    for (int i=0; i<session->setting->n2; i++){
        CG21_VALIDATE_PARTIAL_PKS(session->reshareOutput+i);
    }
}

void CG21_presign_round1(CG21_PRESIGN_SESSION *session){


    for (int i=0; i<session->setting->t2; i++) {

            CG21_PRESIGN_ROUND1(session->RNG,
                                &session->reshareOutput[i],
                                session->setting,
                                &session->r1out[i],
                                &session->r1Store[i],
                                &session->paillierKeys[i].paillier_pk);

        if (i>0) {
            // assume only player 1 generates PiEnc proof for the other players

            PiEnc_SECRETS PiEncSecrets;
            PiEnc_Sample_randoms_and_commit(session->RNG, &session->paillierKeys[0].paillier_sk,
                                            &session->pedersenKeys[i].pedersenPub,
                                            session->r1Store[0].k, &PiEncSecrets, &session->PiEncCommit[i],
                                            &session->PiEncCommitOct[i]);

            char e_[MODBYTES_256_56];
            octet e = {0, sizeof(e_), e_};

            PiEnc_Challenge_gen(&session->paillierKeys[0].paillier_pk, &session->pedersenKeys[i].pedersenPub,
                                session->r1out[0].K, &session->PiEncCommit[i], &session->ssid[0], &e);

            PiEnc_Prove(&session->paillierKeys[0].paillier_sk, session->r1Store[0].k,
                        session->r1Store[0].rho, &PiEncSecrets, &e, &session->PiEnc_proof[i],
                        &session->PiEncProofOct[i]);
        }
    }

}

void CG21_presign_round2(CG21_PRESIGN_SESSION *session){

    int t2 = session->setting->t2;

    // ----- PI-ENC PROOF VALIDATION -----
    // other players verify player 1 Pi_enc proof
    for (int i=1; i<session->setting->t2; i++) {

        char e_[MODBYTES_256_56];
        octet e = {0, sizeof(e_), e_};

        PiEnc_Challenge_gen(&session->paillierKeys[0].paillier_pk, &session->pedersenKeys[i].pedersenPub,
                            session->r1out[0].K, &session->PiEncCommit[i], &session->ssid[0], &e);

        int rc = PiEnc_Verify(&session->paillierKeys[0].paillier_pk, &session->pedersenKeys[i].pedersenPriv,
                              session->r1out[0].K, &session->PiEncCommit[i], &e, &session->PiEnc_proof[i]);

        if (rc != PiEnc_OK){
            printf("\npi-enc range proof Failed!");
            exit(rc);
        }
        else{
            printf("\nPlayer %d verified pi-enc range proof from player 1 successfully!", i+1);
        }
    }
    // -------------------------------

    // ----- PRE-SIGN ROUND 2 -----
    for (int i=0; i<t2; i++) {
        for (int j=0; j<t2; j++){
            if (i==j){
                continue;
            }
            CG21_PRESIGN_ROUND2(session->RNG,session->r2out+i*t2+j,session->r2Store+i*t2+j,
                                session->r1out+j,session->r1Store+i,&(session->paillierKeys+j)->paillier_pk,
                                &(session->paillierKeys+i)->paillier_pk);
        }
    }
    // ---------------------------

    // ----- PI-LOGSTAR PROOF GENERATION -----
    // assume only player 1 generates PiLogStar proof for the other players
    for (int i=1; i<session->setting->t2; i++) {

        PiLogstar_SECRETS PiLogSecrets;
        ECP_SECP256K1 G;
        ECP_SECP256K1_generator(&G);
        char t[SFS_SECP256K1 + 1];
        octet g_ = {0, sizeof(t), t};
        ECP_SECP256K1_toOctet(&g_, &G, true);

        ECP_SECP256K1_toOctet(&g_, &G, true);

        int rc = PiLogstar_Sample_and_commit(session->RNG, &session->paillierKeys[0].paillier_sk,
                                    &session->pedersenKeys[i].pedersenPub,session->r1Store[0].gamma, &g_,
                                    &PiLogSecrets, &session->PiLogCommit1[i], &session->PiLogCommitOct1[i]);
        if (rc != PiLogstar_OK){
            printf("PiLogstar_Sample_and_commit failed!, %d", rc);
            exit(rc);
        }

        char e_[MODBYTES_256_56];
        octet e = {0, sizeof(e_), e_};

        PiLogstar_Challenge_gen(&session->paillierKeys[0].paillier_pk, &session->pedersenKeys[i].pedersenPub,
                                session->r1out[0].G, &session->PiLogCommit1[i], (session->ssid + 0), session->r2Store[i].Gamma, &e);

        PiLogstar_Prove(&session->paillierKeys[0].paillier_sk, session->r1Store[0].gamma,
                        session->r1Store[0].nu,&PiLogSecrets, &e, &session->PiLogProof1[i],
                        &session->PiLogProofOct1[i]);

    }
    // -------------------------------

    // ----- PI-AFFG (D, K, F, GAMMA) PROOF GENERATION -----
//     assume only player 0 generates PiAffG-1 proof for player 1
    for (int i=1; i<session->setting->t2; i++) {
        Piaffg_SECRETS PiAffgSecrets;

        int rc = Piaffg_Sample_and_Commit(session->RNG, &session->paillierKeys[0].paillier_sk,
                                          &session->paillierKeys[i].paillier_pk, &session->pedersenKeys[i].pedersenPub,
                                          session->r1Store[0].gamma, session->r2Store[i].beta, &PiAffgSecrets,
                                          &session->PiAffgCommit1[i], &session->PiAffgCommitOct1[i], session->r1out[i].K);

        if (rc != Piaffg_OK){
            printf("PiAffg_Sample_and_Commit failed!, %d", rc);
            exit(rc);
        }

        char e_[MODBYTES_256_56];
        octet e = {0, sizeof(e_), e_};

        Piaffg_Challenge_gen(&session->paillierKeys[i].paillier_pk, &session->paillierKeys[0].paillier_pk,
                             &session->pedersenKeys[i].pedersenPub, session->r2Store[i].Gamma, (session->r2out+i)->F, (session->r1out+i)->K,
                             (session->r2out+i)->D, &session->PiAffgCommit1[i], (session->ssid + 0), &e);

        Piaffg_Prove(&session->paillierKeys[0].paillier_pk, &session->paillierKeys[i].paillier_pk,
                     &PiAffgSecrets, session->r1Store[0].gamma, session->r2Store[i].beta,
                     session->r2Store[i].s, session->r2Store[i].r, &e, &session->PiAffgProof1[i], &session->PiAffgProofOct1[i]);

    }

    // ----- PI-AFFG (D-hat, K, F-hat, X) PROOF GENERATION -----
//     assume only player 0 generates PiAffG-2 proof for player 1
    for (int i=1; i<session->setting->t2; i++) {
        Piaffg_SECRETS PiAffgSecrets;

        int rc = Piaffg_Sample_and_Commit(session->RNG, &session->paillierKeys[0].paillier_sk,
                                          &session->paillierKeys[i].paillier_pk, &session->pedersenKeys[i].pedersenPub,
                                          session->r1Store[0].a, session->r2Store[i].beta_hat, &PiAffgSecrets,
                                          &session->PiAffgCommit2[i], &session->PiAffgCommitOct2[i], session->r1out[i].K);

        if (rc != Piaffg_OK){
            printf("PiAffg_Sample_and_Commit failed!, %d", rc);
            exit(rc);
        }

        char e_[MODBYTES_256_56];
        octet e = {0, sizeof(e_), e_};

        BIG_256_56 s;
        ECP_SECP256K1 G;

        char oct[EFS_SECP256K1 + 1];
        octet X = {0, sizeof(oct), oct};

        // X should be computed here, it's here for simplicity
        ECP_SECP256K1_generator(&G);    // get curve generator
        BIG_256_56_fromBytesLen(s, session->r1Store->a->val, session->r1Store->a->len);   // load gamma into big
        ECP_SECP256K1_mul(&G, s);   // compute gamma*G
        ECP_SECP256K1_toOctet(&X, &G, true); // store gamma*G

        Piaffg_Challenge_gen(&session->paillierKeys[i].paillier_pk, &session->paillierKeys[0].paillier_pk,
                             &session->pedersenKeys[i].pedersenPub, &X, (session->r2out+i)->F_hat, (session->r1out+i)->K,
                             (session->r2out+i)->D_hat, &session->PiAffgCommit2[i], (session->ssid + 0), &e);

        Piaffg_Prove(&session->paillierKeys[0].paillier_pk, &session->paillierKeys[i].paillier_pk,
                     &PiAffgSecrets, session->r1Store[0].a, session->r2Store[i].beta_hat,
                     session->r2Store[i].s_hat, session->r2Store[i].r_hat, &e, &session->PiAffgProof2[i], &session->PiAffgProofOct2[i]);

    }
}


void CG21_presign_round3(CG21_PRESIGN_SESSION *session){

    int t2 = session->setting->t2;

    // other players verify player 1 Pi_LogStar proof
    for (int i=1; i<session->setting->t2; i++) {

        char e_[MODBYTES_256_56];
        octet e = {0, sizeof(e_), e_};

        ECP_SECP256K1 G;
        ECP_SECP256K1_generator(&G);
        char t[SFS_SECP256K1 + 1];
        octet g_ = {0, sizeof(t), t};
        ECP_SECP256K1_toOctet(&g_, &G, true);

        PiLogstar_Challenge_gen(&session->paillierKeys[0].paillier_pk, &session->pedersenKeys[i].pedersenPub,
                                session->r1out[0].G, &session->PiLogCommit1[i], (session->ssid + 0), session->r2Store[i].Gamma, &e);

        int rc = PiLogstar_Verify(&session->paillierKeys[0].paillier_pk, &session->pedersenKeys[i].pedersenPriv,
                                  session->r1out[0].G, &g_, &session->PiLogCommit1[i], session->r2Store[i].Gamma,
                                  &e, &session->PiLogProof1[i]);
        if (rc == PiLogstar_OK)
        {
            printf("\nPlayer %d verified pi-logStar range proof from player 1 successfully!", i+1);
        }
        else
        {
            printf("\npi-logStar-1 range proof Failed!");
            exit(rc);
        }
    }

    // other players verify player 1 Pi_Affg-1 proof
    for (int i=1; i<session->setting->t2; i++) {

        char e2_[MODBYTES_256_56];
        octet e2 = {0, sizeof(e2_), e2_};

        Piaffg_Challenge_gen(&session->paillierKeys[i].paillier_pk, &session->paillierKeys[0].paillier_pk,
                             &session->pedersenKeys[i].pedersenPub, session->r2Store[i].Gamma, (session->r2out+i)->F, (session->r1out+i)->K,
                             (session->r2out+i)->D, &session->PiAffgCommit1[i], (session->ssid + 0), &e2);

        int rc = Piaffg_Verify(&session->paillierKeys[i].paillier_sk, &session->paillierKeys[0].paillier_pk,
                               &session->pedersenKeys[i].pedersenPriv,session->r1out[i].K, session->r2out[i].D, session->r2Store[i].Gamma,
                               session->r2out[i].F, &session->PiAffgCommit1[i], &e2, &session->PiAffgProof1[i]);
        if (rc == Piaffg_OK)
        {
            printf("\nPlayer %d verified pi-Affg-1 range proof from player 1 successfully!", i+1);
        }
        else
        {
            printf("\npi-Affg-2 range proof Failed!");
            exit(rc);
        }
    }

    // other players verify player 1 Pi_Affg-2 proof
    for (int i=1; i<session->setting->t2; i++) {

        char e2_[MODBYTES_256_56];
        octet e2 = {0, sizeof(e2_), e2_};

        BIG_256_56 s;
        ECP_SECP256K1 G;

        char oct[EFS_SECP256K1 + 1];
        octet X = {0, sizeof(oct), oct};

        // X should be computed here, and should be generated by the prover, it's here only for simplicity
        ECP_SECP256K1_generator(&G);    // get curve generator
        BIG_256_56_fromBytesLen(s, session->r1Store->a->val, session->r1Store->a->len);   // load gamma into big
        ECP_SECP256K1_mul(&G, s);   // compute gamma*G
        ECP_SECP256K1_toOctet(&X, &G, true); // store gamma*G

        Piaffg_Challenge_gen(&session->paillierKeys[i].paillier_pk, &session->paillierKeys[0].paillier_pk,
                             &session->pedersenKeys[i].pedersenPub, &X, (session->r2out+i)->F_hat, (session->r1out+i)->K,
                             (session->r2out+i)->D_hat, &session->PiAffgCommit2[i], (session->ssid + 0), &e2);

        int rc = Piaffg_Verify(&session->paillierKeys[i].paillier_sk, &session->paillierKeys[0].paillier_pk,
                               &session->pedersenKeys[i].pedersenPriv,session->r1out[i].K, session->r2out[i].D_hat,
                               &X,session->r2out[i].F_hat, &session->PiAffgCommit2[i],
                               &e2, &session->PiAffgProof2[i]);
        if (rc == Piaffg_OK)
        {
            printf("\nPlayer %d verified pi-Affg-2 range proof from player 1 successfully!", i+1);
        }
        else
        {
            printf("\npi-Affg-1 range proof Failed!");
            exit(rc);
        }
    }

    for (int i=0; i<t2; i++) {
        for (int j=0; j<t2; j++){
            int status = 1;
            if (i==j){
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

            CG21_PRESIGN_ROUND3_2_1(session->r2out + j * t2 + i,
                                    session->r3Store1 + i,
                                    session->r2Store + i * t2 + j,
                                    session->r1Store + i,
                                    status);

        }
    }

    for (int i=0; i<t2; i++) {
        for (int j = 0; j < t2; j++) {
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

            CG21_PRESIGN_ROUND3_2_2(session->r2out + j * t2 + i,
                                    session->r3out + i,
                                    session->r3Store1 + i,
                                    session->r3Store2 + i,
                                    session->r1Store + i,
                                    &(session->paillierKeys + i)->paillier_sk,
                                    session->r2Store + i * t2 + j,
                                    status);
        }
    }

    // ----- PI-LOGSTAR PROOF GENERATION -----
    // assume only player 1 generates PiLogStar proof for the other players
    for (int i=1; i<session->setting->t2; i++) {

        PiLogstar_SECRETS PiLogSecrets;
        int rc = PiLogstar_Sample_and_commit(session->RNG, &session->paillierKeys[0].paillier_sk,
                                             &session->pedersenKeys[i].pedersenPub,session->r1Store[0].k, session->r3Store1[0].Gamma,
                                             &PiLogSecrets, &session->PiLogCommit2[i], &session->PiLogCommitOct2[i]);
        if (rc != PiLogstar_OK){
            printf("PiLogstar_Sample_and_commit failed!, %d", rc);
            exit(rc);
        }

        char e_[MODBYTES_256_56];
        octet e = {0, sizeof(e_), e_};

        PiLogstar_Challenge_gen(&session->paillierKeys[0].paillier_pk, &session->pedersenKeys[i].pedersenPub,
                                (session->r1out+i)->K, &session->PiLogCommit2[i], (session->ssid + 0), session->r3Store1[i].Delta, &e);

        PiLogstar_Prove(&session->paillierKeys[0].paillier_sk, session->r1Store[0].k,
                        session->r1Store[0].rho,&PiLogSecrets, &e, &session->PiLogProof2[i],
                        &session->PiLogProofOct2[i]);

    }
    // -------------------------------
}

void CG21_presign_output(CG21_PRESIGN_SESSION *session){

    int t2 = session->setting->t2;

    // other players verify player 1 Pi_LogStar proof
    for (int i=1; i<session->setting->t2; i++) {

        char e_[MODBYTES_256_56];
        octet e = {0, sizeof(e_), e_};

        ECP_SECP256K1 G;
        ECP_SECP256K1_generator(&G);

        PiLogstar_Challenge_gen(&session->paillierKeys[0].paillier_pk, &session->pedersenKeys[i].pedersenPub,
                                (session->r1out+i)->K, &session->PiLogCommit2[i], (session->ssid + 0), session->r3Store1[i].Delta, &e);

        int rc = PiLogstar_Verify(&session->paillierKeys[0].paillier_pk, &session->pedersenKeys[i].pedersenPriv,
                                  session->r1out[0].K, session->r3Store1[0].Gamma, &session->PiLogCommit2[i], session->r3Store1[0].Delta,
                                  &e, &session->PiLogProof2[i]);
        if (rc == PiLogstar_OK)
        {
            printf("\nPlayer %d verified pi-logStar-2 range proof from player 1 successfully!", i+1);
        }
        else
        {
            printf("\npi-logStar-2 range proof Failed!");
            exit(rc);
        }
    }


    for (int i=0; i<t2; i++) {
        int rc = 0;
        for (int j=0; j<t2; j++){
            int status = 1;
            if (i==j){
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

            rc = CG21_PRESIGN_OUTPUT_2_1(session->r3out + j,
                                         session->r3out + i,
                                         session->r4Store1 + i,
                                         status);


        }
        if (rc != CG21_OK){
                exit(1);
        }else{
            printf("\nPresign check passed");
        }
    }

    for (int i=0; i<t2; i++) {
        int rc = CG21_PRESIGN_OUTPUT_2_2(session->r1Store + i,
                                         session->r3Store1 + i,
                                         session->r3Store2 + i,
                                         session->r4Store1 + i,
                                         session->r4Store2 + i,
                                         session->r4out + i);

        if (rc != CG21_OK){
                exit(1);
        }else{
            printf("\nPresign finish successfully!");
        }
    }
}

void validation(const CG21_PRESIGN_SESSION *session){

    printf("\n----------- VALIDATION -----------\n");
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
            BIG_256_56_fromBytesLen(suma, (session->r1Store+i)->a->val, (session->r1Store+i)->a->len);
        }else {
            BIG_256_56_fromBytesLen(s, (session->r1Store + i)->a->val, (session->r1Store + i)->a->len);
            BIG_256_56_add(suma, suma, s);
            BIG_256_56_mod(suma, q);
        }
    }

    // PK = accum * G
    ECP_SECP256K1_mul(&G, suma);
    ECP_SECP256K1_toOctet(&PK, &G, true);

    rc = OCT_comp(&PK, session->reshareOutput->pk.X);
    if (rc==0){
        printf("\nRound1:\t\t additive shares are NOT valid!");
        exit(1);
    }else{
        printf("\nRound1:\t\t additive shares are valid");
    }
    // --------------- END OF CHECK 1 -----------------

    /*
    * --------- CHECK 2: sigma values -----------
     * check whether the addition of sigma values becomes \sum\gamma_i * \sum k_i
    */

    BIG_256_56 sumgamma;
    BIG_256_56 sumk;
    BIG_256_56 kgamma;
    DBIG_256_56 dkgamma;

    // step 1: compute \sum\gamma_i and \sum k_i
    for (int i=0; i<t2; i++) {
        if (i==0){
            BIG_256_56_fromBytesLen(sumgamma, (session->r1Store+i)->gamma->val, (session->r1Store+i)->gamma->len);
            BIG_256_56_fromBytesLen(sumk, (session->r4Store2+i)->k->val, (session->r4Store2+i)->k->len);
        }else {
            BIG_256_56_fromBytesLen(s, (session->r1Store + i)->gamma->val, (session->r1Store + i)->gamma->len);
            BIG_256_56_add(sumgamma, sumgamma, s);
            BIG_256_56_mod(sumgamma, q);

            BIG_256_56_fromBytesLen(s, (session->r4Store2 + i)->k->val, (session->r4Store2 + i)->k->len);
            BIG_256_56_add(sumk, sumk, s);
            BIG_256_56_mod(sumk, q);
        }
    }

    // step 2: compute kgamma
    BIG_256_56_mul(dkgamma, sumgamma, sumk);
    BIG_256_56_dmod(kgamma, dkgamma, q);

    // load sum of the delta components calculated in Round 4
    BIG_256_56_fromBytesLen(s, session->r4Store1->delta->val, session->r4Store1->delta->len);

    if (BIG_256_56_comp(s,kgamma) != 0){
        printf("\nRound3/4:\t partial delta components are NOT valid!");
        exit(1);
    }else{
        printf("\nRound3/4:\t partial delta components are valid");
    }
    // --------------- END OF CHECK 2 -----------------



    /*
    * --------- CHECK 3: chi values -----------
     * check whether the addition of \chi values becomes \sum\a_i * \sum k_i
     * Note: a_i are the additive shares that are computed in ROUND1
     * Note: sum k_i is already computed in the previous check
     * Note: sum a_i is already computed in the first check
    */

    BIG_256_56 ka;
    BIG_256_56 sumchi;
    DBIG_256_56 dka;

    // step 1: compute ka
    BIG_256_56_mul(dka, suma, sumk);
    BIG_256_56_dmod(ka, dka, q);

    // step 2: sume of \chi components
    for (int i=0; i<t2; i++) {
        if (i==0){
            BIG_256_56_fromBytesLen(sumchi, (session->r4Store2+i)->chi->val, (session->r4Store2+i)->chi->len);
        }else {
            BIG_256_56_fromBytesLen(s, (session->r4Store2 + i)->chi->val, (session->r4Store2 + i)->chi->len);
            BIG_256_56_add(sumchi, sumchi, s);
            BIG_256_56_mod(sumchi, q);
        }
    }

    if (BIG_256_56_comp(ka,sumchi) != 0){
        printf("\nRound3:\t\t partial chi components are NOT valid!");
        exit(1);
    }else{
        printf("\nRound3:\t\t partial chi components are valid");
    }
    // --------------- END OF CHECK 3 -----------------

    /*
    * --------- CHECK 4: R component -----------
     * check whether k^{-1}G == R (generated in ROUND4)
     * Note: k = /sum k_i is computed already
    */

    // step 1: compute the inverse of k
    BIG_256_56 INVk;
    BIG_256_56_invmodp(INVk, sumk, q);

    char r[EFS_SECP256K1 + 1];
    octet GoldR = {0, sizeof(r), r};

    // step 2: compute k^{-1}G
    ECP_SECP256K1_generator(&G);
    ECP_SECP256K1_mul(&G, INVk);
    ECP_SECP256K1_toOctet(&GoldR, &G, true);

    rc = OCT_comp(&GoldR, (session->r4Store2 + 0)->R);
    if (rc == 0){
        printf("\nOutput:\t\t R component is NOT valid!");
        exit(1);
    }
    printf("\nOutput:\t\t R component is valid");

    // --------------- END OF CHECK 4 -----------------


    /*
    * --------- CHECK 5: Generated R components are similar -----------
    */
    for (int i=0; i<t2-1; i++) {
        rc = OCT_comp((session->r4Store2 + i)->R, (session->r4Store2 + i+1)->R);
        if (rc == 0){
            printf("\nOutput:\t\t Generated R components are NOT similar!");
            exit(1);
        }
    }
    printf("\nOutput:\t\t R components are similar");

}

void Store_CSV_OCT_Helper(FILE *fpt, const octet * oct){
    unsigned char ch;
    for (int i=0; i<oct->len; i++)
    {
        ch=oct->val[i];
        fprintf(fpt,"%02x",ch);
    }
}

void Store_CSV(CG21_PRESIGN_SESSION *session){
    FILE *fpt;
    fpt = fopen("cg21_presign.csv", "w+");
    fprintf(fpt,"%d,%d", session->setting->t2, session->setting->n2);
    fprintf(fpt,"\n");
    Store_CSV_OCT_Helper(fpt, (session->reshareOutput)->pk.X);

    for (int i=0;i<session->setting->t2;i++){
        fprintf(fpt,"\n");
        fprintf(fpt,"%d", (session->r4Store2 +i)->i);
        fprintf(fpt,",");
        Store_CSV_OCT_Helper(fpt, (session->r4Store2 +i)->R);
        fprintf(fpt,",");
        Store_CSV_OCT_Helper(fpt, (session->r4Store2 +i)->k);
        fprintf(fpt,",");
        Store_CSV_OCT_Helper(fpt, (session->r4Store2 +i)->chi);
        fprintf(fpt,",");
        Store_CSV_OCT_Helper(fpt, (session->r1Store +i)->a);
    }

    if (fpt){
        fclose(fpt);
    }
}

void Form_SSID(CG21_PRESIGN_SESSION *session){
    for (int i=0; i<session->setting->t2; i++){
        CG21_PRESIGN_GET_SSID(session->ssid+i,session->reshareOutput+i,
                              session->setting->t1, session->setting->n2, session->auxOutput+i);
    }
}

void Print_SSID(CG21_PRESIGN_SESSION *session, int index){
    printf("\n\n\n--------- SSID --------\n");

    printf("\nuid=");
    OCT_output((session->ssid+index)->uid);

    printf("\nrid=");
    OCT_output((session->ssid+index)->rid);

    printf("\nrho=");
    OCT_output((session->ssid+index)->rho);

    printf("\nj_set_packed=");
    OCT_output((session->ssid+index)->j_set_packed);

    printf("\nX_set_packed=");
    OCT_output((session->ssid+index)->X_set_packed);

    printf("\nq=");
    OCT_output((session->ssid+index)->q);

    printf("\ng=");
    OCT_output((session->ssid+index)->g);

    printf("\nN_set_packed=");
    OCT_output((session->ssid+index)->N_set_packed);

    printf("\ns_set_packed=");
    OCT_output((session->ssid+index)->s_set_packed);

    printf("\nt_set_packed=");
    OCT_output((session->ssid+index)->t_set_packed);

    printf("\nn1=%d", *(session->ssid+index)->n1);

    printf("\nn2=%d", *(session->ssid+index)->n2);

    printf("-----------------------\n");
}

void Validate_SSID(CG21_PRESIGN_SESSION *session){

    char hash[session->setting->t2][SHA256];
    octet HASH[session->setting->t2];
    init_octets((char *)hash, HASH, SHA256, session->setting->t2);

    for (int i=0; i<session->setting->t2; i++){
        hash256 sha;
        HASH256_init(&sha);

        int rc = CG21_hash_SSID(session->ssid+i, &sha);
        if (rc != CG21_OK){
            printf("\nCG21_hash_SSID Failed!");
            exit(rc);
        }

        HASH256_hash(&sha, HASH[i].val);
        HASH[i].len = SHA256;

        if (i>0){
            if (!OCT_comp(&HASH[i], &HASH[i-1])){
                printf("\n\nSSIDs ARE NOT SIMILAR!\n\n");
            }
        }
    }
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

    CG21_PRESIGN_SESSION session;
    session.RNG = &RNG;

    //****** read t,n from file *******
    CG21_RESHARE_SETTING setting;
    file_read_tn(&setting);
    session.setting = &setting;

    int n = setting.n2;

    // specified which users are in set T
    int t_playerIDs[setting.t2];
    for (int i = 0; i < setting.t2; i++) {
        t_playerIDs[i] = i + 1;
    }
    setting.T2 = t_playerIDs;

    /* generate Paillier and Pedersen keys */
    char p_[n][HFS_2048];
    char q_[n][HFS_2048];

    octet P[n];
    octet Q[n];

    init_octets((char *) p_, P, HFS_2048, n);
    init_octets((char *) q_, Q, HFS_2048, n);

    for(int i=0 ;i<n;i++){
        OCT_fromHex(&P[i], PT_hex[i]);
        OCT_fromHex(&Q[i], QT_hex[i]);
    }

    CG21_PAILLIER_KEYS paillierKeys[n];
    CG21_PEDERSEN_KEYS pedersenKeys[n];

    for (int i=0; i<n; i++){
        // Generate Paillier Keys
        PAILLIER_KEY_PAIR(NULL, &P[i],&Q[i], &paillierKeys[i].paillier_pk, &paillierKeys[i].paillier_sk);

        // Generate Pedersen Keys
        ring_Pedersen_setup(&RNG, &pedersenKeys[i].pedersenPriv, &P[i],&Q[i]);
        Pedersen_get_public_param(&pedersenKeys[i].pedersenPub, &pedersenKeys[i].pedersenPriv);
    }

    session.paillierKeys = paillierKeys;
    session.pedersenKeys = pedersenKeys;

    //****** read X_set_packed and j_set_packed from key re-share output file **********
    char keyreshare_X[n][EFS_SECP256K1 + 1];   // r1Store, final ECDSA PK
    char keyreshare_i_packed[n][setting.t1 * 4 + 1];   //r1Store
    char keyreshare_X_set_packed[n][setting.t1 * (EFS_SECP256K1 + 1)]; //r1Store
    char keyreshare_xor_rho[n][EGS_SECP256K1]; //r1Store
    char keyreshare_xor_rid[n][EGS_SECP256K1]; //r1Store
    char keyreshare_sk_x[n][EGS_SECP256K1];    //r1Store
    char keyreshare_sk_y[n][EGS_SECP256K1];    //r1Store

    octet KEYRESHARE_xor_rho[n];
    octet KEYRESHARE_xor_rid[n];
    octet KEYRESHARE_sk_X[n];
    octet KEYRESHARE_sk_Y[n];
    octet KEYRESHARE_X[n];
    octet KEYRESHARE_j_PACKED[n];
    octet KEYRESHARE_X_SET_PACKED[n];

    init_octets((char *)keyreshare_i_packed, KEYRESHARE_j_PACKED, (setting.t1 * 4 + 1), n);
    init_octets((char *)keyreshare_X_set_packed, KEYRESHARE_X_SET_PACKED, setting.t1 * (EFS_SECP256K1 + 1), n);
    init_octets((char *)keyreshare_X, KEYRESHARE_X, EFS_SECP256K1 + 1, n);
    init_octets((char *)keyreshare_xor_rho, KEYRESHARE_xor_rho, EGS_SECP256K1, n);
    init_octets((char *)keyreshare_xor_rid, KEYRESHARE_xor_rid, EGS_SECP256K1, n);
    init_octets((char *)keyreshare_sk_x, KEYRESHARE_sk_X, EGS_SECP256K1, n);
    init_octets((char *)keyreshare_sk_y, KEYRESHARE_sk_Y, EGS_SECP256K1, n);

    CG21_RESHARE_OUTPUT keyReshareOutput[n];

    for (int i=0; i < n; i++){

        keyReshareOutput[i].pk.X = KEYRESHARE_X + i;
        keyReshareOutput[i].pk.X_set_packed = KEYRESHARE_X_SET_PACKED + i;
        keyReshareOutput[i].pk.j_set_packed = KEYRESHARE_j_PACKED + i;
        keyReshareOutput[i].rho = KEYRESHARE_xor_rho + i;
        keyReshareOutput[i].rid = KEYRESHARE_xor_rid + i;
        keyReshareOutput[i].shares.X = KEYRESHARE_sk_X + i;
        keyReshareOutput[i].shares.Y = KEYRESHARE_sk_Y + i;
    }

    session.reshareOutput = keyReshareOutput;


    //****** read N_set_packed, s_set_packed and t_set_packed from Aux. output file **********
    char round4_i_packed[n][n * 4 + 1];
    char round4_N_set_packed[n][n * FS_2048];
    char round4_s_set_packed[n][n * FS_2048];
    char round4_t_set_packed[n][n * FS_2048];

    octet ROUND4_i_PACKED[n];
    octet ROUND4_N_SET_PACKED[n];
    octet ROUND4_s_SET_PACKED[n];
    octet ROUND4_t_SET_PACKED[n];

    init_octets((char *)round4_i_packed, ROUND4_i_PACKED, (n * 4 + 1), n);
    init_octets((char *)round4_N_set_packed, ROUND4_N_SET_PACKED, n * FS_2048, n);
    init_octets((char *)round4_s_set_packed, ROUND4_s_SET_PACKED, n * FS_2048, n);
    init_octets((char *)round4_t_set_packed, ROUND4_t_SET_PACKED, n * FS_2048, n);

    CG21_AUX_OUTPUT AuxOutput[n];
    session.auxOutput = AuxOutput;

    for (int i = 0; i < n; i++) {
        AuxOutput[i].j = ROUND4_i_PACKED + i;
        AuxOutput[i].N = ROUND4_N_SET_PACKED + i;
        AuxOutput[i].s = ROUND4_s_SET_PACKED + i;
        AuxOutput[i].t = ROUND4_t_SET_PACKED + i;
    }

    file_read_keygen_reshare_aux(&setting, keyReshareOutput, AuxOutput);


    // define and initialize variables for SSID
    char uid[n][iLEN];
    char xored_rid[setting.t2][EGS_SECP256K1];
    char xored_rho[setting.t2][EGS_SECP256K1];
    char j_packed[setting.t2][setting.t1 * 4 + 1];
    char j_packed2[setting.t2][n * 4 + 1];
    char X_set_packed[setting.t2][setting.t1 * (EFS_SECP256K1 + 1)];
    char order[setting.t2][EFS_SECP256K1];
    char generator[setting.t2][EFS_SECP256K1 + 1];
    char N_set_packed[setting.t2][n * FS_2048];
    char s_set_packed[setting.t2][n * FS_2048];
    char t_set_packed[setting.t2][n * FS_2048];
    int n1;
    int n2;

    octet UID[setting.t2];
    octet XORed_rid[setting.t2];
    octet XORed_rho[setting.t2];
    octet j_SET_PACKED[setting.t2];
    octet j_SET_PACKED2[setting.t2];
    octet X_SET_PACKED[setting.t2];
    octet q_oct[setting.t2];
    octet g_oct[setting.t2];
    octet N_SET_PACKED[setting.t2];
    octet s_SET_PACKED[setting.t2];
    octet t_SET_PACKED[setting.t2];

    init_octets((char *) uid, UID, iLEN, setting.t2);
    init_octets((char *)xored_rid,  XORed_rid,  EGS_SECP256K1, setting.t2);
    init_octets((char *)xored_rho,  XORed_rho,  EGS_SECP256K1, setting.t2);
    init_octets((char *)j_packed, j_SET_PACKED, (setting.t1 * 4 + 1), setting.t2);
    init_octets((char *)j_packed2, j_SET_PACKED2, (setting.t2 * 4 + 1), setting.t2);
    init_octets((char *)X_set_packed, X_SET_PACKED, setting.t1 * (EFS_SECP256K1 + 1), setting.t2);
    init_octets((char *)order, q_oct, EFS_SECP256K1,      setting.t2);
    init_octets((char *)generator, g_oct, EFS_SECP256K1 + 1,      setting.t2);
    init_octets((char *)N_set_packed, N_SET_PACKED, n * FS_2048, setting.t2);
    init_octets((char *)s_set_packed, s_SET_PACKED, n * FS_2048, setting.t2);
    init_octets((char *)t_set_packed, t_SET_PACKED, n * FS_2048, setting.t2);


    // each party forms its ssid
    CG21_SSID ssid[n];

    char id_[iLEN];
    octet ID_ = {0, sizeof(id_), id_};
    OCT_rand(&ID_, &RNG, iLEN);

    for (int i = 0; i < setting.t2; i++) {
        ssid[i].uid = UID + i;
        ssid[i].rid = XORed_rid + i;
        ssid[i].rho = XORed_rho + i;
        ssid[i].j_set_packed = j_SET_PACKED + i;
        ssid[i].X_set_packed = X_SET_PACKED + i;
        ssid[i].q = q_oct + i;
        ssid[i].g = g_oct + i;
        ssid[i].N_set_packed = N_SET_PACKED + i;
        ssid[i].s_set_packed = s_SET_PACKED + i;
        ssid[i].t_set_packed = t_SET_PACKED + i;
        ssid[i].j_set_packed2 = j_SET_PACKED2 + i;
        ssid[i].n1 = &n1;
        ssid[i].n2 = &n2;
        // players should have same session ID for sigma protocols
        OCT_copy(ssid[i].uid, &ID_);
    }

    session.ssid = ssid;
    Form_SSID(&session);
//    Print_SSID(&session, 0);
    Validate_SSID(&session);

    char round1_psi[n][SGS_SECP256K1];
    char round1_G_out[n][FS_4096];
    char round1_K_out[n][FS_4096];
    char round1_k[n][EGS_SECP256K1];
    char round1_gamma[n][EGS_SECP256K1];
    char round1_rho[n][FS_4096];
    char round1_nu[n][FS_4096];
    char round1_a[n][EGS_SECP256K1];
    char round1_X[n][EFS_SECP256K1 + 1];
    char round1_piEnc_S[n][FS_2048];
    char round1_piEnc_A[n][FS_4096];
    char round1_piEnc_C[n][FS_2048];
    char round1_piEnc_z1[n][HFS_2048];
    char round1_piEnc_z2[n][HFS_4096];
    char round1_piEnc_z3[n][FS_2048 + HFS_2048];

    octet ROUND1_psi[n];
    octet ROUND1_G_out[n];
    octet ROUND1_K_out[n];
    octet ROUND1_k[n];
    octet ROUND1_gamma[n];
    octet ROUND1_rho[n];
    octet ROUND1_nu[n];
    octet ROUND1_a[n];
    octet ROUND1_X[n];
    octet ROUND1_PIENC_S[n];
    octet ROUND1_PIENC_A[n];
    octet ROUND1_PIENC_C[n];
    octet ROUND1_PIENC_z1[n];
    octet ROUND1_PIENC_z2[n];
    octet ROUND1_PIENC_z3[n];

    init_octets((char *)round1_psi, ROUND1_psi, SGS_SECP256K1, n);
    init_octets((char *)round1_G_out, ROUND1_G_out, FS_4096, n);
    init_octets((char *)round1_K_out, ROUND1_K_out, FS_4096, n);
    init_octets((char *)round1_k, ROUND1_k, EGS_SECP256K1, n);
    init_octets((char *)round1_gamma, ROUND1_gamma, EGS_SECP256K1, n);
    init_octets((char *)round1_rho, ROUND1_rho, FS_4096, n);
    init_octets((char *)round1_nu, ROUND1_nu, FS_4096, n);
    init_octets((char *)round1_a, ROUND1_a, EGS_SECP256K1, n);
    init_octets((char *)round1_X, ROUND1_X, EFS_SECP256K1 + 1, n);
    init_octets((char *)round1_piEnc_S, ROUND1_PIENC_S, FS_2048, n);
    init_octets((char *)round1_piEnc_A, ROUND1_PIENC_A, FS_4096, n);
    init_octets((char *)round1_piEnc_C, ROUND1_PIENC_C, FS_2048, n);
    init_octets((char *)round1_piEnc_z1, ROUND1_PIENC_z1, HFS_2048, n);
    init_octets((char *)round1_piEnc_z2, ROUND1_PIENC_z2, HFS_4096, n);
    init_octets((char *)round1_piEnc_z3, ROUND1_PIENC_z3, FS_2048 + HFS_2048, n);


    CG21_PRESIGN_ROUND1_OUTPUT r1Output[n];
    CG21_PRESIGN_ROUND1_STORE r1Store[n];
    PiEnc_COMMITS_OCT PiEnc_commitOct[n];
    PiEnc_PROOFS_OCT PiEnc_proofOct[n];
    PiEnc_PROOFS PiEncProof[n];
    PiEnc_COMMITS PiEnc_commit[n];

    for (int i=0; i < n; i++) {
        r1Output[i].psi = ROUND1_psi + i;
        r1Output[i].K = ROUND1_K_out + i;
        r1Output[i].G = ROUND1_G_out + i;

        r1Store[i].rho = ROUND1_rho + i;
        r1Store[i].gamma = ROUND1_gamma + i;
        r1Store[i].k = ROUND1_k + i;
        r1Store[i].nu = ROUND1_nu + i;
        r1Store[i].a = ROUND1_a + i;

        PiEnc_commitOct[i].A = ROUND1_PIENC_A + i;
        PiEnc_commitOct[i].S = ROUND1_PIENC_S + i;
        PiEnc_commitOct[i].C = ROUND1_PIENC_C + i;

        PiEnc_proofOct[i].z1 = ROUND1_PIENC_z1 + i;
        PiEnc_proofOct[i].z2 = ROUND1_PIENC_z2 + i;
        PiEnc_proofOct[i].z3 = ROUND1_PIENC_z3 + i;
    }

    session.r1out = r1Output;
    session.r1Store = r1Store;

    char id[32];
    octet ID = {0, sizeof(id), id};

    char ad[32];
    octet AD = {0, sizeof(ad), ad};

    // Pseudorandom ID and AD
    OCT_rand(&ID, &RNG, iLEN);
    OCT_rand(&AD, &RNG, iLEN);

    session.PiEncCommitOct = PiEnc_commitOct;
    session.PiEncProofOct = PiEnc_proofOct;
    session.PiEncCommit = PiEnc_commit;
    session.PiEnc_proof = PiEncProof;

    // check whether partial pks form the main pk
    //
    CG21_validate_partial_pk_reshare_output(&session);
    CG21_presign_round1(&session);

    // Round 2
    char round2_r[n*n][FS_4096];
    char round2_r_hat[n*n][FS_4096];
    char round2_s[n*n][FS_4096];
    char round2_s_hat[n*n][FS_4096];
    char round2_beta[n*n][FS_2048];
    char round2_beta_hat[n*n][FS_2048];
    char round2_neg_beta[n*n][FS_2048];
    char round2_neg_beta_hat[n*n][FS_2048];
    char round2_Gamma[n*n][EFS_SECP256K1 + 1];
    char round2_D[n*n][FS_4096];
    char round2_D_hat[n*n][FS_4096];
    char round2_F[n*n][FS_4096];
    char round2_F_hat[n*n][FS_4096];
    char round2_Gamma_out[n*n][EFS_SECP256K1 + 1];

    // Pi-LogStar-1
    char round2_piLog1_S[n][FS_2048];
    char round2_piLog1_A[n][FS_4096];
    char round2_piLog1_D[n][FS_2048];
    char round2_piLog1_Y[n][FS_2048];
    char round2_piLog1_z1[n][HFS_2048];
    char round2_piLog1_z2[n][HFS_4096];
    char round2_piLog1_z3[n][FS_2048 + HFS_2048];

    // Pi-LogStar-2
    char round2_piLog2_S[n][FS_2048];
    char round2_piLog2_A[n][FS_4096];
    char round2_piLog2_D[n][FS_2048];
    char round2_piLog2_Y[n][FS_2048];
    char round2_piLog2_z1[n][HFS_2048];
    char round2_piLog2_z2[n][HFS_4096];
    char round2_piLog2_z3[n][FS_2048 + HFS_2048];

    // Pi-AffG-1
    char round2_AffG1_A[n][2 * FS_2048];
    char round2_AffG1_Bx[n][FS_2048];
    char round2_AffG1_By[n][2 * FS_2048];
    char round2_AffG1_E[n][FS_2048];
    char round2_AffG1_S[n][FS_2048];
    char round2_AffG1_F[n][FS_2048];
    char round2_AffG1_T[n][FS_2048];
    char round2_AffG1_z1[n][FS_2048];
    char round2_AffG1_z2[n][FS_2048];
    char round2_AffG1_z3[n][FS_2048+HFS_2048];
    char round2_AffG1_z4[n][FS_2048+HFS_2048];
    char round2_AffG1_w[n][FS_2048];
    char round2_AffG1_wy[n][FS_2048];

    // Pi-AffG-2
    char round2_AffG2_A[n][2 * FS_2048];
    char round2_AffG2_Bx[n][FS_2048];
    char round2_AffG2_By[n][2 * FS_2048];
    char round2_AffG2_E[n][FS_2048];
    char round2_AffG2_S[n][FS_2048];
    char round2_AffG2_F[n][FS_2048];
    char round2_AffG2_T[n][FS_2048];
    char round2_AffG2_z1[n][FS_2048];
    char round2_AffG2_z2[n][FS_2048];
    char round2_AffG2_z3[n][FS_2048+HFS_2048];
    char round2_AffG2_z4[n][FS_2048+HFS_2048];
    char round2_AffG2_w[n][FS_2048];
    char round2_AffG2_wy[n][FS_2048];

    octet ROUND2_r[n*n];
    octet ROUND2_r_hat[n*n];
    octet ROUND2_s[n*n];
    octet ROUND2_s_hat[n*n];
    octet ROUND2_beta[n*n];
    octet ROUND2_beta_hat[n*n];
    octet ROUND2_neg_beta[n*n];
    octet ROUND2_neg_beta_hat[n*n];
    octet ROUND2_Gamma[n*n];
    octet ROUND2_D[n*n];
    octet ROUND2_D_hat[n*n];
    octet ROUND2_F[n*n];
    octet ROUND2_F_hat[n*n];
    octet ROUND2_Gamma_out[n*n];
    octet ROUND2_PILOG1_S[n];
    octet ROUND2_PILOG1_A[n];
    octet ROUND2_PILOG1_D[n];
    octet ROUND2_PILOG1_Y[n];
    octet ROUND2_PILOG1_z1[n];
    octet ROUND2_PILOG1_z2[n];
    octet ROUND2_PILOG1_z3[n];
    octet ROUND2_PILOG2_S[n];
    octet ROUND2_PILOG2_A[n];
    octet ROUND2_PILOG2_D[n];
    octet ROUND2_PILOG2_Y[n];
    octet ROUND2_PILOG2_z1[n];
    octet ROUND2_PILOG2_z2[n];
    octet ROUND2_PILOG2_z3[n];
    octet ROUND2_AFFG1_A[n];
    octet ROUND2_AFFG1_Bx[n];
    octet ROUND2_AFFG1_By[n];
    octet ROUND2_AFFG1_E[n];
    octet ROUND2_AFFG1_S[n];
    octet ROUND2_AFFG1_F[n];
    octet ROUND2_AFFG1_T[n];
    octet ROUND2_AFFG1_z1[n];
    octet ROUND2_AFFG1_z2[n];
    octet ROUND2_AFFG1_z3[n];
    octet ROUND2_AFFG1_z4[n];
    octet ROUND2_AFFG1_w[n];
    octet ROUND2_AFFG1_wy[n];
    octet ROUND2_AFFG2_A[n];
    octet ROUND2_AFFG2_Bx[n];
    octet ROUND2_AFFG2_By[n];
    octet ROUND2_AFFG2_E[n];
    octet ROUND2_AFFG2_S[n];
    octet ROUND2_AFFG2_F[n];
    octet ROUND2_AFFG2_T[n];
    octet ROUND2_AFFG2_z1[n];
    octet ROUND2_AFFG2_z2[n];
    octet ROUND2_AFFG2_z3[n];
    octet ROUND2_AFFG2_z4[n];
    octet ROUND2_AFFG2_w[n];
    octet ROUND2_AFFG2_wy[n];

    init_octets((char *)round2_r, ROUND2_r, FS_4096, n*n);
    init_octets((char *)round2_r_hat, ROUND2_r_hat, FS_4096, n*n);
    init_octets((char *)round2_s, ROUND2_s, FS_4096, n*n);
    init_octets((char *)round2_s_hat, ROUND2_s_hat, FS_4096, n*n);
    init_octets((char *)round2_beta, ROUND2_beta, FS_2048, n*n);
    init_octets((char *)round2_beta_hat, ROUND2_beta_hat, FS_2048, n*n);
    init_octets((char *)round2_neg_beta, ROUND2_neg_beta, FS_2048, n*n);
    init_octets((char *)round2_neg_beta_hat, ROUND2_neg_beta_hat, FS_2048, n*n);
    init_octets((char *)round2_Gamma, ROUND2_Gamma, EFS_SECP256K1 + 1, n*n);
    init_octets((char *)round2_Gamma_out, ROUND2_Gamma_out, EFS_SECP256K1 + 1, n*n);
    init_octets((char *)round2_D, ROUND2_D, FS_4096, n*n);
    init_octets((char *)round2_D_hat, ROUND2_D_hat, FS_4096, n*n);
    init_octets((char *)round2_F, ROUND2_F, FS_4096, n*n);
    init_octets((char *)round2_F_hat, ROUND2_F_hat, FS_4096, n*n);
    init_octets((char *)round2_piLog1_S, ROUND2_PILOG1_S, FS_2048, n);
    init_octets((char *)round2_piLog1_A, ROUND2_PILOG1_A, FS_4096, n);
    init_octets((char *)round2_piLog1_D, ROUND2_PILOG1_D, FS_2048, n);
    init_octets((char *)round2_piLog1_Y, ROUND2_PILOG1_Y, FS_2048, n);
    init_octets((char *)round2_piLog1_z1, ROUND2_PILOG1_z1, HFS_2048, n);
    init_octets((char *)round2_piLog1_z2, ROUND2_PILOG1_z2, HFS_4096, n);
    init_octets((char *)round2_piLog1_z3, ROUND2_PILOG1_z3, FS_2048 + HFS_2048, n);
    init_octets((char *)round2_piLog2_S, ROUND2_PILOG2_S, FS_2048, n);
    init_octets((char *)round2_piLog2_A, ROUND2_PILOG2_A, FS_4096, n);
    init_octets((char *)round2_piLog2_D, ROUND2_PILOG2_D, FS_2048, n);
    init_octets((char *)round2_piLog2_Y, ROUND2_PILOG2_Y, FS_2048, n);
    init_octets((char *)round2_piLog2_z1, ROUND2_PILOG2_z1, HFS_2048, n);
    init_octets((char *)round2_piLog2_z2, ROUND2_PILOG2_z2, HFS_4096, n);
    init_octets((char *)round2_piLog2_z3, ROUND2_PILOG2_z3, FS_2048 + HFS_2048, n);
    init_octets((char *)round2_AffG1_A, ROUND2_AFFG1_A, 2 * FS_2048, n);
    init_octets((char *)round2_AffG1_Bx, ROUND2_AFFG1_Bx, FS_2048, n);
    init_octets((char *)round2_AffG1_By, ROUND2_AFFG1_By, 2 * FS_2048, n);
    init_octets((char *)round2_AffG1_E, ROUND2_AFFG1_E, FS_2048, n);
    init_octets((char *)round2_AffG1_S, ROUND2_AFFG1_S, FS_2048, n);
    init_octets((char *)round2_AffG1_F, ROUND2_AFFG1_F, FS_2048, n);
    init_octets((char *)round2_AffG1_T, ROUND2_AFFG1_T, FS_2048, n);
    init_octets((char *)round2_AffG1_z1, ROUND2_AFFG1_z1, FS_2048, n);
    init_octets((char *)round2_AffG1_z2, ROUND2_AFFG1_z2, FS_2048, n);
    init_octets((char *)round2_AffG1_z3, ROUND2_AFFG1_z3, FS_2048+HFS_2048, n);
    init_octets((char *)round2_AffG1_z4, ROUND2_AFFG1_z4, FS_2048+HFS_2048, n);
    init_octets((char *)round2_AffG1_w, ROUND2_AFFG1_w, FS_2048, n);
    init_octets((char *)round2_AffG1_wy, ROUND2_AFFG1_wy, FS_2048, n);
    init_octets((char *)round2_AffG2_A, ROUND2_AFFG2_A, 2 * FS_2048, n);
    init_octets((char *)round2_AffG2_Bx, ROUND2_AFFG2_Bx, FS_2048, n);
    init_octets((char *)round2_AffG2_By, ROUND2_AFFG2_By, 2 * FS_2048, n);
    init_octets((char *)round2_AffG2_E, ROUND2_AFFG2_E, FS_2048, n);
    init_octets((char *)round2_AffG2_S, ROUND2_AFFG2_S, FS_2048, n);
    init_octets((char *)round2_AffG2_F, ROUND2_AFFG2_F, FS_2048, n);
    init_octets((char *)round2_AffG2_T, ROUND2_AFFG2_T, FS_2048, n);
    init_octets((char *)round2_AffG2_z1, ROUND2_AFFG2_z1, FS_2048, n);
    init_octets((char *)round2_AffG2_z2, ROUND2_AFFG2_z2, FS_2048, n);
    init_octets((char *)round2_AffG2_z3, ROUND2_AFFG2_z3, FS_2048+HFS_2048, n);
    init_octets((char *)round2_AffG2_z4, ROUND2_AFFG2_z4, FS_2048+HFS_2048, n);
    init_octets((char *)round2_AffG2_w, ROUND2_AFFG2_w, FS_2048, n);
    init_octets((char *)round2_AffG2_wy, ROUND2_AFFG2_wy, FS_2048, n);

    CG21_PRESIGN_ROUND2_OUTPUT r2Output[n*n];
    CG21_PRESIGN_ROUND2_STORE r2Store[n*n];

    PiLogstar_COMMITS_OCT PiLogCommitOct1[n];
    PiLogstar_PROOFS_OCT PiLogProofOct1[n];
    PiLogstar_COMMITS PiLogCommit1[n];
    PiLogstar_PROOFS PiLogProof1[n];

    PiLogstar_COMMITS_OCT PiLogCommitOct2[n];
    PiLogstar_PROOFS_OCT PiLogProofOct2[n];
    PiLogstar_COMMITS PiLogCommit2[n];
    PiLogstar_PROOFS PiLogProof2[n];

    Piaffg_COMMITS PiAffgCommit1[n];
    Piaffg_PROOFS PiAffgProof1[n];
    Piaffg_PROOFS_OCT PiAffgProofOct1[n];
    Piaffg_COMMITS_OCT PiAffgCommitOct1[n];

    Piaffg_COMMITS PiAffgCommit2[n];
    Piaffg_PROOFS PiAffgProof2[n];
    Piaffg_PROOFS_OCT PiAffgProofOct2[n];
    Piaffg_COMMITS_OCT PiAffgCommitOct2[n];

    for (int i=0; i < n; i++) {
        PiLogCommitOct1[i].S = ROUND2_PILOG1_S + i;
        PiLogCommitOct1[i].A = ROUND2_PILOG1_A + i;
        PiLogCommitOct1[i].D = ROUND2_PILOG1_D + i;
        PiLogCommitOct1[i].Y = ROUND2_PILOG1_Y + i;

        PiLogProofOct1[i].z1 = ROUND2_PILOG1_z1 + i;
        PiLogProofOct1[i].z2 = ROUND2_PILOG1_z2 + i;
        PiLogProofOct1[i].z3 = ROUND2_PILOG1_z3 + i;


        PiLogCommitOct2[i].S = ROUND2_PILOG2_S + i;
        PiLogCommitOct2[i].A = ROUND2_PILOG2_A + i;
        PiLogCommitOct2[i].D = ROUND2_PILOG2_D + i;
        PiLogCommitOct2[i].Y = ROUND2_PILOG2_Y + i;

        PiLogProofOct2[i].z1 = ROUND2_PILOG2_z1 + i;
        PiLogProofOct2[i].z2 = ROUND2_PILOG2_z2 + i;
        PiLogProofOct2[i].z3 = ROUND2_PILOG2_z3 + i;

        PiAffgCommitOct1[i].A = ROUND2_AFFG1_A + i;
        PiAffgCommitOct1[i].Bx = ROUND2_AFFG1_Bx + i;
        PiAffgCommitOct1[i].By = ROUND2_AFFG1_By + i;
        PiAffgCommitOct1[i].E = ROUND2_AFFG1_E + i;
        PiAffgCommitOct1[i].S = ROUND2_AFFG1_S + i;
        PiAffgCommitOct1[i].F = ROUND2_AFFG1_F + i;
        PiAffgCommitOct1[i].T = ROUND2_AFFG1_T + i;

        PiAffgProofOct1[i].z1 = ROUND2_AFFG1_z1 + i;
        PiAffgProofOct1[i].z2 = ROUND2_AFFG1_z2 + i;
        PiAffgProofOct1[i].z3 = ROUND2_AFFG1_z3 + i;
        PiAffgProofOct1[i].z4 = ROUND2_AFFG1_z4 + i;
        PiAffgProofOct1[i].w = ROUND2_AFFG1_w + i;
        PiAffgProofOct1[i].wy = ROUND2_AFFG1_wy + i;

        PiAffgCommitOct2[i].A = ROUND2_AFFG2_A + i;
        PiAffgCommitOct2[i].Bx = ROUND2_AFFG2_Bx + i;
        PiAffgCommitOct2[i].By = ROUND2_AFFG2_By + i;
        PiAffgCommitOct2[i].E = ROUND2_AFFG2_E + i;
        PiAffgCommitOct2[i].S = ROUND2_AFFG2_S + i;
        PiAffgCommitOct2[i].F = ROUND2_AFFG2_F + i;
        PiAffgCommitOct2[i].T = ROUND2_AFFG2_T + i;

        PiAffgProofOct2[i].z1 = ROUND2_AFFG2_z1 + i;
        PiAffgProofOct2[i].z2 = ROUND2_AFFG2_z2 + i;
        PiAffgProofOct2[i].z3 = ROUND2_AFFG2_z3 + i;
        PiAffgProofOct2[i].z4 = ROUND2_AFFG2_z4 + i;
        PiAffgProofOct2[i].w = ROUND2_AFFG2_w + i;
        PiAffgProofOct2[i].wy = ROUND2_AFFG2_wy + i;

    }

    for (int i=0; i < (n*n); i++) {
        r2Output[i].D = ROUND2_D + i;
        r2Output[i].F = ROUND2_F + i;
        r2Output[i].D_hat = ROUND2_D_hat + i;
        r2Output[i].F_hat = ROUND2_F_hat + i;
        r2Output[i].Gamma = ROUND2_Gamma_out + i;

        r2Store[i].r = ROUND2_r + i;
        r2Store[i].r_hat = ROUND2_r_hat + i;
        r2Store[i].s = ROUND2_s + i;
        r2Store[i].s_hat = ROUND2_s_hat + i;
        r2Store[i].Gamma = ROUND2_Gamma + i;
        r2Store[i].beta = ROUND2_beta + i;
        r2Store[i].beta_hat = ROUND2_beta_hat + i;
        r2Store[i].neg_beta = ROUND2_neg_beta + i;
        r2Store[i].neg_beta_hat = ROUND2_neg_beta_hat + i;

    }
    session.r2out = r2Output;
    session.r2Store = r2Store;
    session.PiLogCommitOct1 = PiLogCommitOct1;
    session.PiLogProofOct1 = PiLogProofOct1;
    session.PiLogCommit1 = PiLogCommit1;
    session.PiLogProof1 = PiLogProof1;

    session.PiLogCommitOct2 = PiLogCommitOct2;
    session.PiLogProofOct2 = PiLogProofOct2;
    session.PiLogCommit2 = PiLogCommit2;
    session.PiLogProof2 = PiLogProof2;

    session.PiAffgCommit1 = PiAffgCommit1;
    session.PiAffgCommitOct1 = PiAffgCommitOct1;
    session.PiAffgProof1 = PiAffgProof1;
    session.PiAffgProofOct1 = PiAffgProofOct1;

    session.PiAffgCommit2 = PiAffgCommit2;
    session.PiAffgCommitOct2 = PiAffgCommitOct2;
    session.PiAffgProof2 = PiAffgProof2;
    session.PiAffgProofOct2 = PiAffgProofOct2;

    CG21_presign_round2(&session);

    //Round3
    char round3_Delta[n*(n-1)][EFS_SECP256K1 + 1];
    char round3_Gamma2[n][EFS_SECP256K1 + 1];
    char round3_Delta2[n][EFS_SECP256K1 + 1];
    char round3_delta[n*(n-1)][EGS_SECP256K1];
    char round3_delta_store[n*(n-1)][EGS_SECP256K1];
    char round3_chi[n*(n-1)][EGS_SECP256K1];

    octet ROUND3_Delta[n*(n-1)];
    octet ROUND3_Gamma2[n];
    octet ROUND3_Delta2[n];
    octet ROUND3_delta[n*(n-1)];
    octet ROUND3_delta_store[n*(n-1)];
    octet ROUND3_chi[n*(n-1)];

    init_octets((char *)round3_Delta, ROUND3_Delta, EFS_SECP256K1 + 1, n*(n-1));
    init_octets((char *)round3_Gamma2, ROUND3_Gamma2, EFS_SECP256K1 + 1, n);
    init_octets((char *)round3_Delta2, ROUND3_Delta2, EFS_SECP256K1 + 1, n);
    init_octets((char *)round3_delta, ROUND3_delta, EFS_SECP256K1 + 1, n*(n-1));
    init_octets((char *)round3_delta_store, ROUND3_delta_store, EFS_SECP256K1 + 1, n*(n-1));
    init_octets((char *)round3_chi, ROUND3_chi, EFS_SECP256K1 + 1, n*(n-1));

    CG21_PRESIGN_ROUND3_OUTPUT r3Output[n*(n-1)];
    CG21_PRESIGN_ROUND3_STORE_1 r3Store1[n];
    CG21_PRESIGN_ROUND3_STORE_2 r3Store2[n * n - 1];

    for (int i=0; i < n; i++) {
        r3Store1[i].Delta = ROUND3_Delta2 + i;
        r3Store1[i].Gamma = ROUND3_Gamma2 + i;
    }

    for (int i=0; i < n*(n-1); i++) {
        r3Output[i].delta = ROUND3_delta + i;
        r3Output[i].Delta = ROUND3_Delta + i;

        r3Store2[i].delta = ROUND3_delta_store + i;
        r3Store2[i].chi = ROUND3_chi + i;
    }

    session.r3out = r3Output;
    session.r3Store1 = r3Store1;
    session.r3Store2 = r3Store2;

    CG21_presign_round3(&session);


    // Round 4
    char round4_R[n][EFS_SECP256K1 + 1];
    char round4_chi[n][EGS_SECP256K1];
    char round4_k[n][EGS_SECP256K1];
    char round4_Delta[n][EFS_SECP256K1 + 1];
    char round4_delta[n][EGS_SECP256K1];

    octet ROUND4_R[n];
    octet ROUND4_chi[n];
    octet ROUND4_k[n];
    octet ROUND4_Delta[n];
    octet ROUND4_delta[n];

    init_octets((char *)round4_R, ROUND4_R, EFS_SECP256K1 + 1, n);
    init_octets((char *)round4_chi, ROUND4_chi, EGS_SECP256K1, n);
    init_octets((char *)round4_k, ROUND4_k, EGS_SECP256K1, n);
    init_octets((char *)round4_Delta, ROUND4_Delta, EFS_SECP256K1 + 1, n);
    init_octets((char *)round4_delta, ROUND4_delta, EGS_SECP256K1, n);


    CG21_PRESIGN_ROUND4_OUTPUT r4Output[n*(n-1)];
    CG21_PRESIGN_ROUND4_STORE_1 r4Store1[n];
    CG21_PRESIGN_ROUND4_STORE_2 r4Store2[n*(n-1)];

    for (int i=0; i < n; i++) {
        r4Store1[i].Delta = ROUND4_Delta + i;
        r4Store1[i].delta = ROUND4_delta + i;

        r4Store2[i].R = ROUND4_R + i;
        r4Store2[i].chi = ROUND4_chi + i;
        r4Store2[i].k = ROUND4_k + i;
    }


    session.r4out = r4Output;
    session.r4Store1 = r4Store1;
    session.r4Store2 = r4Store2;

    CG21_presign_output(&session);

    validation(&session);
    Store_CSV(&session);

    exit(0);
}