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

    This example is for the implementation of CG21 Paillier and Pedersen parameter generation.

    and for generating Pedersen parameters and validation visit
    https://link.springer.com/content/pdf/10.1007/BFb0052225.pdf, page 19, section 3.1


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

// Safe primes for Paillier and Pederesen param generation
char *PT_hex[] = {"ffa0ec8cec4d2ffbef2a251111a361ad0199133f0aaa715df5ef052ad1efee2efda77a9349a74743e394ecef4da268c63171b8a896df79ec940f0c11d5de4a90d66628646f21f1ac0ac5f13adf45d2fd1d795c766dff1f656c91c3650ac2b59734efd3431332d691815da465b0d6f65b1620f4b1c7b9c18b38f63f478c06ca67",
                   "db47424304e2c5d57f50f6f73881eef53f55ea680d9f48b57df3e404303442c7fa5bd9418c5928cbe3b293281bdf8dce0350d7c65f22acfcf6b0fe5442fdb0c61bf396d13bc81992392d67c260a596b88eebe25661859fbcc8e871760794a3b810da2e881bb0cec6ca9310375d37bcc867436152ee71c59508220c8fbc6d9783",
                   "c883b3abc4b6dd37e41d7bcf2b326442a58a874089691af7dd5a4a039f30551b2b2c11aa1a0dd0cfdc66d5a1ed311d6e331599faec066af94f65ebbdc7b1c9813da0216de612e340a7381a6b73d692bdb093f307fc904b0a44b63b478a88454c05730ba2ea071006ab4132bdfc3bc94994f8958636e7e7a1564117cc543043bb",
                   "ccb0d6ca8525fe14d283a29b4a673ef0b5dae276ff60dc346cb28a83144b3f2f788f7876e817e58eb2944f51cc4b15a815b30f8dfffacf2cac2ddab94a2ff5ac0e14adc2f56ec6bb9bcb66988c165ecb530bd7abc8c7068be9fbc66d53cbd6f42f07b4accab7019d09ec73286d2406d10748209cc0bb1b2d03da14cc7cb7ebdb",
                   "d4bb5a43bc21ea77eab86aca9636d4e7c0d2596d8bc3a00c1ae26a3e442fa2530fbdb8f93e2fd14fa8e26809e5d27b193cdb092fc1c287aba9d132f54764cd95abc77c6e007cc588022a3ff4910ca54f8ea23e836bf6baaec3b701bb0a1a68a3f2af825971f70f347ea260e6e3bd9cf922229f6c366a4c0e113a4f5f45bfb54f",
                   "D1C72114B7EC80C0BBFBF512FB4B52CA7F0EABCB5FC5ACF31A14CDB49BB4C95C213160351B39FD154DB3F783AB8A3F09999719368CF254401EBD8F64A13E4F3E65C4B96DD2F1A48D1812548DD8655245111E37469DE300A288E60D1E3674FEF99BB0C2E17188370B470A5F8851CA1F0C6E7B1020D1192F30EDB6A90777CC3957",
                   "FB309114DA74B0E1B9D65B59F638B72C0B76EC2A5C2B3BE6DFDA2DCFBBE9D073FAFFDCEB712A714E60C697563E1312D6BA3B3808365EE6974022A25541EF2DAB4151DF021575C3A67BE746782ABDE4A371A24BEB615E769AD8AD46FAA6113A2E12C605C923EF22014A6FD7F22C1CA1F13B988C21B73A0F232BE300C1084D1A23",
                   "E70CA10EE2675809EB6565A9D54799B5947E2090947F22EA8D2A55A33B9B395DC5F626C0F5E46FE438D55867F9752422A3109A1F764F5A4C455252F931C53C38788A133EEAE2D34604A7162B0AA5F89733A32259BB4AA1C20E2FD190F57F425E6C6B6A1F744C417BE1C66C9F436A52650E438F23D5002C5C0C25A41686B5BC6B",
                   "F4238DB0B6237AB1170A75140F50B1344EAFA15127F8027D210A525720BEF0675F9829CDB3917A7AB5728E5A8276E7A6A610D2A73DD8DDC6BEB96BDB72C5B3A8D52DA46B919E6765568076F5C59A771E6C651D480E00FA71580092D2C94037D14F1281215F5C1718BB5D72254787AD771A75DA6C5D33C5976DEFA898BF7304B3",
                   "D03E9702648056ACA9D252A2E17F6BBC215BE40CB76DFC6C2F36BBD3DF380378321AE0C06578FB363BA364D34EAE96F6C3D0484BC753776BDA60097A681A2F36C9377B50347A1F8C3A1BEBB571E05278B35ACF6546D586C0EFCB22A884882ECE480A4CFA648756594F6F2D81CA964C55A6FFCE64221223D7D56965BCC060FFC3",
                   "F63594C1249574BD9BD30172B6D162D01069668C1063A0FA21465DF634F6C334DAE8E07EC34AEBACCBE38A5B5D88969F3EEB518562E7180B97FE022F959D0E0A32D1501162EB4F56C1B224994D8639366EE4A53B767E50BB45F2AC40210D2CFE154B0E442467293AB98EB054B549600666736503BD39C19B530315C668D63F67",
                   "D26E19247917D3EDB99F1960983F2290A1FB7510DB823816BF509B0D5B30D3066185E763230DD236E9C71829B323D5BF47E3062CDEE566D44978F542D4B41215FD5736F0A054F7AB610F6553D5BC1A75225D093D87017173DF2F299525273C22CFECA575D67912BF2D3551BADBFA331BCE6D58531E4466E108518C47BEB180A7"};



char *QT_hex[] = {"e4d2fcd44d6bda22588e7f64e47fb32b1783cdc6ea43df8618cd27ae50e38a7d2ff1a252aec54625ab497f3cfe5860547ee0c66cb4ca0e29ccb1098fa3c04cee2565a20510596f5e0c8e4e2adde5aedcbb1803250f3465941880055798f1e36f5ba60e8878328132c070c6fad3c8ad2c155fd4cc88927f4410d498a5a5e40d8b",
                   "ec9732ba347856682086c6538a7a642e18fc409846d25a33afe835a6c0f71e73c70c4ab664c73e1c48750e53e3f86730f8c25f02d8836151be2d0a1575e291dae444d09d5568287ec8fbb7a2bc7a90ddd30d71d33190a521d7f3600ee4a1be514004bd650f100a0fc0e75e202d13fbde36a2bf055a6de03ba8d8fa968a619be3",
                   "ff095fd68d025eb5051e4d06c3b581ce23cd599013bdb9485b3775df8f4af936b6b60906269f48380f71fa49eb04970ab15e4d5ed2b1bbcfc1c2b5f8ed1ee5bee8a8d791dbe3e420f672aeb5d830c632ddc02de95b042ea943341ed73bab492ca32f1ba4c0cdace982e8c1c249e5c92a39e272b79eb09caf294fee74a42a330f",
                   "e93b9900d422108975781193a0b52bd466ed584946251148a37d952df2da8d6366869823aff52b7435ade7ac8a21424db364a63fb2a04375361fe145d3f57cf43fa1cc1b6f52f58ad10ec8f0a9de8bf20a4bb4bcdb82a41eb07e2f1265ebb5d0d490e606dff1a2f5c09fbf3aa68ee4bcc1cb7291ddfad691a27ff277e6126c7b",
                   "e15a6a18a7b6bf0893c00526202ea5fcb7cde901f780406ea78ca951459ce3130fd65687badb4a8e41bbe676c672ff7b5914ca983bf0937fe5f423f2e655b144302a3ae17d2a3f1ef9d779baac67939924ba1a0210d37bc2badb90c76d38daa74704eb93cec5588f2452b9829511332cc7e5933e08392839b79a8cd8336948ab",
                   "F890B673647DE4FEA41CAA06907E226F446166ADCE49B635FB6504B4EDD6501B53AD3E68A0859D22E7FE461C8DAAAAACEC197407A942A85C461FD1E1A46DDE694EB41E9E72FAC45ED7ECE12253AA3363AAA61409372A27ED5A2D3BD6FF59FC26B9E0EFA76CD17AD9128821B32B2D7887934838B12E05C5E0AD7399876BFADF97",
                   "D022D76DED4A8DFA49926E60ED0148C34E839973682633D4D8168E4B58DC950367BB262F92780924D6A54CB2D3592D203DFC1E5057022993310596885263C4B521BBFF4BAE2C86E3731F32A6C5F048558B7B358788FB3C1B1A5B6FBD106D92B49C0982F3F085BE1DD6C0C1DFBCF150ECAE1265C71B1F4B36F8ABC9C363A3A72F",
                   "C56AFD488DC3E731BC8C45B290464CE5E2972BDA7586B81BBF8102E04AC5F6BBC73CF0B6F7467CF6AD7833F0CCF43EEE14DCB203C6B98801BB0E021591DB04872BF26352E540068094F03C7C549D3D377170B7DFAC5810ED91ED4158C655242C25B2F494664BDFEB86DC877C53F4E755670185E542489423A7134CB9D85210F7",
                   "D8CE89E0ED56A6BB6C65B65FF0DAE68B8A65675D5FC3A415CF54126DBC1580FAB23C5FDDD603A8395D80C284440643FF33BFE84E9275AC95CDA2CC29FCD2A16AE4F20F3D22CEF9AB33833A25507C4EE70D24110493192A619FC1298341A6FDA48D91DCB01C0AA402AB311CF88227832BD3025ED4850C824AAF0D4E235CC6F813",
                   "C346063FEC83F926B44F55785F079233D6FB13814A5EC3D98F7756C5EF4D5FB7B5523DD9122592151865E12F02F87FE8F005024E814AEC3DACBD66F3C2CFCA3EB6397ECE6F04BCC1EE0B1B7CF34CE7AA611B50C1622738ADFFDCF55AA270C86BA104386F9F58C5758F4B02B7F44174B2B8429BABDC263DB4D2576CE0BEB70503",
                   "D522D84AA79E269413631D526B11D09A621F717A585385033109EC8F7A1A0DBFE74572B6C9BAA2D9AE8B8E994A08B97531A2D4852BF077314205599EA0A4EECC1535620AD88BC5C54BED9ED0BB00607063AF31B9D9DC13499E66125E2C998CCA8C6FF82B328011D3BC5680477981EA34B39385D8A44BB0F44DEEA5D43854EE17",
                   "D365FE411E7F07CC94B6377126BD9EE5D133F1908B6EECF514D7ABC91BF6C3BA7818E7EFD5F12092C8D733A69CF0BAB8212271BFF54F44387AD61B4E7A204459CE55230E749F799968729E8A40251803091200D1E8D35138CD827E40EFF9C3A5FB64AB444E5D7F0F0AFB8CFFA6B830C4B0E4B93CBBFC20B28B795C396EF28F5F"};


typedef struct
{
    int t;
    int n;

} CG21_NETWORK;

typedef struct
{
    octet *rid;
    octet *i;
    octet *X_packed;
    octet *j_packed;

} CG21_KEYGEN_DATA;

typedef struct
{
    int n2;
    int t2;
    int t1;
    octet *ID;
    csprng *RNG;
    CG21_SSID *ssid;
    CG21_AUX_ROUND1_OUT *round1Out;
    CG21_AUX_ROUND1_STORE_PRIV *round1StorePriv;
    CG21_AUX_ROUND1_STORE_PUB *round1StorePub;
    CG21_AUX_ROUND2 *round2;
    CG21_AUX_ROUND3 *round3;
    CG21_AUX_OUTPUT *output;
    CG21_KEYGEN_DATA *keygenData;
    CG21_PAILLIER_KEYS *paillierKeys;
    CG21_PEDERSEN_KEYS *pedersenKeys;

} CG21_AUX_SESSION;

int file_read_tn(CG21_AUX_SESSION *auxSession){
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

    auxSession->t1 = t_;
    auxSession->t2 = t;
    auxSession->n2 = n;

    printf("\nt1: %d, (t2: %d,n2: %d)",auxSession->t1,auxSession->t2,auxSession->n2);


    fclose(file);

    return 0;
}

int file_read_keygen(const CG21_AUX_SESSION *auxSession, CG21_KEYGEN_DATA *keygenData){
    FILE *file = fopen("cg21_reshare.csv", "r");
    if (file == NULL) {
        printf("Error: could not open file.\n");
        return 1;
    }

    // skip the first line
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

    char *t3 = strtok(line, ",");
    t3 = strtok(NULL, ",");
    OCT_fromHex(keygenData->rid, t3);
    printf("\nrid=");
    OCT_output(keygenData->rid);

    for (int i=0; i<auxSession->n2; i++) {
        if (fgets(line, 2000, file)==NULL){
            exit(1);
        }

        const char *t2 = strtok(line, ",");
        OCT_fromHex(keygenData[i].i, t2);

        // skip the next parameter in the file
        t2 = strtok(NULL, ",");

        // load packed set of Xi
        t2 = strtok(NULL, ",");

        // convert packed set of Xi to octet
        OCT_fromHex(keygenData[i].X_packed, t2);

        // load packed j values
        t2 = strtok(NULL, ",");

        // convert the packed j values to octet
        OCT_fromHex(keygenData[i].j_packed, t2);

        printf("i=");
        OCT_output(keygenData[i].i);

        printf("j-packed=");
        OCT_output(keygenData[i].j_packed);

        printf("Xi-packed=");
        OCT_output(keygenData[i].X_packed);
    }
    /* Close the file */
    fclose(file);

    return 0;
}

void cg21_aux_round1(CG21_AUX_SESSION *auxSession) {

    for (int i = 0; i < auxSession->n2; i++) {

        // get ssid
        CG21_AUX_FORM_SSID(&auxSession->ssid[i], auxSession->keygenData->rid, auxSession->keygenData[i].X_packed,
                           auxSession->keygenData[i].j_packed, auxSession->t1);

        // generate proof for Pi-PRM and then generate V
        int rc = CG21_AUX_ROUND1_GEN_V(auxSession->RNG, &auxSession->round1StorePub[i],
                              &auxSession->round1StorePriv[i],
                              &auxSession->round1Out[i],
                              &auxSession->paillierKeys[i],
                              &auxSession->ssid[i],
                              &auxSession->pedersenKeys[i],
                              i + 1, // Player's IDs start from 1 instead of 0
                              auxSession->t1);

        if (rc != CG21_OK){
            printf("V generation failed, %d\n", rc);
            exit(rc);
        }

        printf("\nPlayer %d: Pi_PRM proof generated", i+1);
        printf("\n-----------------------------");
    }
}

void cg21_aux_round2(CG21_AUX_SESSION *auxSession){

    // each party stores (ssid, i, V_i) received from other parties in Round1
    for (int i = 0; i < auxSession->n2; i++) {
        int c = 0;
        for (int j = 0; j < auxSession->n2; j++) {

            // parties won't get their own (ssid, i, V_i) from broadcast channel
            if (i == j) {
                continue;
            }
            // receive V and i values from round1_store_priv
            auxSession->round2[i].V[c] = *auxSession->round1Out[j].V ;
            auxSession->round2[i].j[c] = auxSession->round1Out[j].i ;

            // receive SSID
            auxSession->round2[i].ssid.g[c] = *auxSession->ssid[j].g;
            auxSession->round2[i].ssid.q[c] = *auxSession->ssid[j].q;
            auxSession->round2[i].ssid.rid[c] = *auxSession->ssid[j].rid;
            auxSession->round2[i].ssid.rho[c] = *auxSession->ssid[j].rho;
            auxSession->round2[i].ssid.X_set_packed[c] = *auxSession->ssid[j].X_set_packed;
            auxSession->round2[i].ssid.j_set_packed[c] = *auxSession->ssid[j].j_set_packed;

            c++;
        }
    }

    // each party checks whether the received ssid is already in its database
    for (int i = 0; i < auxSession->n2; i++) {
        for (int j = 0; j < auxSession->n2-1; j++) {

            CG21_SSID t;
            t.j_set_packed = &auxSession->round2[i].ssid.j_set_packed[j];
            t.X_set_packed = &auxSession->round2[i].ssid.X_set_packed[j];
            t.rid = &auxSession->round2[i].ssid.rid[j];
            t.rho = &auxSession->round2[i].ssid.rho[j];
            t.g = &auxSession->round2[i].ssid.g[j];
            t.q = &auxSession->round2[i].ssid.q[j];

            // check received ssid
            int ret = CG21_AUX_ROUND3_CHECK_SSID(&t, auxSession->keygenData->rid, NULL,
                                                 &auxSession->ssid[i],
                                                 auxSession->t1,false);
            if (ret != CG21_OK){
                printf("\nssid is unknown!, %d", ret);
                exit(1);
            }
        }
    }

    //each party broadcasts (ssid,i,n,s,t,rho,u)
}

void cg21_aux_round3(CG21_AUX_SESSION *auxSession){

    // check ssid, V and N
    for (int i = 0; i < auxSession->n2; i++) {
        for (int j = 0; j < auxSession->n2; j++) {

            // parties won't get their own data from broadcast channel
            if (i == j) {
                continue;
            }

            CG21_SSID ssid;
            ssid.j_set_packed = auxSession->ssid[j].j_set_packed;
            ssid.X_set_packed = auxSession->ssid[j].X_set_packed;
            ssid.rid = auxSession->ssid[j].rid;
            ssid.g = auxSession->ssid[j].g;
            ssid.q = auxSession->ssid[j].q;

            // check received ssid
            int ret = CG21_AUX_ROUND3_CHECK_SSID(&ssid, auxSession->keygenData->rid, NULL,
                                                 &auxSession->ssid[i],
                                                 auxSession->t1,false);
            if (ret != CG21_OK){
                printf("\nssid is unknown, %d!", ret);
                exit(1);
            }

            // check V and N
            ret = CG21_AUX_ROUND3_CHECK_V_N(&ssid,
                                            auxSession->round1StorePub[j],
                                            &auxSession->round1Out[j]);
            if (ret != CG21_OK){
                printf("\nCG21_AUX_ROUND2_CHECK_V_N failed, %d!\n", ret);
                exit(1);
            }

            int rc = CG21_PI_PRM_VERIFY_HELPER(&auxSession->round1StorePub[j],&auxSession->ssid[j]);
            if (rc != CG21_OK)
            {
                printf("Pi_PRM proof verification failed, %d\n", rc);
                exit(rc);
            }
            printf("\nPlayer %d: verified record:%d Pi_PRM proof", i+1, j+1);
        }
    }

    // xor partial rho
    printf("\n");
    for (int i = 0; i < auxSession->n2; i++) {
        CG21_AUX_ROUND3_XOR_RHO(&auxSession->round1StorePub[i],
                                &auxSession->round3[i], true);

        for (int j = 0; j < auxSession->n2; j++) {
            if (i == j) {
                continue;
            }
            CG21_AUX_ROUND3_XOR_RHO(&auxSession->round1StorePub[j],
                                    &auxSession->round3[i], false);
        }
        printf("xored rho=");
        OCT_output(auxSession->round3[i].rho);
    }

    // PiMod, PiFactor: prove
    // here we assume only Player 1 is generating proof the other Players for simplicity
    for (int i = 0; i < auxSession->n2; i++) {
        CG21_SSID ssid;
        ssid.j_set_packed = auxSession->ssid[i].j_set_packed;
        ssid.X_set_packed = auxSession->ssid[i].X_set_packed;
        ssid.rid = auxSession->ssid[i].rid;
        ssid.rho = auxSession->round3[i].rho;
        ssid.g = auxSession->ssid[i].g;
        ssid.q = auxSession->ssid[i].q;

        int rc = CG21_PI_MOD_PROVE_HELPER(auxSession->RNG, &auxSession->round1StorePriv[i],
                                              &ssid,&auxSession->round3[i]);

        if (rc != CG21_OK){
            printf("Pi_MOD proof generation failed, %d\n", rc);
            exit(rc);
        }

        printf("\nPlayer %d: Pi_MOD proof generated", i+1);

        rc = CG21_PI_FACTOR_PROVE_HELPER(auxSession->RNG,&ssid,&auxSession->round1StorePub[i],
                                             &auxSession->round3[i],&auxSession->round1StorePriv[0]);
        if (rc!=CG21_OK){
            printf("\nCG21:PI-factor proof generation failed!,{%d}", rc);
            exit(rc);
        }
        printf("\nPlayer 1: generates pi-factor proof for Player %d", i+1);

        printf("\n-----------------------------");
    }
}

int cg21_output(CG21_AUX_SESSION *auxSession){

    // All Players verify Player 1 pi-factor proof
    for (int i = 1; i < auxSession->n2; i++) {
        CG21_SSID ssid;
        ssid.j_set_packed = auxSession->ssid[i].j_set_packed;
        ssid.X_set_packed = auxSession->ssid[i].X_set_packed;
        ssid.rid = auxSession->ssid[i].rid;
        ssid.rho = auxSession->round3[i].rho;
        ssid.g = auxSession->ssid[i].g;
        ssid.q = auxSession->ssid[i].q;

        int rc = CG21_PI_FACTOR_VERIFY_HELPER(&ssid,&auxSession->round3[i],&auxSession->round1StorePub[0],
                                              &auxSession->round1StorePriv[i]);
        if (rc!=CG21_OK){
            printf("\nCG21:PI-factor proof verification failed!,{%d}", rc);
            exit(rc);
        }
        printf("\nPlayer %d: verified pi-factor proof of Player 1", i+1);

    }

    for (int i = 0; i < auxSession->n2; i++) {
        for (int j = 0; j < auxSession->n2; j++) {

            if (i == j) {
                continue;
            }

            CG21_SSID ssid;
            ssid.j_set_packed = auxSession->ssid[i].j_set_packed;
            ssid.X_set_packed = auxSession->ssid[i].X_set_packed;
            ssid.rid = auxSession->ssid[i].rid;
            ssid.rho = auxSession->round3[i].rho;
            ssid.g = auxSession->ssid[i].g;
            ssid.q = auxSession->ssid[i].q;

            int rc = CG21_PI_MOD_VERIFY_HELPER(&auxSession->round1StorePub[j],&ssid,&auxSession->round3[j]);
            if (rc != CG21_OK)
            {
                printf("Pi_MOD proof verification failed, %d\n", rc);
                exit(rc);
            }

            printf("\nPlayer:%d verified record:%d Pi_PRM/MOD proof", i+1, j+1);
        }
        printf("\n--------------------\n");
    }

    for (int i = 0; i < auxSession->n2; i++) {
        CG21_AUX_PACK_OUTPUT(&auxSession->output[i], auxSession->round1StorePub[i], true);

        for (int j=0; j<auxSession->n2; j++){

            if (i == j) {
                continue;
            }

            CG21_AUX_PACK_OUTPUT(&auxSession->output[i], auxSession->round1StorePub[j],false);
        }
    }

    return CG21_OK;
}

int testPaillierKeys(CG21_PAILLIER_KEYS *pa){
    const char* seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30";
    char seed[16] = {0};
    octet SEED = {sizeof(seed),sizeof(seed),seed};

    // CSPRNG
    csprng RNG;

    // fake random source
    OCT_fromHex(&SEED,seed_hex);

    // initialise strong RNG
    CREATE_CSPRNG(&RNG,&SEED);

    char a1[FS_2048];
    octet A1 = {0,sizeof(a1),a1};
    char b1[FS_2048];
    octet B1 = {0,sizeof(b1),b1};
    char ca1[FS_4096];
    octet CA1 = {0,sizeof(ca1),ca1};

    int v = 5;
    BIG_1024_58 pt[FFLEN_2048];
    FF_2048_init(pt, v, FFLEN_2048);
    FF_2048_toOctet(&A1, pt, FFLEN_2048);

    PAILLIER_ENCRYPT(&RNG, &pa->paillier_pk, &A1, &CA1, NULL);
    PAILLIER_DECRYPT(&pa->paillier_sk, &CA1, &B1);

    int rc = OCT_comp(&B1, &A1);
    if (rc != 1){
        printf("\nDecryption failed!");
        exit(1);
    }

    return CG21_OK;
}

void validation(CG21_AUX_SESSION *auxSession){

    for (int i=1; i<auxSession->n2; i++){

        // test Paillier keys
        testPaillierKeys(&auxSession->paillierKeys[i]);

        // parties should have similar N/s/t/j packed sets but probably with different orders
        int rc = CG21_set_comp(auxSession->output[0].N,auxSession->output[0].j,
                           auxSession->output[i].N,auxSession->output[i].j,
                           auxSession->n2,FS_2048);
        if (rc != 1){
            printf("\nGenerated packed N are not similar");
            exit(1);
        }


        rc = CG21_set_comp(auxSession->output[0].t,auxSession->output[0].j,
                           auxSession->output[i].t,auxSession->output[i].j,
                           auxSession->n2,FS_2048);
        if (rc != 1){
            printf("\nGenerated packed t are not similar");
            exit(1);
        }

        rc = CG21_set_comp(auxSession->output[0].s,auxSession->output[0].j,
                           auxSession->output[i].s,auxSession->output[i].j,
                           auxSession->n2,FS_2048);
        if (rc != 1){
            printf("\nGenerated packed s are not similar");
            exit(1);
        }
    }

    printf("\nValidation is passed successfully.");
}

void Store_CSV_OCT_Helper(FILE *fpt, const octet * oct){
    unsigned char ch;
    for (int i=0; i<oct->len; i++)
    {
        ch=oct->val[i];
        fprintf(fpt,"%02x",ch);
    }
}

void Store_CSV(const CG21_AUX_SESSION *auxSession, int n){
    FILE *fpt;
    fpt = fopen("cg21_aux.csv", "w+");
    fprintf(fpt,"%d", n);

    for (int i=0; i<n; i++){
        fprintf(fpt,"\n");
        Store_CSV_OCT_Helper(fpt, auxSession->output[i].j);
        fprintf(fpt,",");
        Store_CSV_OCT_Helper(fpt, auxSession->output[i].N);
        fprintf(fpt,",");
        Store_CSV_OCT_Helper(fpt, auxSession->output[i].s);
        fprintf(fpt,",");
        Store_CSV_OCT_Helper(fpt, auxSession->output[i].t);
    }

    if (fpt){
        fclose(fpt);
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

    CG21_AUX_SESSION auxSession;
    auxSession.RNG = &RNG;
    file_read_tn(&auxSession);

    int n = auxSession.n2;

    if (n < 2){
        printf("\nn is very small!");
        exit(1);
    }

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

    if (n>12){
        printf("\nn cannot be larger than 12 in this example!");
        exit(1);
    }

    //****** loading X_set_packed and j_set_packed from file **********
    char keygen_j_packed[n][n * 4 + 1];
    char keygen_X_set_packed[n][n * (EFS_SECP256K1 + 1)];
    char keygen_i[n][EGS_SECP256K1];
    char keygen_rid[EGS_SECP256K1];

    octet KEYGEN_j_PACKED[n];
    octet KEYGEN_X_SET_PACKED[n];
    octet KEYGEN_i[n];
    octet KEYGEN_rid = {0, sizeof(keygen_rid), keygen_rid};

    init_octets((char *)keygen_j_packed, KEYGEN_j_PACKED, (n * 4 + 1), n);
    init_octets((char *)keygen_X_set_packed, KEYGEN_X_SET_PACKED, n * (EFS_SECP256K1 + 1), n);
    init_octets((char *)keygen_i, KEYGEN_i, EGS_SECP256K1, n);

    CG21_KEYGEN_DATA keygenData[n];

    for (int i=0;i<n;i++){
        keygenData[i].i = KEYGEN_i + i;
        keygenData[i].j_packed = KEYGEN_j_PACKED + i;
        keygenData[i].X_packed = KEYGEN_X_SET_PACKED + i;
    }
    keygenData->rid = &KEYGEN_rid;
    file_read_keygen(&auxSession, keygenData);
    auxSession.keygenData = keygenData;


    /*---------- CG21_AUX_ROUND1_STORE_PUB ------------*/

    // generate Paillier and Pedersen params
    CG21_PAILLIER_KEYS paillierKeys[n];
    CG21_PEDERSEN_KEYS pedersenKeys[n];

    auxSession.paillierKeys = paillierKeys;
    auxSession.pedersenKeys = pedersenKeys;


    // note: based on the CG21(CSS20):Figure 5, same safe primes p,q are used for both Paillier and Pedersen
    for (int i=0; i<n; i++){
        // Generate Paillier Keys
        PAILLIER_KEY_PAIR(NULL, &P[i],&Q[i], &paillierKeys[i].paillier_pk,
                          &paillierKeys[i].paillier_sk);

        // Generate Pedersen Keys
        ring_Pedersen_setup(&RNG, &pedersenKeys[i].pedersenPriv, &P[i],&Q[i]);

        // copy Pedersen public params into another structure to be shared
        Pedersen_get_public_param(&pedersenKeys[i].pedersenPub, &pedersenKeys[i].pedersenPriv);
        printf("\n{N}=");
        FF_2048_output(pedersenKeys[i].pedersenPub.N, FFLEN_2048);
        printf("\n{s}=");
        FF_2048_output(pedersenKeys[i].pedersenPub.b0, FFLEN_2048);
        printf("\n{t}=");
        FF_2048_output(pedersenKeys[i].pedersenPub.b1, FFLEN_2048);
        printf("\n-----------------------------\n");
    }

    // define and initialize variables for Aux. Round1
    char round1_V[n][SHA256];
    char round1_u[n][EGS_SECP256K1];
    char round1_rho[n][EGS_SECP256K1];
    char ped_pack[n][3*FS_2048];
    char pai_pack[n][FS_4096+HFS_4096];
    char ped_pack_priv[n][6*FS_2048+3*HFS_2048];
    char pai_pack_priv[n][2*HFS_2048];
    char round1_prm_rho[n][HDLOG_VALUES_SIZE];  // for PiPRM
    char round1_prm_irho[n][HDLOG_VALUES_SIZE]; // for PiPRM
    char round1_prm_t[n][HDLOG_VALUES_SIZE];    // for PiPRM
    char round1_prm_it[n][HDLOG_VALUES_SIZE];   // for PiPRM

    octet ROUND1_V[n];
    octet ROUND1_u[n];
    octet ROUND1_rho[n];
    octet ROUND1_PedPub[n];
    octet ROUND1_PaiPub[n];
    octet ROUND1_PedPriv[n];
    octet ROUND1_PaiPriv[n];
    octet ROUND1_PRM_rho[n];    // for PiPRM
    octet ROUND1_PRM_irho[n];   // for PiPRM
    octet ROUND1_PRM_t[n];      // for PiPRM
    octet ROUND1_PRM_it[n];     // for PiPRM

    init_octets((char *) round1_V, ROUND1_V, SHA256, n);
    init_octets((char *) round1_u, ROUND1_u, EGS_SECP256K1, n);
    init_octets((char *) round1_rho, ROUND1_rho, EGS_SECP256K1, n);
    init_octets((char *) ped_pack, ROUND1_PedPub, 3*FS_2048, n);
    init_octets((char *) pai_pack, ROUND1_PaiPub, FS_4096+HFS_4096, n);
    init_octets((char *) ped_pack_priv, ROUND1_PedPriv, 6*FS_2048+3*HFS_2048, n);
    init_octets((char *) pai_pack_priv, ROUND1_PaiPriv, 2*HFS_2048, n);
    init_octets((char *)round1_prm_rho, ROUND1_PRM_rho, HDLOG_VALUES_SIZE, n);
    init_octets((char *)round1_prm_irho, ROUND1_PRM_irho, HDLOG_VALUES_SIZE, n);
    init_octets((char *)round1_prm_t, ROUND1_PRM_t, HDLOG_VALUES_SIZE, n);
    init_octets((char *)round1_prm_it, ROUND1_PRM_it, HDLOG_VALUES_SIZE, n);


    CG21_AUX_ROUND1_STORE_PUB rnd1StorePub[n];
    CG21_AUX_ROUND1_OUT rnd1Out[n];
    CG21_AUX_ROUND1_STORE_PRIV rnd1StorePriv[n];

    auxSession.round1Out=rnd1Out;
    auxSession.round1StorePriv=rnd1StorePriv;
    auxSession.round1StorePub=rnd1StorePub;

    for (int i = 0; i < n; i++) {
        rnd1StorePub[i].u = ROUND1_u + i;
        rnd1StorePub[i].rho = ROUND1_rho + i;
        rnd1StorePub[i].PedPub = ROUND1_PedPub + i;
        rnd1StorePub[i].PaiPub = ROUND1_PaiPub + i;
        rnd1StorePub[i].pedersenProof.rho = ROUND1_PRM_rho + i;
        rnd1StorePub[i].pedersenProof.irho = ROUND1_PRM_irho + i;
        rnd1StorePub[i].pedersenProof.t = ROUND1_PRM_t + i;
        rnd1StorePub[i].pedersenProof.it = ROUND1_PRM_it + i;

        rnd1Out[i].V = ROUND1_V + i;

        rnd1StorePriv[i].PEDERSEN_PRIV = ROUND1_PedPriv + i;
        rnd1StorePriv[i].Paillier_PRIV = ROUND1_PaiPriv + i;
    }

    // define and initialize variables for SSID
    char xored_rid[n][EGS_SECP256K1];
    char xored_rho[n][EGS_SECP256K1];
    char j_packed[n][n * 4 + 1];
    char X_set_packed[n][n * (EFS_SECP256K1 + 1)];
    char order[n][EFS_SECP256K1];
    char generator[n][EFS_SECP256K1 + 1];
    int n1[n];

    octet XORed_rid[n];
    octet XORed_rho[n];
    octet j_SET_PACKED[n];
    octet X_SET_PACKED[n];
    octet q_oct[n];
    octet g_oct[n];

    init_octets((char *)xored_rho,  XORed_rho,  EGS_SECP256K1, n);
    init_octets((char *)xored_rid,  XORed_rid,  EGS_SECP256K1, n);
    init_octets((char *)j_packed, j_SET_PACKED, (n * 4 + 1), n);
    init_octets((char *)X_set_packed, X_SET_PACKED, n * (EFS_SECP256K1 + 1), n);
    init_octets((char *)order, q_oct, EFS_SECP256K1,      n);
    init_octets((char *)generator, g_oct, EFS_SECP256K1 + 1,      n);

    CG21_SSID ssid[n];
    auxSession.ssid = ssid;
    for (int i = 0; i < n; i++) {
        ssid[i].rid = XORed_rid + i;
        ssid[i].rho = XORed_rho + i;
        ssid[i].j_set_packed = j_SET_PACKED + i;
        ssid[i].X_set_packed = X_SET_PACKED + i;
        ssid[i].q = q_oct + i;
        ssid[i].g = g_oct + i;
        ssid[i].n1 = n1 + i;
    }

    // generate V, store (rho and u), broadcast (ssid, i, V)
    cg21_aux_round1(&auxSession);

    /* Key generation round2   */
    char round2_V[n][n-1][SHA256];
    char round2_xored_rid[n][n-1][EGS_SECP256K1];
    char round2_xored_rho[n][n-1][EGS_SECP256K1];
    char round2_j_packed[n][n-1][n * 4 + 1];
    char round2_X_set_packed[n][n-1][n * (EFS_SECP256K1 + 1)];
    char round2_order[n][n-1][EFS_SECP256K1];
    char round2_generator[n][n-1][EFS_SECP256K1 + 1];

    octet ROUND2_V[n * (n - 1)];
    octet ROUND2_XORed_rid[n * (n - 1)];
    octet ROUND2_XORed_rho[n * (n - 1)];
    octet ROUND2_j_SET_PACKED[n * (n - 1)];
    octet ROUND2_X_SET_PACKED[n * (n - 1)];
    octet ROUND2_q_oct[n * (n - 1)];
    octet ROUND2_g_oct[n * (n - 1)];
    int ROUND2_j[n * (n - 1)];

    init_octets((char *)round2_V, ROUND2_V, SHA256, n * (n - 1));
    init_octets((char *)round2_xored_rid, ROUND2_XORed_rid, EGS_SECP256K1, n * (n - 1));
    init_octets((char *)round2_xored_rho, ROUND2_XORed_rho, EGS_SECP256K1, n * (n - 1));
    init_octets((char *)round2_j_packed, ROUND2_j_SET_PACKED, n * 4 + 1, n * (n - 1));
    init_octets((char *)round2_X_set_packed, ROUND2_X_SET_PACKED, n * (EFS_SECP256K1 + 1), n * (n - 1));
    init_octets((char *)round2_order, ROUND2_q_oct, EFS_SECP256K1, n * (n - 1));
    init_octets((char *)round2_generator, ROUND2_g_oct, EFS_SECP256K1 + 1, n * (n - 1));

    CG21_AUX_ROUND2 auxRound2[n];

    auxSession.round2=auxRound2;

    for (int i = 0; i < n; i++) {
        auxRound2[i].j = ROUND2_j + ((n - 1) * i);
        auxRound2[i].V = ROUND2_V + ((n - 1) * i);
        auxRound2[i].ssid.q = ROUND2_q_oct + ((n - 1) * i);
        auxRound2[i].ssid.g = ROUND2_g_oct + ((n - 1) * i);
        auxRound2[i].ssid.j_set_packed = ROUND2_j_SET_PACKED + ((n - 1) * i);
        auxRound2[i].ssid.X_set_packed = ROUND2_X_SET_PACKED + ((n - 1) * i);
        auxRound2[i].ssid.rid = ROUND2_XORed_rid + ((n - 1) * i);
        auxRound2[i].ssid.rho = ROUND2_XORed_rho + ((n - 1) * i);
    }

    cg21_aux_round2(&auxSession);


    /* Key generation round3Store   */

    // for PiMod
    char round3_rho[n][EGS_SECP256K1];
    char round3_x[n][CG21_PAILLIER_PROOF_SIZE];
    char round3_z[n][CG21_PAILLIER_PROOF_SIZE];
    char round3_ab[n][CG21_PAILLIER_PROOF_ITERS*4];
    char round3_w[n][HFS_4096];

    // for PiFactor
    char round3_sigma[n][2*FS_2048+HFS_2048];
    char round3_P_[n][FS_2048];
    char round3_Q_[n][FS_2048];
    char round3_A[n][FS_2048];
    char round3_B[n][FS_2048];
    char round3_T[n][FS_2048];
    char round3_z1[n][FS_2048 + HFS_2048];
    char round3_z2[n][FS_2048 + HFS_2048];
    char round3_w1[n][FS_2048 + HFS_2048];
    char round3_w2[n][FS_2048 + HFS_2048];
    char round3_v[n][2*FS_2048 + HFS_2048];

    // for PiMod
    octet ROUND3_rho[n];
    octet ROUND3_X[n];
    octet ROUND3_Z[n];
    octet ROUND3_AB[n];
    octet ROUND3_W[n];

    // for PiFactor
    octet ROUND3_sigma[n];
    octet ROUND3_P[n];
    octet ROUND3_Q[n];
    octet ROUND3_A[n];
    octet ROUND3_B[n];
    octet ROUND3_T[n];
    octet ROUND3_z1[n];
    octet ROUND3_z2[n];
    octet ROUND3_w1[n];
    octet ROUND3_w2[n];
    octet ROUND3_v[n];

    init_octets((char *)round3_rho, ROUND3_rho, EGS_SECP256K1, n);
    init_octets((char *)round3_x, ROUND3_X, CG21_PAILLIER_PROOF_SIZE, n);
    init_octets((char *)round3_z, ROUND3_Z, CG21_PAILLIER_PROOF_SIZE, n);
    init_octets((char *)round3_ab, ROUND3_AB, CG21_PAILLIER_PROOF_ITERS*4, n);
    init_octets((char *)round3_w, ROUND3_W, HFS_4096, n);
    init_octets((char *)round3_sigma, ROUND3_sigma, 2*FS_2048+HFS_2048, n);
    init_octets((char *)round3_P_, ROUND3_P, FS_2048, n);
    init_octets((char *)round3_Q_, ROUND3_Q, FS_2048, n);
    init_octets((char *)round3_A, ROUND3_A, FS_2048, n);
    init_octets((char *)round3_B, ROUND3_B, FS_2048, n);
    init_octets((char *)round3_T, ROUND3_T, FS_2048, n);
    init_octets((char *)round3_z1, ROUND3_z1, FS_2048 + HFS_2048, n);
    init_octets((char *)round3_z2, ROUND3_z2, FS_2048 + HFS_2048, n);
    init_octets((char *)round3_w1, ROUND3_w1, FS_2048 + HFS_2048, n);
    init_octets((char *)round3_w2, ROUND3_w2, FS_2048 + HFS_2048, n);
    init_octets((char *)round3_v, ROUND3_v, 2*FS_2048 + HFS_2048, n);

    CG21_AUX_ROUND3 auxRound3[n];
    auxSession.round3=auxRound3;

    for (int i = 0; i < n; i++) {

        auxRound3[i].rho = ROUND3_rho + i;

        auxRound3[i].paillierProof.x =  ROUND3_X + i;
        auxRound3[i].paillierProof.w =  ROUND3_W + i;
        auxRound3[i].paillierProof.z =  ROUND3_Z + i;
        auxRound3[i].paillierProof.ab =  ROUND3_AB + i;

        auxRound3[i].factorCommits.sigma = ROUND3_sigma+i;
        auxRound3[i].factorCommits.P = ROUND3_P+i;
        auxRound3[i].factorCommits.Q = ROUND3_Q+i;
        auxRound3[i].factorCommits.A = ROUND3_A+i;
        auxRound3[i].factorCommits.B = ROUND3_B+i;
        auxRound3[i].factorCommits.T = ROUND3_T+i;

        auxRound3[i].factorProof.v = ROUND3_v+i;
        auxRound3[i].factorProof.w1 = ROUND3_w1+i;
        auxRound3[i].factorProof.w2 = ROUND3_w2+i;
        auxRound3[i].factorProof.z1 = ROUND3_z1+i;
        auxRound3[i].factorProof.z2 = ROUND3_z2+i;
    }
    cg21_aux_round3(&auxSession);

    // for packing N_i, s_i, t_i
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

    CG21_AUX_OUTPUT output[n];
    auxSession.output = output;

    for (int i = 0; i < n; i++) {
        output[i].N = ROUND4_N_SET_PACKED + i;
        output[i].s = ROUND4_s_SET_PACKED + i;
        output[i].t = ROUND4_t_SET_PACKED + i;
        output[i].j = ROUND4_i_PACKED + i;
    }

    cg21_output(&auxSession);
    validation(&auxSession);

    Store_CSV(&auxSession, n);

    exit(0);
}
