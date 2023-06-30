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


    In this example, (t1,n1) and (t2,n2) refer to the old and new SSS settings, respectively. T1, T2, N1, and N2
    refer to the different set of IDs. For example, there are t1 different IDs (one for each party) in T1.

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
// Safe primes for Paillier key generation
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


char *RHO = "43defa8e95a95b370308ef5a3e5f7958cb50ba8c1ce07b8381ed27b2859b1af3";

/*
 * Steps:

 */

typedef struct
{
    int t;
    int n;

} CG21_NETWORK;

typedef struct
{
    octet *rid;
    octet *Xi;  // x-coord of partial ECDSA sk
    octet *Yi;  // y-coord of partial ECDSA sk
    octet *X_packed;    // packed partial PK generated in KeyGen
    octet *j_packed;    // ID of each corresponding partial PK in X_packed in packed form
    octet *packed_pk_sum_shares;    // packed PK of each player sum-of-shares generated in KeyGen
    octet *PK; // ECDSA main public key

} CG21_KEYGEN_DATA;

typedef struct
{
    CG21_NETWORK *network;
    CG21_RESHARE_SETTING setting;
    CG21_SSID *ssid;
    CG21_KEYGEN_DATA *keygenData;
    SSS_shares *shares;
    octet *RHO;
    csprng *RNG;
    CG21_PAILLIER_KEYS *paillierKeys;
    CG21_RESHARE_ROUND1_STORE_PUB_T1 *storePubT1;
    CG21_RESHARE_ROUND1_STORE_SECRET_T1 *storeSecretT1;
    CG21_RESHARE_ROUND1_STORE_PUB_N2 *storePubN2;
    CG21_RESHARE_ROUND1_STORE_SECRET_N2 *storeSecretN2;
    CG21_RESHARE_ROUND1_OUT *pubOut;
    CG21_RESHARE_ROUND3_OUTPUT *round3_Output;
    CG21_RESHARE_ROUND4_OUTPUT *round4_Output;
    CG21_RESHARE_ROUND4_STORE *round4_Store;
    CG21_RESHARE_OUTPUT *round5_output;

} CG21_reshare_session;

void init_octets(char* mem, octet *OCTETS, int max, int n)
{
    for (int i = 0; i < n; i++)
    {
        OCTETS[i].val = mem + (i*max);
        OCTETS[i].len = 0;
        OCTETS[i].max = max;
    }
}

int file_read_tn(CG21_reshare_session *session){
    FILE *file = fopen("cg21_keygen.csv", "r");
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

    session->network->t = t;
    session->network->n = n;

    fclose(file);

    return 0;
}

int file_read_keygen(CG21_reshare_session *session){
    FILE *file = fopen("cg21_keygen.csv", "r");
    if (file == NULL) {
        printf("Error: could not open file.\n");
        return 1;
    }

    // skip the first line
    char line[2048];
    if(fgets(line, 10, file)==NULL){
        exit(1);
    }

    if(fgets(line, 2000, file)==NULL){
        exit(1);
    }

    const char *t3 = strtok(line, ",");
    OCT_fromHex(session->keygenData->PK, t3);

    t3 = strtok(NULL, ",");
    OCT_fromHex(session->keygenData->rid, t3);

    printf("\nPK=");
    OCT_output(session->keygenData->PK);

    printf("\nrid=");
    OCT_output(session->keygenData->rid);

    for (int i=0; i<session->network->n; i++) {
        if(fgets(line, 2000, file)==NULL){
            exit(1);
        }

        char *t2 = strtok(line, ",");
        OCT_fromHex(session->keygenData[i].Xi, t2);

        // skip the next parameter in the file
        t2 = strtok(NULL, ",");
        OCT_fromHex(session->keygenData[i].Yi, t2);

        // load packed set of Xi
        t2 = strtok(NULL, ",");

        // convert packed set of Xi to octet
        OCT_fromHex(session->keygenData[i].X_packed, t2);

        // load packed j values
        t2 = strtok(NULL, ",");

        // convert the packed j values to octet
        OCT_fromHex(session->keygenData[i].j_packed, t2);

        // load packed checks
        t2 = strtok(NULL, ",");

        // convert the packed checks values to octet
        OCT_fromHex(session->keygenData[i].packed_pk_sum_shares, t2);

    }
    /* Close the file */
    fclose(file);

    return 0;
}

void usage(char *name, int t, int n)
{
    printf("Usage: %s t n\n", name);
    printf("Current setting is (%d,%d)\n", t,n);
    printf("Run a (t, n) key re-share \n");
    printf("\n");
    printf("  t  New threshold. 2 <= t <= %d \n", n);
    printf("  n  New number of participants in the TSS protocol. 2 <= t <= n\n");
    printf("\n");
    printf("Example:\n");
    printf("  %s %d %d\n", name,t+1,n+1);
}

void cg21_form_ssid(CG21_reshare_session *session, int n){
    for (int i=0;i<n;i++) {
        // get ssid
        CG21_AUX_FORM_SSID(&session->ssid[i], session->keygenData->rid,
                           session->keygenData[i].X_packed,
                           session->keygenData[i].j_packed, n);
    }
}

void cg21_form_SSS_share(CG21_reshare_session *session, int n){
    for (int i=0;i<n;i++) {
        OCT_copy(session->shares[i].X, session->keygenData[i].Xi);
        OCT_copy(session->shares[i].Y, session->keygenData[i].Yi);

    }
}

void cg21_key_reshare_round1(CG21_reshare_session *session){

    // --------------- DEBUG ------------
    BIG_256_56 skx;
    BIG_256_56 h;
    BIG_256_56 q;

    ECP_SECP256K1 G;
    ECP_SECP256K1 G1;

    ECP_SECP256K1_generator(&G);
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    char pk[EFS_SECP256K1 + 1];
    octet PK = {0, sizeof(pk), pk};
    // ----------------------------------

    printf("\n\nROUND 1:\n");


    for (int i=0;i< session->setting.t1; i++) {
        // player_id starts from 1
        int rc = CG21_KEY_RESHARE_ROUND1_T1(session->RNG, session->ssid + i, i + 1, session->setting,
                                            session->shares + i,
                                            session->storeSecretT1 + i, session->storePubT1 + i, session->pubOut + i);


        if (rc!=CG21_OK){
            printf("\nCG21_KEY_REFRESH_ROUND1_T1 FAILED!, %d", rc);
            exit(rc);
        }

        // --------------- DEBUG ------------
        // we use skx after the main for loop to validate additive shares
        if (i==0){
            BIG_256_56_fromBytesLen(skx, (session->storeSecretT1 + i)->a->val, (session->storeSecretT1 + i)->a->len);
        }else{
            BIG_256_56_fromBytesLen(h, (session->storeSecretT1 + i)->a->val, (session->storeSecretT1 + i)->a->len);
            BIG_256_56_add(skx, skx, h);
            BIG_256_56_mod(skx, q);
        }
        printf("\tV%d: ",*(session->pubOut+i)->i);
        OCT_output((session->pubOut+i)->V);
    }

    int c = 0;

    for (int i=session->setting.t1;i< session->setting.n2; i++) {
        // player_id starts from 1
        int rc = CG21_KEY_RESHARE_ROUND1_N2(session->RNG, session->ssid + i, i + 1, session->setting,
                                            session->storeSecretN2 + c,
                                            session->storePubN2 + c, session->pubOut + i);

        c = c + 1;
        if (rc != CG21_OK) {
            printf("\nCG21_KEY_REFRESH_ROUND1_T1 FAILED!, %d", rc);
            exit(rc);
        }

        printf("\tV%d: ",*(session->pubOut+i)->i);
        OCT_output((session->pubOut+i)->V);
    }

    // --------------- DEBUG ------------
    // here we validate SSS shares to additive and their corresponding PKs
    // 1- the sums of additive shares multiply by group generator should result in main PK
    // 2- the addition of partial PKs should result in main PK
    ECP_SECP256K1_mul(&G, skx);
    ECP_SECP256K1_toOctet(&PK, &G, true);
    int rc = OCT_comp(&PK, session->keygenData->PK);
    if (rc==0){
        printf("\ndebug: SSS share to additive failed!");
        exit(1);
    }else{
        printf("\ndebug: SSS share to additive is verified");
    }
    ECP_SECP256K1_fromOctet(&G, session->storePubT1->Xi);
    for (int i=1; i< session->setting.t1; i++){
        ECP_SECP256K1_fromOctet(&G1, (session->storePubT1 + i)->Xi);
        ECP_SECP256K1_add(&G, &G1);
    }
    ECP_SECP256K1_toOctet(&PK, &G, true);
    rc = OCT_comp(&PK, session->keygenData->PK);
    if (rc==0){
        printf("\ndebug: Partial PKs, Xi, are invalid");
        exit(1);
    }else{
        printf("\ndebug: Partial PKs, Xi, are verified");
    }
    // ----------------------------------


    // broadcast (pubOut, ssid)
    // store (storePubT1, storeSecretT1) or (storePubN2, storeSecretN2)
}

void cg21_key_reshare_round2(CG21_reshare_session *session){

    for (int i=0;i<session->setting.n2; i++) {
        for (int j=0; j<session->setting.n2; j++){
            if (i==j)
                continue;
            // check received ssid
            CG21_SSID tt;
            tt.j_set_packed = session->keygenData[i].j_packed;
            tt.X_set_packed = session->keygenData[i].X_packed;
            int ret = CG21_AUX_ROUND3_CHECK_SSID(&session->ssid[j], session->keygenData->rid, NULL,
                                                 &tt, session->setting.n1, false);
            if (ret != CG21_OK){
                printf("\nssid is unknown!");
                exit(1);
            }
        }
    }

    // broadcast (ssid,i,rid,rhp_i,u_i,A_i,v_iz,aG_i) or (ssid,i,rid,rhp_i,u_i,A_i)
    // parties in T1 send each vss shares_i to the corresponding receiver securely
}

void cg21_key_reshare_round3(CG21_reshare_session *session){

    // Each player verifies its VSS checks
    for (int i=0; i< session->setting.n2; i++){
        for (int j=0; j<session->setting.t1; j++){
            if (i==j)
                continue;

            int rc = CG21_KEY_RESHARE_ROUND3_CHECK_V_T1(session->ssid + j, session->setting, session->storePubT1 + j,
                                                        session->pubOut + j);
            if (rc!=CG21_OK){
                exit(rc);
            }
        }

        int c = 0;
        for (int j=session->setting.t1; j<session->setting.n2; j++){
            if (i==j) {
                c = c + 1;
                continue;
            }
            int rc = CG21_KEY_RESHARE_ROUND3_CHECK_V_N2(session->ssid + j, session->setting, session->storePubN2 + c,
                                                        session->pubOut + j);

            c = c + 1;
            if (rc!=CG21_OK){
                exit(rc);
            }
        }

        printf("\nParty %d verified its VSS checks successfully", i+1);
    }

    // Each player XORs the given partial rho_i at this stage, but for simplicity of the example file
    // we load the final XORed rho from a hard-coded variable 'RHO'

    // each player in T1 encrypts the results of his VSS using receivers' PK and broadcast them
    for (int i=0;i< session->setting.t1; i++) {

        int t =0;
        for (int j=0;j< session->setting.n2; j++) {

            if (i==j){
                continue;
            }

            CG21_KEY_RESHARE_ENCRYPT_SHARES(session->RNG, &session->paillierKeys[j].paillier_pk, j+1,
                            &session->storeSecretT1[i],session->storePubT1[i],
                            &session->round3_Output[i*(session->setting.n2-1)+t]);

            t = t +1;
        }
    }

}

void cg21_key_reshare_round4(CG21_reshare_session *session){

    // Each party validates its shares' checks received from T1
    char x_[EFS_SECP256K1 + 1];
    octet X = {0, sizeof(x_), x_};

    for (int i=0; i< session->setting.n2; i++){
        printf("\nParty %d run CG21_KEY_RESHARE_CHECK_VSS_T1/N2", i+1);

        for (int j=0; j<session->setting.t1; j++){
            if (i==j)
                continue;

            // the code in bellow should be replaced with decryption of C_i^j 'CG21_KEY_RESHARE_DECRYPT_SHARES',
            // which is skipped for simplicity of this example
            SSS_shares share;
            share.X = &session->storeSecretT1[j].shares.X[i];
            share.Y = &session->storeSecretT1[j].shares.Y[i];

            int Xstatus = 1;
            if (j==0 || (j==1 && i==0) )
                Xstatus = 0;  // first iteration
            if (j == session->setting.t1-1 || (j == session->setting.t1-2 && i == session->setting.t1-1)) {
                if (Xstatus == 0) {
                    Xstatus = 3; // first iteration = last iteration (t=2)
                } else {
                    Xstatus = 2;  // last iteration (!= first iteration)
                }
            }

            int rc;
            if (i<session->setting.t1) {
                rc = CG21_KEY_RESHARE_CHECK_VSS_T1(session->setting,
                                                   session->storePubT1 + j,
                                                   session->storePubT1 + i,
                                                   &share,
                                                   session->keygenData[i].Xi,
                                                   session->keygenData->PK,
                                                   &X,
                                                   session->keygenData[i].packed_pk_sum_shares,
                                                   session->round4_Store + i,
                                                   Xstatus);
            }
            else
                rc = CG21_KEY_RESHARE_CHECK_VSS_N2(session->setting,
                                                   session->storePubT1 + j,
                                                   &share,
                                                   session->keygenData[i].Xi,
                                                   session->keygenData->PK,
                                                   &X,
                                                   session->keygenData[i].packed_pk_sum_shares,
                                                   session->round4_Store + i,
                                                   Xstatus);
            if (rc!=CG21_OK){
                exit(rc);
            }
        }

    }

    printf("\n");
    // add shares
    for (int i=0; i< session->setting.n2; i++){

        SSS_shares share;
        char x[EGS_SECP256K1];
        char y[EGS_SECP256K1];
        octet ssX = {0, sizeof(x), x};
        octet ssY = {0, sizeof(y), y};
        share.X = &ssX;
        share.Y = &ssY;

        OCT_copy(share.X, &session->storeSecretT1[0].shares.X[i]);
        OCT_copy(share.Y, &session->storeSecretT1[0].shares.Y[i]);

        // init a sum using the first share
        CG21_KEY_RESHARE_SUM_SHARES(&share, &session->round4_Store[i], true);

        // add rest of received shares
        for (int j=1; j< session->setting.t1; j++){
            OCT_copy(share.X, &session->storeSecretT1[j].shares.X[i]);
            OCT_copy(share.Y, &session->storeSecretT1[j].shares.Y[i]);
            CG21_KEY_RESHARE_SUM_SHARES(&share, &session->round4_Store[i], false);
        }
    }

    // schnorr prove
    for (int i=0; i< session->setting.t1; i++){
        CG21_KEY_RESHARE_PROVE_T1(&session->round4_Output[i],&session->storeSecretT1[i],&session->storePubT1[i],
                                  &session->round4_Store[i],session->ssid+i, session->RHO, i+1,session->setting.n1);
    }

    int c = 0;
    for (int i=session->setting.t1; i<session->setting.n2; i++){
        CG21_KEY_RESHARE_PROVE_N2(&session->round4_Output[i],&session->storeSecretN2[c],&session->storePubN2[c],
                                  &session->round4_Store[i],session->ssid+i, session->RHO, i+1,session->setting.n1);
        c = c + 1;
    }

}

void cg21_key_reshare_round5(CG21_reshare_session *session){

    //schnorr verify
    for (int i=0; i<session->setting.n2; i++) {

        printf("\n\n--------PLAYER %d----------------", i+1);

        for (int j = 0; j < session->setting.t1; j++) {

            if (i == j) {
                continue;
            }

            int rc = CG21_KEY_RESHARE_VERIFY_T1(&session->round4_Output[j], &session->storePubT1[j], session->setting,
                                                &session->round4_Store[i], &session->ssid[i],j + 1);
            if (rc != CG21_OK) {
                printf("\nT1: player%d's proof rejected, %d", j + 1, rc);
                exit(rc);
            }
            else
                printf("\nT1:  player%d's proof validated", j+1);

        }

        int c = 0;
        for (int j = session->setting.t1; j < session->setting.n2; j++) {

            if (i == j) {
                c = c + 1;
                continue;
            }

            int rc = CG21_KEY_RESHARE_VERIFY_N2(&session->round4_Output[j], &session->storePubN2[c], session->setting,
                                                &session->round4_Store[i],  &session->ssid[i],j + 1);
            if (rc != CG21_OK) {
                printf("\nN2-T1: player%d's proof rejected, %d", j + 1, rc);
                exit(rc);
            }
            else
                printf("\nN2-T1: player%d's proof validated", j+1);
            c = c + 1;
        }

    }

    // Key re-share output
    for (int i=0; i<session->setting.n2; i++){
        bool first_entry = true;
        if (i<session->setting.t1){
            CG21_KEY_RESHARE_OUTPUT(session->round5_output+i,session->round4_Store+i,
                                    session->storePubT1+i,session->keygenData->PK,
                                    session->setting, session->keygenData->rid,i+1,true);
            first_entry = false;
        }
        for (int j=0;j<session->setting.t1;j++){
            if (i==j)
                continue;
            CG21_KEY_RESHARE_OUTPUT(session->round5_output+i,session->round4_Store+i,
                                    session->storePubT1+j,session->keygenData->PK,session->setting,
                                    session->keygenData->rid,j+1,first_entry);
            first_entry = false;
        }
    }
}


void validation(const CG21_reshare_session *session){
    /*
     * 1- First we add up all the x_i to get skx
     */

    printf("\nChecking correctness of the results ...");
    int n;
    int t;
    n = session->setting.n2;
    t = session->setting.t2;

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
    BIG_256_56_fromBytesLen(skx, session->storeSecretT1->a->val, session->storeSecretT1->a->len);
    for (int i=1; i<session->setting.t1; i++){
        BIG_256_56_fromBytesLen(h, (session->storeSecretT1+i)->a->val, (session->storeSecretT1+i)->a->len);

        BIG_256_56_add(skx, skx, h);
        BIG_256_56_mod(skx, q);
    }

    // compute PK = skx*G
    ECP_SECP256K1_mul(&G, skx);
    ECP_SECP256K1_toOctet(&Golden_PK, &G, true);

    for (int i=0;i<n;i++){
        int rc = OCT_comp(&Golden_PK, (session->round5_output+i)->pk.X);
        if (rc==0){
            printf("X is invalid");
            exit(1);
        }
        else{
            printf("\n\tPlayer %d Public Key is valid.", i+1);
        }
    }

    Golden_SK.len = EGS_SECP256K1;
    BIG_256_56_toBytes(Golden_SK.val, skx);

    for (int j=0;j<n-t+1;j++){
        int c=0;
        for (int i=j;i<j+t;i++){
            OCT_copy(&shares.X[c], (session->round5_output+i)->shares.X);
            OCT_copy(&shares.Y[c], (session->round5_output+i)->shares.Y);
            c++;
        }
        SSS_recover_secret(t, &shares, &S);

        int rc = OCT_comp(&Golden_SK, &S);
        if (rc==0){
            printf("\n\tshares of players (%d, ..., %d) are invalid", j, j+t-1);
            exit(1);
        }
        else{
            if (t<3)
                printf("\n\tSK recovered from players %d and %d successfully.", j, j+t-1);
            else
                printf("\n\tSK recovered from players (%d, ..., %d) successfully.", j, j+t-1);
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

void Store_CSV(CG21_reshare_session *session){
    FILE *fpt;
    fpt = fopen("cg21_reshare.csv", "w+");
    fprintf(fpt,"%d", session->round5_output->pk.pack_size);
    fprintf(fpt,"\n");
    fprintf(fpt,"%d,%d", session->setting.t2, session->setting.n2);
    fprintf(fpt,"\n");
    Store_CSV_OCT_Helper(fpt, (session->round5_output+0)->pk.X);
    fprintf(fpt,",");
    Store_CSV_OCT_Helper(fpt, (session->round5_output+0)->rid);
    fprintf(fpt,",");
    Store_CSV_OCT_Helper(fpt, (session->round5_output+0)->rho);

    for (int i=0;i<session->setting.n2;i++){
        fprintf(fpt,"\n");
        Store_CSV_OCT_Helper(fpt, (session->round5_output+i)->shares.X);
        fprintf(fpt,",");
        Store_CSV_OCT_Helper(fpt, (session->round5_output+i)->shares.Y);
        fprintf(fpt,",");
        Store_CSV_OCT_Helper(fpt, (session->round5_output+i)->pk.X_set_packed);
        fprintf(fpt,",");
        Store_CSV_OCT_Helper(fpt, (session->round5_output+i)->pk.j_set_packed);
    }

    if (fpt){
        fclose(fpt);
    }
}

int main(int argc, char *argv[]) {

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

    //****** read t,n from file *******
    CG21_NETWORK p;
    CG21_reshare_session session;
    session.network = &p;
    file_read_tn(&session);
    int n1 = p.n;
    int t1 = p.t;

    /* Read arguments */
    if (argc != 3) {
        usage(argv[0],t1,n1);
        exit(EXIT_FAILURE);
    }

    int t2 = atoi(argv[1]); // t is the threshold
    int n2 = atoi(argv[2]); // n is the total number of the nodes
    // Note: currently we do not allow new members to join key re-sharing so n2 <= n1
    // Assumptions: T1 \in N2,  |N2 - N1| = 0, where T1, N1,N2 are the set of old t parties, old N1 parties
    // and N2 new parties, respectively.
    if (t2 < 1 || n2 < t1 || t2 > n2 || n2 > n1) {
        usage(argv[0],t1,n1);
        exit(EXIT_FAILURE);
    }

    char p_[n2][HFS_2048];
    char q_[n2][HFS_2048];

    octet P[n2];
    octet Q[n2];

    init_octets((char *) p_, P, HFS_2048, n2);
    init_octets((char *) q_, Q, HFS_2048, n2);

    for(int i=0 ;i<n2;i++){
        OCT_fromHex(&P[i], PT_hex[i]);
        OCT_fromHex(&Q[i], QT_hex[i]);
    }

    CG21_PAILLIER_KEYS paillierKeys[n2];
    session.paillierKeys = paillierKeys;

    for (int i=0; i<n2; i++) {
        // Generate Paillier Keys
        PAILLIER_KEY_PAIR(NULL, &P[i], &Q[i], &paillierKeys[i].paillier_pk,
                          &paillierKeys[i].paillier_sk);
    }

    int t1_playerIDs[t1];
    int n2_playerIDs[n2];

    // Pick IDs for T1 and N2. Note that T1 should be subset of N2 based on the assumptions in CG21:Key Re-Share
    // IDs start from one
    for (int i = 0; i < t1; i++) {
        t1_playerIDs[i] = i + 1;
        n2_playerIDs[i] = i + 1;
    }

    // N2 includes all the nodes in T1 plus n2-t1 more IDs
    for (int i = t1; i < n2; i++) {
        n2_playerIDs[i] = i + 1;
    }

    //****** read X_set_packed and j_set_packed from file **********
    char keygen_j_packed[n1][n1 * 4 + 1];
    char keygen_X_set_packed[n1][n1 * (EFS_SECP256K1 + 1)];
    char keygen_pack_pk_sum_shares[n1][(n1-1)*(EFS_SECP256K1 + 1)];    // VSS: checks
    char keygen_i[n1][EGS_SECP256K1];
    char keygen_yi[n1][EGS_SECP256K1];
    char keygen_rid[EGS_SECP256K1];
    char pk[EFS_SECP256K1 + 1];

    octet KEYGEN_j_PACKED[n1];
    octet KEYGEN_X_SET_PACKED[n1];
    octet KEYGEN_PACKED_PK_SUM_SHARES[n1];
    octet KEYGEN_i[n1];
    octet KEYGEN_Yi[n1];
    octet KEYGEN_rid = {0, sizeof(keygen_rid), keygen_rid};
    octet KEYGEN_PK = {0, sizeof(pk), pk};

    init_octets((char *)keygen_j_packed, KEYGEN_j_PACKED, (n1 * 4 + 1), n1);
    init_octets((char *)keygen_X_set_packed, KEYGEN_X_SET_PACKED, n1 * (EFS_SECP256K1 + 1), n1);
    init_octets((char *)keygen_i, KEYGEN_i, EGS_SECP256K1, n1);
    init_octets((char *)keygen_yi, KEYGEN_Yi, EGS_SECP256K1, n1);
    init_octets((char *)keygen_pack_pk_sum_shares, KEYGEN_PACKED_PK_SUM_SHARES, (n1-1)*(EFS_SECP256K1 + 1), n1);


    CG21_KEYGEN_DATA keygenData[n1];

    for (int i=0;i<n1;i++){
        keygenData[i].Xi = KEYGEN_i + i;
        keygenData[i].Yi = KEYGEN_Yi + i;
        keygenData[i].j_packed = KEYGEN_j_PACKED + i;
        keygenData[i].X_packed = KEYGEN_X_SET_PACKED + i;
        keygenData[i].packed_pk_sum_shares = KEYGEN_PACKED_PK_SUM_SHARES + i;
    }
    keygenData->rid = &KEYGEN_rid;
    keygenData->PK = &KEYGEN_PK;

    session.keygenData = keygenData;
    file_read_keygen(&session);

    // fill an instance with CG21_RESHARE_SETTING
    CG21_RESHARE_SETTING setting;
    CG21_KEY_RESHARE_GET_RESHARE_SETTING(&setting, t1, n1, t2, n2, t1_playerIDs, n2_playerIDs);

    printf("T1:");
    for (int i=0; i<t1; i++){
        if(i+1==t1)
            printf("%d", *(setting.T1 + i));
        else
            printf("%d-", *(setting.T1 + i));
    }
    printf("\nN2:");
    for (int i=0; i<n2; i++){
        if(i+1==n2)
            printf("%d", *(setting.N2 + i));
        else
            printf("%d-", *(setting.N2 + i));
    }

    // define and initialize variables for SSID
    // Since T1 is a subset of N2, we only need to initialize n2 SSIDs
    char xored_rid[n2][EGS_SECP256K1];
    char xored_rho[n2][EGS_SECP256K1];
    char j_packed[n2][n1 * 4 + 1];
    char X_set_packed[n2][n1 * (EFS_SECP256K1 + 1)];
    char order[n2][EFS_SECP256K1];
    char generator[n2][EFS_SECP256K1 + 1];
    int n1_[n2];

    octet XORed_rid[n2];
    octet XORed_rho[n2];
    octet j_SET_PACKED[n2];
    octet X_SET_PACKED[n2];
    octet q_oct[n2];
    octet g_oct[n2];

    init_octets((char *)xored_rho,  XORed_rho,  EGS_SECP256K1, n2);
    init_octets((char *)xored_rid,  XORed_rid,  EGS_SECP256K1, n2);
    init_octets((char *)j_packed, j_SET_PACKED, (n1 * 4 + 1), n2);
    init_octets((char *)X_set_packed, X_SET_PACKED, n1 * (EFS_SECP256K1 + 1), n2);
    init_octets((char *)order, q_oct, EFS_SECP256K1,      n2);
    init_octets((char *)generator, g_oct, EFS_SECP256K1 + 1,      n2);

    // each party forms its ssid
    CG21_SSID ssid[n2];
    for (int i = 0; i < n2; i++) {
        ssid[i].rid = XORed_rid + i;
        ssid[i].rho = XORed_rho + i;
        ssid[i].j_set_packed = j_SET_PACKED + i;
        ssid[i].X_set_packed = X_SET_PACKED + i;
        ssid[i].q = q_oct + i;
        ssid[i].g = g_oct + i;
        ssid[i].n1 = n1_ + i;
    }

    // load rho
    char rho[EGS_SECP256K1];
    octet rho_OCT = {0, sizeof(rho), rho};
    OCT_fromHex(&rho_OCT, RHO);
    session.RHO = &rho_OCT;

    session.ssid = ssid;
    cg21_form_ssid(&session, n2);

    //each party in T1 forms it SSS_share
    char shares_x[t1][EGS_SECP256K1];
    char shares_y[t1][EGS_SECP256K1];
    octet shares_X[t1];
    octet shares_Y[t1];
    init_octets((char *)shares_x, shares_X, EGS_SECP256K1, t1);
    init_octets((char *)shares_y, shares_Y, EGS_SECP256K1, t1);

    SSS_shares shares[t1];
    for (int i = 0; i < t1; i++) {
        shares[i].X = shares_X + i;
        shares[i].Y = shares_Y + i;
    }

    session.shares = shares;
    cg21_form_SSS_share(&session,t1);

    // CG21 ke re-share round1_store_priv
    char round1_a[t1][EGS_SECP256K1];            // Secret additive share
    char round1_aG[t1][EFS_SECP256K1 + 1];       // Public Key associated with the additive share
    char round1_shares_x[t1][n2][EGS_SECP256K1];      // VSS: x
    char round1_shares_y[t1][n2][EGS_SECP256K1];      // VSS: y
    char round1_checks[t1][t2*(EFS_SECP256K1 + 1)];    // VSS: checks
    char round1_rho[n2][EGS_SECP256K1];                  // partial rho (rho_i)
    char round1_u[n2][EGS_SECP256K1];
    char round1_r[n2][SGS_SECP256K1];
    char round1_A[n2][SFS_SECP256K1 + 1];
    char round1_V[n2][SHA256];
    int round1_i[n2];
    int round1_i2[n2];

    octet ROUND1_a[t1];
    octet ROUND1_aG[t1];
    octet ROUND1_SHARES_X[t1 * n2];
    octet ROUND1_SHARES_Y[t1 * n2];
    octet ROUND1_CHECKS[t1];
    octet ROUND1_rho[n2];
    octet ROUND1_u[n2];
    octet ROUND1_A[n2];
    octet ROUND1_r[n2];
    octet ROUND1_V[n2];

    init_octets((char *)round1_a, ROUND1_a, EGS_SECP256K1, t1);
    init_octets((char *)round1_aG, ROUND1_aG, EFS_SECP256K1 + 1, t1);
    init_octets((char *)round1_shares_x, ROUND1_SHARES_X, EGS_SECP256K1,     t1 * n2);
    init_octets((char *)round1_shares_y, ROUND1_SHARES_Y, EGS_SECP256K1,     t1 * n2);
    init_octets((char *)round1_checks,   ROUND1_CHECKS,   t2*(EFS_SECP256K1 + 1), t1);
    init_octets((char *)round1_rho, ROUND1_rho, EGS_SECP256K1, n2);
    init_octets((char *)round1_u, ROUND1_u, EGS_SECP256K1, n2);
    init_octets((char *) round1_A, ROUND1_A, SFS_SECP256K1 + 1, n2);
    init_octets((char *) round1_r, ROUND1_r, SGS_SECP256K1, n2);
    init_octets((char *) round1_V, ROUND1_V, SHA256, n2);

    CG21_RESHARE_ROUND1_STORE_PUB_T1 storePubT1[t1];
    CG21_RESHARE_ROUND1_STORE_SECRET_T1 storeSecretT1[t1];
    CG21_RESHARE_ROUND1_OUT pubOut[n2];

    for (int i = 0; i < t1; i++) {
        storePubT1[i].Xi = ROUND1_aG + i;
        storePubT1[i].rho = ROUND1_rho + i;
        storePubT1[i].u = ROUND1_u + i;
        storePubT1[i].A = ROUND1_A + i;
        storePubT1[i].checks = ROUND1_CHECKS + i;
        storePubT1[i].i = round1_i2 + i;

        storeSecretT1[i].r = ROUND1_r + i;
        storeSecretT1[i].a = ROUND1_a + i;
        storeSecretT1[i].shares.X = ROUND1_SHARES_X + (n2 * i);
        storeSecretT1[i].shares.Y = ROUND1_SHARES_Y + (n2 * i);

        pubOut[i].V = ROUND1_V + i;
        pubOut[i].i = round1_i + i;
    }

    CG21_RESHARE_ROUND1_STORE_PUB_N2 storePubN2[n2 - t1];
    CG21_RESHARE_ROUND1_STORE_SECRET_N2 storeSecretN2[n2 - t1];
    int c = 0;
    for (int i = t1; i < n2; i++) {
        storePubN2[c].rho = ROUND1_rho + i;
        storePubN2[c].u = ROUND1_u + i;
        storePubN2[c].A = ROUND1_A + i;
        storePubN2[c].i = round1_i2 + i;

        storeSecretN2[c].r = ROUND1_r + i;

        pubOut[i].V = ROUND1_V + i;
        pubOut[i].i = round1_i + i;
        c = c + 1;
    }


    session.RNG = &RNG;
    session.setting = setting;
    session.storePubT1 = storePubT1;
    session.storeSecretT1 = storeSecretT1;
    session.storePubN2 = storePubN2;
    session.storeSecretN2 = storeSecretN2;
    session.pubOut = pubOut;

    cg21_key_reshare_round1(&session);


    // CG21 ke re-share round2
    cg21_key_reshare_round2(&session);


    // CG21 ke re-share round3
    // Each party receives t1 messages from T1 and (n2-t1) messages from N2-T1 parties
    // in total, each party in N2 receives n2 messages in two different forms

    // we don't know whether a party is a member of T1 at this stage. Thus, some parties may receive t1 checks
    // while some other that are in T1 will receive t1-1 checks,
    // since they don't need to send their own checks to themselves

    // a party may receive t1 shares or t1-1 shares for the same reason as above
    char round3_double_pack[setting.n2][t1 * t2 * (EFS_SECP256K1 + 1)];    // VSS: checks
    char round3_sk_x[n2][EGS_SECP256K1];    //store
    char round3_sk_y[n2][EGS_SECP256K1];    //store
    char round3_xor_rho[n2][EGS_SECP256K1]; //store
    char round3_C_out[n2][n2-1][FS_4096]; //round3_output
    char round3_X_out[n2][n2-1][EGS_SECP256K1]; //round3_output
    char round4_proof_psi[n2][SGS_SECP256K1];   //round3_output
    char round4_proof_A[n2][SFS_SECP256K1 + 1]; //round3_output

    char round5_X[n2][EFS_SECP256K1 + 1];   // store, final ECDSA PK
    char round5_i_packed[n2][n2 * 4 + 1];   //store
    char round5_X_set_packed[n2][n2 * (EFS_SECP256K1 + 1)]; //store
    char round5_xor_rho[n2][EGS_SECP256K1]; //store
    char round5_xor_rid[n2][EGS_SECP256K1]; //store
    char round5_sk_x[n2][EGS_SECP256K1];    //store
    char round5_sk_y[n2][EGS_SECP256K1];    //store

    octet ROUND3_sk_X[n2];
    octet ROUND3_sk_Y[n2];
    octet ROUND3_xor_rho[n2];
    octet ROUND3_double_pack[setting.n2];

    octet ROUND3_C_out[n2*(n2-1)];
    octet ROUND3_X_out[n2*(n2-1)];
    octet ROUND4_PROOF_A[n2];
    octet ROUND4_PROOF_psi[n2];
    int round3_i[n2*(n2-1)];
    int round3_j[n2*(n2-1)];
    int round4_i[n2];

    octet ROUND5_xor_rho[n2];
    octet ROUND5_xor_rid[n2];
    octet ROUND5_sk_X[n2];
    octet ROUND5_sk_Y[n2];
    octet ROUND5_X[n2];
    octet ROUND5_j_PACKED[n2];
    octet ROUND5_X_SET_PACKED[n2];

    init_octets((char *)round3_sk_x, ROUND3_sk_X, EGS_SECP256K1, n2);
    init_octets((char *)round3_sk_y, ROUND3_sk_Y, EGS_SECP256K1, n2);
    init_octets((char *)round3_xor_rho,  ROUND3_xor_rho,  EGS_SECP256K1, n2);
    init_octets((char *)round3_C_out, ROUND3_C_out, FS_4096, n2*(n2-1));
    init_octets((char *)round3_X_out, ROUND3_X_out, EGS_SECP256K1, n2*(n2-1));
    init_octets((char *)round4_proof_A, ROUND4_PROOF_A, SFS_SECP256K1 + 1, n2);
    init_octets((char *)round4_proof_psi, ROUND4_PROOF_psi, SGS_SECP256K1, n2);
    init_octets((char *)round3_double_pack, ROUND3_double_pack, t1 * t2 * (EFS_SECP256K1 + 1), n2);
    init_octets((char *)round5_i_packed, ROUND5_j_PACKED, (n2 * 4 + 1), n2);
    init_octets((char *)round5_X_set_packed, ROUND5_X_SET_PACKED, n2 * (EFS_SECP256K1 + 1), n2);
    init_octets((char *)round5_X, ROUND5_X, EFS_SECP256K1 + 1, n2);
    init_octets((char *)round5_xor_rho,  ROUND5_xor_rho,  EGS_SECP256K1, n2);
    init_octets((char *)round5_xor_rid,  ROUND5_xor_rid,  EGS_SECP256K1, n2);
    init_octets((char *)round5_sk_x, ROUND5_sk_X, EGS_SECP256K1, n2);
    init_octets((char *)round5_sk_y, ROUND5_sk_Y, EGS_SECP256K1, n2);

    // each party receives t1 number of Xi, shares, and checks from other parties
    CG21_RESHARE_ROUND3_OUTPUT round3_Output[t1*n2];
    CG21_RESHARE_ROUND4_OUTPUT round4_Output[n2];
    CG21_RESHARE_ROUND4_STORE round4_Store[n2];
    CG21_RESHARE_OUTPUT round5_output[n2];

    // parameters to broadcast at the end of Round3
    for (int i=0; i<t1*n2; i++){
        round3_Output[i].i = round3_i + i;
        round3_Output[i].j = round3_j + i;
        round3_Output[i].C = ROUND3_C_out + i;
        round3_Output[i].X = ROUND3_X_out + i;
    }

    for (int i=0; i<n2; i++){

        round4_Output[i].proof.psi = ROUND4_PROOF_psi + i;
        round4_Output[i].proof.A = ROUND4_PROOF_A + i;
        round4_Output[i].i = round4_i + i;

        // parameters to store at the end of Round4
        round4_Store[i].shares.X = ROUND3_sk_X + i;
        round4_Store[i].shares.Y = ROUND3_sk_Y + i;
        round4_Store[i].rho = ROUND3_xor_rho + i;
        round4_Store[i].pack_all_checks = ROUND3_double_pack + i;

        round5_output[i].pk.X = ROUND5_X + i;
        round5_output[i].pk.X_set_packed = ROUND5_X_SET_PACKED + i;
        round5_output[i].pk.j_set_packed = ROUND5_j_PACKED + i;
        round5_output[i].rho = ROUND5_xor_rho + i;
        round5_output[i].rid = ROUND5_xor_rid + i;
        round5_output[i].shares.X = ROUND5_sk_X + i;
        round5_output[i].shares.Y = ROUND5_sk_Y + i;
    }

    session.round3_Output = round3_Output;
    session.round4_Output = round4_Output;
    session.round4_Store = round4_Store;
    session.round5_output = round5_output;

    cg21_key_reshare_round3(&session);

    cg21_key_reshare_round4(&session);

    cg21_key_reshare_round5(&session);

    validation(&session);
    Store_CSV(&session);

    exit(0);
}