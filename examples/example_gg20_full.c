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
#include <string.h>
#include "amcl/mta.h"
#include "amcl/mpc.h"
#include "amcl/mta_zkp.h"
#include "amcl/nm_commitment.h"
#include "amcl/gmr.h"
#include "amcl/ggn.h"
#include "amcl/schnorr.h"
#include "amcl/gg20_zkp.h"
#include "amcl/shamir.h"

#define IDLEN 16

/* Example of the full flow */

// Safe primes for BC Setup
int primes_len = 4;

char *primes[] =
{
    "C421122418EF6FE4D4F14F0F03EABA927C20B1A22BCBE90EC227EFE34AC912095D389ADE615CF55C80874533F4270BB705ABFFDB6007FEF0B44B2DBF31EDA0D5F39523B5826F9854FBF733B98EF450E77DD8B5B15C4E3CE5C195F46E524C8BF6F0C9F6D86CE8642A8B9A0C79CA64A103AB76CD65261F97AED4C17C433CEA5DEF",
    "ED7859031659B9A5AC011687A60444B19F5A73F31F9EE83D710F2FEAE1C4FED558A1C5C3842EA01DB86C6D07BE9971F8AA7820DD1E8BB8C9AE888319F0E03BDCD8D3DBEBF8A48765188C001A121F7E48D458E1E8A43684A861F0FBE87DC541A06CA98CECB6954F906A52C2B3D0978AE945A1EA2F9285978F76F01E99FD8B6EEF",
    "D93E4899805ED36219F38C3030D6FF92012E2B41ADC38DFFFFDB110AEAA36D619A5CFD63B02711EA482941E20A3F89A36E2CAF0BD675B154FDE6D5A457BCBD337383EE65B33CDAB078EE8F8E36E55D22BB5DF75D14F570E529A4681B4947A4F5ECCC575763BD765FDE1038DEDF24BEF02BA9A1EA4C17ACA3A1B33D2FB7D974AB",
    "E4481CEDDBDDDF6E980FBC825B004E52D028784CD3B8290D9810FD987AF2053C3F4056C3A354BFF55B9BB5867A819A22B71BC1069A310087E4FBF98FD291DBCC443AB910301B34A2DEE68D1365E77EDF9A0A21B3928C38046BC15AC338F7E38B9E4586E02655F98523CD041FBB51A358E505A5D1B0A161955B6AC60CB0E37707",
    "F5F3BB1CEECD21110EFB4BC9CF0AA7AEBB98675A7567D6A1EA4E866FED4838F1B41D8232599718CD82F2936CD15198DC16ADD280C32D6860882704AEF397E1A956DB17E36AEB92D5CF76689DACC9CEFE418EF699C948CE680AFF878768CE8F4BB68F14AB5E8C38209E6C2C54125533B22960BBD350CF76C3B12BBC9FBAAAAA27",
    "E8E1F9281CB8C10BC01B42197E834F648A5C8AE111F7DB40DD25A6F8896A703D0F84D36EB6D1FC048DC74FD3164742CA86607C81670199FC3F1BF5AB22F2B11E4E2434E757C0484A4162E26B75A0715167C5E8E293B7CEFD475FAA8B10F2324D78150E56B1186E257066D8860603FBCE59865FB0A25FB41014C1740C8EAA29AF",
    "C3278DF1CD5330CD6DABE2FC9E32B9A560C32F7F140C601D2A5788F856A387531EFA695D728038F8CA2945D01C10A5DA823025BA27D7640E96593C031674380592AF4B8FE29A9C464FF41B1CACD47A4B255A5CA93E2F2A806AF00A67FB78A15D3ED8A37CEBA10CA7D0036412805AEBB88EC8A745F237AC01002D49C459EB2AB7",
    "DCE9B24D4DE749296335C0F0DB421A330E21DF04C722ADDECC4B72448C387072C84CD7DB1146E1E07BE78585DEF4F1D5E15F53B0942CCA89B0E812B0F6653C7DA8ACB771593D4B2B37A28AD80DD7184698742C110F0506B86BF8A2A20E8975DF2D2A57930438B8528E63C3430DBFCE204712E8D40550E81DA03622953BEA2DFB",
    "D09A3ECE562DD033EC2C562C2B0B4EEB0D2262FE046C030BAAFD7CBA8F73E9734E337D3551FC6B487CA359A84F598EC5EC6FDBA014A0A0009EF582B9F90DE90C0BA7F941648C4F3A8CF904974BA05E8C23EDA5895025441251B2CFC5A216568E702427DEA178D37BF3D28F1B35E17E58F5551511331961703F3D410924859107",
    "C03136A1E1E5BA88568A19142F41E9FAC2E76A2D839B550038005E420008AF7D6D7C80EA8A31A936D39C93D2031B20845F23464371909EE589BF80E850C94B9F0FBF516C3DE362868C811505EE15B869844A54FFB32B0620A7FC5BA040898A91AA68657D8B43990166E5A5AF06828AE0F7C1D0EE333C2AF8DE7603F2F662792F",
    "DF88593FBF2482954BAAA2A48C59E2FDF85936C282514FFB47F18B8D1484C7E8BE1862D0A84D5B753389A2BFBAFF63B03406AC29893B88911F8664E547A63CB58E9A941463D7946CF0909E24E7BD8EF11AFC4EEAFC8F3366DB0A9AB091325AC82C9BAE218B115F8700BAA1F478E194A927F1FBE3A3EF423BCFAE78850059B69B",
    "D3AE06CD993690F64104D4ECBE6B2386693B766431B86E038CAE39EE81BD8A71387FBCB9D17B5BFAAFB883D68B005E228CD455A4BFF69843F948A9168D1F87545FCBB969260E07BDD44F10E79E7409DED45ADDF32BA1CF33F9B2F68758622FE660F4E47A651F6403D99E7B148768CDDBEC71EBE931D5A95B820B5A75BD495003",
    "DAA27689A7D8F9B21106DBE472C324EB1CA899F58F0F72F336957312A8ECDB4EBC3B50C38D5A2E9C2D1E552C7EA8D89315DD9C5CA7F9EB99C41F7A857D44F420109FE17092799E60E3537FC9193056979E0FF886B36C2898F45F599E4C5CCDDF9A8EC8DA0D20A53A6849124E027D30D641E21E69FF374792534BD682FCDCA35B",
    "FBF9D46697C40BCA51A759C47E360F2DD8B81B6241B0A3645645FAC692E9E8F3407EFB6F238AE91F9DEA49240D26E37904673F55E91927CDEA248FE1352B97B226AB159A1539747383B1168FE8CF1B1DF4CD9147053E3702AE491FBCA4CCE835B4B351DF44F5333C185275DB21B807D0BC180BF697EC07AB843E0FA595851A87",
    "FD44B39DF09A18F215EB391D50D21CD5EAC8BE2E5CC901DF852DE85C93341F82633AAAD07C19863E0CD7861AEEE1C0B4B69275AA8DD2D33C0F5E048EA13E9A6D8E01B77FED72347D527BD7508D2F5EC18E5CB2B27D40BAB5C10A17123E75042F4047C3B1AEB6D36BF0F93BB214501ECBB8F95CC1A3A99219F6933763580CDA2F",
    "C2442E9569C8999831594E818A159C8C0AF6F7ED2989358E8D9E01D6B8A0D354F5F97D9CEAB766AF12F3CC5C511FE19A587FF1E7029C8E500432D357D90E3EF042E4F308C325760D726BC9B1D78BA439FB0236D85DB301E548C4201B9E74D5832AD3ED06E37CD6DBFD9C23D194068DB1B9209813557FBC0714142AD6F6C56AA3",
    "DC3B22CFF90690B10EC73C115FED0E3AD3FA01A68F8C8AA1905CA47008E8C4AF9D7922AE4D41794D8123D1768A3E0F8B35DA0001086ADC5EBB92640DD2514CBAD000283F7C5A6C340C040C09654A204C3947A22AC05F72E13C3EBDE61B9D281016E40C559474D33381C974767408EE9E108619AE96E4CC87EB11E39772BA00B3",
    "C5E0280A5F1B358D16EDEF14540C3C9D468D4AEBC74C9DB605A2E4CEC9F27095A3FDE659E1E6C95FB4BB60533DD89E71D808A8C5EB5A8A51B9FED24F7AE9003FFD6F5401D991153C52002E7DB4F6766363B2CA77E9A113808E7C35713D188AD55CE25B9DB1308A08F3366523E425F77D924346078D8E0E9948674BAD88EA59B7",
    "FC33DF361A7B1D3C3D1C06FBF3CCAD6C067B27FF28B61B1EFDB364FFFEE79993D9D10213A778A02C6C823DB101CB7C7A483B9F2B060BD1B7EDC13DB890B323AE02B7209DA66B3289069EE8C7747A6D7242194DC48DBDFFB740534A591AE2F41446B08F9966DA045FC9C3F9188F1EF1308509D50BC970314B6AA335EA2839993B",
    "E63B5740DDB573CF1F0A72DAF3EA00D65CA2A538036D20078CC7E3BDC95529F1D13ABC182EBF8BE42CA87C0AEED4952C1D1FADC3C3C8A363F66FABCA012890FBC76C935B479B4F302F1DC12289D34F1F69EC2278045603F5FE532B0CD86E6261852F99517B6226F013B04DCE1D940DF7FB8BC8A799D153C1490A915A8342B77F"
};

/* Party related structures */
typedef struct
{
    PAILLIER_private_key paillier_sk;
    BIT_COMMITMENT_priv bc_sm;

    octet *SKX; // X share of the full key (t,n) sharing
    octet *SKY; // Y share of the full key (t,n) sharing
} MPC_priv_key_material;

typedef struct
{
    octet *PK;  // Full ECDSA PK
    octet *SPK; // ECDSA PK associated to the player share

    PAILLIER_public_key paillier_pk;
    BIT_COMMITMENT_pub  bc_pm;
} MPC_pub_key_material;

typedef struct
{
    octet *ID;

    MPC_priv_key_material skm;
    MPC_pub_key_material  pkm;
} MPC_player;

typedef struct
{
    int t;
    int n;

    MPC_player *players;
} MPC_party;

/* Keygen related structures
 *
 * Note that these structures hold all the values
 * generated in the round, even if they are not to be
 * transmitted. The values to be transmitted and what channel
 * to use are specified in the keygen functions
 */

typedef struct
{
    octet *SK;  // ECDSA secret key
    octet *PK;  // ECDSA pubilc key

    octet *R; // Decommitment string
    octet *C; // Commitment string to PK
} MPC_keygen_round1;

typedef struct
{
    SSS_shares SHARES; // Shares for VSS
    octet *CHECKS;     // Checks for VSS
} MPC_keygen_round2;

typedef struct
{
    octet *SCHNORR_C;
    octet *SCHNORR_P;

    GMR_proof Y;

    BIT_COMMITMENT_setup_proof BCP;
} MPC_keygen_round3;

typedef struct
{
    octet *ID;

    MPC_party *party;

    MPC_keygen_round1 *round1;
    MPC_keygen_round2 *round2;
    MPC_keygen_round3 *round3;
} MPC_keygen_session;

/* Signing related structures
 *
 * Note that these structures hold all the values
 * generated in the round, even if they are not to be
 * transmitted. The values to be transmitted and what channel
 * to use are specified in the signing functions
 */

typedef struct
{
    octet *W;   // Secret additive share
    octet *WG;  // Public Key associated with the additive share
} MPC_signing_additive_shares;

typedef struct
{
    octet *GAMMA;
    octet *GAMMAPT;
    octet *K;
    octet *R;       // Decommitment for GAMMAPT
    octet *C;       // Commitment for GAMMAPT
} MPC_signing_round1;

typedef struct
{
    octet *R;     // Random value from K encryption. Saved for round 5
    octet *CA;    // Encryption of K. Saved for round 5
    octet *DELTA;
    octet *SIGMA;
} MPC_signing_round2;

typedef struct
{
    octet *INVKGAMMA;
    octet *T;         // Check for SIGMA
    octet *L;         // Random value used in computing T
    octet *C;         // Phase3 commitment. ECP
    GG20_ZKP_proof p;
} MPC_signing_round3;

typedef struct
{
    octet *R;
    octet *RP;
} MPC_signing_round4;

typedef struct
{
    octet *RI;         // Checks for K, R
    GGN_commitment *c; // t commitments, since they are tailored for each player
    GGN_proof *p;      // t proofs, since they are tailored for each player
} MPC_signing_round5;

typedef struct
{
    octet *SI;                     // Check for SIGMAs
    GG20_ZKP_phase6_commitment c;  // Commitment for SI consistency
    GG20_ZKP_proof p;              // Proof for SI consistency              
} MPC_signing_round6;

typedef struct
{
    octet *SI; // Signature S shares
    octet *S;  // Reconciled S component
} MPC_signing_round7;

typedef struct
{
    octet *ID;

    MPC_party *party;

    MPC_signing_additive_shares *shares;

    MPC_signing_round1 *round1;
    MPC_signing_round2 *round2;
    MPC_signing_round3 *round3;
    MPC_signing_round4 *round4;
    MPC_signing_round5 *round5;
    MPC_signing_round6 *round6;
    MPC_signing_round7 *round7;
} MPC_signing_session;

// Utility functions
void init_octets(char* mem, octet *OCTETS, int max, int n)
{
    int i = 0;

    for (i = 0; i < n; i++)
    {
        OCTETS[i].val = mem + (i*max);
        OCTETS[i].len = 0;
        OCTETS[i].max = max;
    }
}

/* *** Keygen functions *** */

/* Keygen - Round 1
 *
 * This can be viewed as the secret key material generation.
 * In particular, we generate keypairs for the ECDSA Signature
 * and the Paillier cryptosystem, in addition to the modulus
 * for the Bit Commitment ZKP.
 *
 * The ECDSA Public Key is not broadcast here, but a NM Commitment
 * to it is generated and the commitment string broadcast here.
 * The decommitment string MUST be saved for later.
 *
 * The rest of the (public) key material is broadcast as is.
 * The reason for broadcasting the Paillier Key here is the specification
 * in the paper. The moment to broadcast the modulus is not
 * specified, so there is a case to be done for broadcasting it
 * in round 3.
 */
int MPC_keygen_round1_generate(csprng *RNG, MPC_player *p, MPC_keygen_round1 *r, int i)
{
    int rc;

    char oct1[HFS_2048];
    octet OCT1 = {0, sizeof(oct1), oct1};
    char oct2[HFS_2048];
    octet OCT2 = {0, sizeof(oct2), oct2};

    ECP_SECP256K1 ECP;

    char pk[2 * EFS_SECP256K1 + 1];
    octet PK = {0, sizeof(pk), pk};

    // Generate ECDSA Key Pair
    printf("\t[Player %d] Generate ECDSA key pair\n", i);

    MPC_ECDSA_KEY_PAIR_GENERATE(RNG, r->SK, &PK);
    rc = ECP_SECP256K1_PUBLIC_KEY_VALIDATE(&PK);
    if (rc != 0)
    {
        printf("\t\tError generating ECDSA key pair. rc %d\n", rc);
        return rc;
    }

    // Convert PK to compressed form
    ECP_SECP256K1_fromOctet(&ECP, &PK);
    ECP_SECP256K1_toOctet(r->PK, &ECP, true);

    // Commit to the ECDSA public key
    printf("\t[Player %d] Commit to ECDSA PK\n", i);

    NM_COMMITMENT_commit(RNG, &PK, r->R, r->C);

    // Generate Paillier Key pair
    printf("\t[Player %d] Generate Paillier key pair\n", i);

    PAILLIER_KEY_PAIR(RNG, NULL, NULL, &p->pkm.paillier_pk, &p->skm.paillier_sk);

    // Load Primes for BC setup
    OCT_fromHex(&OCT1, primes[(2 * i) % primes_len]);
    OCT_fromHex(&OCT2, primes[(2 * i + 1) % primes_len]);

    // Generate BC modulus
    printf("\t[Player %d] Generate BC modulus\n", i);

    BIT_COMMITMENT_setup(RNG, &p->skm.bc_sm, &OCT1, &OCT2, NULL, NULL);
    BIT_COMMITMENT_priv_to_pub(&p->pkm.bc_pm, &p->skm.bc_sm);

    printf("\t[Player %d] Broadcast commitment C, Paillier PK and BC modulus (N, B0, B1)\n", i);

    return MPC_OK;
}

/* Keygen - VSS of ECDSA SK for Round 2
 *
 * The output of this computation are the shares and checks for this playe
 * ECDSA secret key. Note that the check for the coefficient
 * of degree 0 is the ECDSA PK generated in Round 1. So it
 * will pass the decommitment for the commitment sent in Round 1
 *
 * This part of computation can be performed as soon as the ECDSA
 * keypair from Round 1 is done. There is a case to be done
 * for moving this in the body of Round 1, given how inexpensive it
 * is, but I'm separating it to better reflect the paper.
 * Either way, the shares and decommitment for the free term in the exponent
 * MUST NOT be broadcast until every other player broadcasts the
 * result of its Round 1
 */
void MPC_keygen_round2_vss(csprng *RNG, MPC_keygen_round1 *r1, MPC_keygen_round2 *r2, int i, int t, int n)
{
    printf("\t[Player %d] Generate VSS Shares for secret key\n", i);

    VSS_make_shares(t, n, RNG, &r2->SHARES, r2->CHECKS, r1->SK);

    printf("\t[Player %d] Broadcast Checks and decommitment string.\n", i);
    printf("\t[Player %d] Transmit shares with point2point channel\n", i);
}

/* Keygen - VSS verification and shares composition for Round 2
 *
 * Once the shares and decommitments are received they can be
 * verified and summed to compute the full key share for the player.
 * Moreover, the full public key can be computed by adding all the
 * free terms in the exponents from the checks.
 *
 * Note that it would be beneficial to have a routine to verify
 * shares and the decommitment of the free term in the exponent
 * so they can be processed as they are received, instead of processing
 * them in bulk. Here it is done in bulk for simplicity.
 */
int MPC_keygen_round2_compose(MPC_keygen_session *s, int i)
{
    int j, n, rc;

    n = s->party->n;

    char ws[n][EFS_SECP256K1 + 1];
    octet WS[n];

    init_octets((char *)ws, WS, EFS_SECP256K1 + 1, n);

    SSS_shares *SHARES;
    octet *CHECKS;
    MPC_player *p;

    printf("\t[Player %d] Verify Shares\n", i);

    /* Decommit Free term in the exponent and verify shares */
    for (j = 0; j < n; j++)
    {
        if (i == j) continue; // Trust ourselves

        // Load appropriate shares and checks
        SHARES = &(s->round2[j].SHARES);
        CHECKS = s->round2[j].CHECKS;

        // Decommit free term in the exponent
        rc = NM_COMMITMENT_decommit(CHECKS + 0, (s->round1)[j].R, (s->round1)[j].C);
        if (rc != NM_COMMITMENT_OK)
        {
            printf("\t\tInvalid Commitment for Player %d. rc %d\n", j, rc);
            return rc;
        }

        // Check the share is for the right player
        if (!OCT_comp(SHARES->X+i, s->round2[i].SHARES.X+i))
        {
            printf("\t\tInvalid X share for Player %d.\n", j);
            return MPC_FAIL;
        }

        // VSS Verification for the received share
        rc = VSS_verify_shares(s->party->t, SHARES->X+i, SHARES->Y+i, CHECKS);
        if (rc != VSS_OK)
        {
            printf("\t\tInvalid Shares for Player %d. rc %d\n", j, rc);
            return rc;
        }
    }

    /* Compose Public Key */

    printf("\t[Player %d] Generate full PK\n", i);

    p = s->party->players + i;

    for (j = 0; j < n; j++)
    {
        OCT_copy(WS+j, s->round2[j].CHECKS + 0);
    }

    rc = MPC_SUM_ECPS(p->pkm.PK, WS, n);
    if (rc != MPC_OK)
    {
        printf("\t\tInvalid format for PK Shares for Player %d. rc %d\n", i, rc);
        return rc;
    }

    /* Compose Shares */

    printf("\t[Player %d] Combine full share\n", i);

    for (j = 0; j < n; j++)
    {
        OCT_copy(WS+j, s->round2[j].SHARES.Y + i);
    }

    MPC_SUM_BIGS(p->skm.SKY, WS, n);

    OCT_copy(p->skm.SKX, s->round2[i].SHARES.X+i);

    /* TODO This should not be stored here
     *
     * This should be computed by each player for all players
     */
    BIG_256_56 w;
    ECP_SECP256K1 G;
    ECP_SECP256K1_generator(&G);
    BIG_256_56_fromBytesLen(w, p->skm.SKY->val, p->skm.SKY->len);
    ECP_SECP256K1_mul(&G, w);
    ECP_SECP256K1_toOctet(p->pkm.SPK, &G, true);

    return MPC_OK;
}

/* Keygen - Generate Proofs of well formedness of the key material
 *
 * Generate a Schnorr Proof of knowledge of the secret share
 * Generate a Square-Freeness proof for the Paillier Keys
 * Generate a proof of well formedness for the ZKP modulus N, b0, b1
 *
 * The Schnorr Proof is performed here as specified in the paper,
 * but it is inexpensive enough that it could be moved in round 1 and
 * verified in round 2 to fail early. As for the other two proofs,
 * they are quite slow and it is a good idea to have them performed
 * as the last step.
 */
void MPC_keygen_round3_proofs(csprng *RNG, MPC_player *p, MPC_keygen_round3 *r3, octet *SESSION_ID, int i)
{
    char rv[EGS_SECP256K1];
    octet RV = {0, sizeof(rv), rv};
    char e[EGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    char mp[HFS_2048];
    octet MP = {0, sizeof(mp), mp};
    char mq[HFS_2048];
    octet MQ = {0, sizeof(mq), mq};

    MODULUS_priv m;

    /* Prove knowledge of DLOG PK = s.G */
    printf("\t[Player %d] Prove knowledge of secret key\n", i);

    SCHNORR_commit(RNG, &RV, r3->SCHNORR_C);
    SCHNORR_challenge(p->pkm.SPK, r3->SCHNORR_C, p->ID, SESSION_ID, &E);
    SCHNORR_prove(&RV, &E, p->skm.SKY, r3->SCHNORR_P);

    OCT_clear(&RV);

    /* Prove Square Freeness of the Paillier modulus */
    printf("\t[Player %d] Prove Square-Freeness of Paillier modulus\n", i);

    FF_2048_toOctet(&MP, p->skm.paillier_sk.p, HFLEN_2048);
    FF_2048_toOctet(&MQ, p->skm.paillier_sk.q, HFLEN_2048);
    MODULUS_fromOctets(&m, &MP, &MQ);

    GMR_prove(&m, p->ID, SESSION_ID, r3->Y);

    OCT_clear(&MP);
    OCT_clear(&MQ);
    MODULUS_kill(&m);

    /* Prove well formedness of the BC modulus */
    printf("\t[Player %d] Prove Well formedness of BC modulus\n", i);

    BIT_COMMITMENT_setup_prove(RNG, &p->skm.bc_sm, &r3->BCP, p->ID, SESSION_ID);

    printf("\t[Player %d] Broadcast Schnorr Proof (C, P), GMR Proof Y and BC proof values\n", i);
}

/* Keygen - Verify the ZKP for round 3
 *
 * Verify the Schnorr Proof for the secret key u
 * Verify the Square-Freeness proof for the paillier PK
 * Verify the proof of well formedness for the BC modulus
 *
 * This is done in bulk here for simplicity, but as for Round 2
 * there is a strong case to be made to have a routine to perform
 * this asyncronously as soon as the proofs come in from the other
 * players.
 */
int MPC_keygen_round3_verify(MPC_keygen_session *s, int i)
{
    int j, n, rc;

    char e[EGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    char mn[FS_2048];
    octet MN = {0, sizeof(mn), mn};

    MPC_keygen_round3 *r;
    MPC_player *p;

    n = s->party->n;

    printf("\t[Player %d] Verify key material ZKP\n", i);

    for (j = 0; j < n; j++)
    {
        if(j == i) continue; // Trust ourselves

        // Load appropriate player and round communications
        r  = s->round3 + j;
        p  = s->party->players + j;

        /* Verify Schnorr Proof */
        SCHNORR_challenge(p->pkm.SPK, r->SCHNORR_C, p->ID, s->ID, &E);
        rc = SCHNORR_verify(p->pkm.SPK, r->SCHNORR_C, &E, r->SCHNORR_P);
        if (rc != SCHNORR_OK)
        {
            printf("\t\tInvalid Schnorr Proof for Player %d. rc %d\n", j, rc);
            return rc;
        }

        /* Verify GMR proof of Square-Freeness */
        PAILLIER_PK_toOctet(&MN, &p->pkm.paillier_pk);
        rc = GMR_verify(&MN, r->Y, p->ID, s->ID);
        if (rc != GMR_OK)
        {
            printf("\t\tInvalid GMR Proof for Player %d. rc %d\n", j, rc);
            return rc;
        }

        /* Verify well formedness of BC modulus */
        rc = BIT_COMMITMENT_setup_verify(&p->pkm.bc_pm, &r->BCP, p->ID, s->ID);
        if (rc != BIT_COMMITMENT_OK)
        {
            printf("\t\tInvalid BC Proof for Player %d. rc %d\n", j, rc);
            return rc;
        }
    }

    printf("\t[Player %d] Broadcast Success\n", i);

    return MPC_OK;
}

/* Keygen - Orchestrate the Key Setup for all players */
int key_setup(csprng *RNG, MPC_party *p)
{
    int i, t, n, rc;

    n = p->n;
    t = p->t;

    /* Setup Keygen memory */

    // Round1 memory
    char round1_sk[n][EGS_SECP256K1];
    char round1_pk[n][EFS_SECP256K1 + 1];
    char round1_r[n][EGS_SECP256K1];
    char round1_c[n][EGS_SECP256K1];
    octet ROUND1_SK[n];
    octet ROUND1_PK[n];
    octet ROUND1_R[n];
    octet ROUND1_C[n];

    init_octets((char *)round1_sk, ROUND1_SK, EGS_SECP256K1,     n);
    init_octets((char *)round1_pk, ROUND1_PK, EFS_SECP256K1 + 1, n);
    init_octets((char *)round1_r,  ROUND1_R,  EGS_SECP256K1,     n);
    init_octets((char *)round1_c,  ROUND1_C,  EGS_SECP256K1,     n);

    MPC_keygen_round1 r1[n];

    for (i = 0; i < n; i++)
    {
        r1[i].SK = ROUND1_SK + i;
        r1[i].PK = ROUND1_PK + i;
        r1[i].C  = ROUND1_C + i;
        r1[i].R  = ROUND1_R + i;
    }

    // Keygen Round2 memory
    char round2_shares_x[n][n][EGS_SECP256K1];
    char round2_shares_y[n][n][EGS_SECP256K1];
    char round2_checks[n][t][EFS_SECP256K1 + 1];
    octet ROUND2_CHECKS[n * t];
    octet ROUND2_SHARES_X[n * n];
    octet ROUND2_SHARES_Y[n * n];

    init_octets((char *)round2_shares_x, ROUND2_SHARES_X, EGS_SECP256K1,     n * n);
    init_octets((char *)round2_shares_y, ROUND2_SHARES_Y, EGS_SECP256K1,     n * n);
    init_octets((char *)round2_checks,   ROUND2_CHECKS,   EFS_SECP256K1 + 1, n * t);

    MPC_keygen_round2 r2[n];

    for (i = 0; i < n; i++)
    {
        r2[i].SHARES.X = ROUND2_SHARES_X + (n * i);
        r2[i].SHARES.Y = ROUND2_SHARES_Y + (n * i);
        r2[i].CHECKS   = ROUND2_CHECKS + (t * i);
    }

    // Keygen Round3 memory
    char round3_sc[n][EFS_SECP256K1 + 1];
    char round3_sp[n][EGS_SECP256K1];

    octet ROUND3_SC[n];
    octet ROUND3_SP[n];

    init_octets((char *)round3_sc, ROUND3_SC, EFS_SECP256K1 + 1, n);
    init_octets((char *)round3_sp, ROUND3_SP, EGS_SECP256K1,     n);

    MPC_keygen_round3 r3[n];

    for (i = 0; i < n; i++)
    {
        r3[i].SCHNORR_C = ROUND3_SC + i;
        r3[i].SCHNORR_P = ROUND3_SP + i;
    }

    // Keygen Session memory
    char id[IDLEN];
    octet ID = {0, sizeof(id), id};
    MPC_keygen_session s;

    s.ID     = &ID;
    s.party  = p;
    s.round1 = r1;
    s.round2 = r2;
    s.round3 = r3;

    /* Agree on session ID for keygen */
    OCT_rand(s.ID, RNG, s.ID->max);

    printf("\n *** Keygen ***\n");

    /* Round 1 - generate key material, commitment */

    printf("\nRound 1 - Generate Key Material\n");

    for (i = 0; i < n; i++)
    {
        rc = MPC_keygen_round1_generate(RNG, p->players +i, s.round1 + i, i);
        if (rc != MPC_OK)
        {
            return rc;
        }

        printf("\n");
    }

    /* Round 2 - compute VSS shares and checks */

    printf("\nRound 2 - Compute VSS Shares and Checks\n");

    for (i = 0; i < n; i++)
    {
        MPC_keygen_round2_vss(RNG, s.round1 + i, s.round2 + i, i, t, n);

        printf("\n");
    }

    /* Round 2 - Verify VSS Shares and combine them */

    printf("\nRound 2 - Verify and combine VSS Shares\n");

    for (i = 0; i < n; i++)
    {
        rc = MPC_keygen_round2_compose(&s, i);
        if (rc != MPC_OK)
        {
            return rc;
        }

        printf("\n");
    }

    /* Round 3 - Generate Proofs for Key Material */

    printf("\nRound 3 - Generate Proofs for key material\n");

    for (i = 0; i < n; i++)
    {
        MPC_keygen_round3_proofs(RNG, p->players + i, s.round3 + i, s.ID, i);
        printf("\n");
    }

    /* Round 3 - Verify Proofs for Key Material */
    printf("\n\nRound 3 - Verify Proofs for Key Material\n");

    for (i = 0; i < n; i++)
    {
        rc = MPC_keygen_round3_verify(&s, i);
        if (rc != MPC_OK)
        {
            return rc;
        }

        printf("\n");
    }

    return MPC_OK;
}

/* *** Signature functions ***/

/* Sign - Convert shamir shares to additive */
void MPC_sign_share_conversion(MPC_signing_session *s, int i)
{
    int j, k, t;

    t = s->party->t;

    char x[t-1][EGS_SECP256K1];
    octet X[t-1];

    init_octets((char *) x, X, EGS_SECP256K1, t-1);

    MPC_player *p;
    MPC_signing_additive_shares *sh;

    k = 0;
    for (j = 0; j < t; j++)
    {
        if (i == j) continue; // Do not include own shares in computation

        // This looks like we are accessing the secret key material,
        // but it is the X component of the Shamir Share, which
        // is not secret
        OCT_copy(X + k, s->party->players[j].skm.SKX);
        k++;
    }

    printf("\t[Player %d] Convert Shamir Share to additive Share\n", i);

    p  = s->party->players + i;
    sh = s->shares + i;

    SSS_shamir_to_additive(t, p->skm.SKX, p->skm.SKY, X, sh->W);

    /* TODO This should not be computed here
     *
     * This should be computed by each player for all players
     * using the same Lagrange coefficient above and the stored
     * xi.G from the keygen
     */
    BIG_256_56 w;
    ECP_SECP256K1 G;
    ECP_SECP256K1_generator(&G);
    BIG_256_56_fromBytesLen(w, sh->W->val, sh->W->len);
    ECP_SECP256K1_mul(&G, w);
    ECP_SECP256K1_toOctet(sh->WG, &G, true);
}

/* Sign - Generate secret values k, gamma for signature */
void MPC_sign_round1_generate(csprng *RNG, MPC_signing_round1* r, int i)
{
    BIG_256_56 k;
    BIG_256_56 q;

    char gammapt[2 * EFS_SECP256K1 + 1];
    octet GAMMAPT = {0, sizeof(gammapt), gammapt};

    ECP_SECP256K1 ECP;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    printf("\t[Player %d] Generate Random k, gamma\n", i);

    BIG_256_56_randomnum(k, q, RNG);
    BIG_256_56_toBytes(r->K->val, k);
    r->K->len = EGS_SECP256K1;

    MPC_ECDSA_KEY_PAIR_GENERATE(RNG, r->GAMMA, &GAMMAPT);

    // Convert GAMMAPT to compressed form
    ECP_SECP256K1_fromOctet(&ECP, &GAMMAPT);
    ECP_SECP256K1_toOctet(r->GAMMAPT, &ECP, true);

    printf("\t[Player %d] Commit to gamma.G\n", i);

    NM_COMMITMENT_commit(RNG, r->GAMMAPT, r->R, r->C);

    printf("\t[Player %d] Transmit commitment C\n", i);
}

/* Sign -
 * Perform MTA with Range Proof and Receiver ZK Proof for all players
 * Instead of saving all the shares and then summing them, each player
 * initialises DELTA with its own KGAMMA share and then accumulates the
 * shares on top of it as they come. This saves memory and it is still
 * fairly easy to parallelise with an opportune lock on DELTA.
 *
 * Given a Alice in the players:
 * Step 1.  Alice encrypts its share and proves it is in the appropriate range in ZK
 *
 * The result from Step 1. is then transmitted to all the other players.
 *
 * Let's call Bob a generic receinver:
 * Step 2.  Bob verifies the ZK proof and aborts if the verification fails
 * Step 2A. Bob homomorphically multiplies its share and adds an obfuscation value z
 * Step 2B. Bob proves knowledge of z and range of its share
 * Step 2C. Bob adds BETA to its DELTA
 * Step 3.  Alice verifies the ZK proof and aborts if the verification fails
 * Step 3A. Alice decrypts the obfuscated product, retrieving ALPHA
 * Step 3B. Alice adds ALPHA to its DELTA
 *
 */
int MPC_sign_round2_mta(csprng *RNG, MPC_signing_session *s)
{
    int i, j, t, rc;

    t = s->party->t;

    /* Memory Setup */

    BIG_256_56 delta[t];

    char cb[FS_4096];
    octet CB = {0, sizeof(cb), cb};

    char rb[FS_4096];
    octet RB = {0, sizeof(rb), rb};

    char z[EGS_SECP256K1];
    octet Z = {0, sizeof(z), z};

    char e[EGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    char alpha[EGS_SECP256K1];
    octet ALPHA = {0, sizeof(alpha), alpha};

    char beta[EGS_SECP256K1];
    octet BETA = {0, sizeof(beta), beta};

    MTA_RP_commitment alice_rp_c;
    MTA_RP_rv         alice_rp_rv;
    MTA_RP_proof      alice_rp_proof;

    MTA_ZK_commitment bob_zk_c;
    MTA_ZK_rv         bob_zk_rv;
    MTA_ZK_proof      bob_zk_proof;

    MPC_player *alice;
    MPC_player *bob;

    MPC_signing_round1 *alice_r1;
    MPC_signing_round2 *alice_r2;
    MPC_signing_round1 *bob_r1;

    // Initialize accumulator for delta = k * gamma
    for (i = 0; i < t; i++)
    {
        MTA_ACCUMULATOR_SET(delta[i], s->round1[i].GAMMA, s->round1[i].K);
    }

    /* MtA runs */
    for (i = 0; i < t; i++)
    {
        alice    = s->party->players + i;
        alice_r1 = s->round1 + i;
        alice_r2 = s->round2 + i;

        /* Alice - Initiate MTA protocol
        *
        * This is reused for all instances of the MTA protocol initiated
        * by Alice
        */

        printf("\t[Player %d] MTA Pass 1\n", i);

        MTA_CLIENT1(RNG, &alice->pkm.paillier_pk, alice_r1->K, alice_r2->CA, alice_r2->R);

        for (j = 0; j < t; j++)
        {
            if (i == j) continue; // No MtA with ourselves

            /* Alice - Generate Range Proof with Bob BC Public Modulus */

            printf("\t[Player %d] Generate Range Proof for Pass 1\n", i);

            bob    = s->party->players + j;
            bob_r1 = s->round1 + j;

            MTA_RP_commit(RNG, &alice->skm.paillier_sk, &bob->pkm.bc_pm, alice_r1->K, &alice_rp_rv, &alice_rp_c);
            MTA_RP_challenge(&alice->pkm.paillier_pk, &bob->pkm.bc_pm, alice_r2->CA, &alice_rp_c, alice->ID, s->ID, &E);
            MTA_RP_prove(&alice->skm.paillier_sk, alice_r1->K, alice_r2->R, &alice_rp_rv, &E, &alice_rp_proof);

            MTA_RP_rv_kill(&alice_rp_rv);

            printf("\t[Player %d] Transmit CA and proof (Z, U, W, S, S1, S2) to Player %d\n", i, j);

            /* Bob - Verify Range Proof and perform second step of MTA protocol */

            printf("\t[Player %d] Verify proof\n", j);

            OCT_clear(&E);
            MTA_RP_challenge(&alice->pkm.paillier_pk, &bob->pkm.bc_pm, alice_r2->CA, &alice_rp_c, alice->ID, s->ID, &E);

            rc = MTA_RP_verify(&alice->pkm.paillier_pk, &bob->skm.bc_sm, alice_r2->CA, &alice_rp_c, &E, &alice_rp_proof);
            if (rc != MTA_OK)
            {
                printf("\t\tInvalid Range Proof for Player %d. rc %d\n", i, rc);
                return MPC_FAIL;
            }

            printf("\t[Player %d] MTA Pass 2 with ZK Proof\n", j);

            MTA_SERVER(RNG, &alice->pkm.paillier_pk, bob_r1->GAMMA, alice_r2->CA, &Z, &RB, &CB, &BETA);

            MTA_ZK_commit(RNG, &alice->pkm.paillier_pk, &alice->pkm.bc_pm, bob_r1->GAMMA, &Z, alice_r2->CA, &bob_zk_rv, &bob_zk_c);
            MTA_ZK_challenge(&alice->pkm.paillier_pk, &alice->pkm.bc_pm, alice_r2->CA, &CB, &bob_zk_c, bob->ID, s->ID, &E);
            MTA_ZK_prove(&alice->pkm.paillier_pk, bob_r1->GAMMA, &Z, &RB, &bob_zk_rv, &E, &bob_zk_proof);

            MTA_ZK_rv_kill(&bob_zk_rv);
            OCT_clear(&RB);
            OCT_clear(&Z);

            printf("\t[Player %d] Add BETA to the accumulator\n", j);

            MTA_ACCUMULATOR_ADD(delta[j], &BETA);

            printf("\t[Player %d] Transmit CB and proof (Z, Z1, T, V, W, S, S1, S2, T1, T2)\n", j);

            /* Alice - Verify ZK proof and perform last step of MTA protocol */

            printf("\t[Player %d] Verify proof\n", i);

            OCT_clear(&E);
            MTA_ZK_challenge(&alice->pkm.paillier_pk, &alice->pkm.bc_pm, alice_r2->CA, &CB, &bob_zk_c, bob->ID, s->ID, &E);

            rc = MTA_ZK_verify(&alice->skm.paillier_sk, &alice->skm.bc_sm, alice_r2->CA, &CB, &bob_zk_c, &E, &bob_zk_proof);
            if (rc != MTA_OK)
            {
                printf("\t\tInvalid ZK Proof for Player %d. rc %d\n", j, rc);
                return MPC_FAIL;
            }

            printf("\t[Player %d] MTA Pass 3 and sum with accumulator\n", i);

            MTA_CLIENT2(&alice->skm.paillier_sk, &CB, &ALPHA);

            MTA_ACCUMULATOR_ADD(delta[i], &ALPHA);
        }
    }

    // Put the accumulators in the correct round structs
    for (i = 0; i < t; i++)
    {
        BIG_256_56_toBytes(s->round2[i].DELTA->val, delta[i]);
        s->round2[i].DELTA->len = EGS_SECP256K1;
    }

    return MPC_OK;
}

/* Perform MTA with Range Proof and Receiver ZK Proof with check for all
 * players.
 * The same consideration aobut parallelisation done for the MtA holds.
 *
 * There is a case to be done for reusing the same encryption of k
 * and RP Proof for both the MtA and MtAwC. I'm doing it separately here
 * to better reflect the paper.
 *
 * Given a Alice in the players:
 * Step 1.  Alice encrypts its share and proves it is in the appropriate range in ZK
 *
 * The result from Step 1. is then transmitted to all the other players.
 *
 * Let's call Bob a gneric receinver:
 * Step 2.  Bob verifies the ZK proof and aborts if the verification fails
 * Step 2A. Bob homomorphically multiplies its share and adds an obfuscation value z
 * Step 2B. Bob proves knowledge of z and range and DLOG knowledge for its share
 * Step 2C. Bob adds BETA to its DELTA
 * Step 3.  Alice verifies the ZK proof and aborts if the verification fails
 * Step 3A. Alice decrypts the obfuscated product, retrieving ALPHA
 * Step 3B. Alice adds ALPHA to its DELTA
 *
 */
int MPC_sign_round2_mtawc(csprng *RNG, MPC_signing_session *s)
{
    int i, j, t, rc;

    t = s->party->t;

    /* Memory Setup */

    BIG_256_56 sigma[t];

    char ca[FS_4096];
    octet CA = {0, sizeof(ca), ca};

    char cb[FS_4096];
    octet CB = {0, sizeof(cb), cb};

    char ra[FS_4096];
    octet RA = {0, sizeof(ra), ra};

    char rb[FS_4096];
    octet RB = {0, sizeof(rb), rb};

    char z[EGS_SECP256K1];
    octet Z = {0, sizeof(z), z};

    char e[EGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    char alpha[EGS_SECP256K1];
    octet ALPHA = {0, sizeof(alpha), alpha};

    char beta[EGS_SECP256K1];
    octet BETA = {0, sizeof(beta), beta};

    MTA_RP_commitment alice_rp_c;
    MTA_RP_rv         alice_rp_rv;
    MTA_RP_proof      alice_rp_proof;

    MTA_ZKWC_commitment bob_zkwc_c;
    MTA_ZKWC_rv         bob_zkwc_rv;
    MTA_ZKWC_proof      bob_zkwc_proof;

    MPC_player *alice;
    MPC_player *bob;

    MPC_signing_round1 *alice_r1;

    // Initialize accumulator for sigma = k * w
    for (i = 0; i < t; i++)
    {
        MTA_ACCUMULATOR_SET(sigma[i], s->shares[i].W, s->round1[i].K);
    }

    /* MtAWC runs */
    for (i = 0; i < t; i++)
    {
        alice    = s->party->players + i;
        alice_r1 = s->round1 + i;

        /* Alice - Initiate MTAWC protocol
        *
        * This is reused for all instances of the MTAWC protocol initiated
        * by Alice
        */

        printf("\t[Player %d] MTAWC Pass 1\n", i);

        MTA_CLIENT1(RNG, &alice->pkm.paillier_pk, alice_r1->K, &CA, &RA);

        for (j = 0; j < t; j++)
        {
            if (i == j) continue; // No MtAWC with ourselves

            /* Alice - Generate Range Proof with Bob BC Public Modulus */

            printf("\t[Player %d] Generate Range Proof for Pass 1\n", i);

            bob = s->party->players + j;

            MTA_RP_commit(RNG, &alice->skm.paillier_sk, &bob->pkm.bc_pm, alice_r1->K, &alice_rp_rv, &alice_rp_c);
            MTA_RP_challenge(&alice->pkm.paillier_pk, &bob->pkm.bc_pm, &CA, &alice_rp_c, alice->ID, s->ID, &E);
            MTA_RP_prove(&alice->skm.paillier_sk, alice_r1->K, &RA, &alice_rp_rv, &E, &alice_rp_proof);

            MTA_RP_rv_kill(&alice_rp_rv);

            printf("\t[Player %d] Transmit CA and proof (Z, U, W, S, S1, S2) to Player %d\n", i, j);

            /* Bob - Verify Range Proof and perform second step of MTAWC protocol */

            printf("\t[Player %d] Verify proof\n", j);

            OCT_clear(&E);
            MTA_RP_challenge(&alice->pkm.paillier_pk, &bob->pkm.bc_pm, &CA, &alice_rp_c, alice->ID, s->ID, &E);

            rc = MTA_RP_verify(&alice->pkm.paillier_pk, &bob->skm.bc_sm, &CA, &alice_rp_c, &E, &alice_rp_proof);
            if (rc != MTA_OK)
            {
                printf("\t\tInvalid Range Proof for Player %d. rc %d\n", i, rc);
                return MPC_FAIL;
            }

            printf("\t[Player %d] MTA Pass 2 with ZKWC Proof\n", j);

            MTA_SERVER(RNG, &alice->pkm.paillier_pk, s->shares[j].W, &CA, &Z, &RB, &CB, &BETA);

            MTA_ZKWC_commit(RNG, &alice->pkm.paillier_pk, &alice->pkm.bc_pm, s->shares[j].W, &Z, &CA, &bob_zkwc_rv, &bob_zkwc_c);
            MTA_ZKWC_challenge(&alice->pkm.paillier_pk, &alice->pkm.bc_pm, &CA, &CB, s->shares[j].WG, &bob_zkwc_c, bob->ID, s->ID, &E);
            MTA_ZKWC_prove(&alice->pkm.paillier_pk, s->shares[j].W, &Z, &RB, &bob_zkwc_rv, &E, &bob_zkwc_proof);

            MTA_ZKWC_rv_kill(&bob_zkwc_rv);
            OCT_clear(&RB);
            OCT_clear(&Z);

            printf("\t[Player %d] Add BETA to the accumulator\n", j);

            MTA_ACCUMULATOR_ADD(sigma[j], &BETA);

            printf("\t[Player %d] Transmit CB and proof (Z, Z1, T, V, W, S, S1, S2, T1, T2)\n", j);

            /* Alice - Verify ZK proof and perform last step of MTA protocol */

            printf("\t[Player %d] Verify proof\n", i);

            OCT_clear(&E);
            MTA_ZKWC_challenge(&alice->pkm.paillier_pk, &alice->pkm.bc_pm, &CA, &CB, s->shares[j].WG, &bob_zkwc_c, bob->ID, s->ID, &E);

            rc = MTA_ZKWC_verify(&alice->skm.paillier_sk, &alice->skm.bc_sm, &CA, &CB, s->shares[j].WG, &bob_zkwc_c, &E, &bob_zkwc_proof);
            if (rc != MTA_OK)
            {
                printf("\t\tInvalid ZKWC Proof for Player %d. rc %d\n", j, rc);
                return MPC_FAIL;
            }

            printf("\t[Player %d] MTA Pass 3 and sum with accumulator\n", i);

            MTA_CLIENT2(&alice->skm.paillier_sk, &CB, &ALPHA);

            MTA_ACCUMULATOR_ADD(sigma[i], &ALPHA);
        }

        OCT_clear(&RA);
    }

    // Put the accumulators in the correct round structs
    for (i = 0; i < t; i++)
    {
        BIG_256_56_toBytes(s->round2[i].SIGMA->val, sigma[i]);
        s->round2[i].SIGMA->len = EGS_SECP256K1;
    }

    return MPC_OK;
}

/* Sign - Compute commitment and well formedness proof for Phase3 */
void MPC_sign_round3_commitment(csprng *RNG, MPC_signing_session *s, int i)
{
    MPC_player *p;
    MPC_signing_round2 *r2;
    MPC_signing_round3 *r3;

    char e[EGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    GG20_ZKP_rv rv;

    p = s->party->players + i;
    r2 = s->round2 + i;
    r3 = s->round3 + i;

    printf("\t[Player %d] Compute commitment to sigma T and ZKP that T is well formed\n", i);

    MPC_PHASE3_T(RNG, r2->SIGMA, r3->L, r3->T);

    GG20_ZKP_phase3_commit(RNG, &rv, r3->C);
    GG20_ZKP_phase3_challenge(r3->T, r3->C, p->ID, s->ID, &E);
    GG20_ZKP_phase3_prove(&rv, &E, r2->SIGMA, r3->L, &r3->p);

    printf("\t[Player %d] Broadcast T value and ZK Proof, along with the DELTA value\n", i);

    GG20_ZKP_rv_kill(&rv);
}

/* Sign - Verify well formedness proof for Phase3 */
int MPC_sign_round3_verify(MPC_signing_session *s, int i)
{
    int t, j, rc;

    t = s->party->t;

    MPC_player *p;
    MPC_signing_round3 *r3;

    char e[EGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    /* Verify ZKP for T */

    printf("\t[Player %d] Verify ZKP of well formedness for T\n", i);

    for(j = 0; j < t; j++)
    {
        if (i == j) continue; // Trust self

        r3 = s->round3 + j;
        p  = s->party->players + j;

        GG20_ZKP_phase3_challenge(r3->T, r3->C, p->ID, s->ID, &E);
        rc = GG20_ZKP_phase3_verify(r3->T, r3->C, &E, &r3->p);
        if (rc != GG20_ZKP_OK)
        {
            printf("\t\tInvalid ZKP for player %d. rc %d\n", j, rc);
            return MPC_FAIL;
        }
    }

    return MPC_OK;
}

/* Sign - Combine the k * gamma shares and combine (k * gamma) ^ -1 */
void MPC_sign_round3_invkgamma(MPC_signing_session *s, int i)
{
    int j, t;

    t = s->party->t;

    char kgamma[t][EGS_SECP256K1];
    octet KGAMMA[t];

    init_octets((char *) kgamma, KGAMMA, EGS_SECP256K1, t);

    printf("\t[Player %d] Combine receinved delta in k * gamma and invert it\n", i);

    // Load all KGAMMA shares (DELTAs)
    for (j = 0; j < t; j++)
    {
        OCT_copy(KGAMMA + j, s->round2[j].DELTA);
    }

    MPC_INVKGAMMA(KGAMMA, s->round3[i].INVKGAMMA, t);
}

/* Sign - decommit gamma_i.G and combine them
 *
 * Doing this in bulk, but the same reasoning to bulk
 * operations in keygen apply here.
 */
int MPC_sign_round4_combine_R(MPC_signing_session *s, int i)
{
    int j, t, rc;

    MPC_signing_round1 *r1;
    MPC_signing_round4 *r4;

    t = s->party->t;
    r4 = s->round4 + i;

    char gammapt[t][EFS_SECP256K1 + 1];
    octet GAMMAPT[t];

    init_octets((char *)gammapt, GAMMAPT, EFS_SECP256K1 + 1, t);

    /* Verify Decommitmet of gamma_i.G */
    for (j = 0; j < t; j++)
    {
        r1 = s->round1 + j;
        OCT_copy(GAMMAPT + j, r1->GAMMAPT);

        if (i == j) continue; // Trust ourselves

        rc = NM_COMMITMENT_decommit(r1->GAMMAPT, r1->R, r1->C);
        if (rc != NM_COMMITMENT_OK)
        {
            printf("\t\tInvalid Commitment for Player %d\n", j);
            return MPC_FAIL;
        }
    }

    /* Combine to retreive R component */
    printf("\t[Player %d] Recombine R component of the signautre\n", i);

    rc = MPC_R(s->round3[i].INVKGAMMA, GAMMAPT, r4->R, r4->RP, t);
    if (rc != MPC_OK)
    {
        printf("\t\tError recombining R component. rc %d", rc);
        return rc;
    }

    return MPC_OK;
}

/* Sign - Compute proof of consistency with Paillier ciphertext */
int MPC_sign_round5_prove(csprng *RNG, MPC_signing_session *s, int i)
{
    int j, rc;

    MPC_player *p;
    MPC_player *o;

    MPC_signing_round1 *r1;
    MPC_signing_round2 *r2;
    MPC_signing_round4 *r4;
    MPC_signing_round5 *r5;

    p  = s->party->players + i;
    r1 = s->round1 + i;
    r2 = s->round2 + i;
    r4 = s->round4 + i;
    r5 = s->round5 + i;

    GGN_rv rv;

    char e[EGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    printf("\t[Player %d] Generate check Rt = k.R\n", i);

    rc = MPC_ECP_GENERATE_CHECK(r4->RP, r1->K, r5->RI);
    if (rc != MPC_OK)
    {
        printf("\t\tError generatring Rt\n");
        return rc;
    }

    printf("\t[Player %d] Generate consistency proofs for Rt and E(K)\n", i);

    for (j = 0; j < s->party->t; j++)
    {
        if (i == j) continue; // No proof for self

        o = s->party->players + j;

        rc = GGN_commit(RNG, &p->skm.paillier_sk, &o->pkm.bc_pm, r4->RP, r1->K, &rv, r5->c + j);
        if (rc != GGN_OK)
        {
            printf("\t\tError generating proof for player %d\n rc %d", i, rc);
            return MPC_FAIL;
        }

        GGN_challenge(&p->pkm.paillier_pk, &o->pkm.bc_pm, r4->RP, r5->RI, r2->CA, r5->c + j, p->ID, s->ID, &E);
        GGN_prove(&p->skm.paillier_sk, r1->K, r2->R, &rv, &E, r5->p + j);

        GGN_rv_kill(&rv);
    }

    printf("\t[Player %d] Broadcast Rt and consistency proof\n", i);

    return MPC_OK;
}

/* Sign - Verify proof of consistency with Paillier ciphertext
 * and check that recombining the Ri the public key is retrieved
 *
 * The same reasoning on parallelisation made for the other functions applies
 */
int MPC_sign_round5_verify(MPC_signing_session *s, int i)
{
    int j, t, rc;

    t = s->party->t;

    char rt[t][EFS_SECP256K1 + 1];
    octet RT[t];

    char e[EGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    init_octets((char *)rt, RT, EFS_SECP256K1 + 1, t);

    MPC_player *p;
    MPC_player *o;
    MPC_signing_round2 *r2;
    MPC_signing_round4 *r4;
    MPC_signing_round5 *r5;

    p  = s->party->players + i;

    /* Verify the proofs of consistency for the checks */

    printf("\t[Player %d] Verify Proofs of consistency for Rt\n", i);

    for (j = 0; j < t; j++)
    {
        o = s->party->players + j;
        r2 = s->round2 + j;
        r4 = s->round4 + j;
        r5 = s->round5 + j;

        OCT_copy(RT + j, r5->RI);

        if (i == j) continue; // Trust ourselves

        GGN_challenge(&o->pkm.paillier_pk, &p->pkm.bc_pm, r4->RP, r5->RI, r2->CA, r5->c + i, o->ID, s->ID, &E);
        rc = GGN_verify(&o->pkm.paillier_pk, &p->skm.bc_sm, r4->RP, r5->RI, r2->CA, r5->c + i, &E, r5->p + i);
        if (rc != GGN_OK)
        {
            printf("\t\tInvalid Proof for Player %d. rc %d\n", j, rc);
            return MPC_FAIL;
        }
    }

    /* Verify R using the checks */

    printf("\t[Player %d] Verify R with the received checks\n", i);

    rc = MPC_ECP_VERIFY(RT, NULL, t);
    if (rc != MPC_OK)
    {
        printf("\t\tInvalid checks for R. rc %d\n", rc);
        return MPC_FAIL;
    }

    return MPC_OK;
}

/* Sign - compute check for sigma and ZKP of consistency with T from round 3 */
int MPC_sign_round6_prove(csprng *RNG, MPC_signing_session *s, int i)
{
    int rc;

    char e[EGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    MPC_player *p;
    MPC_signing_round2 *r2;
    MPC_signing_round3 *r3;
    MPC_signing_round4 *r4;
    MPC_signing_round6 *r6;

    p  = s->party->players + i;
    r2 = s->round2 + i;
    r3 = s->round3 + i;
    r4 = s->round4 + i;
    r6 = s->round6 + i;

    GG20_ZKP_rv rv;

    /* Generate check for consistency of sigma */

    printf("\t[Player %d] Generate check for consistency of sigma\n", i);

    rc = MPC_ECP_GENERATE_CHECK(r4->RP, r2->SIGMA, r6->SI);
    if (rc != MPC_OK)
    {
        printf("\t\tError genereting Si. rc %d\n", rc);
        return rc;
    }

    /* Generate ZKP of consistency of the check */
    rc = GG20_ZKP_phase6_commit(RNG, r4->RP, &rv, &r6->c);
    if (rc != GG20_ZKP_OK)
    {
        printf("\t\tError generating commit for phase6 proof. rc %d\n", rc);
        return rc;
    }

    GG20_ZKP_phase6_challenge(r4->RP, r3->T, r6->SI, &r6->c, p->ID, s->ID, &E);
    GG20_ZKP_phase6_prove(&rv, &E, r2->SIGMA, r3->L, &r6->p);

    // Clean memory
    GG20_ZKP_rv_kill(&rv);

    return MPC_OK;
}

/* Sign - Verify the checks and consistency proofs for Phase 6 */
int MPC_sign_round6_verify(MPC_signing_session *s, int i)
{
    int j, t, rc;

    t = s->party->t;

    char e[EGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    char si[t][EFS_SECP256K1 + 1];
    octet SI[t];

    init_octets((char *)si, SI, EFS_SECP256K1 + 1, t);

    MPC_signing_round3 *r3;
    MPC_signing_round4 *r4;
    MPC_signing_round6 *r6;

    /* Verify the consistency of the SI checks */

    printf("\t[Player %d] Verify the consistency of the SI checks\n", i);

    for (j = 0; j < t; j++)
    {
        r3 = s->round3 + j;
        r4 = s->round4 + j;
        r6 = s->round6 + j;

        OCT_copy(SI + j, r6->SI);

        if (i == j) continue; // Trust ourselves

        GG20_ZKP_phase6_challenge(r4->RP, r3->T, r6->SI, &r6->c, s->party->players[j].ID, s->ID, &E);
        rc = GG20_ZKP_phase6_verify(r4->RP, r3->T, r6->SI, &r6->c, &E, &r6->p);
        if (rc != GG20_ZKP_OK)
        {
            printf("\t\tInvalid check for player %d. rc %d\n", j, rc);
            return MPC_FAIL;
        }
    }

    /* Verify R, SIGMA using the checks */

    printf("\t[Player %d] Verify R, SIGMA using checks\n", i);

    rc = MPC_ECP_VERIFY(SI, s->party->players[i].pkm.PK, t);
    if (rc != MPC_OK)
    {
        printf("\t\tInvalid checks for R, SIGMA. rc %d\n", rc);
        return MPC_FAIL;
    }

    return MPC_OK;
}

/* Sign - compute S component of the signature */
int MPC_sign_round7_si(MPC_signing_session *s, octet *HM, int i)
{
    int rc;

    printf("\t[Player %d] Compute share s_i of the signature S component\n", i);

    rc = MPC_S(HM, s->round4[i].R, s->round1[i].K, s->round2[i].SIGMA, s->round7[i].SI);
    if (rc != MPC_OK)
    {
        printf("\t\tError generating S share. rc %d\n", rc);
        return rc;
    }

    return MPC_OK;
}

/* Sign - compute S component of the signature */
int MPC_sign_round7_combine(MPC_signing_session *s, octet *HM, int i)
{
    int j, t, rc;

    t = s->party->t;

    char si[t][EGS_SECP256K1];
    octet SI[t];

    init_octets((char *)si, SI, EGS_SECP256K1, t);

    for (j = 0; j < t; j++)
    {
        OCT_copy(SI + j, s->round7[j].SI);
    }

    printf("\t[Player %d] Recombine S component of signature\n", i);

    MPC_SUM_BIGS(s->round7[i].S, SI, t);

    printf("\t[Player %d] Verify Signature\n", i);

    rc = MPC_ECDSA_VERIFY(HM, s->party->players[i].pkm.PK, s->round4[i].R, s->round7[i].S);
    if (rc != MPC_OK)
    {
        fprintf(stderr, "\t\tInvalid signature. rc: %d\n", rc);
        return rc;
    }

    return MPC_OK;
}

/* Sign - Orchestrate the signing functions
 *
 * Step 1.  Each player generates random k, gamma and commits to gamma.G
 * Step 2.  Each player performs a MTA with shares k_i, gamma_j and accumulates the shares
 * Step 2A. Each player performs a MTAWC with shares k_i, sk_j and accumulates the shares
 * Step 3.  Players compute the Phase3 values and ZKP and sigma.
 * Step 3A. Players broadcast delta shares and recombine (k * gamma)^-1
 * Step 4.  Players decommit gamma_i.G and recombine the R component
 * Step 5.  Compute checks Rt for R, K and ZKP of consistency with the encryption from round 2
 * Step 5A. Verify Rt consistency and then use them to check R, K
 * Step 6.  Compute checks SI for R, SIGMA and ZKP of consistency with T from round 3
 * Step 6A  Verify  SI consistency and use them to check R, SIGMA
 * Step 7.  Compute the signature S component share
 * Step 7A. Recombine the full S component
 */
int signature(csprng *RNG, MPC_party *p, octet *MSG)
{
    int i, t, rc;

    t = p->t;

    /* Signing Session Memory Setup */
    char hm[SHA256];
    octet HM = {0, sizeof(hm), hm};

    // Additive shares
    char as_w[t][EGS_SECP256K1];
    char as_wg[t][EFS_SECP256K1 + 1];

    octet AS_W[t];
    octet AS_WG[t];

    init_octets((char *)as_w,  AS_W,  EGS_SECP256K1,     t);
    init_octets((char *)as_wg, AS_WG, EFS_SECP256K1 + 1, t);

    MPC_signing_additive_shares as[t];

    for (i = 0; i < t; i++)
    {
        as[i].W  = AS_W + i;
        as[i].WG = AS_WG + i;
    }

    // Round 1
    char phase1_gamma[t][EGS_SECP256K1];
    char phase1_gammapt[t][EFS_SECP256K1 + 1];
    char phase1_k[t][EGS_SECP256K1];
    char phase1_r[t][EGS_SECP256K1];
    char phase1_c[t][EGS_SECP256K1];

    octet PHASE1_GAMMA[t];
    octet PHASE1_GAMMAPT[t];
    octet PHASE1_K[t];
    octet PHASE1_R[t];
    octet PHASE1_C[t];

    init_octets((char *)phase1_gamma,   PHASE1_GAMMA,   EGS_SECP256K1,     t);
    init_octets((char *)phase1_gammapt, PHASE1_GAMMAPT, EFS_SECP256K1 + 1, t);
    init_octets((char *)phase1_k,       PHASE1_K,       EGS_SECP256K1,     t);
    init_octets((char *)phase1_r,       PHASE1_R,       EGS_SECP256K1,     t);
    init_octets((char *)phase1_c,       PHASE1_C,       EGS_SECP256K1,     t);

    MPC_signing_round1 r1[t];

    for (i = 0; i < t; i++)
    {
        r1[i].GAMMA   = PHASE1_GAMMA + i;
        r1[i].GAMMAPT = PHASE1_GAMMAPT + i;
        r1[i].K       = PHASE1_K + i;
        r1[i].R       = PHASE1_R + i;
        r1[i].C       = PHASE1_C + i;
    }

    // Round 2
    char phase2_r[t][FS_4096];
    char phase2_ca[t][FS_4096];
    char phase2_delta[t][EGS_SECP256K1];
    char phase2_sigma[t][EGS_SECP256K1];

    octet PHASE2_R[t];
    octet PHASE2_CA[t];
    octet PHASE2_DELTA[t];
    octet PHASE2_SIGMA[t];

    init_octets((char *)phase2_r,     PHASE2_R,     FS_4096,       t);
    init_octets((char *)phase2_ca,    PHASE2_CA,    FS_4096,       t);
    init_octets((char *)phase2_delta, PHASE2_DELTA, EGS_SECP256K1, t);
    init_octets((char *)phase2_sigma, PHASE2_SIGMA, EGS_SECP256K1, t);

    MPC_signing_round2 r2[t];

    for (i = 0; i < t; i++)
    {
        r2[i].R     = PHASE2_R + i;
        r2[i].CA    = PHASE2_CA + i;
        r2[i].DELTA = PHASE2_DELTA + i;
        r2[i].SIGMA = PHASE2_SIGMA + i;
    }

    // Round 3
    char phase3_invkgamma[t][EGS_SECP256K1];
    char phase3_t[t][EFS_SECP256K1 + 1];
    char phase3_l[t][EGS_SECP256K1];
    char phase3_c[t][EFS_SECP256K1 + 1];

    octet PHASE3_INVKGAMMA[t];
    octet PHASE3_T[t];
    octet PHASE3_L[t];
    octet PHASE3_C[t];

    init_octets((char *)phase3_invkgamma, PHASE3_INVKGAMMA, EGS_SECP256K1,     t);
    init_octets((char *)phase3_t,         PHASE3_T,         EFS_SECP256K1 + 1, t);
    init_octets((char *)phase3_l,         PHASE3_L,         EGS_SECP256K1,     t);
    init_octets((char *)phase3_c,         PHASE3_C,         EFS_SECP256K1 + 1, t);

    MPC_signing_round3 r3[t];

    for (i = 0; i < t; i++)
    {
        r3[i].INVKGAMMA = PHASE3_INVKGAMMA + i;
        r3[i].T         = PHASE3_T + i;
        r3[i].L         = PHASE3_L + i;
        r3[i].C         = PHASE3_C + i;
    }

    // Round 4
    char phase4_r[t][EGS_SECP256K1];
    char phase4_rp[t][EFS_SECP256K1 + 1];

    octet PHASE4_R[t];
    octet PHASE4_RP[t];

    init_octets((char *)phase4_r,  PHASE4_R,  EGS_SECP256K1,     t);
    init_octets((char *)phase4_rp, PHASE4_RP, EFS_SECP256K1 + 1, t);

    MPC_signing_round4 r4[t];

    for (i = 0; i < t; i++)
    {
        r4[i].R  = PHASE4_R  + i;
        r4[i].RP = PHASE4_RP + i;
    }

    // Round 5
    char phase5_ri[t][EFS_SECP256K1 + 1];
    octet PHASE5_RI[t];
    init_octets((char *)phase5_ri, PHASE5_RI, EFS_SECP256K1 + 1, t);

    GGN_commitment phase5_c[t][t];
    GGN_proof phase5_p[t][t];

    MPC_signing_round5 r5[t];

    for (i = 0; i < t; i++)
    {
        r5[i].RI = PHASE5_RI + i;
        r5[i].c  = phase5_c[i];
        r5[i].p  = phase5_p[i];
    }

    // Round 6
    char phase6_si[t][EFS_SECP256K1 + 1];
    octet PHASE6_SI[t];
    init_octets((char *)phase6_si, PHASE6_SI, EFS_SECP256K1 + 1, t);

    MPC_signing_round6 r6[t];

    for (i = 0; i < t; i++)
    {
        r6[i].SI = PHASE6_SI + i;
    }

    // Round 7
    char phase7_si[t][EGS_SECP256K1];
    char phase7_s[t][EGS_SECP256K1];

    octet PHASE7_SI[t];
    octet PHASE7_S[t];

    init_octets((char *)phase7_si, PHASE7_SI, EGS_SECP256K1, t);
    init_octets((char *)phase7_s,  PHASE7_S,  EGS_SECP256K1, t);

    MPC_signing_round7 r7[t];

    for (i = 0; i < t; i++)
    {
        r7[i].SI = PHASE7_SI + i;
        r7[i].S  = PHASE7_S  + i;
    }

    // Session
    char id[IDLEN];
    octet ID = {0, sizeof(id), id};

    MPC_signing_session s;

    s.ID     = &ID;
    s.shares = as;
    s.party  = p;
    s.round1 = r1;
    s.round2 = r2;
    s.round3 = r3;
    s.round4 = r4;
    s.round5 = r5;
    s.round6 = r6;
    s.round7 = r7;

    /* Agree on session ID for signature */
    OCT_rand(s.ID, RNG, s.ID->max);

    printf("\n *** Signature ***\n");

    printf("\nSign message '%s'\n", MSG->val);

    printf("\nPreparation\n");

    /* Preparation - hash message */

    printf("\t[Everyone] Compute Message hash\n");

    MPC_HASH(SHA256, MSG, &HM);

    /* Preparation - convert shares to additive */
    for (i = 0; i < t; i++)
    {
        MPC_sign_share_conversion(&s, i);
        printf("\n");
    }

    char w[EFS_SECP256K1 + 1];
    octet W = {0, sizeof(w), w};
    MPC_SUM_ECPS(&W, AS_WG, t);

    if (!OCT_comp(&W, p->players->pkm.PK))
    {
        printf("Not te same\n");
        OCT_output(&W);
        OCT_output(p->players->pkm.PK);
        return MPC_FAIL;
    }

    /* Round 1 - Generate Secret values */
    printf("\nRound 1\n");

    for (i = 0; i < t; i++)
    {
        MPC_sign_round1_generate(RNG, s.round1 + i, i);
        printf("\n");
    }

    /* Round 2 - MTA/WC runs */
    printf("\nRound 2\n");

    rc = MPC_sign_round2_mta(RNG, &s);
    if (rc != MPC_OK)
    {
        return rc;
    }

    rc = MPC_sign_round2_mtawc(RNG, &s);
    if (rc != MPC_OK)
    {
        return rc;
    }

    /* Round 3 - Generate commitment for sigma and its ZKP */
    printf("\nRound 3\n");

    for (i = 0; i < t; i++)
    {
        MPC_sign_round3_commitment(RNG, &s, i);
        printf("\n");
    }

    /* Round 3 - Verify commitment ZKP */
    for (i = 0; i < t; i++)
    {
        rc = MPC_sign_round3_verify(&s, i);
        if (rc != MPC_OK)
        {
            return rc;
        }
        printf("\n");
    }

    /* Round 3 - Recombine inverse of k * gamma */
    for (i = 0; i < t; i++)
    {
        MPC_sign_round3_invkgamma(&s, i);
        printf("\n");
    }

    /* Round 4 - Combine R component */

    printf("\nRound 4\n");

    for (i = 0; i < t; i++)
    {
        rc = MPC_sign_round4_combine_R(&s, i);
        if (rc != MPC_OK)
        {
            return rc;
        }
        printf("\n");
    }

    /* Round 5 - Generate checks and proofs */
    printf("\nRound 5\n");

    for (i = 0; i < t; i++)
    {
        rc = MPC_sign_round5_prove(RNG, &s, i);
        if (rc != MPC_OK)
        {
            return rc;
        }
        printf("\n");
    }

    /* Round 5 - Verify checks and proofs */
    for (i = 0; i < t; i++)
    {
        rc = MPC_sign_round5_verify(&s, i);
        if (rc != MPC_OK)
        {
            return rc;
        }
        printf("\n");
    }

    /* Round 6 - Generate checks and proofs */
    printf("\nRound 6\n");

    for (i = 0; i < t; i++)
    {
        rc = MPC_sign_round6_prove(RNG, &s, i);
        if (rc != MPC_OK)
        {
            return rc;
        }
        printf("\n");
    }

    /* Round 6 - Verify checks and proofs */
    for (i = 0; i < t; i++)
    {
        rc = MPC_sign_round6_verify(&s, i);
        if (rc != MPC_OK)
        {
            return rc;
        }
        printf("\n");
    }

    /* Round 7 - Compute S shares */
    printf("\nRound 7\n");

    for (i = 0; i < t; i++)
    {
        rc = MPC_sign_round7_si(&s, &HM, i);
        if (rc != MPC_OK)
        {
            return rc;
        }
        printf("\n");
    }

    /* Round 7 - Combine S shares */
    for (i = 0; i < t; i++)
    {
        rc = MPC_sign_round7_combine(&s, &HM, i);
        if (rc != MPC_OK)
        {
            return rc;
        }
        printf("\n");
    }

    printf("\nGenerated Signature:\n");

    printf("\tR = ");
    OCT_output(s.round4->R);
    printf("\tS = ");
    OCT_output(s.round7->S);

    return MPC_OK;
}

void usage(char *name)
{
    printf("Usage: %s t n\n", name);
    printf("Run a full (t, n) keygen and signature flow\n");
    printf("\n");
    printf("  t  Threshold for the MPC protocol. t <= n\n");
    printf("  n  Number of participants in the MPC protocol. t <= n, n>1\n");
    printf("\n");
    printf("Example:\n");
    printf("  %s 3 4\n", name);
}

int main(int argc, char *argv[])
{
    int i, t, n, rc;

    /* Read arguments */
    if (argc != 3)
    {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    t = atoi(argv[1]);
    n = atoi(argv[2]);

    if (t < 1 || n < 2 || t > n)
    {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Memory setup
     *
     * Setup the necessary memory for a (t, n) party
     */
    char player_ids[n][IDLEN];
    char player_pks[n][EFS_SECP256K1 + 1];
    char player_spks[n][EFS_SECP256K1 + 1];
    char player_skx[n][EGS_SECP256K1];
    char player_sky[n][EGS_SECP256K1];
    octet PLAYER_IDS[n];
    octet PLAYER_PKS[n];
    octet PLAYER_SPKS[n];
    octet PLAYER_SKX[n];
    octet PLAYER_SKY[n];

    init_octets((char *)player_ids,  PLAYER_IDS,  IDLEN,             n);
    init_octets((char *)player_pks,  PLAYER_PKS,  EFS_SECP256K1 + 1, n);
    init_octets((char *)player_spks, PLAYER_SPKS, EFS_SECP256K1 + 1, n);
    init_octets((char *)player_skx,  PLAYER_SKX,  EGS_SECP256K1,     n);
    init_octets((char *)player_sky,  PLAYER_SKY,  EGS_SECP256K1,     n);

    MPC_player players[n];

    for (i = 0; i < n; i++)
    {
        players[i].ID      = PLAYER_IDS + i;
        players[i].pkm.PK  = PLAYER_PKS + i;
        players[i].pkm.SPK = PLAYER_SPKS + i;
        players[i].skm.SKX = PLAYER_SKX + i;
        players[i].skm.SKY = PLAYER_SKY + i;
    }

    MPC_party p = {t, n, players};

    // Deterministic RNG for example
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    // Assign IDs to players
    for (i = 0; i < n; i++)
    {
        OCT_rand(PLAYER_IDS+i, &RNG, IDLEN);
    }

    printf("MPC full flow example\n");

    // Key setup phase
    rc = key_setup(&RNG, &p);
    if (rc != MPC_OK)
    {
        exit(EXIT_FAILURE);
    }

    // Signature phase
    char* msg = "BANANA";
    octet MSG = {0, sizeof(msg), msg};

    rc = signature(&RNG, &p, &MSG);
    if (rc != MPC_OK)
    {
        exit(EXIT_FAILURE);
    }

    printf("\nDone\n");
}
