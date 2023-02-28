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

/* Example of the resharing */

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

/* Reshare related structures
 *
 * Note that these structures hold all the values
 * generated in the round, even if they are not to be
 * transmitted. The values to be transmitted and what channel
 * to use are specified in the reshare functions
 */

typedef struct
{
    octet *R;   // Decommitment string
    octet *C;   // Commitment string to PK
} MPC_reshare_round1;

typedef struct
{
    SSS_shares SHARES; // Shares for VSS
    octet *CHECKS;     // Checks for VSS
} MPC_reshare_round2;

typedef struct
{
    octet *SCHNORR_C;
    octet *SCHNORR_P;

    GMR_proof Y;
    BIT_COMMITMENT_setup_proof BCP;
} MPC_reshare_round3;

typedef struct
{
    octet *W;   // Secret additive share
    octet *WG;  // Public Key associated with the additive share
} MPC_reshare_additive_shares;

typedef struct
{
    octet *ID;

    MPC_party *old_party;
    MPC_party *new_party;

    MPC_reshare_additive_shares* shares;

    MPC_reshare_round1 *round1;
    MPC_reshare_round2 *round2;
    MPC_reshare_round3 *round3;
} MPC_reshare_session;

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

/* DEMO ONLY
 * Trusted Key Setup for old party. This generates the SSS shares
 * with a trusted dealer to have the starting setup. In a real
 * world scenario this would have been set up with a proper
 * trustless Keygen
 */
int trusted_key_setup(csprng *RNG, MPC_party *p)
{
    int i, n, rc;

    n = p->n;

    ECP_SECP256K1 ECP;

    char sk[EGS_SECP256K1];
    octet SK = {0, sizeof(sk), sk};

    char pk[2 * EFS_SECP256K1 + 1];
    octet PK = {0, sizeof(pk), pk};

    char skx[n][EGS_SECP256K1];
    char sky[n][EGS_SECP256K1];
    octet SKX[n];
    octet SKY[n];

    init_octets((char *)skx, SKX, EGS_SECP256K1, n);
    init_octets((char *)sky, SKY, EGS_SECP256K1, n);

    SSS_shares shares = {SKX, SKY};

    // Generate ECDSA Key Pair
    printf("\t[Dealer] Generate ECDSA key pair\n");

    MPC_ECDSA_KEY_PAIR_GENERATE(RNG, &SK, &PK);
    rc = ECP_SECP256K1_PUBLIC_KEY_VALIDATE(&PK);
    if (rc != 0)
    {
        printf("\t\tError generating ECDSA key pair. rc %d\n", rc);
        return rc;
    }

    // Generate shares
    SSS_make_shares(p->t, n, RNG, &shares, &SK);

    for(i = 0; i < n; i++)
    {
        OCT_copy(p->players[i].skm.SKX, SKX+i);
        OCT_copy(p->players[i].skm.SKY, SKY+i);
    }

    // Convert PK to compressed form
    ECP_SECP256K1_fromOctet(&ECP, &PK);
    ECP_SECP256K1_toOctet(p->players[0].pkm.PK, &ECP, true);

    for (i = 1; i < n; i++)
    {
        OCT_copy(p->players[i].pkm.PK, p->players[0].pkm.PK);
    }

    return MPC_OK;
}

/* *** Resharing functions *** */

/* Reshare - Round 1
 *
 * The old party converts their SSS shares to additive shares
 * and commit to the equivalent public keys.
 */
void MPC_reshare_round1_commit(csprng *RNG, MPC_reshare_session *s, int i)
{
    int j, k, oldt;

    oldt = s->old_party->t;

    char x[oldt-1][EGS_SECP256K1];
    octet X[oldt-1];

    init_octets((char *) x, X, EGS_SECP256K1, oldt-1);

    MPC_player *p;
    MPC_reshare_round1 *r;
    MPC_reshare_additive_shares *sh;

    p = s->old_party->players + i;
    r = s->round1 + i;
    sh = s->shares + i;

    printf("\t[Old Player %d] Convert Shamir Share to additive\n", i);

    k = 0;
    for (j = 0; j < oldt; j++)
    {
        if (i == j) continue; // Do not include own shares in computation

        // This looks like we are accessing the secret key material,
        // but it is the X component of the Shamir Share, which
        // is not secret
        OCT_copy(X + k, s->old_party->players[j].skm.SKX);
        k++;
    }

    SSS_shamir_to_additive(oldt, p->skm.SKX, p->skm.SKY, X, sh->W);

    /* TODO This should not be stored here
     *
     * This should be computed by each player for all players
     * using the same Lagrange coefficient above and the stored
     * xi.G from the original keygen
     */
    BIG_256_56 w;
    ECP_SECP256K1 G;
    ECP_SECP256K1_generator(&G);
    BIG_256_56_fromBytesLen(w, sh->W->val, sh->W->len);
    ECP_SECP256K1_mul(&G, w);
    ECP_SECP256K1_toOctet(sh->WG, &G, true);

    // Commit to the ECDSA public key
    printf("\t[Old Player %d] Commit to additive share PK\n", i);

    NM_COMMITMENT_commit(RNG, sh->WG, r->R, r->C);

    printf("\t[Old Player %d] Broadcast commitment C\n", i);
}

/* Reshare - Round 2 - Generate VSS Shares
 *
 * Generate the (newt, newn) VSS shares for the old party additive shares.
 */
void MPC_reshare_round2_vss(csprng *RNG, MPC_reshare_session *s, int i)
{
    int newt, newn;

    newt = s->new_party->t;
    newn = s->new_party->n;

    MPC_reshare_round2 *r;
    MPC_reshare_additive_shares *sh;

    r  = s->round2 + i;
    sh = s->shares + i;

    printf("\t[Old Player %d] Generate VSS Shares for additive share\n", i);

    VSS_make_shares(newt, newn, RNG, &r->SHARES, r->CHECKS, sh->W);

    printf("\t[Old Player %d] Broadcast Checks and decommitment string.\n", i);
    printf("\t[Old Player %d] Transmit shares with point2point channel\n", i);
}

/* Reshare - Round 2 - Compose New Party shares
 *
 * Once the shares and decommitments are received they can be
 * verified and summed to compute the full key share for the player.
 * Moreover, the full public key can be computed by adding all the
 * free terms in the exponents from the checks.
 *
 * This is equivalent to the Keygen Round 2 and the same parallelisation
 * observation applies.
 */
int MPC_reshare_round2_compose(MPC_reshare_session *s, int i)
{
    int j, oldt, rc;

    oldt = s->old_party->t;

    char ws[oldt][EFS_SECP256K1 + 1];
    octet WS[oldt];

    init_octets((char *)ws, WS, EFS_SECP256K1 + 1, oldt);

    MPC_player *p;
    MPC_reshare_round1 *r1;
    MPC_reshare_round2 *r2;

    printf("\t[New Player %d] Verify Shares\n", i);

    /* Decommit Free term in the exponent and verify shares */
    for (j = 0; j < oldt; j++)
    {
        p = s->old_party->players + j;
        r1 = s->round1 + j;
        r2 = s->round2 + j;

        // Decommit free term in the exponent
        rc = NM_COMMITMENT_decommit(r2->CHECKS + 0, r1->R, r1->C);
        if (rc != NM_COMMITMENT_OK)
        {
            printf("\t\tInvalid Commitment for Old Player %d. rc %d\n", j, rc);
            return rc;
        }

        // Check all the shares are for the same player
        if (!OCT_comp(r2->SHARES.X+i, s->round2->SHARES.X+i))
        {
            printf("\t\tInvalid X share from Old Player %d.\n", j);
            return MPC_FAIL;
        }

        // VSS Verification for the received share
        rc = VSS_verify_shares(s->new_party->t, r2->SHARES.X+i, r2->SHARES.Y+i, r2->CHECKS);
        if (rc != VSS_OK)
        {
            printf("\t\tInvalid Shares from Old Player %d. rc %d\n", j, rc);
            return MPC_FAIL;
        }
    }

    /* Compose Public Key */

    printf("\t[New Player %d] Compose full PK\n", i);

    p = s->new_party->players + i;

    for (j = 0; j < oldt; j++)
    {
        OCT_copy(WS+j, s->round2[j].CHECKS + 0);
    }

    rc = MPC_SUM_ECPS(p->pkm.PK, WS, oldt);
    if (rc != MPC_OK)
    {
        printf("\t\tInvalid format for PK Shares from Player %d. rc %d\n", i, rc);
        return rc;
    }

    printf("\t[New Player %d] Verify the public key is still the same\n", i);

    if (!OCT_comp(s->old_party->players->pkm.PK, p->pkm.PK))
    {
        printf("\t\tNew Public Key does not match\n");
        return MPC_FAIL;
    }

    /* Compose Shares */

    printf("\t[New Player %d] Combine full share\n", i);

    for (j = 0; j < oldt; j++)
    {
        OCT_copy(WS+j, s->round2[j].SHARES.Y + i);
    }

    MPC_SUM_BIGS(p->skm.SKY, WS, oldt);

    OCT_copy(p->skm.SKX, s->round2->SHARES.X+i);

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

/* Reshare - Round 3 - Generate additional key material
 *
 * Generate additional key material: Paillier Keypair and BC modulus
 * Generate a Schnorr Proof of knowledge of the secret share
 * Generate a Square-Freeness proof for the Paillier Keys
 * Generate a proof of well formedness for the ZKP modulus N, b0, b1
 */
void MPC_reshare_round3_proofs(csprng *RNG, MPC_reshare_session *s, int i)
{
    char oct1[HFS_2048];
    octet OCT1 = {0, sizeof(oct1), oct1};
    char oct2[HFS_2048];
    octet OCT2 = {0, sizeof(oct2), oct2};

    char rv[EGS_SECP256K1];
    octet RV = {0, sizeof(rv), rv};

    char e[EGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    MODULUS_priv m;

    MPC_player *p;
    MPC_reshare_round3 *r;

    p = s->new_party->players + i;
    r = s->round3 + i;

    // Generate Paillier Key pair
    printf("\t[New Player %d] Generate Paillier key pair\n", i);

    PAILLIER_KEY_PAIR(RNG, NULL, NULL, &p->pkm.paillier_pk, &p->skm.paillier_sk);

    // Load Primes for BC setup
    OCT_fromHex(&OCT1, primes[(2 * i) % primes_len]);
    OCT_fromHex(&OCT2, primes[(2 * i + 1) % primes_len]);

    // Generate BC modulus
    printf("\t[New Player %d] Generate BC modulus\n", i);

    BIT_COMMITMENT_setup(RNG, &p->skm.bc_sm, &OCT1, &OCT2, NULL, NULL);
    BIT_COMMITMENT_priv_to_pub(&p->pkm.bc_pm, &p->skm.bc_sm);

    /* Prove knowledge of DLOG PK = s.G */
    printf("\t[New Player %d] Prove knowledge of secret key\n", i);

    SCHNORR_commit(RNG, &RV, r->SCHNORR_C);
    SCHNORR_challenge(p->pkm.SPK, r->SCHNORR_C, p->ID, s->ID, &E);
    SCHNORR_prove(&RV, &E, p->skm.SKY, r->SCHNORR_P);

    OCT_clear(&RV);

    /* Prove Square Freeness of the Paillier modulus */
    printf("\t[New Player %d] Prove Square-Freeness of Paillier modulus\n", i);

    FF_2048_toOctet(&OCT1, p->skm.paillier_sk.p, HFLEN_2048);
    FF_2048_toOctet(&OCT2, p->skm.paillier_sk.q, HFLEN_2048);
    MODULUS_fromOctets(&m, &OCT1, &OCT2);

    GMR_prove(&m, p->ID, s->ID, r->Y);

    OCT_clear(&OCT1);
    OCT_clear(&OCT2);
    MODULUS_kill(&m);

    /* Prove well formedness of the BC modulus */
    printf("\t[New Player %d] Prove Well formedness of BC modulus\n", i);

    BIT_COMMITMENT_setup_prove(RNG, &p->skm.bc_sm, &r->BCP, p->ID, s->ID);

    printf("\t[New Player %d] Broadcast Public Key material, GMR Proof Y and BC proof values\n", i);
}

/* Reshare - Round 3 - Verify Key Material
 *
 * Verify the Square-Freeness proof for the paillier PK
 * Verify the proof of well formedness for the BC modulus
 *
 * This is equivalent to the verification of Round 3 of the Keygen,
 * without the Schnorr Proof. The same observation on parallelisation
 * applies.
 */
int MPC_reshare_round3_verify(MPC_reshare_session *s, int i)
{
    int j, n, rc;

    char e[EGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    char mn[FS_2048];
    octet MN = {0, sizeof(mn), mn};

    MPC_reshare_round3 *r;
    MPC_player *p;

    n = s->new_party->n;

    printf("\t[New Player %d] Verify key material ZKP\n", i);

    for (j = 0; j < n; j++)
    {
        if(j == i) continue; // Trust ourselves

        // Load appropriate player and round communications
        r = s->round3 + j;
        p = s->new_party->players + j;

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
            printf("\t\tInvalid GMR Proof for New Player %d. rc %d\n", j, rc);
            return rc;
        }

        /* Verify well formedness of BC modulus */
        rc = BIT_COMMITMENT_setup_verify(&p->pkm.bc_pm, &r->BCP, p->ID, s->ID);
        if (rc != BIT_COMMITMENT_OK)
        {
            printf("\t\tInvalid BC Proof for New Player %d. rc %d\n", j, rc);
            return rc;
        }
    }

    printf("\t[New Player %d] Broadcast Success\n", i);

    return MPC_OK;
}

/* Reshare - Orchestrate the Key Setup for all players
 *
 * Step 1.  The Old Party Players convert their SSS shares to additive shares
 * Step 1A. The Old Party Players commit to the equivalent PK for the additive shares
 * Step 2.  The Old Party Players generate VSS shares and checks for the additive shares
 * Step 2A. The New Party Players combine the shares and checks into their new SSS share and full PK
 * Step 2B. The New Party Players verify that the full PK is unchanged
 * Step 3.  The New Party Players generate the additional key material and proofs for it
 * Step 3A. The New Party Players verify the additional key material proofs.
 * Step 3B. The New Party Players broadcast their success
 * Step 3C. The Old Party Players delete the old key material
 */
int reshare(csprng *RNG, MPC_party *old_p, MPC_party *new_p)
{
    int i, oldt, newt, newn, rc;

    oldt = old_p->t;
    newn = new_p->n;
    newt = new_p->t;

    /* Setup Keygen memory */

    // Reshare Round1 memory
    char round1_r[oldt][EGS_SECP256K1];
    char round1_c[oldt][EGS_SECP256K1];
    octet ROUND1_R[oldt];
    octet ROUND1_C[oldt];

    init_octets((char *)round1_r,  ROUND1_R,  EGS_SECP256K1, oldt);
    init_octets((char *)round1_c,  ROUND1_C,  EGS_SECP256K1, oldt);

    MPC_reshare_round1 r1[oldt];

    for (i = 0; i < oldt; i++)
    {
        r1[i].C = ROUND1_C + i;
        r1[i].R = ROUND1_R + i;
    }

    // Reshare Round2 memory
    char round2_shares_x[oldt][newn][EGS_SECP256K1];
    char round2_shares_y[oldt][newn][EGS_SECP256K1];
    char round2_checks[oldt][newt][EFS_SECP256K1 + 1];

    octet ROUND2_SHARES_X[oldt * newn];
    octet ROUND2_SHARES_Y[oldt * newn];
    octet ROUND2_CHECKS[oldt * newt];

    init_octets((char *)round2_shares_x, ROUND2_SHARES_X, EGS_SECP256K1,     oldt * newn);
    init_octets((char *)round2_shares_y, ROUND2_SHARES_Y, EGS_SECP256K1,     oldt * newn);
    init_octets((char *)round2_checks,   ROUND2_CHECKS,   EFS_SECP256K1 + 1, oldt * newt);

    MPC_reshare_round2 r2[oldt];

    for (i = 0; i < oldt; i++)
    {
        r2[i].SHARES.X  = ROUND2_SHARES_X + (newn * i);
        r2[i].SHARES.Y  = ROUND2_SHARES_Y + (newn * i);
        r2[i].CHECKS    = ROUND2_CHECKS + (newt * i);
    }

    // Reshare Round3 memory
    char round3_schnorr_c[newn][EFS_SECP256K1 + 1];
    char round3_schnorr_p[newn][EGS_SECP256K1];
    octet ROUND3_SCHNORR_C[newn];
    octet ROUND3_SCHNORR_P[newn];

    init_octets((char *)round3_schnorr_c, ROUND3_SCHNORR_C, EFS_SECP256K1 + 1, newn);
    init_octets((char *)round3_schnorr_p, ROUND3_SCHNORR_P, EGS_SECP256K1,     newn);

    MPC_reshare_round3 r3[newn];

    for (i = 0; i < newn; i++)
    {
        r3[i].SCHNORR_C = ROUND3_SCHNORR_C + i;
        r3[i].SCHNORR_P = ROUND3_SCHNORR_P + i;
    }

    // Keygen Session memory
    char id[IDLEN];
    octet ID = {0, sizeof(id), id};

    char as_w[oldt][EGS_SECP256K1];
    char as_wg[oldt][EFS_SECP256K1 + 1];

    octet AS_W[oldt];
    octet AS_WG[oldt];

    init_octets((char *)as_w,  AS_W,  EGS_SECP256K1,     oldt);
    init_octets((char *)as_wg, AS_WG, EFS_SECP256K1 + 1, oldt);

    MPC_reshare_additive_shares shares[oldt];

    for (i = 0; i < oldt; i++)
    {
        shares[i].W  = AS_W + i;
        shares[i].WG = AS_WG + i;
    }

    MPC_reshare_session s;

    s.ID        = &ID;
    s.shares    = shares;
    s.old_party = old_p;
    s.new_party = new_p;
    s.round1    = r1;
    s.round2    = r2;
    s.round3    = r3;

    /* Agree on session ID for keygen */
    OCT_rand(s.ID, RNG, s.ID->max);

    printf("\n *** Keygen ***\n");

    /* Round 1 - Commit to old PK shares */

    printf("\nRound 1 - Old party - Commit to old PK shares\n");

    for (i = 0; i < oldt; i++)
    {
        MPC_reshare_round1_commit(RNG, &s, i);
        printf("\n");
    }

    /* Round 2 - Old Party - Compute VSS shares and checks */

    printf("\nRound 2 - Old Party - Generate Schnorr Proof, compute VSS Shares and Checks\n");

    for (i = 0; i < oldt; i++)
    {
        MPC_reshare_round2_vss(RNG, &s, i);

        printf("\n");
    }

    /* Round 2 - New Party - Verify VSS Shares and combine them */

    printf("\nRound 2 - New Party - Combine VSS Shares and check Schnorr Proof\n");

    for (i = 0; i < newn; i++)
    {
        rc = MPC_reshare_round2_compose(&s, i);
        if (rc != MPC_OK)
        {
            return rc;
        }

        printf("\n");
    }

    /* Round 3 - New Party - Generate Proofs for Key Material */

    printf("\nRound 3 - New Party - Generate additional key material and Proofs\n");

    for (i = 0; i < newn; i++)
    {
        MPC_reshare_round3_proofs(RNG, &s, i);
        printf("\n");
    }

    /* Round 3 - New Party - Verify Proofs for Key Material */

    printf("\n\nRound 3 - New Party - Verify Proofs for Key Material\n");

    for (i = 0; i < newn; i++)
    {
        rc = MPC_reshare_round3_verify(&s, i);
        if (rc != MPC_OK)
        {
            return rc;
        }

        printf("\n");
    }

    /* The old party deletes its key material
     *
     * All the material in the player skm must be cleaned, except
     * for the X share, which may be left alone.
     *
     * Not doing it here so the resharing can be verified manually
     * in the main
     */
    printf("\nThe old party can now delete the old key material\n");

    return MPC_OK;
}

void usage(char *name)
{
    printf("Usage: %s t n t1 n2\n", name);
    printf("Run a resharing from a (t, n) to a (t1, n1)\n");
    printf("\n");
    printf("  t    Old threshold. 2 <= t <= n\n");
    printf("  n    Old number of participants. t <= n\n");
    printf("  t1   New threshold. 2 <= t1 <= n\n");
    printf("  n1   New number of participants. t1 <= n\n");
    printf("\n");
    printf("Example:\n");
    printf("  %s 3 4 5 6\n", name);
}

int main(int argc, char *argv[])
{
    int i, t, n, t1, n1, rc;

    /* Read arguments */
    if (argc != 5)
    {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    t = atoi(argv[1]);
    n = atoi(argv[2]);

    if (t < 2 || n < 2 || t > n)
    {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    t1 = atoi(argv[3]);
    n1 = atoi(argv[4]);

    if (t1 < 2 || n1 < 2 || t1 > n1)
    {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Memory setup */

    // Old Party
    char old_player_ids[n][IDLEN];
    char old_player_pks[n][EFS_SECP256K1 + 1];
    char old_player_skx[n][EGS_SECP256K1];
    char old_player_sky[n][EGS_SECP256K1];
    octet OLD_PLAYER_IDS[n];
    octet OLD_PLAYER_PKS[n];
    octet OLD_PLAYER_SKX[n];
    octet OLD_PLAYER_SKY[n];

    init_octets((char *)old_player_ids, OLD_PLAYER_IDS, IDLEN,             n);
    init_octets((char *)old_player_pks, OLD_PLAYER_PKS, EFS_SECP256K1 + 1, n);
    init_octets((char *)old_player_skx, OLD_PLAYER_SKX, EGS_SECP256K1,     n);
    init_octets((char *)old_player_sky, OLD_PLAYER_SKY, EGS_SECP256K1,     n);

    MPC_player old_players[n];

    for (i = 0; i < n; i++)
    {
        old_players[i].ID      = OLD_PLAYER_IDS + i;
        old_players[i].pkm.PK  = OLD_PLAYER_PKS + i;
        old_players[i].skm.SKX = OLD_PLAYER_SKX + i;
        old_players[i].skm.SKY = OLD_PLAYER_SKY + i;
    }

    MPC_party old_p = {t, n, old_players};

    // New Party

    char new_player_ids[n1][IDLEN];
    char new_player_pks[n1][EFS_SECP256K1 + 1];
    char new_player_spks[n1][EFS_SECP256K1 + 1];
    char new_player_skx[n1][EGS_SECP256K1];
    char new_player_sky[n1][EGS_SECP256K1];
    octet NEW_PLAYER_IDS[n1];
    octet NEW_PLAYER_PKS[n1];
    octet NEW_PLAYER_SPKS[n1];
    octet NEW_PLAYER_SKX[n1];
    octet NEW_PLAYER_SKY[n1];

    init_octets((char *)new_player_ids,  NEW_PLAYER_IDS,  IDLEN,             n1);
    init_octets((char *)new_player_pks,  NEW_PLAYER_PKS,  EFS_SECP256K1 + 1, n1);
    init_octets((char *)new_player_spks, NEW_PLAYER_SPKS, EFS_SECP256K1 + 1, n1);
    init_octets((char *)new_player_skx,  NEW_PLAYER_SKX,  EGS_SECP256K1,     n1);
    init_octets((char *)new_player_sky,  NEW_PLAYER_SKY,  EGS_SECP256K1,     n1);

    MPC_player new_players[n1];

    for (i = 0; i < n1; i++)
    {
        new_players[i].ID      = NEW_PLAYER_IDS + i;
        new_players[i].pkm.PK  = NEW_PLAYER_PKS + i;
        new_players[i].pkm.SPK = NEW_PLAYER_SPKS + i;
        new_players[i].skm.SKX = NEW_PLAYER_SKX + i;
        new_players[i].skm.SKY = NEW_PLAYER_SKY + i;
    }

    MPC_party new_p = {t1, n1, new_players};

    // Deterministic RNG for example
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    // Assign IDs to players
    for (i = 0; i < n; i++)
    {
        OCT_rand(OLD_PLAYER_IDS+i, &RNG, IDLEN);
    }

    for (i = 0; i < n1; i++)
    {
        OCT_rand(NEW_PLAYER_IDS+i, &RNG, IDLEN);
    }

    printf("MPC resharing example\n");

    // Minimal Key Setup for old party
    rc = trusted_key_setup(&RNG, &old_p);
    if (rc != MPC_OK)
    {
        exit(EXIT_FAILURE);
    }

    // Resharing
    rc = reshare(&RNG, &old_p, &new_p);
    if (rc != MPC_OK)
    {
        exit(EXIT_FAILURE);
    }

    // Check the full SK is the same
    char old_sk[EGS_SECP256K1];
    char new_sk[EGS_SECP256K1];
    octet OLD_SK = {0, sizeof(old_sk), old_sk};
    octet NEW_SK = {0, sizeof(new_sk), new_sk};

    SSS_shares old_shares = {OLD_PLAYER_SKX, OLD_PLAYER_SKY};
    SSS_shares new_shares = {NEW_PLAYER_SKX, NEW_PLAYER_SKY};

    SSS_recover_secret(t,  &old_shares, &OLD_SK);
    SSS_recover_secret(t1, &new_shares, &NEW_SK);

    if (!OCT_comp(&OLD_SK, &NEW_SK))
    {
        printf("ERROR Old Key does not match New Key\n");
        exit(EXIT_FAILURE);
    }

    printf("\nDone\n");
}
