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

#include <string.h>
#include "amcl/mta.h"
#include "amcl/mpc.h"
#include "amcl/commitments.h"
#include "amcl/factoring_zk.h"
#include "amcl/schnorr.h"

/* Example of the full flow */

typedef struct
{
    PAILLIER_private_key paillier_sk;
    PAILLIER_public_key  paillier_pk;
    PAILLIER_public_key  paillier_cpk;

    COMMITMENTS_BC_priv_modulus bc_sm;
    COMMITMENTS_BC_pub_modulus  bc_pm;
    COMMITMENTS_BC_pub_modulus  bc_cpm;

    octet *SK;
    octet *PK;
    octet *CPK;
    octet *FPK;
} key_material;

// Safe primes for BC Setup
char *A_P_hex = "e008507e09c24d756280f3d94912fb9ac16c0a8a1757ee01a350736acfc7f65880f87eca55d6680253383fc546d03fd9ebab7d8fa746455180888cb7c17edf58d3327296468e5ab736374bc9a0fa02606ed5d3a4a5fb1677891f87fbf3c655c3e0549a86b17b7ddce07c8f73e253105e59f5d3ed2c7ba5bdf8495df40ae71a7f";
char *A_Q_hex = "dbffe278edd44c2655714e5a4cc82e66e46063f9ab69df9d0ed20eb3d7f2d8c7d985df71c28707f32b961d160ca938e9cf909cd77c4f8c630aec34b67714cbfd4942d7147c509db131bc2d6a667eb30df146f64b710f8f5247848b0a75738a38772e31014fd63f0b769209928d586499616dcc90700b393156e12eea7e15a835";

char *B_P_hex = "efa013403e9ea93daf97f1dd4b42eba602410e048852b20cd448d51793ac2ee725e79eaac82d22cdd6cfb966cba62904a26da47d7a6085fba194e24eddbc92f66a0bd990c8cb9abf98fff48d52d33215d68f6f030cd9440f85987b2ab44332646ea38bc218fedc83a24cf57b7615c0fc9289778f7ba60f4ed71c7c3c571054fb";
char *B_Q_hex = "f95b9d7027be3950de9a050eba7301d5234ad89bf260d47e94a724b49759ab9a8fca22fe484e5e5ddf0845734cd3322d271e146e1e6eed6e16a2740c294097cd65deeacbfa563cce42065720836d421bcfd73c6dcab3aa0c4d480ac445e9ba11fb7825559b29ab4f9f6f079acbd0dc5c38702f386b3c95107540195a4508401b";

// Unique identifiers for actors
char *alice_id = "alice_unique_id";
char *bob_id   = "bob_unique_id";

int generate_key_material(csprng *RNG, key_material *km, octet *P, octet *Q)
{
    int rc;

    char pk[EFS_SECP256K1 + 1];
    octet PK = {0, sizeof(pk), pk};

    char out[2][FS_2048];
    octet OUT1 = {0, sizeof(out[0]), out[0]};
    octet OUT2 = {0, sizeof(out[1]), out[1]};

    ECP_SECP256K1 ECP;

    // ECDSA Key Pair
    printf("\n\tGenerate ECDSA key pair\n");

    MPC_ECDSA_KEY_PAIR_GENERATE(RNG, km->SK, &PK);
    rc = ECP_SECP256K1_PUBLIC_KEY_VALIDATE(&PK);
    if (rc != 0)
    {
        return rc;
    }

    ECP_SECP256K1_fromOctet(&ECP, &PK);
    ECP_SECP256K1_toOctet(km->PK, &ECP, true);

    printf("\t\tSK = ");
    OCT_output(km->SK);
    printf("\t\tPK = ");
    OCT_output(km->PK);

    // Paillier Key pair
    printf("\n\tGenerate Paillier key pair. Associated primes\n");

    PAILLIER_KEY_PAIR(RNG, NULL, NULL, &km->paillier_pk, &km->paillier_sk);

    FF_2048_toOctet(&OUT1, km->paillier_sk.p, HFLEN_2048);
    FF_2048_toOctet(&OUT2, km->paillier_sk.q, HFLEN_2048);

    printf("\t\tP = ");
    OCT_output(&OUT1);
    printf("\t\tQ = ");
    OCT_output(&OUT2);

    // BC modulus
    printf("\n\tGenerate BC modulus\n");

    COMMITMENTS_BC_setup(RNG, &km->bc_sm, P, Q, NULL, NULL);
    COMMITMENTS_BC_export_public_modulus(&km->bc_pm, &km->bc_sm);

    FF_2048_toOctet(&OUT1, km->bc_sm.P, HFLEN_2048);
    FF_2048_toOctet(&OUT2, km->bc_sm.Q, HFLEN_2048);

    printf("\t\tP  = ");
    OCT_output(&OUT1);
    printf("\t\tQ  = ");
    OCT_output(&OUT2);

    FF_2048_toOctet(&OUT1, km->bc_sm.b0, FFLEN_2048);
    FF_2048_toOctet(&OUT2, km->bc_sm.b1, FFLEN_2048);

    printf("\t\tB0 = ");
    OCT_output(&OUT1);
    printf("\t\tB1 = ");
    OCT_output(&OUT2);

    return MPC_OK;
}

void key_material_zkp(csprng *RNG, key_material *km, octet *C, octet *P, octet *E, octet *Y, octet *ID, octet *AD)
{
    char r[EGS_SECP256K1];
    octet R = {0, sizeof(r), r};

    char s_e[EGS_SECP256K1];
    octet S_E = {0, sizeof(s_e), s_e};

    char p[HFS_2048] = {0};
    octet M_P = {0, sizeof(p), p};

    char q[HFS_2048];
    octet M_Q = {0, sizeof(q), q};

    FACTORING_ZK_modulus m;

    /* Prove knowledge of DLOG PK = s.G */

    SCHNORR_commit(RNG, &R, C);
    SCHNORR_challenge(km->PK, C, ID, AD, &S_E);
    SCHNORR_prove(&R, &S_E, km->SK, P);

    printf("\n\tProve knowledge of ECDSA sk\n");
    printf("\t\tC = ");
    OCT_output(C);
    printf("\t\tE = ");
    OCT_output(&S_E);
    printf("\t\tP = ");
    OCT_output(P);
    printf("\t\tID = ");
    OCT_output(ID);
    printf("\t\tAD = ");
    OCT_output(AD);

    OCT_clear(&R);

    /* Prove knowledge of factorization of the Paillier modulus */

    FF_2048_toOctet(&M_P, km->paillier_sk.p, HFLEN_2048);
    FF_2048_toOctet(&M_Q, km->paillier_sk.q, HFLEN_2048);

    FACTORING_ZK_modulus_fromOctets(&m, &M_P, &M_Q);
    FACTORING_ZK_prove(RNG, &m, ID, AD, NULL, E, Y);

    printf("\n\tProve knowledge of the Paillier Secret Key\n");
    printf("\t\tE = ");
    OCT_output(E);
    printf("\t\tY = ");
    OCT_output(Y);

    OCT_clear(&M_P);
    OCT_clear(&M_Q);
    FACTORING_ZK_modulus_kill(&m);
}

int key_material_verify_zkp(key_material *km, octet *C, octet *P, octet *E, octet *Y, octet *ID, octet *AD)
{
    int rc;

    char s_e[EGS_SECP256K1];
    octet S_E = {0, sizeof(s_e), s_e};

    char n[FS_2048];
    octet N = {0, sizeof(n), n};

    /* Verify Schnorr Proof for counterparty PK */
    printf("\n\tVerify Proof of knowledge of ECDSA sk\n");

    SCHNORR_challenge(km->CPK, C, ID, AD, &S_E);
    rc = SCHNORR_verify(km->CPK, C, &S_E, P);
    if (rc != SCHNORR_OK)
    {
        return rc;
    }

    printf("\t\tSuccess\n");

    /* Verify Factoring Proof for Paillier PK */
    printf("\n\tVerify Proof of knowledge of Paillier sk\n");

    PAILLIER_PK_toOctet(&N, &km->paillier_cpk);

    rc = FACTORING_ZK_verify(&N, E, Y, ID, AD);
    if (rc != FACTORING_ZK_OK)
    {
        return rc;
    }

    printf("\t\tSuccess\n");

    return MPC_OK;
}

/* Key Setup.
 *
 * Step 1.  Generate ECDSA key pair, Paillier key pair and Bit Commitment modulus
 * Setp 1A. Commit to ECDSA public Key, generating commitment and decommitment values. Send nonce
 *          for liveliness.
 * Step 1B. Transmit Paillier public key, Bit Commitment public modulus and the commitment value
 *
 * Upon receipt of the commitment value from the other party:
 *
 * Step 2.  Decommit value for counterparty PK. Abort if it fails
 * Step 2A. Combine public keys
 *
 * Step 3. Produce ZKP of correctness of key material and transmit
 * Step 4. Verify counterparty proof of correctness of key material
 */
void key_setup(csprng *RNG, key_material *alice_km, key_material *bob_km)
{
    int rc;

    char safe_p[HFS_2048];
    octet SAFE_P = {0, sizeof(safe_p), safe_p};

    char safe_q[HFS_2048];
    octet SAFE_Q = {0, sizeof(safe_q), safe_q};

    // Octets for NIZKP ID and AD
    char id[2][32];
    octet A_ID = {0, sizeof(id[0]), id[0]};
    octet B_ID = {0, sizeof(id[1]), id[1]};

    char ad[2][32];
    octet A_AD = {0, sizeof(ad[0]), ad[0]};
    octet B_AD = {0, sizeof(ad[1]), ad[1]};

    // Octets for Non Malleable Commitments
    char commit_r[2][SHA256];
    octet A_COMMIT_R = {0, sizeof(commit_r[0]), commit_r[0]};
    octet B_COMMIT_R = {0, sizeof(commit_r[1]), commit_r[1]};

    char commit_c[2][SHA256];
    octet A_COMMIT_C = {0, sizeof(commit_c[0]), commit_c[0]};
    octet B_COMMIT_C = {0, sizeof(commit_c[1]), commit_c[1]};

    // Octets for Key Setup ZKPs
    char kzkp_c[2][EFS_SECP256K1 + 1];
    octet A_KZKP_C = {0, sizeof(kzkp_c[0]), kzkp_c[0]};
    octet B_KZKP_C = {0, sizeof(kzkp_c[1]), kzkp_c[1]};

    char kzkp_p[2][EGS_SECP256K1];
    octet A_KZKP_P = {0, sizeof(kzkp_p[0]), kzkp_p[0]};
    octet B_KZKP_P = {0, sizeof(kzkp_p[1]), kzkp_p[1]};

    char kzkp_e[2][SHA256];
    octet A_KZKP_E = {0, sizeof(kzkp_e[0]), kzkp_e[0]};
    octet B_KZKP_E = {0, sizeof(kzkp_e[1]), kzkp_e[1]};

    char kzkp_y[2][FS_2048];
    octet A_KZKP_Y = {0, sizeof(kzkp_y[0]), kzkp_y[0]};
    octet B_KZKP_Y = {0, sizeof(kzkp_y[1]), kzkp_y[1]};

    // Octet for paillier PK transmission
    char paillier_pk[FS_2048];
    octet PAILLIER_PK = {0, sizeof(paillier_pk), paillier_pk};

    /* Alice - generate key material, commitment and AD*/

    printf("\n[Alice] Generate key material\n");

    OCT_jstring(&A_ID, alice_id);
    OCT_rand(&B_AD, RNG, B_AD.len);

    OCT_fromHex(&SAFE_P, A_P_hex);
    OCT_fromHex(&SAFE_Q, A_Q_hex);

    rc = generate_key_material(RNG, alice_km, &SAFE_P, &SAFE_Q);
    if (rc != MPC_OK)
    {
        printf("\nFAILURE generating Alice key material. rc %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\n[Alice] Commit to generated PK\n");

    COMMITMENTS_NM_commit(RNG, alice_km->PK, &A_COMMIT_R, &A_COMMIT_C);

    printf("\tR = ");
    OCT_output(&A_COMMIT_R);
    printf("\tC = ");
    OCT_output(&A_COMMIT_C);

    printf("\n[Alice] Transmit commitment C\n");

    // Transmit commitment C, Paillier PK and BC [u] modulus
    PAILLIER_PK_toOctet(&PAILLIER_PK, &alice_km->paillier_pk);
    PAILLIER_PK_fromOctet(&bob_km->paillier_cpk, &PAILLIER_PK);
    COMMITMENTS_BC_export_public_modulus(&bob_km->bc_cpm, &alice_km->bc_sm);

    /* Bob - generate key material, commitment and AD */

    printf("\n[Bob] Generate key material\n");

    OCT_jstring(&B_ID, bob_id);
    OCT_rand(&A_AD, RNG, A_AD.len);

    OCT_fromHex(&SAFE_P, B_P_hex);
    OCT_fromHex(&SAFE_Q, B_Q_hex);

    rc = generate_key_material(RNG, bob_km, &SAFE_P, &SAFE_Q);
    if (rc != MPC_OK)
    {
        printf("\nFAILURE generating Bob key material. rc %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\n[Bob] Commit to generated PK\n");

    COMMITMENTS_NM_commit(RNG, bob_km->PK, &B_COMMIT_R, &B_COMMIT_C);

    printf("\tR = ");
    OCT_output(&A_COMMIT_R);
    printf("\tC = ");
    OCT_output(&A_COMMIT_C);

    printf("\n[Bob] Transmit commitment C\n");

    // Transmit commitment C, Paillier PK and BC public modulus
    PAILLIER_PK_toOctet(&PAILLIER_PK, &bob_km->paillier_pk);
    PAILLIER_PK_fromOctet(&alice_km->paillier_cpk, &PAILLIER_PK);
    COMMITMENTS_BC_export_public_modulus(&alice_km->bc_cpm, &bob_km->bc_sm);

    /* Alice/Bob - transmit decommitment strings and message */

    printf("\n[Alice] Transmit decommitment value R and PK\n");
    printf("\n[Bob] Transmit decommitment value R and PK\n");

    OCT_copy(alice_km->CPK, bob_km->PK);
    OCT_copy(bob_km->CPK, alice_km->PK);

    /* Alice - decommit Bob PK and combine */

    printf("\n[Alice] Decommit Bob PK and combine full PK\n");
    rc = COMMITMENTS_NM_decommit(alice_km->CPK, &B_COMMIT_R, &B_COMMIT_C);
    if (rc != COMMITMENTS_OK)
    {
        printf("\n FAILURE decommitting Bob PK\n");
        exit(EXIT_FAILURE);
    }

    printf("\tDecommitment successful\n");

    rc = MPC_SUM_PK(alice_km->PK, alice_km->CPK, alice_km->FPK);
    if (rc != MPC_OK)
    {
        printf("\nFAILURE combining ECDSA PK for Alice\n");
        exit(EXIT_FAILURE);
    }

    printf("\tCombined PK = ");
    OCT_output(alice_km->FPK);

    /* Bob - decommit Alice PK */

    printf("\n[Bob] Decommit Alice PK and combine full PK\n");
    rc = COMMITMENTS_NM_decommit(bob_km->CPK, &A_COMMIT_R, &A_COMMIT_C);
    if (rc != COMMITMENTS_OK)
    {
        printf("\n FAILURE decommitting Alice PK\n");
        exit(EXIT_FAILURE);
    }

    printf("\tDecommitment successful\n");

    rc = MPC_SUM_PK(bob_km->PK, bob_km->CPK, bob_km->FPK);
    if (rc != MPC_OK)
    {
        printf("\nFAILURE combining ECDSA PK for Bob\n");
        exit(EXIT_FAILURE);
    }

    printf("\tCombined PK = ");
    OCT_output(bob_km->FPK);

    /* Alice - generate key material ZKP */

    printf("\n[Alice] Prove correctness of key material\n");
    key_material_zkp(RNG, alice_km, &A_KZKP_C, &A_KZKP_P, &A_KZKP_E, &A_KZKP_Y, &A_ID, &A_AD);

    printf("\n[Alice] Transmit C, P, E, Y\n");

    /* Bob - generate key material ZKP */

    printf("\n[Bob] Prove correctness of key material\n");
    key_material_zkp(RNG, bob_km, &B_KZKP_C, &B_KZKP_P, &B_KZKP_E, &B_KZKP_Y, &B_ID, &B_AD);

    printf("\n[Bob] Transmit C, P, E, Y\n");

    /* Alice/Bob - verify key material ZKP */

    printf("\n[Alice] Verify Key Material ZKP\n");
    rc = key_material_verify_zkp(alice_km, &B_KZKP_C, &B_KZKP_P, &B_KZKP_E, &B_KZKP_Y, &B_ID, &B_AD);
    if (rc != MPC_OK)
    {
        printf("\n FAILURE invalid ZKP for Bob key material. rc %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\n[Bob] Verify Key Material ZKP\n");
    rc = key_material_verify_zkp(bob_km, &A_KZKP_C, &A_KZKP_P, &A_KZKP_E, &A_KZKP_Y, &A_ID, &A_AD);
    if (rc != MPC_OK)
    {
        printf("\n FAILURE invalid ZKP for Alice key material. rc %d\n", rc);
        exit(EXIT_FAILURE);
    }
}

/* Perform MTA with Range Proof and Receiver ZK Proof
 *
 * Step 1.  Alice encrypts its share and proves it is in the appropriate range in ZK
 * Step 2.  Bob verifies the ZK proof and aborts if the verification fails
 * Step 2A. Bob homomorphically multiplies its share and adds an obfuscation value z
 * Step 2B. Bob proves knowledge of z and range of its share
 * Step 3.  Alice verifies the ZK proof and aborts if the verification fails
 * Step 3A. Alice decrypts the obfuscated product.
 */
void mta(csprng *RNG, key_material *alice_km, key_material *bob_km, octet *K, octet *GAMMA, octet *ALPHA, octet *BETA, char *alice_name, char *bob_name)
{
    int rc;

    char ca[FS_4096];
    octet CA = {0, sizeof(ca), ca};

    char cb[FS_4096];
    octet CB = {0, sizeof(cb), cb};

    char r[FS_4096];
    octet R = {0, sizeof(r), r};

    char z[EGS_SECP256K1];
    octet Z = {0, sizeof(z), z};

    char e[EGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    MTA_RP_commitment    alice_rp_c;
    MTA_RP_commitment_rv alice_rp_rv;
    MTA_RP_proof         alice_rp_proof;

    MTA_ZK_commitment    bob_zk_c;
    MTA_ZK_commitment_rv bob_zk_rv;
    MTA_ZK_proof         bob_zk_proof;

    char out[5][FS_4096];
    octet OUT1 = {0, sizeof(out[0]), out[0]};
    octet OUT2 = {0, sizeof(out[1]), out[1]};
    octet OUT3 = {0, sizeof(out[2]), out[2]};
    octet OUT4 = {0, sizeof(out[3]), out[3]};
    octet OUT5 = {0, sizeof(out[4]), out[4]};


    /* Alice - Initiate MTA protocol and generate Range Proof */

    printf("\n[%s] MTA Pass 1 with Range Proof\n", alice_name);

    MPC_MTA_CLIENT1(RNG, &alice_km->paillier_pk, K, &CA, &R);

    printf("\tCA = ");
    OCT_output(&CA);

    printf("\n\tRange Proof\n");

    MTA_RP_commit(RNG, &alice_km->paillier_sk, &alice_km->bc_cpm, K, &alice_rp_c, &alice_rp_rv);
    MTA_RP_challenge(&alice_km->paillier_pk, &alice_km->bc_cpm, &CA, &alice_rp_c, &E);
    MTA_RP_prove(&alice_km->paillier_sk, &alice_rp_rv, K, &R, &E, &alice_rp_proof);

    MTA_RP_commitment_toOctets(&OUT1, &OUT2, &OUT3, &alice_rp_c);
    printf("\t\tZ  = ");
    OCT_output(&OUT1);
    printf("\t\tU  = ");
    OCT_output(&OUT2);
    printf("\t\tW  = ");
    OCT_output(&OUT3);

    printf("\t\tE  = ");
    OCT_output(&E);

    MTA_RP_proof_toOctets(&OUT1, &OUT2, &OUT3, &alice_rp_proof);
    printf("\t\tS  = ");
    OCT_output(&OUT1);
    printf("\t\tS1 = ");
    OCT_output(&OUT2);
    printf("\t\tS2 = ");
    OCT_output(&OUT3);

    MTA_RP_commitment_rv_kill(&alice_rp_rv);
    OCT_clear(&R);

    // Transmit CA, Commitment and Proof
    printf("\n[%s] Transmit CA and proof (Z, U, W, S, S1, S2)\n", alice_name);

    /* Bob - Verify Range Proof and perform second step of MTA protocol */

    OCT_clear(&E);
    MTA_RP_challenge(&bob_km->paillier_cpk, &bob_km->bc_pm, &CA, &alice_rp_c, &E);

    printf("\n[%s] Verify proof\n", bob_name);
    printf("\tE = ");
    OCT_output(&E);

    rc = MTA_RP_verify(&bob_km->paillier_cpk, &bob_km->bc_sm, &CA, &E, &alice_rp_c, &alice_rp_proof);
    if (rc != MTA_OK)
    {
        printf("FAILURE %s - MTA Invalid %s Range Proof. rc %d\n", bob_name, alice_name, rc);
        exit(EXIT_FAILURE);
    }

    printf("\tSuccess\n");

    printf("\n[%s] MTA Pass 2 with ZK Proof\n", bob_name);

    MPC_MTA_SERVER(RNG, &bob_km->paillier_cpk, GAMMA, &CA, &Z, &R, &CB, BETA);

    printf("\tCB   = ");
    OCT_output(&CB);
    printf("\tBETA = ");
    OCT_output(BETA);

    printf("\n\tZK Proof\n");

    MTA_ZK_commit(RNG, &bob_km->paillier_cpk, &bob_km->bc_cpm, GAMMA, &Z, &CA, &bob_zk_c, &bob_zk_rv);
    MTA_ZK_challenge(&bob_km->paillier_cpk, &bob_km->bc_cpm, &CA, &CB, &bob_zk_c, &E);
    MTA_ZK_prove(&bob_km->paillier_cpk, &bob_zk_rv, GAMMA, &Z, &R, &E, &bob_zk_proof);

    MTA_ZK_commitment_toOctets(&OUT1, &OUT2, &OUT3, &OUT4, &OUT5, &bob_zk_c);
    printf("\t\tZ  = ");
    OCT_output(&OUT1);
    printf("\t\tZ1 = ");
    OCT_output(&OUT2);
    printf("\t\tT  = ");
    OCT_output(&OUT3);
    printf("\t\tV  = ");
    OCT_output(&OUT4);
    printf("\t\tW  = ");
    OCT_output(&OUT5);

    printf("\t\tE  = ");
    OCT_output(&E);

    MTA_ZK_proof_toOctets(&OUT1, &OUT2, &OUT3, &OUT4, &OUT5, &bob_zk_proof);
    printf("\t\tS  = ");
    OCT_output(&OUT1);
    printf("\t\tS1 = ");
    OCT_output(&OUT2);
    printf("\t\tS2 = ");
    OCT_output(&OUT3);
    printf("\t\tT1 = ");
    OCT_output(&OUT4);
    printf("\t\tT2 = ");
    OCT_output(&OUT5);

    MTA_ZK_commitment_rv_kill(&bob_zk_rv);
    OCT_clear(&R);
    OCT_clear(&Z);

    // Transmit CB, Commitment and Proof
    printf("\n[%s] Transmit CB and proof (Z, Z1, T, V, W, S, S1, S2, T1, T2)\n", bob_name);

    /* Alice - Verify ZK proof and perform last step of MTA protocol */

    OCT_clear(&E);
    MTA_ZK_challenge(&alice_km->paillier_pk, &alice_km->bc_pm, &CA, &CB, &bob_zk_c, &E);

    printf("\n[%s] Verify proof\n", alice_name);
    printf("\tE = ");
    OCT_output(&E);

    rc = MTA_ZK_verify(&alice_km->paillier_sk, &alice_km->bc_sm, &CA, &CB, &E, &bob_zk_c, &bob_zk_proof);
    if (rc != MTA_OK)
    {
        printf("FAILURE %s - MTA Invalid %s ZK Proof. rc %d\n", alice_name, bob_name, rc);
        exit(EXIT_FAILURE);
    }

    printf("\tSuccess\n");

    printf("\n[%s] MTA Pass 3\n", alice_name);

    MPC_MTA_CLIENT2(&alice_km->paillier_sk, &CB, ALPHA);

    printf("ALPHA = ");
    OCT_output(ALPHA);
}

/* Perform MTAWC with Range Proof and Receiver ZK Proof
 *
 * Step 1.  Alice encrypts its share and proves it is in the appropriate range in ZK
 * Step 2.  Bob verifies the ZK proof and aborts if the verification fails
 * Step 2A. Bob homomorphically multiplies its share and adds an obfuscation value z
 * Step 2B. Bob proves knowledge of z and range of its share. It also proves that its
 *          share is the exponent of a known DLOG.
 * Step 3.  Alice verifies the ZK proof and aborts if the verification fails
 * Step 3A. Alice decrypts the obfuscated product.
 */
void mtawc(csprng *RNG, key_material *alice_km, key_material *bob_km, octet *K, octet *ALPHA, octet *BETA, char *alice_name, char *bob_name)
{
    int rc;

    char ca[FS_4096];
    octet CA = {0, sizeof(ca), ca};

    char cb[FS_4096];
    octet CB = {0, sizeof(cb), cb};

    char r[FS_4096];
    octet R = {0, sizeof(r), r};

    char z[EGS_SECP256K1];
    octet Z = {0, sizeof(z), z};

    char e[EGS_SECP256K1];
    octet E = {0, sizeof(e), e};

    MTA_RP_commitment    alice_rp_c;
    MTA_RP_commitment_rv alice_rp_rv;
    MTA_RP_proof         alice_rp_proof;

    MTA_ZKWC_commitment    bob_zk_c;
    MTA_ZKWC_commitment_rv bob_zk_rv;
    MTA_ZKWC_proof         bob_zk_proof;

    char out[6][FS_4096];
    octet OUT1 = {0, sizeof(out[0]), out[0]};
    octet OUT2 = {0, sizeof(out[1]), out[1]};
    octet OUT3 = {0, sizeof(out[2]), out[2]};
    octet OUT4 = {0, sizeof(out[3]), out[3]};
    octet OUT5 = {0, sizeof(out[4]), out[4]};
    octet OUT6 = {0, sizeof(out[5]), out[5]};

    /* Alice - Initiate MTA protocol and generate Range Proof */

    printf("\n[%s] MTAWC Pass 1 with Range Proof\n", alice_name);

    MPC_MTA_CLIENT1(RNG, &alice_km->paillier_pk, K, &CA, &R);

    printf("\tCA = ");
    OCT_output(&CA);

    printf("\n\tRange Proof\n");

    MTA_RP_commit(RNG, &alice_km->paillier_sk, &alice_km->bc_cpm, K, &alice_rp_c, &alice_rp_rv);
    MTA_RP_challenge(&alice_km->paillier_pk, &alice_km->bc_cpm, &CA, &alice_rp_c, &E);
    MTA_RP_prove(&alice_km->paillier_sk, &alice_rp_rv, K, &R, &E, &alice_rp_proof);

    MTA_RP_commitment_rv_kill(&alice_rp_rv);
    MTA_RP_commitment_toOctets(&OUT1, &OUT2, &OUT3, &alice_rp_c);
    printf("\t\tZ  = ");
    OCT_output(&OUT1);
    printf("\t\tU  = ");
    OCT_output(&OUT2);
    printf("\t\tW  = ");
    OCT_output(&OUT3);

    printf("\t\tE  = ");
    OCT_output(&E);

    MTA_RP_proof_toOctets(&OUT1, &OUT2, &OUT3, &alice_rp_proof);
    printf("\t\tS  = ");
    OCT_output(&OUT1);
    printf("\t\tS1 = ");
    OCT_output(&OUT2);
    printf("\t\tS2 = ");
    OCT_output(&OUT3);

    MTA_RP_commitment_rv_kill(&alice_rp_rv);
    OCT_clear(&R);

    // Transmit CA, Commitment and Proof
    printf("\n[%s] Transmit CA and proof (Z, U, W, S, S1, S2)\n", alice_name);

    /* Bob - Verify Range Proof and perform second step of MTAWC protocol */

    OCT_clear(&E);
    MTA_RP_challenge(&bob_km->paillier_cpk, &bob_km->bc_pm, &CA, &alice_rp_c, &E);

    printf("\n[%s] Verify proof\n", bob_name);
    printf("\tE = ");
    OCT_output(&E);

    rc = MTA_RP_verify(&bob_km->paillier_cpk, &bob_km->bc_sm, &CA, &E, &alice_rp_c, &alice_rp_proof);
    if (rc != MTA_OK)
    {
        printf("FAILURE %s - MTAWC Invalid %s Range Proof. rc %d\n", bob_name, alice_name, rc);
        exit(EXIT_FAILURE);
    }

    printf("\tSuccess\n");

    printf("\n[%s] MTAWC Pass 2 with ZK Proof\n", bob_name);

    MPC_MTA_SERVER(RNG, &bob_km->paillier_cpk, bob_km->SK, &CA, &Z, &R, &CB, BETA);

    printf("\tCB   = ");
    OCT_output(&CB);
    printf("\tBETA = ");
    OCT_output(BETA);

    printf("\n\tZK Proof\n");

    MTA_ZKWC_commit(RNG, &bob_km->paillier_cpk, &bob_km->bc_cpm, bob_km->SK, &Z, &CA, &bob_zk_c, &bob_zk_rv);
    MTA_ZKWC_challenge(&bob_km->paillier_cpk, &bob_km->bc_cpm, &CA, &CB, bob_km->PK, &bob_zk_c, &E);
    MTA_ZKWC_prove(&bob_km->paillier_cpk, &bob_zk_rv, bob_km->SK, &Z, &R, &E, &bob_zk_proof);

    MTA_ZKWC_commitment_toOctets(&OUT1, &OUT2, &OUT3, &OUT4, &OUT5, &OUT6, &bob_zk_c);
    printf("\t\tU  = ");
    OCT_output(&OUT1);
    printf("\t\tZ  = ");
    OCT_output(&OUT2);
    printf("\t\tZ1 = ");
    OCT_output(&OUT3);
    printf("\t\tT  = ");
    OCT_output(&OUT4);
    printf("\t\tV  = ");
    OCT_output(&OUT5);
    printf("\t\tW  = ");
    OCT_output(&OUT6);

    printf("\t\tE  = ");
    OCT_output(&E);

    MTA_ZKWC_proof_toOctets(&OUT1, &OUT2, &OUT3, &OUT4, &OUT5, &bob_zk_proof);
    printf("\t\tS  = ");
    OCT_output(&OUT1);
    printf("\t\tS1 = ");
    OCT_output(&OUT2);
    printf("\t\tS2 = ");
    OCT_output(&OUT3);
    printf("\t\tT1 = ");
    OCT_output(&OUT4);
    printf("\t\tT2 = ");
    OCT_output(&OUT5);

    MTA_ZKWC_commitment_rv_kill(&bob_zk_rv);
    OCT_clear(&R);
    OCT_clear(&Z);

    // Transmit CB, Commitment and Proof
    printf("\n[%s] Transmit CB and proof (Z, Z1, T, V, W, S, S1, S2, T1, T2)\n", bob_name);

    /* Alice - Verify ZK proof and perform last step of MTAWC protocol */

    OCT_clear(&E);
    MTA_ZKWC_challenge(&alice_km->paillier_pk, &alice_km->bc_pm, &CA, &CB, alice_km->CPK, &bob_zk_c, &E);

    printf("\n[%s] Verify proof\n", alice_name);
    printf("\tE = ");
    OCT_output(&E);

    rc = MTA_ZKWC_verify(&alice_km->paillier_sk, &alice_km->bc_sm, &CA, &CB, alice_km->CPK, &E, &bob_zk_c, &bob_zk_proof);
    if (rc != MTA_OK)
    {
        printf("FAILURE %s - MTAWC Invalid %s ZK Proof. rc %d\n", alice_name, bob_name, rc);
        exit(EXIT_FAILURE);
    }

    printf("\tSuccess\n");

    printf("\n[%s] MTAWC Pass 3\n", alice_name);

    MPC_MTA_CLIENT2(&alice_km->paillier_sk, &CB, ALPHA);

    printf("ALPHA = ");
    OCT_output(ALPHA);
}

/* Phase 5 interactive proof of consistency of the signature shares
 *
 * Step 1.  Each player generates random values phi and rho and commitments
 *          V, A and commits to the value (V, A). It also generates a nonce
 *          for liveliness
 * Step 2.  The values (V, A) are decommited and the players prove they are
 *          well formed
 * Step 2A. The well formedness proofs are transmitted and verified
 * Step 3.  Each player generates a proof for the commitments (V, A) and transmits
 *          a commitment to the proof
 * Step 3A. The proofs are decommitted and verified
 */
void phase5(csprng *RNG, octet *RP1, octet *RP2, octet *R1, octet *R2, octet *HM, octet *S1, octet *S2, octet *PK)
{
    int rc;

    char rho[2][EGS_SECP256K1];
    octet RHO1 = {0, sizeof(rho[0]), rho[0]};
    octet RHO2 = {0, sizeof(rho[1]), rho[1]};

    char phi[2][EGS_SECP256K1];
    octet PHI1 = {0, sizeof(phi[0]), phi[0]};
    octet PHI2 = {0, sizeof(phi[1]), phi[1]};

    char v[2][EFS_SECP256K1 + 1];
    octet V1 = {0, sizeof(v[0]), v[0]};
    octet V2 = {0, sizeof(v[1]), v[1]};
    octet *V[2] = {&V1, &V2};

    char a[2][EFS_SECP256K1 + 1];
    octet A1 = {0, sizeof(a[0]), a[0]};
    octet A2 = {0, sizeof(a[1]), a[1]};
    octet *A[2] = {&A1, &A2};

    char u[2][EFS_SECP256K1 + 1];
    octet U1 = {0, sizeof(u[0]), u[0]};
    octet U2 = {0, sizeof(u[1]), u[1]};
    octet *U[2] = {&U1, &U2};

    char t[2][EFS_SECP256K1 + 1];
    octet T1 = {0, sizeof(t[0]), t[0]};
    octet T2 = {0, sizeof(t[1]), t[1]};
    octet *T[2] = {&T1, &T2};

    // Octets for NIZKP ID and AD
    char id[2][32];
    octet A_ID = {0, sizeof(id[0]), id[0]};
    octet B_ID = {0, sizeof(id[1]), id[1]};

    char ad[2][32];
    octet A_AD = {0, sizeof(ad[0]), ad[0]};
    octet B_AD = {0, sizeof(ad[1]), ad[1]};

    // Octets for Non Malleable Commitments
    char double_ecp[2 * EFS_SECP256K1 + 2];
    octet DOUBLE_ECP = {0, sizeof(double_ecp), double_ecp};

    char commit_r[2][SHA256];
    octet A_COMMIT_R = {0, sizeof(commit_r[0]), commit_r[0]};
    octet B_COMMIT_R = {0, sizeof(commit_r[1]), commit_r[1]};

    char commit_c[2][SHA256];
    octet A_COMMIT_C = {0, sizeof(commit_c[0]), commit_c[0]};
    octet B_COMMIT_C = {0, sizeof(commit_c[1]), commit_c[1]};

    // Octets for Schnorr Proofs
    char schnorr_r[2][EGS_SECP256K1];
    octet SCHNORR_R1 = {0, sizeof(schnorr_r[0]), schnorr_r[0]};
    octet SCHNORR_R2 = {0, sizeof(schnorr_r[1]), schnorr_r[1]};

    char schnorr_e[2][EGS_SECP256K1];
    octet SCHNORR_E1 = {0, sizeof(schnorr_e[0]), schnorr_e[0]};
    octet SCHNORR_E2 = {0, sizeof(schnorr_e[1]), schnorr_e[1]};

    char schnorr_c[2][EFS_SECP256K1 + 1];
    octet SCHNORR_C1 = {0, sizeof(schnorr_c[0]), schnorr_c[0]};
    octet SCHNORR_C2 = {0, sizeof(schnorr_c[1]), schnorr_c[1]};

    char schnorr_p[2][EGS_SECP256K1];
    octet SCHNORR_P1 = {0, sizeof(schnorr_p[0]), schnorr_p[0]};
    octet SCHNORR_P2 = {0, sizeof(schnorr_p[1]), schnorr_p[1]};

    char schnorr_a[2][EGS_SECP256K1];
    octet SCHNORR_A1 = {0, sizeof(schnorr_a[0]), schnorr_a[0]};
    octet SCHNORR_A2 = {0, sizeof(schnorr_a[1]), schnorr_a[1]};

    char schnorr_b[2][EGS_SECP256K1];
    octet SCHNORR_B1 = {0, sizeof(schnorr_b[0]), schnorr_b[0]};
    octet SCHNORR_B2 = {0, sizeof(schnorr_b[1]), schnorr_b[1]};

    char schnorr_d[2][EFS_SECP256K1 + 1];
    octet SCHNORR_D1 = {0, sizeof(schnorr_d[0]), schnorr_d[0]};
    octet SCHNORR_D2 = {0, sizeof(schnorr_d[1]), schnorr_d[1]};


    char schnorr_t[2][EGS_SECP256K1];
    octet SCHNORR_T1 = {0, sizeof(schnorr_t[0]), schnorr_t[0]};
    octet SCHNORR_T2 = {0, sizeof(schnorr_t[1]), schnorr_t[1]};

    char schnorr_u[2][EGS_SECP256K1];
    octet SCHNORR_U1 = {0, sizeof(schnorr_u[0]), schnorr_u[0]};
    octet SCHNORR_U2 = {0, sizeof(schnorr_u[1]), schnorr_u[1]};

    /* Alice - commitment */

    printf("\n[Alice] Generate commitment (V, A) for Phase5 proof and nm commit to it\n");

    OCT_jstring(&A_ID, alice_id);
    OCT_rand(&B_AD, RNG, B_AD.len);

    rc = MPC_PHASE5_commit(RNG, RP1, S1, &PHI1, &RHO1, &V1, &A1);
    if (rc != MPC_OK)
    {
        fprintf(stderr, "FAILURE Alice Phase5 commit rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\tPHI = ");
    OCT_output(&PHI1);
    printf("\tRHO = ");
    OCT_output(&RHO1);
    printf("\tV   = ");
    OCT_output(&V1);
    printf("\tA   = ");
    OCT_output(&A1);

    // Generate commitment to V, A
    printf("\n\tCommitment\n");

    OCT_copy(&DOUBLE_ECP, &V1);
    OCT_joctet(&DOUBLE_ECP, &A1);
    COMMITMENTS_NM_commit(RNG, &DOUBLE_ECP, &A_COMMIT_R, &A_COMMIT_C);

    printf("\t\tR = ");
    OCT_output(&A_COMMIT_R);
    printf("\t\tC = ");
    OCT_output(&A_COMMIT_C);

    printf("\n[Alice] Transmit C value for the (V, A) NM commitment\n");

    /* Bob - commitment */

    printf("\n[Bob] Generate commitment (V, A) for Phase5 proof and nm commit to it\n");

    OCT_jstring(&B_ID, bob_id);
    OCT_rand(&A_AD, RNG, A_AD.len);

    rc = MPC_PHASE5_commit(RNG, RP2, S2, &PHI2, &RHO2, &V2, &A2);
    if (rc != MPC_OK)
    {
        fprintf(stderr, "FAILURE Bob Phase5 commit rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\tPHI = ");
    OCT_output(&PHI2);
    printf("\tRHO = ");
    OCT_output(&RHO2);
    printf("\tV   = ");
    OCT_output(&V2);
    printf("\tA   = ");
    OCT_output(&A2);

    // Generate commitment to V, A
    printf("\n\tCommitment\n");

    OCT_copy(&DOUBLE_ECP, &V2);
    OCT_joctet(&DOUBLE_ECP, &A2);
    COMMITMENTS_NM_commit(RNG, &DOUBLE_ECP, &B_COMMIT_R, &B_COMMIT_C);

    printf("\t\tR = ");
    OCT_output(&B_COMMIT_R);
    printf("\t\tC = ");
    OCT_output(&B_COMMIT_C);

    printf("\n[Bob] Transmit C value for the (V, A) NM commitment\n");

    // Decommit commitments
    printf("\n[Alice] Transmit decommitment value R and (V, A)\n");
    printf("\n[Bob] Transmit decommitment value R and (V, A)\n");

    printf("\n[Alice] Decommit Bob (V, A)\n");

    OCT_copy(&DOUBLE_ECP, &V2);
    OCT_joctet(&DOUBLE_ECP, &A2);
    rc = COMMITMENTS_NM_decommit(&DOUBLE_ECP, &B_COMMIT_R, &B_COMMIT_C);
    if (rc != COMMITMENTS_OK)
    {
        printf("\nFAILURE - Invalid Bob (V, A) commitment\n");
        exit(EXIT_FAILURE);
    }

    printf("\tSuccess\n");

    printf("\n[Bob] Decommit Alice (V, A)\n");

    OCT_copy(&DOUBLE_ECP, &V1);
    OCT_joctet(&DOUBLE_ECP, &A1);
    rc = COMMITMENTS_NM_decommit(&DOUBLE_ECP, &A_COMMIT_R, &A_COMMIT_C);
    if (rc != COMMITMENTS_OK)
    {
        printf("\nFAILURE - Invalid Alice (V, A) commitment\n");
        exit(EXIT_FAILURE);
    }

    printf("\tSuccess\n");

    /* Alice/Bob - Prove well formedness of commitments (V, A) */

    printf("\n[Alice] Generate DSchnorr Proof for PHI, SK, V\n");

    SCHNORR_D_commit(RNG, RP1, &SCHNORR_A1, &SCHNORR_B1, &SCHNORR_D1);
    SCHNORR_D_challenge(RP1, &V1, &SCHNORR_D1, &A_ID, &A_AD, &SCHNORR_E1);
    SCHNORR_D_prove(&SCHNORR_A1, &SCHNORR_B1, &SCHNORR_E1, S1, &PHI1, &SCHNORR_T1, &SCHNORR_U1);

    printf("\tD = ");
    OCT_output(&SCHNORR_D1);
    printf("\tE = ");
    OCT_output(&SCHNORR_E1);
    printf("\tT = ");
    OCT_output(&SCHNORR_T1);
    printf("\tU = ");
    OCT_output(&SCHNORR_U1);

    printf("\n[Alice] Generate Schnorr Proof for A, RHO\n");

    SCHNORR_commit(RNG, &SCHNORR_R1, &SCHNORR_C1);
    SCHNORR_challenge(&A1, &SCHNORR_C1, &A_ID, &A_AD, &SCHNORR_E1);
    SCHNORR_prove(&SCHNORR_R1, &SCHNORR_E1, &RHO1, &SCHNORR_P1);

    printf("\tC = ");
    OCT_output(&SCHNORR_C1);
    printf("\tE = ");
    OCT_output(&SCHNORR_E1);
    printf("\tP = ");
    OCT_output(&SCHNORR_P1);

    printf("\n[Alice] Transmit proofs (D, T, U) and (C, P)\n");

    printf("\n[Bob] Generate DSchnorr Proof for PHI, SK, V\n");

    SCHNORR_D_commit(RNG, RP2, &SCHNORR_A2, &SCHNORR_B2, &SCHNORR_D2);
    SCHNORR_D_challenge(RP2, &V2, &SCHNORR_D2, &B_ID, &B_AD, &SCHNORR_E2);
    SCHNORR_D_prove(&SCHNORR_A2, &SCHNORR_B2, &SCHNORR_E2, S2, &PHI2, &SCHNORR_T2, &SCHNORR_U2);

    printf("\tC = ");
    OCT_output(&SCHNORR_D2);
    printf("\tE = ");
    OCT_output(&SCHNORR_E2);
    printf("\tT = ");
    OCT_output(&SCHNORR_T2);
    printf("\tU = ");
    OCT_output(&SCHNORR_U2);

    printf("\n[Bob] Generate Schnorr Proof for A, RHO\n");

    SCHNORR_commit(RNG, &SCHNORR_R2, &SCHNORR_C2);
    SCHNORR_challenge(&A2, &SCHNORR_C2, &B_ID, &B_AD, &SCHNORR_E2);
    SCHNORR_prove(&SCHNORR_R2, &SCHNORR_E2, &RHO2, &SCHNORR_P2);

    printf("\tC = ");
    OCT_output(&SCHNORR_C2);
    printf("\tE = ");
    OCT_output(&SCHNORR_E2);
    printf("\tP = ");
    OCT_output(&SCHNORR_P2);

    printf("\n[Bob] Transmit proofs (D, T, U) and (C, P)\n");

    printf("\n[Alice] Verify well formedness of Bob commitment (V, A)\n");

    printf("\tVerify Proof for V\n");

    SCHNORR_D_challenge(RP2, &V2, &SCHNORR_D2, &B_ID, &B_AD, &SCHNORR_E2);
    printf("\t\tE = ");
    OCT_output(&SCHNORR_E2);

    rc = SCHNORR_D_verify(RP2, &V2, &SCHNORR_D2, &SCHNORR_E2, &SCHNORR_T2, &SCHNORR_U2);
    if (rc != SCHNORR_OK)
    {
        printf("\nFAILURE - Invalid Bob V DSchnorr proof rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\t\tSuccess\n");

    printf("\n\tVerify Proof for A\n");

    SCHNORR_challenge(&A2, &SCHNORR_C2, &B_ID, &B_AD, &SCHNORR_E2);
    printf("\t\tE = ");
    OCT_output(&SCHNORR_E2);

    rc = SCHNORR_verify(&A2, &SCHNORR_C2, &SCHNORR_E2, &SCHNORR_P2);
    if (rc != SCHNORR_OK)
    {
        printf("\nFAILURE - Invalid Bob A Schnorr proof rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\t\tSuccess\n");

    printf("\n[Bob] Verify well formedness of Alice commitment (V, A)\n");

    printf("\tVerify Proof for V\n");

    SCHNORR_D_challenge(RP1, &V1, &SCHNORR_D1, &A_ID, &A_AD, &SCHNORR_E1);
    printf("\t\tE = ");
    OCT_output(&SCHNORR_E1);

    rc = SCHNORR_D_verify(RP1, &V1, &SCHNORR_D1, &SCHNORR_E1, &SCHNORR_T1, &SCHNORR_U1);
    if (rc != SCHNORR_OK)
    {
        printf("\nFAILURE - Invalid Alice V DSchnorr proof rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\t\tSuccess\n");

    printf("\n\tVerify Proof for A\n");

    SCHNORR_challenge(&A1, &SCHNORR_C1, &A_ID, &A_AD, &SCHNORR_E1);
    printf("\t\tE = ");
    OCT_output(&SCHNORR_E1);

    rc = SCHNORR_verify(&A1, &SCHNORR_C1, &SCHNORR_E1, &SCHNORR_P1);
    if (rc != SCHNORR_OK)
    {
        printf("\nFAILURE - Invalid Alice A Schnorr proof\n");
        exit(EXIT_FAILURE);
    }

    printf("\t\tSuccess\n");

    /* Alice/Bob - proof */

    printf("\n[Alice] Generate and commit to proof for commitments {V1, V2} and {A1, A2}\n");

    rc = MPC_PHASE5_prove(&PHI1, &RHO1, V, A, PK, HM, R1, &U1, &T1);
    if (rc != MPC_OK)
    {
        fprintf(stderr, "FAILURE Alice Phase5 prove rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\tU = ");
    OCT_output(&U1);
    printf("\tT = ");
    OCT_output(&T1);

    // Generate commitment to U, T
    printf("\n\tCommitment\n");

    OCT_copy(&DOUBLE_ECP, &U1);
    OCT_joctet(&DOUBLE_ECP, &T1);
    COMMITMENTS_NM_commit(RNG, &DOUBLE_ECP, &A_COMMIT_R, &A_COMMIT_C);

    printf("\t\tR = ");
    OCT_output(&A_COMMIT_R);
    printf("\t\tC = ");
    OCT_output(&A_COMMIT_C);

    printf("\n[Alice] Transmit C value for the (U, T) NM commitment\n");

    printf("\n[Bob] Generate and proof for commitments {V1, V2} and {A1, A2}\n");

    rc = MPC_PHASE5_prove(&PHI2, &RHO2, V, A, PK, HM, R2, &U2, &T2);
    if (rc != MPC_OK)
    {
        fprintf(stderr, "FAILURE Alice Phase5 prove rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\tU = ");
    OCT_output(&U2);
    printf("\tT = ");
    OCT_output(&T2);

    // Generate commitment to U, T
    printf("\n\tCommitment\n");

    OCT_copy(&DOUBLE_ECP, &U2);
    OCT_joctet(&DOUBLE_ECP, &T2);
    COMMITMENTS_NM_commit(RNG, &DOUBLE_ECP, &B_COMMIT_R, &B_COMMIT_C);

    printf("\t\tR = ");
    OCT_output(&B_COMMIT_R);
    printf("\t\tC = ");
    OCT_output(&B_COMMIT_C);

    printf("\n[Bob] Transmit C value for the (U, T) NM commitment\n");

    // Decommit proofs
    printf("\n[Alice] Transmit decommitment value R and (U, T)\n");
    printf("\n[Bob] Transmit decommitment value R and (U, T)\n");

    printf("\n[Alice] Decommit Bob (U, T)\n");

    OCT_copy(&DOUBLE_ECP, &U2);
    OCT_joctet(&DOUBLE_ECP, &T2);
    rc = COMMITMENTS_NM_decommit(&DOUBLE_ECP, &B_COMMIT_R, &B_COMMIT_C);
    if (rc != COMMITMENTS_OK)
    {
        printf("\nFAILURE - Invalid Bob (U, T) commitment\n");
        exit(EXIT_FAILURE);
    }

    printf("\tSuccess\n");

    printf("\n[Bob] Decommit Alice (U, T)\n");

    OCT_copy(&DOUBLE_ECP, &U1);
    OCT_joctet(&DOUBLE_ECP, &T1);
    rc = COMMITMENTS_NM_decommit(&DOUBLE_ECP, &A_COMMIT_R, &A_COMMIT_C);
    if (rc != COMMITMENTS_OK)
    {
        printf("\nFAILURE - Invalid Alice (U, T) commitment\n");
        exit(EXIT_FAILURE);
    }

    printf("\tSuccess\n");

    /* Alice/Bob - verify, same for both */

    printf("\n[Alice - Bob] Verify proof {T1, T2}, {U1, U2}\n");

    rc = MPC_PHASE5_verify(U, T);
    if (rc != MPC_OK)
    {
        fprintf(stderr, "FAILURE Alice/Bob Phase5 verify rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }
}

/* Signature.
 *
 * Step 1.  Each player generates random k, gamma and commits to gamma.G
 *          It also generates a nonce for liveliness
 * Step 2.  Each player performs a MTA with shares k_i, gamma_j
 * Step 2A. Each player performs a MTAWC with shares k_i, sk_j
 * Step 3.  Each player sums the output of the MTA runs with the product k_i * gamma_i
 * Step 3A. The values from Step 3 are shared and combined by each player
 * Step 4.  The values gamma_i.G are revealed and combined with the value from Step 3A
 *          to compute the R component of the signature
 * Step 5.  Each player sums the outputs of the MTAWC runs with the product k_i * sk_i
 * Step 5A. Each player uses the value from Step 5 to compute its share of the s component of the signature
 * Step 5B. The players engage in the Phase5 ZKP to check the consistency of the signature shares
 * Step 5C. The players broadcast their signature shares and verify that the reconciled signature is valid
 */
void signature(csprng *RNG, octet *M, key_material *alice_km, key_material *bob_km)
{
    int rc;

    // Random generation
    BIG_256_56 q;
    BIG_256_56 k1;
    BIG_256_56 k2;

    char oct_k[2][EGS_SECP256K1];
    octet K1 = {0, sizeof(oct_k[0]), oct_k[0]};
    octet K2 = {0, sizeof(oct_k[1]), oct_k[1]};

    char gamma[2][EGS_SECP256K1];
    octet GAMMA1 = {0, sizeof(gamma[0]), gamma[0]};
    octet GAMMA2 = {0, sizeof(gamma[1]), gamma[1]};

    char gammapt[2][EFS_SECP256K1 + 1];
    octet GAMMAPT1 = {0, sizeof(gammapt[0]), gammapt[0]};
    octet GAMMAPT2 = {0, sizeof(gammapt[1]), gammapt[1]};

    // Octets for NIZKP ID and AD
    char id[2][32];
    octet A_ID = {0, sizeof(id[0]), id[0]};
    octet B_ID = {0, sizeof(id[1]), id[1]};

    char ad[2][32];
    octet A_AD = {0, sizeof(ad[0]), ad[0]};
    octet B_AD = {0, sizeof(ad[1]), ad[1]};

    // Octets for Non Malleable Commitments
    char commit_r[2][SHA256];
    octet A_COMMIT_R = {0, sizeof(commit_r[0]), commit_r[0]};
    octet B_COMMIT_R = {0, sizeof(commit_r[1]), commit_r[1]};

    char commit_c[2][SHA256];
    octet A_COMMIT_C = {0, sizeof(commit_c[0]), commit_c[0]};
    octet B_COMMIT_C = {0, sizeof(commit_c[1]), commit_c[1]};

    // Octets for Schnorr Proofs
    char schnorr_r[2][EGS_SECP256K1];
    octet SCHNORR_R1 = {0, sizeof(schnorr_r[0]), schnorr_r[0]};
    octet SCHNORR_R2 = {0, sizeof(schnorr_r[1]), schnorr_r[1]};

    char schnorr_e[2][EGS_SECP256K1];
    octet SCHNORR_E1 = {0, sizeof(schnorr_e[0]), schnorr_e[0]};
    octet SCHNORR_E2 = {0, sizeof(schnorr_e[1]), schnorr_e[1]};

    char schnorr_c[2][EFS_SECP256K1 + 1];
    octet SCHNORR_C1 = {0, sizeof(schnorr_c[0]), schnorr_c[0]};
    octet SCHNORR_C2 = {0, sizeof(schnorr_c[1]), schnorr_c[1]};

    char schnorr_p[2][EGS_SECP256K1];
    octet SCHNORR_P1 = {0, sizeof(schnorr_p[0]), schnorr_p[0]};
    octet SCHNORR_P2 = {0, sizeof(schnorr_p[1]), schnorr_p[1]};

    // Octets for MTA/WC
    char alpha[2][EGS_SECP256K1];
    octet ALPHA1 = {0, sizeof(alpha[0]), alpha[0]};
    octet ALPHA2 = {0, sizeof(alpha[1]), alpha[1]};

    char beta[2][EGS_SECP256K1];
    octet BETA1 = {0, sizeof(beta[0]), beta[0]};
    octet BETA2 = {0, sizeof(beta[1]), beta[1]};

    // Octets for reconciliation
    char delta[2][EGS_SECP256K1];
    octet DELTA1 = {0, sizeof(delta[0]), delta[0]};
    octet DELTA2 = {0, sizeof(delta[1]), delta[1]};

    char ikgamma[2][EGS_SECP256K1];
    octet IKGAMMA1 = {0, sizeof(ikgamma[0]), ikgamma[0]};
    octet IKGAMMA2 = {0, sizeof(ikgamma[1]), ikgamma[1]};

    char sigr[2][EGS_SECP256K1];
    octet SIGR1 = {0, sizeof(sigr[0]), sigr[0]};
    octet SIGR2 = {0, sizeof(sigr[1]), sigr[1]};

    char sigrp[2][EFS_SECP256K1 + 1];
    octet SIGRP1 = {0, sizeof(sigrp[0]), sigrp[0]};
    octet SIGRP2 = {0, sizeof(sigrp[1]), sigrp[1]};

    char sigma[2][EGS_SECP256K1];
    octet SIGMA1 = {0, sizeof(sigma[0]), sigma[0]};
    octet SIGMA2 = {0, sizeof(sigma[1]), sigma[1]};

    char hm[SHA256];
    octet HM = {0, sizeof(hm), hm};

    char sigs[3][EGS_SECP256K1];
    octet SIGS1 = {0, sizeof(sigs[0]), sigs[0]};
    octet SIGS2 = {0, sizeof(sigs[1]), sigs[1]};
    octet SIGS = {0, sizeof(sigs[2]),  sigs[2]};

    // ECP conversion workspace
    char ncp[2 * EFS_SECP256K1 + 1];
    octet NCP = {0, sizeof(ncp), ncp};

    ECP_SECP256K1 P;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    /* Alice - Generate k and gamma and commit to gamma.G */

    printf("\n[Alice] Generate random K and GAMMA and commit to GAMMA.G\n");

    OCT_jstring(&A_ID, alice_id);
    OCT_rand(&B_AD, RNG, B_AD.len);

    BIG_256_56_randomnum(k1, q, RNG);
    BIG_256_56_toBytes(K1.val, k1);
    K1.len = EGS_SECP256K1;

    MPC_ECDSA_KEY_PAIR_GENERATE(RNG, &GAMMA1, &NCP);
    ECP_SECP256K1_fromOctet(&P, &NCP);
    ECP_SECP256K1_toOctet(&GAMMAPT1, &P, true);

    printf("\tK       = ");
    OCT_output(&K1);
    printf("\tGAMMA   = ");
    OCT_output(&GAMMA1);
    printf("\tGAMMA.G = ");
    OCT_output(&GAMMAPT1);

    COMMITMENTS_NM_commit(RNG, &GAMMAPT1, &A_COMMIT_R, &A_COMMIT_C);

    printf("\n\tCommitment\n");
    printf("\t\tR = ");
    OCT_output(&A_COMMIT_R);
    printf("\t\tC = ");
    OCT_output(&A_COMMIT_C);

    // Transmit commitment C
    printf("\n[Alice] Transmit commitment value C\n");

    /* Bob - Generate k and gamma and commit to gamma.G */

    printf("\n[Bob] Generate random K and GAMMA and commit to GAMMA.G\n");

    OCT_jstring(&B_ID, bob_id);
    OCT_rand(&A_AD, RNG, A_AD.len);

    BIG_256_56_randomnum(k2, q, RNG);
    BIG_256_56_toBytes(K2.val, k2);
    K2.len = EGS_SECP256K1;

    MPC_ECDSA_KEY_PAIR_GENERATE(RNG, &GAMMA2, &NCP);
    ECP_SECP256K1_fromOctet(&P, &NCP);
    ECP_SECP256K1_toOctet(&GAMMAPT2, &P, true);

    printf("\tK       = ");
    OCT_output(&K2);
    printf("\tGAMMA   = ");
    OCT_output(&GAMMA2);
    printf("\tGAMMA.G = ");
    OCT_output(&GAMMAPT2);

    COMMITMENTS_NM_commit(RNG, &GAMMAPT2, &B_COMMIT_R, &B_COMMIT_C);

    printf("\n\tCommitment\n");
    printf("\t\tR = ");
    OCT_output(&B_COMMIT_R);
    printf("\t\tC = ");
    OCT_output(&B_COMMIT_C);


    // Transmit commitment C
    printf("\n[Bob] Transmit commitment value C\n");

    /* Alice/Bob - Initiate MTA with shares k1, gamma2 and k2, gamma1 */

    printf("\n[Alice-Bob] Run MTA with K1, GAMMA2\n");
    mta(RNG, alice_km, bob_km, &K1, &GAMMA2, &ALPHA1, &BETA2, "Alice", "Bob");
    printf("\n[Bob-Alice] Run MTA with K2, GAMMA1\n");
    mta(RNG, bob_km, alice_km, &K2, &GAMMA1, &ALPHA2, &BETA1, "Bob", "Alice");

    /* Alice/Bob - combine received shares to compute an additive share of kgamma */

    printf("\n[Alice] Recombine additive shares to compute K1*GAMMA1 + ALPHA1 + BETA1\n");
    MPC_SUM_MTA(&K1, &GAMMA1, &ALPHA1, &BETA1, &DELTA1);
    printf("\tDELTA = ");
    OCT_output(&DELTA1);

    printf("\n[Bob] Recombine additive shares to compute K2*GAMMA2 + ALPHA2 + BETA2\n");
    MPC_SUM_MTA(&K2, &GAMMA2, &ALPHA2, &BETA2, &DELTA2);
    printf("\tDELTA = ");
    OCT_output(&DELTA2);

    /* Alice/Bob - Initiate MTAWC with shares k1, sk1 and k2, sk2 */

    printf("\n[Alice-Bob] Run MTAWC with K1, SK2\n");
    mtawc(RNG, alice_km, bob_km, &K1, &ALPHA1, &BETA2, "Alice", "Bob");
    printf("\n[Bob-Alice] Run MTAWC with K2, SK1\n");
    mtawc(RNG, bob_km, alice_km, &K2, &ALPHA2, &BETA1, "Bob", "Alice");

    /* Alice/Bob - combine received shares to compute an additive share of kw */

    printf("\n[Alice] Recombine additive shares to compute K1*SK1 + ALPHA1 + BETA1\n");
    MPC_SUM_MTA(&K1, alice_km->SK, &ALPHA1, &BETA1, &SIGMA1);
    printf("\tSIGMA = ");
    OCT_output(&SIGMA1);

    printf("\n[Bob] Recombine additive shares to compute K2*SK2 + ALPHA2 + BETA2\n");
    MPC_SUM_MTA(&K2, bob_km->SK,   &ALPHA2, &BETA2, &SIGMA2);
    printf("\tSIGMA = ");
    OCT_output(&SIGMA2);

    /* Alice/Bob - broadcast DELTA1, DELTA2 and compute (kgamma)^(-1) */

    printf("\n[Alice] Transmit share of DELTA\n");
    printf("\n[Bob] Transmit share of DELTA\n");

    printf("\n[Alice] Combine DELTA shares and invert modulo curve order\n");
    MPC_INVKGAMMA(&DELTA1, &DELTA2, &IKGAMMA1);
    printf("\tIKGAMMA = ");
    OCT_output(&IKGAMMA1);

    printf("\n[Bob] Combine DELTA shares and invert modulo curve order\n");
    MPC_INVKGAMMA(&DELTA1, &DELTA2, &IKGAMMA2);
    printf("\tIKGAMMA = ");
    OCT_output(&IKGAMMA2);

    /* Alice - transmit decommitment and message for gamma.G and prove knowldege of gamma */

    printf("\n[Alice] Generate Schnorr Proof for DLOG GAMMA, GAMMA.G\n");

    SCHNORR_commit(RNG, &SCHNORR_R1, &SCHNORR_C1);
    SCHNORR_challenge(&GAMMAPT1, &SCHNORR_C1, &A_ID, &A_AD, &SCHNORR_E1);
    SCHNORR_prove(&SCHNORR_R1, &SCHNORR_E1, &GAMMA1, &SCHNORR_P1);

    printf("\tC = ");
    OCT_output(&SCHNORR_C1);
    printf("\tE = ");
    OCT_output(&SCHNORR_E1);
    printf("\tP = ");
    OCT_output(&SCHNORR_P1);

    printf("\n[Alice] Transmit GAMMA.G with decommitment R and proof (C, P)\n");

    /* Bob - transmit decommitment and message for gamma.G and prove knowldege of gamma */

    printf("\n[Bob] Generate Schnorr Proof for DLOG GAMMA, GAMMA.G\n");

    SCHNORR_commit(RNG, &SCHNORR_R2, &SCHNORR_C2);
    SCHNORR_challenge(&GAMMAPT2, &SCHNORR_C2, &B_ID, &B_AD, &SCHNORR_E2);
    SCHNORR_prove(&SCHNORR_R2, &SCHNORR_E2, &GAMMA2, &SCHNORR_P2);

    printf("\tC = ");
    OCT_output(&SCHNORR_C2);
    printf("\tE = ");
    OCT_output(&SCHNORR_E2);
    printf("\tP = ");
    OCT_output(&SCHNORR_P2);

    printf("\n[Bob] Transmit GAMMA.G with decommitment R and proof (C, P)\n");

    /* Alice - verify decommitment of gamma.G and Schnorr Proof */

    printf("\n[Alice] Decommit GAMMA.G received from Bob\n");

    rc = COMMITMENTS_NM_decommit(&GAMMAPT2, &B_COMMIT_R, &B_COMMIT_C);
    if (rc != MPC_OK)
    {
        printf("\nFAILURE - Invalid Bob gamma.G commitment\n");
        exit(EXIT_FAILURE);
    }

    printf("\tSuccess\n");

    printf("\n[Alice] Verify Schnorr Proof for GAMMA.G\n");

    OCT_clear(&SCHNORR_E2);
    SCHNORR_challenge(&GAMMAPT2, &SCHNORR_C2, &B_ID, &B_AD, &SCHNORR_E2);

    printf("\tE = ");
    OCT_output(&SCHNORR_E2);

    rc = SCHNORR_verify(&GAMMAPT2, &SCHNORR_C2, &SCHNORR_E2, &SCHNORR_P2);
    if (rc != SCHNORR_OK)
    {
        printf("\nFAILURE - Invalid Bob gamma.G Schnorr proof\n");
        exit(EXIT_FAILURE);
    }

    printf("\tSuccess\n");

    /* Bob - verify decommitment of gamma.G and Schnorr Proof */

    printf("\n[Bob] Decommit GAMMA.G received from Alice\n");

    rc = COMMITMENTS_NM_decommit(&GAMMAPT1, &A_COMMIT_R, &A_COMMIT_C);
    if (rc != COMMITMENTS_OK)
    {
        printf("\nFAILURE - Invalid Alice gamma.G commitment\n");
        exit(EXIT_FAILURE);
    }

    printf("\tSuccess\n");

    printf("\n[Bob] Verify Schnorr Proof for GAMMA.G\n");

    OCT_clear(&SCHNORR_E1);
    SCHNORR_challenge(&GAMMAPT1, &SCHNORR_C1, &A_ID, &A_AD, &SCHNORR_E1);

    printf("\tE = ");
    OCT_output(&SCHNORR_E1);

    rc = SCHNORR_verify(&GAMMAPT1, &SCHNORR_C1, &SCHNORR_E1, &SCHNORR_P1);
    if (rc != SCHNORR_OK)
    {
        printf("\nFAILURE - Invalid Alice gamma.G Schnorr proof\n");
        exit(EXIT_FAILURE);
    }

    printf("\tSuccess\n");

    /* Alice/Bob - reconcile R and get x component */

    printf("\n[Alice] Reconcile R component of the signature\n");

    rc = MPC_R(&IKGAMMA1, &GAMMAPT1, &GAMMAPT2, &SIGR1, &SIGRP1);
    if (rc != MPC_OK)
    {
        fprintf(stderr, "FAILURE Alice recombining R rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\tR  = ");
    OCT_output(&SIGR1);
    printf("\tRP = ");
    OCT_output(&SIGRP1);

    printf("\n[Bob] Reconcile R component of the signature\n");

    rc = MPC_R(&IKGAMMA1, &GAMMAPT1, &GAMMAPT2, &SIGR2, &SIGRP2);
    if (rc != MPC_OK)
    {
        fprintf(stderr, "FAILURE Bob recombinig R rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\tR  = ");
    OCT_output(&SIGR2);
    printf("\tRP = ");
    OCT_output(&SIGRP2);

    /* Alice/Bob - compute shares for S */

    MPC_HASH(HASH_TYPE_SECP256K1, M, &HM);

    printf("\n[Alice] Generate share for signature S component\n");

    rc = MPC_S(&HM, &SIGR1, &K1, &SIGMA1, &SIGS1);
    if (rc != MPC_OK)
    {
        fprintf(stderr, "FAILURE computing Alice S share rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\tS = ");
    OCT_output(&SIGS1);

    printf("\n[Bob] Generate share for signature S component\n");

    rc = MPC_S(&HM, &SIGR2, &K2, &SIGMA2, &SIGS2);
    if (rc != MPC_OK)
    {
        fprintf(stderr, "FAILURE computing Bob S share rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\tS = ");
    OCT_output(&SIGS2);

    /* Phase 5 */

    printf("\n[Alice-Bob] Interactively prove consistency of S shares\n");

    phase5(RNG, &SIGRP1, &SIGRP2, &SIGR1, &SIGR2, &HM, &SIGS1, &SIGS2, alice_km->FPK);

    /* Alice/Bob - broadcast shares and combine */

    printf("\n[Alice-Bob] Reconcile S component of signature\n");

    MPC_SUM_S(&SIGS1, &SIGS2, &SIGS);

    printf("\tS = ");
    OCT_output(&SIGS);

    /* Check signature validity */

    printf("\n[Alice-Bob] Verify reconciled signature\n");

    rc =  MPC_ECDSA_VERIFY(&HM, alice_km->FPK, &SIGR1, &SIGS);
    if (rc != MPC_OK)
    {
        fprintf(stderr, "FAILURE invalid Alice rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    rc = MPC_ECDSA_VERIFY(&HM, bob_km->FPK, &SIGR2, &SIGS);
    if (rc != MPC_OK)
    {
        fprintf(stderr, "FAILURE invalid Bob signature rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("\tSignature valid\n");
    printf("\nSignature\n");
    printf("\tR = ");
    OCT_output(&SIGR1);
    printf("\tS = ");
    OCT_output(&SIGS);
}

int main()
{
    key_material alice_km;

    char a_sk[EGS_SECP256K1];
    char a_pk[EFS_SECP256K1 + 1];
    char a_cpk[EFS_SECP256K1 + 1];
    char a_fpk[EFS_SECP256K1 + 1];
    octet A_SK  = {0, sizeof(a_sk),  a_sk};
    octet A_PK  = {0, sizeof(a_pk),  a_pk};
    octet A_CPK = {0, sizeof(a_cpk), a_cpk};
    octet A_FPK = {0, sizeof(a_fpk), a_fpk};
    alice_km.SK =  &A_SK;
    alice_km.PK =  &A_PK;
    alice_km.CPK = &A_CPK;
    alice_km.FPK = &A_FPK;

    key_material bob_km;

    char b_sk[EGS_SECP256K1];
    char b_pk[EFS_SECP256K1 + 1];
    char b_cpk[EFS_SECP256K1 + 1];
    char b_fpk[EFS_SECP256K1 + 1];
    octet B_SK  = {0, sizeof(b_sk),  b_sk};
    octet B_PK  = {0, sizeof(b_pk),  b_pk};
    octet B_CPK = {0, sizeof(b_cpk), b_cpk};
    octet B_FPK = {0, sizeof(b_fpk), b_fpk};
    bob_km.SK =  &B_SK;
    bob_km.PK =  &B_PK;
    bob_km.CPK = &B_CPK;
    bob_km.FPK = &B_FPK;

    // Deterministic RNG for example
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    printf("MPC full flow example\n");

    // Key setup phase
    printf("\n ** Key Setup **\n");

    key_setup(&RNG, &alice_km, &bob_km);

    // Signature phase
    printf("\n ** Signature **\n");

    char* msg = "BANANA";
    octet MSG = {0, sizeof(msg), msg};
    printf("\nSign message '%s'\n", msg);

    signature(&RNG, &MSG, &alice_km, &bob_km);

    printf("\nDone\n");
}
