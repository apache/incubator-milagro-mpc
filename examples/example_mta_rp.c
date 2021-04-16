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
#include "amcl/mta_zkp.h"

/* MTA Range Proof smoke tests */

// Primes for Paillier key
char *P_hex = "94f689d07ba20cf7c7ca7ccbed22ae6b40c426db74eaee4ce0ced2b6f52a5e136663f5f1ef379cdbb0c4fdd6e4074d6cff21082d4803d43d89e42fd8dfa82b135aa31a8844ffea25f255f956cbc1b9d8631d01baf1010d028a190b94ce40f3b72897e8196df19edf1ff62e6556f2701d52cef1442e3301db7608ecbdcca703db";
char *Q_hex = "9a9ad73f246df853e129c589925fdad9df05606a61081e62e72be4fb33f6e5ec492cc734f28bfb71fbe2ba9a11e4c02e2c0d103a5cbb0a9d6402c07de63b1b995dd72ac8f29825d66923a088b421fb4d52b0b855d2f5dde2be9b0ca0cee6f7a94e5566735fe6cff1fcad3199602f88528d19aa8d0263adff8f5053c38254a2a3";

// Safe primes for BC setup
char *PT_hex = "CA5F37B7C0DDF6530B30A41116588218DE95F1F36B807FD7C28E4C467EE3F35967BC01D28B71F8A627A353675A81C86A1FF03DCECAF1686891183FA317BA34A4A1148D40A89F1F3AC0C200511C6CFE02342CD75354C25A2E069886DD4FB73BD365660D163F1282B143119AB8F375A73875EC16B634F52593B73BC6D875F2D3EF";
char *QT_hex = "C2FC545C1C803F6C7625FBC4ECF9355734D6B6058FD714816D3ECFB93F1F705C9CE90D4F8796A05148AB5ABC201F90889231CC6BF5F68ED15EE4D901F603930A280EEABF10C613BFCB67A816363C839EB902B02607EB48AB8325E2B72620D4D294A232803217090DFB50AF8C620D4679E77CE3053437ED518F4F68840DCF1AA3";

// Paillier ciphertext and plaintext
char* M_hex = "0000000000000000000000000000000000000000000000000000000000000002";
char* C_hex = "19c8b725dbd74b7dcaf72bd9ff2cd207b47cb1095393685906171af9e2f2959e7f68729e0e40f97a22bbca93373d618ad51dd077c0d102938598a8ecc8a656e978ebd14007da99db8e691d85fc18a428097ee8a63dcf95b84b660294474a20ed2edcf2b1b4f305c1cc25860a08d1348c2a4d24cc1a97b51f920e2985b8108b3392a5eafc443cf3449e288eb49dbde2228a56233afa5a6643e5ae6ec6aa8937a666ef74a30625c35bb22c3cc57b700f8eae7690f8d37edbfd27ccb2e882f70d0d85e0cc825347453a28e98e877ab1eeaa6efa09f034bc8976bffb86420106978066ff52221b315f71eb32cbf608d2b72cfa4c88e43282598f175b48ba3b5c14d72b2d90baabc00025450740ac89fc0dcd7d2f80cf12c721b6ec493c2025d7adc683b78f1d711b639a1b0dd043b9defa7ff928e257599dd95525bc8b45e1b88470311e11feb72749e5fc98f69051ddd1101b1bcc92f649681bd7ae316575444625d9d73d3684789142650951321e17f6b2f92103f36dbbd004cd66cda366e80faa4f57b71b9abb042f6cc932716fa3e6fdf50674e3d1e6d871f723d3f4f672c1270b41e7cdd5930a2572ddfc8ce370576a7a75ee6924f53122d717146c74eb6167811a2488bb899cc2da9dc2e29df66b5a03ed986fdad6ef177151ddd2698055050709c475b4ed5a2ab0be00c8b03e24193fb79f91cfd81fbcb838e45c25f8ba05";
char* R_hex = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018c5947fda2edea04c1f87c207e0bab17aff5f77ac21d04cb194631efd1f7256dc37de9473fc86009df36206974859c09023ac8179b02aacea8d89a01f4de161db955d450cef55ce959897636973b952371e349778e67c61ef6fae5f73fd728d423a594b6a76d5faca97d59d6ae40c53f3bd42dfccc93183e355422ba7af308a87d32c0352d478156275f98bc74e9ed4f2c7a9853c9f35b996fafe765b56c7f2e83771c6b676b75436e5c1697b838b3908aee92001cbccf3bf6cfb7aaea27a358a12cfe1ddde886b975ae14517e5912eba3ff9792e46403a998edd371020bbc5fbd6a705e669383303030ef79653ce16e13122233c626bb101ee8dd27bf4ff86";

int main()
{
    int rc;

    PAILLIER_private_key priv_key;
    PAILLIER_public_key  pub_key;

    BIT_COMMITMENT_priv priv_mod;
    BIT_COMMITMENT_pub  pub_mod;

    MTA_RP_commitment co;
    MTA_RP_rv         rv;
    MTA_RP_proof      proof;

    char c[2*FS_2048];
    octet C = {0, sizeof(c), c};

    char r[2*FS_2048];
    octet R = {0, sizeof(r), r};

    char m[MODBYTES_256_56];
    octet M = {0, sizeof(m), m};

    char e[MODBYTES_256_56];
    octet E = {0, sizeof(e), e};

    char p[HFS_2048];
    octet P = {0, sizeof(p), p};

    char q[HFS_2048];
    octet Q = {0, sizeof(q), q};

    char z[FS_2048];
    octet Z = {0, sizeof(z), z};

    char u[FS_4096];
    octet U = {0, sizeof(u), u};

    char w[FS_2048];
    octet W = {0, sizeof(w), w};

    char s[HFS_4096];
    octet S = {0, sizeof(s), s};

    char s1[HFS_2048];
    octet S1 = {0, sizeof(s1), s1};

    char s2[FS_2048 + HFS_2048];
    octet S2 = {0, sizeof(s2), s2};

    char id[32];
    octet ID = {0, sizeof(id), id};

    char ad[32];
    octet AD = {0, sizeof(ad), ad};

    // Deterministic RNG for testing
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    // Pseudorandom ID and AD
    OCT_rand(&ID, &RNG, ID.len);
    OCT_rand(&AD, &RNG, AD.len);

    // Load paillier key
    OCT_fromHex(&P, P_hex);
    OCT_fromHex(&Q, Q_hex);

    PAILLIER_KEY_PAIR(NULL, &P, &Q, &pub_key, &priv_key);

    printf("Run MTA Range Proof\nParameters:\n");
    printf("\tPaillier Key\n");
    printf("\t\tP = ");
    OCT_output(&P);
    printf("\t\tQ = ");
    OCT_output(&Q);

    // Generate BC commitment modulus
    OCT_fromHex(&P, PT_hex);
    OCT_fromHex(&Q, QT_hex);
    BIT_COMMITMENT_setup(&RNG, &priv_mod, &P, &Q, NULL, NULL);

    BIT_COMMITMENT_priv_to_pub(&pub_mod, &priv_mod);

    FF_2048_output(priv_mod.alpha, FFLEN_2048);
    printf("\n");
    FF_2048_output(priv_mod.b0, FFLEN_2048);

    printf("\n\tBit Commitment Modulus\n");
    printf("\t\tP = ");
    OCT_output(&P);
    printf("\t\tQ = ");
    OCT_output(&Q);

    // Load Paillier encryption values
    OCT_fromHex(&M, M_hex);
    OCT_fromHex(&R, R_hex);
    OCT_fromHex(&C, C_hex);

    printf("\nInput:\n");
    printf("\t\tM = ");
    OCT_output(&M);
    printf("\t\tC = ");
    OCT_output(&C);
    printf("\t\tR = ");
    OCT_output(&R);

    // Prover - commit to values for the proof and output
    // the commitment to octets for transmission
    MTA_RP_commit(&RNG, &priv_key, &pub_mod, &M, &rv, &co);
    MTA_RP_commitment_toOctets(&Z, &U, &W, &co);

    printf("\nCommitment Phase\n");
    printf("\tGenerate Random Values:");
    printf("\n\t\tALPHA = ");
    FF_2048_output(rv.alpha, HFLEN_2048);
    printf("\n\t\tBETA  = ");
    FF_2048_output(rv.beta, FFLEN_2048);
    printf("\n\t\tGAMMA = ");
    FF_2048_output(rv.gamma, FFLEN_2048 + HFLEN_2048);
    printf("\n\t\tRHO   = ");
    FF_2048_output(rv.rho, FFLEN_2048 + HFLEN_2048);
    printf("\n\n\tGenerate Commitment:\n");
    printf("\t\tZ = ");
    OCT_output(&Z);
    printf("\t\tU = ");
    OCT_output(&U);
    printf("\t\tW = ");
    OCT_output(&W);

    // Prover - compute deterministic challenge
    MTA_RP_challenge(&pub_key, &pub_mod, &C, &co, &ID, &AD, &E);

    printf("\nCompute deterministic challenge\n");
    printf("\t\tE = ");
    OCT_output(&E);

    // Prover - generate proof and otuput it to octets for transmission
    MTA_RP_prove(&priv_key, &M, &R, &rv, &E, &proof);
    MTA_RP_proof_toOctets(&S, &S1, &S2, &proof);

    printf("\nProof Phase\n");
    printf("\t\tS =  ");
    OCT_output(&S);
    printf("\t\tS1 =  ");
    OCT_output(&S1);
    printf("\t\tS2 =  ");
    OCT_output(&S2);

    // Prover - clean random values
    MTA_RP_rv_kill(&rv);

    // Transmit the proof and commitment to the verifier

    // Verifier - read commitment and proof from octets
    MTA_RP_proof_fromOctets(&proof, &S, &S1, &S2);
    MTA_RP_commitment_fromOctets(&co, &Z, &U, &W);

    // Verifier - compute deterministic challenge
    MTA_RP_challenge(&pub_key, &pub_mod, &C, &co, &ID, &AD, &E);

    printf("\nVerification\n");

    rc = MTA_RP_verify(&pub_key, &priv_mod, &C, &co, &E, &proof);
    if (rc == MTA_OK)
    {
        printf("\t\tSuccess!\n");
    }
    else
    {
        printf("\t\tFailure!\n");
    }
}
