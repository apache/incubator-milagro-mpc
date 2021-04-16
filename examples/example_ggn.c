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

/* GGN Proof example */

#include <string.h>
#include "amcl/ggn.h"

// Primes for Paillier key
char *P_hex = "c39f253734727ac925e786ec50abcf9b5bb46e1cba747342dee478c6efdb59d6c63c8495ab18e1b4c56e9bed152ad63681e0af18a6a21db1fe5faa9e7eae17e17013ccb3b4fbd4efb86a50b4b25fa081ccc90b9c22d455452fd0f7b878f36da06b82285fbdb0511e8a01eea7f79e4381cffb3b0e5f34755c086d51be5584200f";
char *Q_hex = "d1f98d7be4e10120eec3f0225af8f33c8fbecc4bd846ac36bcf0bafedbc03bb6eb3f121c65a9c27b9931cda44eed1d4a5eeb32a3fe8f5643f01caebd75e37206b2c7debe83d9ce7197831e9fd5954eb61f1bcba4c1f64a3bf5cc73a488298998f4650cc82ac8a0fc17c0f698f09bb560c41341dd70d1ceef1ac7df7e286a3941";

// Safe primes for BC setup
char *PT_hex = "CA5F37B7C0DDF6530B30A41116588218DE95F1F36B807FD7C28E4C467EE3F35967BC01D28B71F8A627A353675A81C86A1FF03DCECAF1686891183FA317BA34A4A1148D40A89F1F3AC0C200511C6CFE02342CD75354C25A2E069886DD4FB73BD365660D163F1282B143119AB8F375A73875EC16B634F52593B73BC6D875F2D3EF";
char *QT_hex = "C2FC545C1C803F6C7625FBC4ECF9355734D6B6058FD714816D3ECFB93F1F705C9CE90D4F8796A05148AB5ABC201F90889231CC6BF5F68ED15EE4D901F603930A280EEABF10C613BFCB67A816363C839EB902B02607EB48AB8325E2B72620D4D294A232803217090DFB50AF8C620D4679E77CE3053437ED518F4F68840DCF1AA3";

// Paillier ciphertext and plaintext
char* K_hex = "316e5fe3f60876f456e3c15e05e2d4ee79649e6a18008f08ff7a4c67bcdf5391";
char* C_hex = "2373194729f056ef064cae6f98f5da88f0d39ad77884a04009fe3741bdc9354ae25fe1b0d42b6b6e0cb81e02a22f112fc1d8b3649344b08a6d10dff8988a806040f5b46ad971711f23b254da53d73ec1a4592327b07297cb6cce74855f7f5401efcf1eb7c5f2c344119321b2f3ee54da292e5e65930e1655f524194664f148bcf715267e08f489c1762473edaf47f233c123bc2b17015f12cef26c282ed13d91035ddac65b058f2e7b28718679785fe5d70d803d503bfe098f1cf4fb713051e90dab945c05eecbefa39dbe7660689f71a3cfcebe37f874435a56546a70cb0c2fb098ce6427fd525c6b6e12aaff95405af4950829249399861637b4c19a7b48ad669dbeb8d8e530a060f1d2482a3b507fdc547d6b5123cad94c204877992a756ba24d27686e2d876c1f0c396dd608aedf830b8d8cb9805c67e2e3538f472939fb4202c03971ea75ad61e74c7b39498c38241a9360331e8ffe0285d9861633e8c3f53de0c833db08dd62dd01724a057cfcdd2cc5a46cec9c8f04281d087381a8455a85dd30ca65a12803f7c995de107315d02653ee1baea153b58eec3f96af17c73ee4b2bd01977c9d32b5b256e27cbd3b8b2b473533ec160632db76cf3e8f308b81cce9ac3652be3053708d30a78fcaf609ef804d7e14811a9e24b4e74eb8b15b20773e728e5513c23523bf222c9e8b306210da7c4c0d03b6c5fa144c1ee4882b";
char* R_hex = "2174746e69b220c3ee9512b3e4da121866b7c656de08febb40e774ec90b459df9af8c22523e2816a23e33f134ede2fc35c49458f5f3a1e6c5b3578cc74b461e0b4a6ea83bdbe66a368692376d02bda4f80fbc1d1e9255c07aae2a2f8d7122ef00bd5fea48c8317124ebdba0545d9e43d87ee1f1b6117cefb484d8df4fb752cefb3d99af3ea070e2cb06bbf644aa781687c82f76e87324ba8fe0b9cd3b617f679081bc0e371cf6e3157edd82cc1b07f2629908847d109af71d9c802b1ca5e481a024968581dcbd2b4d668bfc7a0b338fe5f8801a79d6ba8852af580f5a72bcd2efb3a580ceeab2d5fc5587bd2c6b0e00bac0100f32b3abe44cc49e4b0576d8982c1578d1780c09b44b22fc852f2007e1a32982c918d77ca26f17bc5a2ab1a3238f94a6fa0f31e5b84818299ecb6efc0639552c5a6314d3eb8522b12afc22558a9d6d0024f3e661a1baa37d35e08e23811eaa20cc62c3e93b220d83281a900662d1aa05779cbda64ce0f333f227b3fb680962983a15f2031aca1a37a9499100a1f935a8ad1e858fd9c7088880619c6f052cc8970984b67c16eb0743ebb3db6a90a85ae40f24f3b6d8f591802c2213a591f2a3a8d96cade8961f69460f6692b5124e7100ed2a339ec457a763455140e717917d8d5957cdfddaf62b5c57ff926db3e0799c596041623bf199724351bb2b1566c7b0634adceda670e0d5a939e0c9b72";

// ECP for DLOG
char* ECPR_hex  = "0274ec825739bb45d8e451dec0cb85baf356b931c754b5ccdef159389a27422b57";
char* ECPRT_hex = "02a143a6f56e92af5e0ecaae7b8ae133750de551d6a00e9fa7c3e993deea0be12f";

int main()
{
    int rc;

    PAILLIER_private_key priv_key;
    PAILLIER_public_key  pub_key;

    BIT_COMMITMENT_priv priv_mod;
    BIT_COMMITMENT_pub  pub_mod;

    GGN_commitment co;
    GGN_rv         rv;
    GGN_proof      proof;

    char c[2*FS_2048];
    octet C = {0, sizeof(c), c};

    char r[2*FS_2048];
    octet R = {0, sizeof(r), r};

    char k[MODBYTES_256_56];
    octet K = {0, sizeof(k), k};

    char e[MODBYTES_256_56];
    octet E = {0, sizeof(e), e};

    char p[HFS_2048];
    octet P = {0, sizeof(p), p};

    char q[HFS_2048];
    octet Q = {0, sizeof(q), q};

    char id[32];
    octet ID = {0, sizeof(id), id};

    char ad[32];
    octet AD = {0, sizeof(ad), ad};

    char ecpr_oct[MODBITS_SECP256K1];
    octet ECPR_OCT = {0, sizeof(ecpr_oct), ecpr_oct};

    char ecprt_oct[MODBITS_SECP256K1];
    octet ECPRT_OCT = {0, sizeof(ecprt_oct), ecprt_oct};

    char z[FS_2048];
    octet Z = {0, sizeof(z), z};

    char u1[EFS_SECP256K1 + 1];
    octet U1 = {0, sizeof(u1), u1};

    char u2[FS_4096];
    octet U2 = {0, sizeof(u2), u2};

    char u3[FS_2048];
    octet U3 = {0, sizeof(u3), u3};

    char s1[HFS_4096];
    octet S1 = {0, sizeof(s1), s1};

    char s2[HFS_2048];
    octet S2 = {0, sizeof(s2), s2};

    char s3[FS_2048 + HFS_2048];
    octet S3 = {0, sizeof(s3), s3};

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

    printf("Run GGN Proof\nParameters:\n");
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
    OCT_fromHex(&K, K_hex);
    OCT_fromHex(&R, R_hex);
    OCT_fromHex(&C, C_hex);

    printf("\n\tPaillier Input:\n");
    printf("\t\tK = ");
    OCT_output(&K);
    printf("\t\tC = ");
    OCT_output(&C);
    printf("\t\tr = ");
    OCT_output(&R);

    // Load values for DLOG
    OCT_fromHex(&ECPR_OCT, ECPR_hex);
    OCT_fromHex(&ECPRT_OCT, ECPRT_hex);

    printf("\n\tECP Input\n");
    printf("\t\tR  =");
    OCT_output(&ECPR_OCT);
    printf("\t\tRt = ");
    OCT_output(&ECPRT_OCT);

    // Prover - commit to values for the proof and output
    // the commitment to octets for transmission
    rc = GGN_commit(&RNG, &priv_key, &pub_mod, &ECPR_OCT, &K, &rv, &co);
    if (rc != GGN_OK)
    {
        printf("\nFAILURE GGN_commit: rc %d\n", rc);
        exit(EXIT_FAILURE);
    }

    GGN_commitment_toOctets(&Z, &U1, &U2, &U3, &co);

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
    printf("\t\tZ  = ");
    OCT_output(&Z);
    printf("\t\tU1 = ");
    OCT_output(&U1);
    printf("\t\tU2 = ");
    OCT_output(&U2);
    printf("\t\tU2 = ");
    OCT_output(&U2);

    // Prover - compute deterministic challenge
    GGN_challenge(&pub_key, &pub_mod, &ECPR_OCT, &ECPRT_OCT, &C, &co, &ID, &AD, &E);

    printf("\nCompute deterministic challenge\n");
    printf("\t\tE = ");
    OCT_output(&E);

    // Prover - generate proof and output it to octets for transmission
    GGN_prove(&priv_key, &K, &R, &rv, &E, &proof);
    GGN_proof_toOctets(&S1, &S2, &S3, &proof);

    printf("\nProof Phase\n");
    printf("\t\tS1 = ");
    OCT_output(&S1);
    printf("\t\tS2 = ");
    OCT_output(&S2);
    printf("\t\tS3 = ");
    OCT_output(&S3);

    // Prover - clean random values
    GGN_rv_kill(&rv);

    // Verifier - compute deterministic challenge and verify proofs
    GGN_challenge(&pub_key, &pub_mod, &ECPR_OCT, &ECPRT_OCT, &C, &co, &ID, &AD, &E);

    printf("\nVerification\n");

    rc = GGN_verify(&pub_key, &priv_mod, &ECPR_OCT, &ECPRT_OCT, &C, &co, &E, &proof);
    if (rc == GGN_OK)
    {
        printf("\t\tSuccess!\n");
    }
    else
    {
        printf("\t\tFailure!\n");
    }
}
