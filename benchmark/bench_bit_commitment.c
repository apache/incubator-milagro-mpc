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

/*
   Benchmark Bit Commitment Paillier Plaintext Proof.
 */

#include "bench.h"
#include "amcl/bit_commitment.h"

#define MIN_TIME 5.0
#define MIN_ITERS 10

// Primes for Paillier key
char *P_hex = "94f689d07ba20cf7c7ca7ccbed22ae6b40c426db74eaee4ce0ced2b6f52a5e136663f5f1ef379cdbb0c4fdd6e4074d6cff21082d4803d43d89e42fd8dfa82b135aa31a8844ffea25f255f956cbc1b9d8631d01baf1010d028a190b94ce40f3b72897e8196df19edf1ff62e6556f2701d52cef1442e3301db7608ecbdcca703db";
char *Q_hex = "9a9ad73f246df853e129c589925fdad9df05606a61081e62e72be4fb33f6e5ec492cc734f28bfb71fbe2ba9a11e4c02e2c0d103a5cbb0a9d6402c07de63b1b995dd72ac8f29825d66923a088b421fb4d52b0b855d2f5dde2be9b0ca0cee6f7a94e5566735fe6cff1fcad3199602f88528d19aa8d0263adff8f5053c38254a2a3";

// BC setup
char *PT_hex =    "CA5F37B7C0DDF6530B30A41116588218DE95F1F36B807FD7C28E4C467EE3F35967BC01D28B71F8A627A353675A81C86A1FF03DCECAF1686891183FA317BA34A4A1148D40A89F1F3AC0C200511C6CFE02342CD75354C25A2E069886DD4FB73BD365660D163F1282B143119AB8F375A73875EC16B634F52593B73BC6D875F2D3EF";
char *QT_hex =    "C2FC545C1C803F6C7625FBC4ECF9355734D6B6058FD714816D3ECFB93F1F705C9CE90D4F8796A05148AB5ABC201F90889231CC6BF5F68ED15EE4D901F603930A280EEABF10C613BFCB67A816363C839EB902B02607EB48AB8325E2B72620D4D294A232803217090DFB50AF8C620D4679E77CE3053437ED518F4F68840DCF1AA3";
char *ALPHA_hex = "1128dc85f9bbdde2826244bcefd0ec6668c19ee254b81bbbfc7575ec45922fc573567d45dc27fc659ec29e8909548a94f1d1ed280cfa49d75192c8cb04925884fa2e7ee9cce71bf5f699f73c07a9bcfbeed87aa4446099a940a03b6828a292319f3a4a71206bd902e9f99f6d6226344a14a0eb2b127b0e8925db779c21fa15ef 465212e8b5c0a8bd2fb3d171bfdad345d15676ad65f20447d8d28d9f7a3be092903966725054e94d95f7aff0ff854efeae993e9b97a2942fa7426cd1bfb843cd635c1058fb73d21ab7f9cc2319a307129f4f84369c01f0e29ea3716dfa692c56a3e4aae1437e9110464003afcb5a654661984f80eadefe04b511f2acd09a7ac5";
char *B0_hex =    "544c8b0766c7490f7c6abfe0517709f3ab2c9b81fa8455cd8f99302dc58efa8d73318b078b31e49336d05caae1be491e620ec4893dfd50153c75d99d81970995c48b73cbb379097f69d55d4fb07de6124388b30c5718ccc5bd251945a1a51de335a7ebc4e226d7a60d82a7afc485845e849228de10211b2b8d7a759dd24ec4a4 57fdae3380b96fa8f3e12ba112a2ea07c1a74484ae7938e80afd4f17e17dddb7257fdcddfbcf2d2c51f350fb0c30a4eed76625039e5310da553ceaad1f9993c3b25bff1a657800308d4864199baeec8036945a9ac2bb429bd92d568b500f65268743179451623d45e7e25234812de34c9c1b1db6ab2184800b97b7117d8247a7";

// Paillier ciphertext and plaintext
char* M_hex = "0000000000000000000000000000000000000000000000000000000000000002";
char* C_hex = "19c8b725dbd74b7dcaf72bd9ff2cd207b47cb1095393685906171af9e2f2959e7f68729e0e40f97a22bbca93373d618ad51dd077c0d102938598a8ecc8a656e978ebd14007da99db8e691d85fc18a428097ee8a63dcf95b84b660294474a20ed2edcf2b1b4f305c1cc25860a08d1348c2a4d24cc1a97b51f920e2985b8108b3392a5eafc443cf3449e288eb49dbde2228a56233afa5a6643e5ae6ec6aa8937a666ef74a30625c35bb22c3cc57b700f8eae7690f8d37edbfd27ccb2e882f70d0d85e0cc825347453a28e98e877ab1eeaa6efa09f034bc8976bffb86420106978066ff52221b315f71eb32cbf608d2b72cfa4c88e43282598f175b48ba3b5c14d72b2d90baabc00025450740ac89fc0dcd7d2f80cf12c721b6ec493c2025d7adc683b78f1d711b639a1b0dd043b9defa7ff928e257599dd95525bc8b45e1b88470311e11feb72749e5fc98f69051ddd1101b1bcc92f649681bd7ae316575444625d9d73d3684789142650951321e17f6b2f92103f36dbbd004cd66cda366e80faa4f57b71b9abb042f6cc932716fa3e6fdf50674e3d1e6d871f723d3f4f672c1270b41e7cdd5930a2572ddfc8ce370576a7a75ee6924f53122d717146c74eb6167811a2488bb899cc2da9dc2e29df66b5a03ed986fdad6ef177151ddd2698055050709c475b4ed5a2ab0be00c8b03e24193fb79f91cfd81fbcb838e45c25f8ba05";
char* R_hex = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018c5947fda2edea04c1f87c207e0bab17aff5f77ac21d04cb194631efd1f7256dc37de9473fc86009df36206974859c09023ac8179b02aacea8d89a01f4de161db955d450cef55ce959897636973b952371e349778e67c61ef6fae5f73fd728d423a594b6a76d5faca97d59d6ae40c53f3bd42dfccc93183e355422ba7af308a87d32c0352d478156275f98bc74e9ed4f2c7a9853c9f35b996fafe765b56c7f2e83771c6b676b75436e5c1697b838b3908aee92001cbccf3bf6cfb7aaea27a358a12cfe1ddde886b975ae14517e5912eba3ff9792e46403a998edd371020bbc5fbd6a705e669383303030ef79653ce16e13122233c626bb101ee8dd27bf4ff86";

// RV for Range Proof
char *RP_ALPHA_hex = "000000000000000000000000000000000000000000000000000000000000000000000034c0ff00df5f36f8800e0bcd51642ab69326cb3ad5cdfe042daa9750fbaffd56802f7f7b0a49846d15cf7b96450b88361ca4b4bb18bdfa094a03eed4015dc89a0899ef71379abe57612c55cb164728a2973d2788d2306cb49402badf67";
char *BETA_hex     = "14acae6984a03a7927d162a3f94cd66dbd920936128e6a5c6f8d9a46291fb86c9b29a538d8c2313f38abfdfd531414aa3a54d0692de748fc0a65ec7ae5e1998b86ccc198e9f3e8135312f222c7df878c52ac09fc8675f6862c0b8ee9cb83850c829f2ab6d7fba66d55ec4bcadba53aa2577dd9a2007a89badc84645b635aa579132ff5c26911b613763130cc684def93bac53dbeccb81459db35feb1c2a6d217ab1941904d29b7029ee39bd784e86cb6567af7c2b8283cc45185475b9feae2395a74dfc646adb4a482f716caa98290f1a17dc371798c40e927ef561eda5213da0db93bcf3665455f3bc033aa15e4e77168e87193a619e6d6c4b38a463b39c5ef";
char *GAMMA_hex    = "00000000000000000000000000000000000000000000000000000000000000000000005081190690c2aae12a2bf970d225865d08b9a469c675a3af3e34addb83f88f7d74bd1aaae27079b161e9926b7850ec939224fa5e8da08e7d1aa2276f605a55c519aa5ae20c9ee1f7fdb3d642d9c2655a4cbdd151d92ec18609f656ca70520001f396b52e8870068e327cef08bb5382be986b0de414bb25d1366562566f0b63ac459bbf4c5c427b5e59d4e384772497d4f78f867f003633b161bf1cc5f748a98f428774c9d661d5b3fd5f60e7b879b564ef4a2b9563b93131cc2a5a32211e4b34387a1b098ca80b5e42544e4e4bf1d7a39abe3e7b9d1ab3b0fe855c1ff83d1238d63afb1f7fc9399ef6a6d1eaeaae764fd27ec69c547e5cee4d5f568835c5707cd0701f08c8211a19b28c19e24253667449d0979dfbb5d602ec24c9afd096e6eaa8be8e6b6ae09c19f8c7840df9f1512f8040f56734c64a7b36631ee4b465d118c8ced6967b8005eacf6206e6723ff99c3e847a051ad5bd30a92ebf3c4f";
char *RHO_hex      = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000033328f754ce65910a3d10719b59bd6f0ddd401a38381e98a76a44f34471f3d0d0c920237578a30f061c0f031d1907d3e6c5a687c5ef75473b4ee43e719c4b0e68229ab21dc3d573c005487380ee5d060f015e5f74db5575ff91e2859828cbd83bad80e37087ddb7a176b0f9012c02da70116213b2a37a82304062ed5d00f111bfcef8d821c2ed699fc3308ecad8f5c453b1694f550fe294780543e5cbfa14c495cfe6de839badcbf3b9697575dc8cd42c7258cee376ed8ce630411069e2f64cf6c9d987b35040a6652afdbbdc726541ded92317f2ad6252c328a68f7d75f9d64083f83c21fe1dac5595044291b1f836d1106d16e648320a9703a4d258ae9437bc0c5f948797e0412d4438b9b00dc94705701e66352e28561174d4e1f405b2b";

int main()
{
    int rc;

    int iterations;
    clock_t start;
    double elapsed;

    PAILLIER_private_key priv_key;
    PAILLIER_public_key  pub_key;

    BIT_COMMITMENT_priv priv_mod;
    BIT_COMMITMENT_pub  pub_mod;

    BIT_COMMITMENT_commitment co;
    BIT_COMMITMENT_rv         rv;
    BIT_COMMITMENT_proof      proof;

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

    char alpha[FS_2048];
    octet ALPHA = {0, sizeof(alpha), alpha};

    char b0[FS_2048];
    octet B0 = {0, sizeof(b0), b0};

    char oct[FS_2048 + HFS_2048];
    octet OCT = {0, sizeof(oct), oct};

    // Load paillier key
    OCT_fromHex(&P, P_hex);
    OCT_fromHex(&Q, Q_hex);
    PAILLIER_KEY_PAIR(NULL, &P, &Q, &pub_key, &priv_key);

    // Generate BC commitment modulus
    OCT_fromHex(&P,     PT_hex);
    OCT_fromHex(&Q,     QT_hex);
    OCT_fromHex(&ALPHA, ALPHA_hex);
    OCT_fromHex(&B0,    B0_hex);
    BIT_COMMITMENT_setup(NULL, &priv_mod, &P, &Q, &ALPHA, &B0);
    BIT_COMMITMENT_priv_to_pub(&pub_mod, &priv_mod);

    // Load Paillier encryption values
    OCT_fromHex(&M, M_hex);
    OCT_fromHex(&R, R_hex);
    OCT_fromHex(&C, C_hex);

    // Load Random Values for Range Proof
    OCT_fromHex(&OCT, RP_ALPHA_hex);
    OCT_pad(&OCT, FS_2048);
    FF_2048_fromOctet(rv.alpha, &OCT, FFLEN_2048);

    OCT_fromHex(&OCT, BETA_hex);
    FF_2048_fromOctet(rv.beta, &OCT, FFLEN_2048);

    OCT_fromHex(&OCT, GAMMA_hex);
    FF_2048_fromOctet(rv.gamma, &OCT, FFLEN_2048 + HFLEN_2048);

    OCT_fromHex(&OCT, RHO_hex);
    FF_2048_fromOctet(rv.rho, &OCT, FFLEN_2048 + HFLEN_2048);

    print_system_info();

    printf("Timing info\n");
    printf("===========\n");

    iterations = 0;
    start = clock();
    do
    {
        BIT_COMMITMENT_commit(NULL, &priv_key, &pub_mod, &M, &rv, &co);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    elapsed = MILLISECOND * elapsed / iterations;
    printf("\tBIT_COMMITMENT_commit\t\t%8d iterations\t", iterations);
    printf("%8.2lf ms per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        BIT_COMMITMENT_prove(&priv_key, &M, &R, &rv, &E, &proof);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    elapsed = MILLISECOND * elapsed / iterations;
    printf("\tBIT_COMMITMENT_prove\t\t%8d iterations\t", iterations);
    printf("%8.2lf ms per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        rc = BIT_COMMITMENT_verify(&pub_key, &priv_mod, &C, &co, &E, &proof);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    if (rc != BIT_COMMITMENT_OK)
    {
        printf("FAILURE BIT_COMMITMENT_verify: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    elapsed = MILLISECOND * elapsed / iterations;
    printf("\tBIT_COMMITMENT_verify\t\t%8d iterations\t", iterations);
    printf("%8.2lf ms per iteration\n", elapsed);

    exit(EXIT_SUCCESS);
}
