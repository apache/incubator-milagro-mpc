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
   Benchmark GGN Proof.
 */

#include "bench.h"
#include "amcl/ggn.h"

#define MIN_TIME 5.0
#define MIN_ITERS 10

// Primes for Paillier key
char *P_hex = "c39f253734727ac925e786ec50abcf9b5bb46e1cba747342dee478c6efdb59d6c63c8495ab18e1b4c56e9bed152ad63681e0af18a6a21db1fe5faa9e7eae17e17013ccb3b4fbd4efb86a50b4b25fa081ccc90b9c22d455452fd0f7b878f36da06b82285fbdb0511e8a01eea7f79e4381cffb3b0e5f34755c086d51be5584200f";
char *Q_hex = "d1f98d7be4e10120eec3f0225af8f33c8fbecc4bd846ac36bcf0bafedbc03bb6eb3f121c65a9c27b9931cda44eed1d4a5eeb32a3fe8f5643f01caebd75e37206b2c7debe83d9ce7197831e9fd5954eb61f1bcba4c1f64a3bf5cc73a488298998f4650cc82ac8a0fc17c0f698f09bb560c41341dd70d1ceef1ac7df7e286a3941";

// BC setup
char *PT_hex = "CA5F37B7C0DDF6530B30A41116588218DE95F1F36B807FD7C28E4C467EE3F35967BC01D28B71F8A627A353675A81C86A1FF03DCECAF1686891183FA317BA34A4A1148D40A89F1F3AC0C200511C6CFE02342CD75354C25A2E069886DD4FB73BD365660D163F1282B143119AB8F375A73875EC16B634F52593B73BC6D875F2D3EF";
char *QT_hex = "C2FC545C1C803F6C7625FBC4ECF9355734D6B6058FD714816D3ECFB93F1F705C9CE90D4F8796A05148AB5ABC201F90889231CC6BF5F68ED15EE4D901F603930A280EEABF10C613BFCB67A816363C839EB902B02607EB48AB8325E2B72620D4D294A232803217090DFB50AF8C620D4679E77CE3053437ED518F4F68840DCF1AA3";
char *ALPHA_hex = "1128dc85f9bbdde2826244bcefd0ec6668c19ee254b81bbbfc7575ec45922fc573567d45dc27fc659ec29e8909548a94f1d1ed280cfa49d75192c8cb04925884fa2e7ee9cce71bf5f699f73c07a9bcfbeed87aa4446099a940a03b6828a292319f3a4a71206bd902e9f99f6d6226344a14a0eb2b127b0e8925db779c21fa15ef 465212e8b5c0a8bd2fb3d171bfdad345d15676ad65f20447d8d28d9f7a3be092903966725054e94d95f7aff0ff854efeae993e9b97a2942fa7426cd1bfb843cd635c1058fb73d21ab7f9cc2319a307129f4f84369c01f0e29ea3716dfa692c56a3e4aae1437e9110464003afcb5a654661984f80eadefe04b511f2acd09a7ac5";
char *B0_hex =    "544c8b0766c7490f7c6abfe0517709f3ab2c9b81fa8455cd8f99302dc58efa8d73318b078b31e49336d05caae1be491e620ec4893dfd50153c75d99d81970995c48b73cbb379097f69d55d4fb07de6124388b30c5718ccc5bd251945a1a51de335a7ebc4e226d7a60d82a7afc485845e849228de10211b2b8d7a759dd24ec4a4 57fdae3380b96fa8f3e12ba112a2ea07c1a74484ae7938e80afd4f17e17dddb7257fdcddfbcf2d2c51f350fb0c30a4eed76625039e5310da553ceaad1f9993c3b25bff1a657800308d4864199baeec8036945a9ac2bb429bd92d568b500f65268743179451623d45e7e25234812de34c9c1b1db6ab2184800b97b7117d8247a7";

// Paillier ciphertext and plaintext
char* K_hex = "316e5fe3f60876f456e3c15e05e2d4ee79649e6a18008f08ff7a4c67bcdf5391";
char* C_hex = "2373194729f056ef064cae6f98f5da88f0d39ad77884a04009fe3741bdc9354ae25fe1b0d42b6b6e0cb81e02a22f112fc1d8b3649344b08a6d10dff8988a806040f5b46ad971711f23b254da53d73ec1a4592327b07297cb6cce74855f7f5401efcf1eb7c5f2c344119321b2f3ee54da292e5e65930e1655f524194664f148bcf715267e08f489c1762473edaf47f233c123bc2b17015f12cef26c282ed13d91035ddac65b058f2e7b28718679785fe5d70d803d503bfe098f1cf4fb713051e90dab945c05eecbefa39dbe7660689f71a3cfcebe37f874435a56546a70cb0c2fb098ce6427fd525c6b6e12aaff95405af4950829249399861637b4c19a7b48ad669dbeb8d8e530a060f1d2482a3b507fdc547d6b5123cad94c204877992a756ba24d27686e2d876c1f0c396dd608aedf830b8d8cb9805c67e2e3538f472939fb4202c03971ea75ad61e74c7b39498c38241a9360331e8ffe0285d9861633e8c3f53de0c833db08dd62dd01724a057cfcdd2cc5a46cec9c8f04281d087381a8455a85dd30ca65a12803f7c995de107315d02653ee1baea153b58eec3f96af17c73ee4b2bd01977c9d32b5b256e27cbd3b8b2b473533ec160632db76cf3e8f308b81cce9ac3652be3053708d30a78fcaf609ef804d7e14811a9e24b4e74eb8b15b20773e728e5513c23523bf222c9e8b306210da7c4c0d03b6c5fa144c1ee4882b";
char* R_hex = "2174746e69b220c3ee9512b3e4da121866b7c656de08febb40e774ec90b459df9af8c22523e2816a23e33f134ede2fc35c49458f5f3a1e6c5b3578cc74b461e0b4a6ea83bdbe66a368692376d02bda4f80fbc1d1e9255c07aae2a2f8d7122ef00bd5fea48c8317124ebdba0545d9e43d87ee1f1b6117cefb484d8df4fb752cefb3d99af3ea070e2cb06bbf644aa781687c82f76e87324ba8fe0b9cd3b617f679081bc0e371cf6e3157edd82cc1b07f2629908847d109af71d9c802b1ca5e481a024968581dcbd2b4d668bfc7a0b338fe5f8801a79d6ba8852af580f5a72bcd2efb3a580ceeab2d5fc5587bd2c6b0e00bac0100f32b3abe44cc49e4b0576d8982c1578d1780c09b44b22fc852f2007e1a32982c918d77ca26f17bc5a2ab1a3238f94a6fa0f31e5b84818299ecb6efc0639552c5a6314d3eb8522b12afc22558a9d6d0024f3e661a1baa37d35e08e23811eaa20cc62c3e93b220d83281a900662d1aa05779cbda64ce0f333f227b3fb680962983a15f2031aca1a37a9499100a1f935a8ad1e858fd9c7088880619c6f052cc8970984b67c16eb0743ebb3db6a90a85ae40f24f3b6d8f591802c2213a591f2a3a8d96cade8961f69460f6692b5124e7100ed2a339ec457a763455140e717917d8d5957cdfddaf62b5c57ff926db3e0799c596041623bf199724351bb2b1566c7b0634adceda670e0d5a939e0c9b72";

// ECP for DLOG
char* ECPR_hex  = "0274ec825739bb45d8e451dec0cb85baf356b931c754b5ccdef159389a27422b57";
char* ECPRT_hex = "02a143a6f56e92af5e0ecaae7b8ae133750de551d6a00e9fa7c3e993deea0be12f";

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

    char alpha[FS_2048];
    octet ALPHA = {0, sizeof(alpha), alpha};

    char b0[FS_2048];
    octet B0 = {0, sizeof(b0), b0};

    char ecpr_oct[MODBITS_SECP256K1];
    octet ECPR_OCT = {0, sizeof(ecpr_oct), ecpr_oct};

    char ecprt_oct[MODBITS_SECP256K1];
    octet ECPRT_OCT = {0, sizeof(ecprt_oct), ecprt_oct};

    char oct[FS_2048 + HFS_2048];
    octet OCT = {0, sizeof(oct), oct};

    // Leave these blank (but not empty!)
    char id[32] = {0};
    octet ID = {sizeof(id), sizeof(id), id};

    char ad[32] = {0};
    octet AD = {sizeof(ad), sizeof(ad), ad};

    // Load paillier key
    OCT_fromHex(&P, P_hex);
    OCT_fromHex(&Q, Q_hex);

    PAILLIER_KEY_PAIR(NULL, &P, &Q, &pub_key, &priv_key);

    // Generate BC commitment modulus
    OCT_fromHex(&P, PT_hex);
    OCT_fromHex(&Q, QT_hex);
    OCT_fromHex(&ALPHA, ALPHA_hex);
    OCT_fromHex(&B0,    B0_hex);
    BIT_COMMITMENT_setup(NULL, &priv_mod, &P, &Q, &ALPHA, &B0);

    BIT_COMMITMENT_priv_to_pub(&pub_mod, &priv_mod);

    // Load Paillier encryption values
    OCT_fromHex(&K, K_hex);
    OCT_fromHex(&R, R_hex);
    OCT_fromHex(&C, C_hex);

    // Load values for DLOG
    OCT_fromHex(&ECPR_OCT, ECPR_hex);
    OCT_fromHex(&ECPRT_OCT, ECPRT_hex);

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
        rc = GGN_commit(NULL, &priv_key, &pub_mod, &ECPR_OCT, &K, &rv, &co);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    if (rc != GGN_OK)
    {
        printf("FAILURE GGN_commit: rc %d\n", rc);
        exit(EXIT_FAILURE);
    }

    elapsed = MILLISECOND * elapsed / iterations;
    printf("\tGGN_commit\t%8d iterations\t", iterations);
    printf("%8.2lf ms per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        GGN_challenge(&pub_key, &pub_mod, &ECPR_OCT, &ECPRT_OCT, &C, &co, &ID, &AD, &E);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    elapsed = MICROSECOND * elapsed / iterations;
    printf("\tGGN_challenge\t%8d iterations\t", iterations);
    printf("%8.2lf us per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        GGN_prove(&priv_key, &K, &R, &rv, &E, &proof);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    elapsed = MILLISECOND * elapsed / iterations;
    printf("\tGGN_prove\t%8d iterations\t", iterations);
    printf("%8.2lf ms per iteration\n", elapsed);

    iterations = 0;
    start = clock();
    do
    {
        rc = GGN_verify(&pub_key, &priv_mod, &ECPR_OCT, &ECPRT_OCT, &C, &co, &E, &proof);
        iterations++;
        elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
    }
    while (elapsed < MIN_TIME || iterations < MIN_ITERS);

    if (rc != GGN_OK)
    {
        printf("FAILURE GGN_verify: rc %d\n", rc);
        exit(EXIT_FAILURE);
    }

    elapsed = MILLISECOND * elapsed / iterations;
    printf("\tGGN_verify\t%8d iterations\t", iterations);
    printf("%8.2lf ms per iteration\n", elapsed);

    exit(EXIT_SUCCESS);
}
