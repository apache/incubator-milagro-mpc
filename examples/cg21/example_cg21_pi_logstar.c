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
 This example refers to none-interactive pi^{secrets} in CG21's,
 described in https://eprint.iacr.org/2021/060.pdf, page 63.

 The process is as follows:
 1) Prover generates a Paillier key pair (pk, sk, N) and shares (pk, N) with Verifier
 2) Verifier generates Ring-Pedersen parameters and share (s,t, \hat{N}) them with Prover
 3) Prover commits his randomly chosen numbers
 4) Prover computes deterministic challenge
 5) Prover generates range proof for his secret value
 6) Verifier computes deterministic challenge
 7) Verifier validates the correctness of the proof
 */

#include "amcl/cg21/cg21_utilities.h"
#include "amcl/cg21/cg21_rp_pi_logstar.h"

// Prover's Paillier parameters
char *P_hex = "94f689d07ba20cf7c7ca7ccbed22ae6b40c426db74eaee4ce0ced2b6f52a5e136663f5f1ef379cdbb0c4fdd6e4074d6cff21082d4803d43d89e42fd8dfa82b135aa31a8844ffea25f255f956cbc1b9d8631d01baf1010d028a190b94ce40f3b72897e8196df19edf1ff62e6556f2701d52cef1442e3301db7608ecbdcca703db";
char *Q_hex = "9a9ad73f246df853e129c589925fdad9df05606a61081e62e72be4fb33f6e5ec492cc734f28bfb71fbe2ba9a11e4c02e2c0d103a5cbb0a9d6402c07de63b1b995dd72ac8f29825d66923a088b421fb4d52b0b855d2f5dde2be9b0ca0cee6f7a94e5566735fe6cff1fcad3199602f88528d19aa8d0263adff8f5053c38254a2a3";

// Verifier's Ring-Pedersen parameters
char *PT_hex = "CA5F37B7C0DDF6530B30A41116588218DE95F1F36B807FD7C28E4C467EE3F35967BC01D28B71F8A627A353675A81C86A1FF03DCECAF1686891183FA317BA34A4A1148D40A89F1F3AC0C200511C6CFE02342CD75354C25A2E069886DD4FB73BD365660D163F1282B143119AB8F375A73875EC16B634F52593B73BC6D875F2D3EF";
char *QT_hex = "C2FC545C1C803F6C7625FBC4ECF9355734D6B6058FD714816D3ECFB93F1F705C9CE90D4F8796A05148AB5ABC201F90889231CC6BF5F68ED15EE4D901F603930A280EEABF10C613BFCB67A816363C839EB902B02607EB48AB8325E2B72620D4D294A232803217090DFB50AF8C620D4679E77CE3053437ED518F4F68840DCF1AA3";

// Prover's input
char* k_hex = "0000000000000000000000000000000000000000000000000000000000000002";
char* K_hex = "19c8b725dbd74b7dcaf72bd9ff2cd207b47cb1095393685906171af9e2f2959e7f68729e0e40f97a22bbca93373d618ad51dd077c0d102938598a8ecc8a656e978ebd14007da99db8e691d85fc18a428097ee8a63dcf95b84b660294474a20ed2edcf2b1b4f305c1cc25860a08d1348c2a4d24cc1a97b51f920e2985b8108b3392a5eafc443cf3449e288eb49dbde2228a56233afa5a6643e5ae6ec6aa8937a666ef74a30625c35bb22c3cc57b700f8eae7690f8d37edbfd27ccb2e882f70d0d85e0cc825347453a28e98e877ab1eeaa6efa09f034bc8976bffb86420106978066ff52221b315f71eb32cbf608d2b72cfa4c88e43282598f175b48ba3b5c14d72b2d90baabc00025450740ac89fc0dcd7d2f80cf12c721b6ec493c2025d7adc683b78f1d711b639a1b0dd043b9defa7ff928e257599dd95525bc8b45e1b88470311e11feb72749e5fc98f69051ddd1101b1bcc92f649681bd7ae316575444625d9d73d3684789142650951321e17f6b2f92103f36dbbd004cd66cda366e80faa4f57b71b9abb042f6cc932716fa3e6fdf50674e3d1e6d871f723d3f4f672c1270b41e7cdd5930a2572ddfc8ce370576a7a75ee6924f53122d717146c74eb6167811a2488bb899cc2da9dc2e29df66b5a03ed986fdad6ef177151ddd2698055050709c475b4ed5a2ab0be00c8b03e24193fb79f91cfd81fbcb838e45c25f8ba05";
char* rho_hex = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018c5947fda2edea04c1f87c207e0bab17aff5f77ac21d04cb194631efd1f7256dc37de9473fc86009df36206974859c09023ac8179b02aacea8d89a01f4de161db955d450cef55ce959897636973b952371e349778e67c61ef6fae5f73fd728d423a594b6a76d5faca97d59d6ae40c53f3bd42dfccc93183e355422ba7af308a87d32c0352d478156275f98bc74e9ed4f2c7a9853c9f35b996fafe765b56c7f2e83771c6b676b75436e5c1697b838b3908aee92001cbccf3bf6cfb7aaea27a358a12cfe1ddde886b975ae14517e5912eba3ff9792e46403a998edd371020bbc5fbd6a705e669383303030ef79653ce16e13122233c626bb101ee8dd27bf4ff86";

char* rid = "34c0687fea39222bedec7b4a42bbd9c7f49a666d6e056e3b135306479824f339";
char* rho = "43defa8e95a95b370308ef5a3e5f7958cb50ba8c1ce07b8381ed27b2859b1af3";
char* j_set = "00010002";
char* j_set2 = "000100020003";
char* X_set = "022c0bd00359b1f902831eab32f04f81c076f12a9e27ad4ed7c20ae2c56cfaea4602e2c0107a1a07b80118eca61071dab5218aeab6f722320730eff88d366d0a32d6";
char* N_set = "e47e0125f57c4c98000a79115539c9682695feb114a36040418fd11d650cd4f0941ffc35ba45b7544e7a0845ae062e7062209a9c925c728175848e58075d28a70f9be19fd21d3c95a376eecba14d99cb9112fdbfbe70e3af8c9c3a07a494073339faa26f59385e182cc497cb8009daec35dfc8c674d8a606198ee69bce5822e9580f7e221550f2179e30dd96d5438cbd207cc9744baed9199af05f65ef0fc18e608c8f8f23efcdf12e1d1e07117570a1eab64409c547d0674dd53b6b051af5f1b99c47e14e78d468e1c294224da46da1c8f030846f36949ccbed198e8b87189a626d37a50296bdbf224ae94085f3fcd65d1fd23c7fa41d793dbdb0d906b320edcaa7339147b1b8a9272e4f39e52885a29e34c77c14204f37307f71461ae6a3973e52cae4832771ca9181bed4b94a46002a3b396b6f63ef82f8830df8d290fc0a805d0ad407fe520f9388b07a60f77bdca89d36b41c2bc0e1a64cc96c294b34853f8b933db000b1358ce16c9b9d91bc7986197d7b1289a3e35be1c667835402156a07654b4b29cd7f97640720698f6dd1cbbddcf64e1e197f17f412b2723683afd9202292a8163558336bbe26e42dbdde3e5bfa0f2d8fddb5ec54d097a26de0b3ac4d371f1d2525c44d7f169a3eeb20a50f57a7c614e37cd653e2c0056b4969a32d3a2b55360d57b943fbf1c5cbc61801c7b1d34059200c114e8a587f768caa29c7c287aa56336589e7eeb7f567e407243af5b5ce8dad5a267731445c9ffdfb7e8e54c8e51d46fbde385d6830f253888b8c86c3a95a2f12386ed1bceb7aeda1ee66df85ff019d24bc36464e18b4916b0af1f4beb529d1ac7484b9979b29f317cdc0d445c67e74a32286abde3810a838dcb0035ea88c390db0503c35de00ce929fa3196cd4ff7e312dacb8e494e5962eedae71ef2a00ac23c4b0b10f0be62f10c235f6bf182edde07e36dfc8f0569a9b9f146acda83abf0dbb2c5d1dea7d5d620a872516edb1653f203eaba60bdcfe1cc5f46c14e99750a44788e154752c9ec26717404f71a769c4cc0d7f8f90896fe54bc3c23412627245fdb18e5fc9750038f5";
char* s_set = "de8a29782aa0fc51d3404822e63990cdc4166f5630ffb4f441db32a3687a47a35789acac8b0cc93134a8f6b8d826395b4dec072ad6dfd799fe3fbe3d21b84ba8460a4fb91de7f83fa5ecfe1cef25754e561162f3e9e8488363b09538d3ab50021c8bcacb80a23371d70f6fd39bce95d24a085e37b18ebbb5dc6d5a9f129057eef4c9d1a6b52cfa7cb5a3fc9928c9080de47c51a0e5b700e138ede22d3874eab0850311594d8bf5c955018811ce4ad35f5833d743fd6b5cfefc29f99bfc5ee95876cfa5b9621406029d3f4f85568ff652dbea677699befb1feb3e30178a15811307ffef5cec912c5ff3da95a83ae49c14e18894ddcf4b728cbbfcf7747d746afb612dc667154254b5e2aa61f3365a5f2e64102c78a56e2ecfeb75577dc08a102847528e666cfadaf47092e0a584a859b2a79b58bee81f1b99ee8dc84d9bbe12199ce78019da0bc5bcf20534231b774cfdb9c594b37fe719f9d2330ed7a6d416d14d7e2ec177151950e5622e6f1b13991bc02033f27ff34589e272864e7d7242e2514f6e1092f852fc2ea51591cc3ca2616336aca7309cedff3637660db1e4f1dafc09f8fb04f4b5b44d4b644507f0b188a0d648d2cb9211679fcb2926d0c1fa5d62db6906fe77145eb7ecc5a3c930ddf54eefd26b2814c2fe44cb8990a23b0fb02109c6963c925b922cb05d6ee126adbb168b70960b42717a30fe1e6cc694c46d9f82deb13cd1ab243ba904ce8e26266d2108a67c3cce9760881a9a234e92a8a0fdfe62b5ca182c28128cb12c372d29668e378b9d100d9de92b8984f35da57c6342abc2eda4407a269a5e992436491fb70e9505b63dd3768843264ad83143c017b647692e50d2f7107ff31e17d0ff4333db9b124659ee87252ece37ec297a230075a6bc1391f621f02fff084324c11b8fcc17d9cc89c4462b3a8ccfadf7544aa35e1eb45a6f9437792f9932ee872aad3aaf90bf72360f3dc2d0ac85be978b274486f5f33746f7203a9a3d847a67f0ef3ef05c33313a8b403bdf515d534c84e82809a4f2bd2648629b78c156b8a772107a692bccc70a95b72e7b3f8e8b51d1ea3c";
char* t_set = "c86c939ba5083e8752c3284f9b55c042294f14d5331a59bef52f29122fc7a2da0fffc43a6f88d70dd7ef5204772eb657b4ccd15d30891bee0117ecfe1acad7b638ffd76e10a6aaed47042c37cb7981a32fdef5f3064ff1086c2054aa6b71fe821ec3ba9f92c2331b1f6fd01f43058e1b870d0ab8ab16558570ca151fefa37e3738754f75f984a3e7dc1ba9204bca127e9db95b74a9971cf3d64314b0ef20fc43a79a72ee288163a98e6eaba71fc1f755bc38c05121366b8fffc2b1111feec63e07e6630421f3533dffeaa1f7e9c684d8d31d9df5e20f60c917aea74a20649cd7565ba0c5b68189997dd1977f2a040a7af15d746bb8ddaa87f9385bfb8845fc4cbb3869938165190bec6337fa165e9968ad4632386123c1b5f9efc2851267f370bad0a5b5d091dfd092324d38d04257ff249ecb1be33e401091a78512c8a40722ade93d948c612caba69a8ee5438bf8d742dacba6b42e5bce8072fc411b9aca5086732fb56e7600e0eba62dba2d02b7af827a03ebe045863ac7912cd8dc15e415f5d3d2628da4c36e7b59022e94e677443da9ceb79e2802ab7ced58272ad62df047437476211749bc6230c3fff03c3ab11b695ad0568dd12d447539d431e596fcfa5298fbe839865d363ed020075abd06fcacdba53d023726ca6e3936b5d457c40eaf0db18a14ae26469d4e4a1544592c38c0c673d5465bcdbea427a2b15662111d50aad54839ec87de13c60574b63ddb4cad2e831a6e98e67a414704a3e2b103e5eb24978bb84b764a39a5b291adbfd46413d452c97a5739496298dbf9c311d54a9a604b1a9b342d832d4faeab27d45ded9ec4f3614c50ababea5d1400c4587bae623330c6624c76e7177e64262de8994c22d886b38a56256f5bc4d9cc8336da585af762d0964904b03214d94837f4cff01acc2711d46896dffdcd2d62dbacf72a2d0d8ea1c62f812d8919581ef0b17d12cf01779401d5c54881e0f167299ed703d20157a9c69d867af7f33250def0445c50ebc2fa8c3f48cf5db258c749991e4698cddbc1ca68ea527f9e74395c2e7b628021b7db04dd996a9ac621052a57d9";
char* q = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
char* g = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
int iLEN = 32;

char* pad_string(char* C){
    const char* zero = "0";
    int len = (int)strlen(C);
    if (len%2==1) {
        char *buff = malloc(strlen(C) + 2);
        int i;
        int j;

        for (i = 0; zero[i] != '\0'; i++) {
            buff[i] = zero[i];
        }

        for (j = 0; C[j] != '\0'; j++) {
            buff[i + j] = C[j];
        }
        buff[i + j] = '\0';
        return buff;
    }
    else
        return C;
}

typedef struct
{
    PAILLIER_public_key  paillier_pub_key;
    PAILLIER_private_key paillier_priv_key;
    PEDERSEN_PUB pedersen_pub;
    PiLogstar_PROOFS proof;
    PiLogstar_PROOFS_OCT proof_oct;
    PiLogstar_COMMITS commits;
    PiLogstar_COMMITS_OCT commits_oct;
    PiLogstar_SECRETS secrets;
    octet x;
    octet C;
    octet rho;
    octet e;
    octet X;
    octet g;
}  Prover;

typedef struct
{
    PAILLIER_public_key  paillier_pub_key;
    PAILLIER_private_key paillier_priv_key;
    PEDERSEN_PRIV pedersen_priv;
    PEDERSEN_PUB pedersen_pub;
    PiLogstar_COMMITS commits;
    PiLogstar_COMMITS_OCT commits_oct;
    PiLogstar_PROOFS proof;
    octet C;
    PiLogstar_PROOFS_OCT proof_oct;
    octet e;
    octet X;
    octet g;
}  Verifier;

int main()
{
    int rc;

    Prover prover;
    Verifier verifier;

    ECP_SECP256K1 X;
    BIG_1024_58 xx[HFLEN_2048];

    char c[FS_4096];
    octet C = {0, sizeof(c), c};
    prover.C = C;

    char rr[FS_4096];
    octet rho1 = {0, sizeof(rr), rr};
    prover.rho = rho1;

    char m[MODBYTES_256_56];
    octet x1 = {0, sizeof(m), m};
    prover.x = x1;

    char e_[MODBYTES_256_56];
    octet e1 = {0, sizeof(e_), e_};
    prover.e = e1;

    char e2_[MODBYTES_256_56];
    octet e2 = {0, sizeof(e2_), e2_};
    verifier.e = e2;

    char p[HFS_2048];
    octet P = {0, sizeof(p), p};

    char q_[HFS_2048];
    octet Q = {0, sizeof(q_), q_};

    char z[FS_2048];
    octet S1 = {0, sizeof(z), z};
    prover.commits_oct.S = &S1;

    char u[FS_4096];
    octet A1 = {0, sizeof(u), u};
    prover.commits_oct.A = &A1;

    char w[FS_2048];
    octet D = {0, sizeof(w), w};
    prover.commits_oct.D = &D;

    char t2[FS_2048];
    octet Y_oct = {0, sizeof(t2), t2};
    prover.commits_oct.Y = &Y_oct;

    char s[HFS_4096];
    octet z2_ = {0, sizeof(s), s};
    prover.proof_oct.z2 = &z2_;

    char s1[HFS_2048];
    octet z1_ = {0, sizeof(s1), s1};
    prover.proof_oct.z1 = &z1_;

    char s2[FS_2048 + HFS_2048];
    octet z3_ = {0, sizeof(s2), s2};
    prover.proof_oct.z3 = &z3_;

    char t20[SFS_SECP256K1 + 1];
    octet g_ = {0, sizeof(t20), t20};
    prover.g = g_;

    char t21[SFS_SECP256K1 + 1];
    octet g_2 = {0, sizeof(t21), t21};
    verifier.g = g_2;

    char id[32];
    octet ID = {0, sizeof(id), id};

    char oct10[HFS_2048];
    octet X_oct = {0, sizeof(oct10), oct10};

    /*
   ----------------------------- FORM SSID
   outputs of key re-sharing and Aux. protocols form SSID

   */
    int n=3;    // number of octets in packages
    int t=2;
    char xored_rid[EGS_SECP256K1];
    char xored_rho[EGS_SECP256K1];
    char j_packed[n * 4 + 1];
    char j_packed2[t * 4 + 1];
    char X_set_packed[n * (EFS_SECP256K1 + 1)];
    char order[EFS_SECP256K1];
    char generator[EFS_SECP256K1 + 1];
    char N_set_packed[n * FS_2048];
    char s_set_packed[n * FS_2048];
    char t_set_packed[n * FS_2048];
    int n1;
    int n2;

    octet xored_rid_ = {0, sizeof(xored_rid), xored_rid};
    octet xored_rho_ = {0, sizeof(xored_rho), xored_rho};
    octet j_packed_ = {0, sizeof(j_packed), j_packed};
    octet j_packed2_ = {0, sizeof(j_packed2), j_packed2};
    octet X_set_packed_ = {0, sizeof(X_set_packed), X_set_packed};
    octet order_ = {0, sizeof(order), order};
    octet generator_ = {0, sizeof(generator), generator};
    octet N_set_packed_ = {0, sizeof(N_set_packed), N_set_packed};
    octet s_set_packed_ = {0, sizeof(s_set_packed), s_set_packed};
    octet t_set_packed_ = {0, sizeof(t_set_packed), t_set_packed};

    OCT_fromHex(&xored_rid_, rid);
    OCT_fromHex(&xored_rho_, rho);
    OCT_fromHex(&j_packed_, j_set);
    OCT_fromHex(&j_packed2_, j_set2);
    OCT_fromHex(&X_set_packed_, X_set);
    OCT_fromHex(&order_, q);
    OCT_fromHex(&generator_, g);
    OCT_fromHex(&N_set_packed_, N_set);
    OCT_fromHex(&s_set_packed_, s_set);
    OCT_fromHex(&t_set_packed_, t_set);

    CG21_SSID ssid;
    ssid.uid = &ID ;
    ssid.rid = &xored_rid_ ;
    ssid.rho = &xored_rho_ ;
    ssid.j_set_packed = &j_packed_ ;
    ssid.j_set_packed2 = &j_packed2_ ;
    ssid.X_set_packed = &X_set_packed_ ;
    ssid.q = &order_ ;
    ssid.g = &generator_ ;
    ssid.N_set_packed = &N_set_packed_ ;
    ssid.s_set_packed = &s_set_packed_ ;
    ssid.t_set_packed = &t_set_packed_ ;
    ssid.n1 = &n1;
    ssid.n2 = &n2;

    n1 = t;
    n2 = n;

    // Deterministic RNG for testing
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    // Pseudorandom ID and AD
    OCT_rand(&ID, &RNG, ID.len);

    /*
    ----------------------------- LOAD INPUTS
    (x, X, rho) are provided as the inputs such that C = (1 + N0)^x x rho^{N}

    */
    OCT_fromHex(&prover.x, k_hex);
    OCT_fromHex(&prover.rho, rho_hex);
    OCT_fromHex(&prover.C, K_hex);
    verifier.C = prover.C;

    printf("\nInput:\n");
    printf("\t\tx = ");
    OCT_output(&prover.x);
    printf("\t\tC = ");
    OCT_output(&prover.C);
    printf("\t\trho = ");
    OCT_output(&prover.rho);

    // Compute X = xG
    OCT_fromHex(&X_oct, pad_string(k_hex));
    OCT_pad(&X_oct, HFS_2048);
    FF_2048_fromOctet(xx, &X_oct, HFLEN_2048);

    ECP_SECP256K1_generator(&X);
    ECP_mul_1024(&X, xx);
    ECP_SECP256K1_toOctet(&X_oct, &X, true);
    prover.X = X_oct;
    verifier.X = X_oct;

    /*
    ----------------------------- SETUP (by Prover and Verifier)
    Prover generates Paillier (pk, sk, N0) and shares (pk, N0) with Verifier
    Verifier generates ring pedersen parameters (p, q, s, t, Nt) and shares (s,t, Nt) with Prover
    */
    // Load Paillier keys
    OCT_fromHex(&P, P_hex);
    OCT_fromHex(&Q, Q_hex);

    // Generate Paillier keys
    PAILLIER_KEY_PAIR(NULL, &P, &Q,&prover.paillier_pub_key, &prover.paillier_priv_key);
    verifier.paillier_pub_key = prover.paillier_pub_key;

    printf("Setup:\n");
    printf("\tProver's Paillier Key\n");
    printf("\t\tP = ");
    OCT_output(&P);
    printf("\t\tQ = ");
    OCT_output(&Q);
    printf("\t\tN = ");
    FF_4096_output(prover.paillier_pub_key.n, HFLEN_4096);


    //Generate Ring-Pedersen parameters
    OCT_fromHex(&P, PT_hex);
    OCT_fromHex(&Q, QT_hex);
    ring_Pedersen_setup(&RNG, &verifier.pedersen_priv, &P, &Q);

    // Generate s,t
    Pedersen_get_public_param(&verifier.pedersen_pub, &verifier.pedersen_priv);
    prover.pedersen_pub = verifier.pedersen_pub;

    printf("\n\tVerifier's Pedersen parameters\n");
    printf("\t\tP = ");
    OCT_output(&P);
    printf("\t\tQ = ");
    OCT_output(&Q);
    printf("\t\ts = ");
    FF_2048_output(verifier.pedersen_priv.b0, FFLEN_2048);
    printf("\n\t\tt = ");
    FF_2048_output(verifier.pedersen_priv.b1, FFLEN_2048);
    //-------------------------------------------------------------------

    ECP_SECP256K1 G;
    ECP_SECP256K1_generator(&G);
    ECP_SECP256K1_toOctet(&g_, &G, true);
    ECP_SECP256K1_toOctet(&g_2, &G, true);

    //-------------- PROVER SAMPLES RANDOMS AND COMMITS
    PiLogstar_Sample_and_commit(&RNG, &prover.paillier_priv_key, &prover.pedersen_pub,
                                &prover.x, &prover.g , &prover.secrets, &prover.commits, &prover.commits_oct);

    verifier.commits_oct.S = prover.commits_oct.S;
    verifier.commits_oct.A = prover.commits_oct.A;
    verifier.commits_oct.D = prover.commits_oct.D;
    verifier.commits_oct.Y = prover.commits_oct.Y;


    printf("\nCommitment Phase\n");
    printf("\tGenerate Random Values:");
    printf("\n\t\talpha = ");
    FF_2048_output(prover.secrets.alpha, HFLEN_2048);
    printf("\n\t\tr  = ");
    FF_2048_output(prover.secrets.r, FFLEN_2048);
    printf("\n\t\tgamma = ");
    FF_2048_output(prover.secrets.gamma, FFLEN_2048 + HFLEN_2048);
    printf("\n\t\tmu   = ");
    FF_2048_output(prover.secrets.mu, FFLEN_2048 + HFLEN_2048);
    printf("\n\n\tGenerate Commitment:\n");
    printf("\t\tS = ");
    OCT_output(prover.commits_oct.S);
    printf("\t\tA = ");
    OCT_output(prover.commits_oct.A);
    printf("\t\tC = ");
    OCT_output(prover.commits_oct.D);

    //-------------------------------------------------------------------


    //-------------- PROVER GENERATE A CHALLENGE
    PiLogstar_Challenge_gen(&prover.paillier_pub_key, &prover.pedersen_pub,
                            &prover.C, &prover.commits, &ssid, &prover.X, &prover.e);

    printf("\nCompute deterministic challenge\n");
    printf("\t\te = ");
    OCT_output(&prover.e);
    //-------------------------------------------------------------------

    //-------------- PROVER PROVES THE RANGES OF k
    PiLogstar_Prove(&prover.paillier_priv_key, &prover.x, &prover.rho,
                &prover.secrets, &prover.e, &prover.proof, &prover.proof_oct);

    verifier.proof_oct.z1 = prover.proof_oct.z1;
    verifier.proof_oct.z2 = prover.proof_oct.z2;
    verifier.proof_oct.z3 = prover.proof_oct.z3;

    printf("\nProof Phase\n");
    printf("\t\tz1 =  ");
    OCT_output(prover.proof_oct.z1);
    printf("\t\tz2 =  ");
    OCT_output(prover.proof_oct.z2);
    printf("\t\tz3 =  ");
    OCT_output(prover.proof_oct.z3);
    //-------------------------------------------------------------------

    // Prover - clean random values
    PiLogstar_clean_secrets(&prover.secrets);

    // Transmit the proof and commitment in octet form to the verifier

    // Verifier - read commitment and proof from octets
    PiLogstar_proofs_fromOctets(&verifier.proof, &verifier.proof_oct);
    rc = PiLogstar_commits_fromOctets(&verifier.commits, &verifier.commits_oct);
    if (rc != Pilogstar_Y_OK)
    {
        printf("\t\tpi-logstar Y is not a valid point!\n");
        exit(1);
    }

    //-------------- VERIFIER GENERATEs THE CHALLENGE
    PiLogstar_Challenge_gen(&verifier.paillier_pub_key, &verifier.pedersen_pub,
                            &verifier.C, &verifier.commits, &ssid, &verifier.X, &verifier.e);
    //-------------------------------------------------------------------

    //-------------- VERIFIER VALIDATES THE PROOFS
    printf("\nVerification\n");

    rc = PiLogstar_Verify(&verifier.paillier_pub_key, &verifier.pedersen_priv,
                      &verifier.C, &verifier.g, &verifier.commits, &verifier.X, &verifier.e, &verifier.proof);
    if (rc == PiLogstar_OK)
    {
        printf("\t\tpi-logstar Verify done!\n");
    }
    else
    {
        printf("\t\tpi-logstar Range Proof Failed!\n");
    }
    //-------------------------------------------------------------------
}
