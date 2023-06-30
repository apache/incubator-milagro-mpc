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
#include "amcl/cg21/cg21_rp_pi_affg.h"
#include "amcl/cg21/cg21_utilities.h"

#define IDLEN 32

// Alice Paillier and Pedersen key
char *P1_hex = "C6C646679CD5B694841621AAD2FE7840E39B777C0BDEB36597594DA4FA0F07E4FC0B8E719F05203850FF8540A62394A8984E880C3AD0A407736BFE4631D7C501C43EB2463629CDF897BDA60664660FC5209BF73C6A33EF1FD2995C830C8A10339A5ED90EFD0698D470659C244CC927AAB4CD7D1F4D616A135EF250E9BB119673";
char *Q1_hex = "B6A1CED9AD6A84F36615652BB7794062911DFF67275F58F2F6C64356ABE8C1BBD4DB522C544071F15DC1704D0278731F2519EDD143B6F4065250CCB5625888DF1747470A83E515A7B3CCB71D20E661799C5CA21599EEF104989A5DC4399983FCD6ABD2B27802B1B790EEB0DBB8786167B5B41EB9D1EC65F3B4CE0F8129CC0635";

// Bob Paillier key
char *P2_hex = "f592ad30c88d719fd272095257c90395d16f6c613a3ccf1b556646a99c316275ce6bf0565f1f28e705342158c79e0d5614bcfeec3b02d60eb5bd490b930b04c64103b2b0257d73156715012c77f43872024488297b1f03d521200ffadeb3f85e86378837ed34c366b5f58e8dd042e320381d765a871f963f80fc4ac4bb4c096f";
char *Q2_hex = "c49346cef2c4249b7df76b93191e916db4582549697a526a6aa0094c09d83dc71be94598e64fba8e34f3b27c3a40090be0a44e1818b14c5513e0b9d9cdc9bb19398a29725fa851b08addaacb430ebe55128f6c43d611d2a35ddb7e7fba5edae177c9de0271912110709125ce18dd403be71ce96784ec856115e2fc4462ccd5d5";

// Alice - Safe primes for BC setup
char *PT_hex = "c2cc5ab59ecd22f46f0869dee3d9a99cd5bd131b07ca12b295a41a900c345ba41e3f25a251f080571058c74ca16f7949acc6c62737541562ac4fea45ad4db247a505675655efbdfd81cf8b78454ad466ee11e2ebadd884cc6f67ae2c5ab3fffb97f67198092c1bbc6d19cf456232b7e3bc39d1a5ebb77f120f09c58492f415b3";
char *QT_hex = "c6207e07c2e8b616d36b790d4ff127eb7d70b5e3b46d0acefc0a460ba544e03cf3a3d3c6e329aa2f5e0eb258bd0d7a140c5e9779ce0ec4e0f1982157ded95b3a48a1bbdffc1cec430dfbe535cc5b07ebb069e78c814f4f68ab6d5b2bd8e93a1aca4267fbe8d07b151c42393113d33deb21da82bf22e7fbfc1f64996bd1c52507";
char *b0_hex    = "88eaeef31d1152f83ce9e540560ba743c662b79f59dab569453d792e7aeb2e29f55bf0ce5a35b7e51b6c226405209950fce8e71a985ebd85fded7829c115485e0bb5044c103ff36e2f86489667285c092c38d28c3f8196da4fff2c4f78b7c9003a8811b4bfd7dcb86688ffa26245cf1d924f76544cd0aeb60f179885560f0fa9a83eeef875b95ebba4d27af87d690c981505b1d8ae44ef50a6b77e89f5999632af0f2777eb3db15d7988226ca6034bf014a6c5b264cd2e4dced71cc20d82ffefacd956fa9de02b2d29ece1d3617b25fbc0a5ef3f4c2e7922d029dfa0fb1bdfef0ab3c6d302b0bd5c42edc3bd20aaeee7990b5f509516bf0b6813d69ec301d7c9";
char *alpha_hex = "8f9424c8b45bacf7824dc46e6452bd1bb6b1b07218daf70652a84946682d7b4fe5239d9efd60b76e5f9401b98ec4c1cf789b7761f1c7429c0c94243ab378b7bbf16e1c8cb65afb315f0fac3ad9f321679857ee8b6c1b462ddd6bf42d023e2a6462b32c9b5c4314927ff39ea8507a93dcfd4d6284e83f3b96e0eb07d82ce808b3eae22121fad8ff8309ec7e6e01b6c12ff647a717e51fc896b5e04dcd0fe11fd3260aaa8c52be2370135816f178742ff0775b947e5e56727dfed3ae174ae956674c8e8b1e7d973e0078c0ffc38dba2b962e74a60cd8c40ae9bb559cd2d3593050ca44072a24c9024281638c129b57b585e319b8af3295d8daa6f454f3e9f4fe5";
// Paillier ciphertext and plaintext

char* x_hex = "beac2bc96ab257a7c938af4183cdecf83808672bb078a7cea319b61af3385a46";
char* y_hex = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000043735af54b5e4d21d66e2466871d5e7b99302080135ab25eed0a5fbcac8d3a8e629938277cb66daeb03ba0a1f187ef2e2abe0b9144def657588932dea87fdbb4e01c4733f1d7e6878604c4b5c7c6571ced41757b93583521b30832ce270e2481df77772d493edcee4eaa177811c55393685d0ff79cac95236e1347256b966bf6999c2b1a5f6f3d84c2c1074e2562de3fbc846bcafbca2f1e7238e352e367818e";

char* rho_hex   = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003076a3ba79fc136853ae3eb8b4f925ed8e9e24fd5e83244a803849f8331da46a0cfe7e635cfc3ff5c802bfec5b57fe9b92c82967bfc854928bf1220dc4353d4178d128f83c7349f0d39e884e3069c8514890e6ac679d99b189c435a8ffde58d4d8785970ca5298e0f1b13d557acac3a591a64238674694c04d48679415c248f9c45847a81b4dbb65f717da69bfb3664846af50a028249d8f947f24855ef9b6e2e9e3a885faa7f22838dc3e3aceb277421f2f0396784929fc91dba00a12cf893e0de5cc9859ab948ea0ce81bb9bbb3d79dc623f0b82b6fa6981b47745dfbf6fdfe3f9c5cce21a9859db3c456e174319f84ac795c90d6d5447873d22b54baa1b91";
char* rho_y_hex = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044596895a97afffeb6e5a534adda2b73153090ad0b9e1335a9f016b34952064d9075f20f53bec36959ff660eda93e4209137444ed6a67e7a447d822687f8f7083eac440fa85fa0fa33c5f09a966e81530d5f2f8463e10dbf7d0ef730d06c3bfe547e5e152646dc34b31366ceb9b8735cc708852c658e0830d6fb16abc3849e7d01c1b37b853f9664f8f36b697b0dc2be3ae1c9033d678106ac7e8797ab88a3edbe816c72b2f972955f699160694d18b4ff47bd78aaca600327d72304fc7fb63e04a649afc560aa332822b27b81152de0c4110add8625234956a923c084504f046fa15da6ff5811ecfa82552d42d2b158a18e75579fe383500bd9eaf4f1e69257";

char* C_hex = "04cccc3397ddc572851dd88dde8dcb256faf303de07e2cada8a565310c2cf50442a7feb89724678db6b63ad4d8d175af9634cc9e4bbff6a9c8280d364b0c9a9ee9f5e8d70ba115330b90febd32ccd512a7bf9bff52c7cd77d308039a8240c5d8d119fe2a3d1135ac479d36f59015934cb319e6e69490148f40a5356752c7b3e5407ffa0d4a12eb8259542f11b4c0d14c7445f7c6ea079386f653a1cafb76dba8e2a7fcf8e74280b2546480c1c8715ffef8c93a7a8552a5e578b42fe7cf633df0dfc43b784b1ae2a9385b30dad63becb610787fc703ac34eed47a536f6cf7a977a42193dc91b851a9a7ebc430eb9f6af77f319a78be3451f5723845362cc612e5748debe9b4b2fcb45d89de8ab28d5d6ede10ecbd714d60bb4e8a07e456753ca503cf720e12c0097273165b7d0f69c8d2ae314d263777126b46d2c4f1d3260c35e257657af2c2528e601586eb3a179fccce765df8ccd7082374e913ce4e3f0e3038227a853457d850a90ac0b5cb7cf2707bc4a1d165654fe3cc04775f1d6837624985d4061205d31a923399a5eb1398c9d2d6dc427122f74a44414b4d251a1d287ca73da4b4d66fc4544393a99b6976f91ecb16947075614568cdbed87b0c3e9b4aefa0a92e9c610a64d03e4dbd18697eb02ccf0a4f3c9c91b9b7427ad632070b3d9624adf23727ded3b33c5aa8799ec3d765a770395f2f76e26d70ffc3d1d2ed";
char* Y_hex = "0ff844057f8578e1eb44ddd5a9a4e5489f73b5576f4ffe9e418f5423f29e222631c9995f20824b48294957353c7320f7f7e900c7cc25fcdcccfe25fe20c59166b71610ddc3e86479166e424285654d8c28fc014d709776a71f2faf79571a9feaf2ea3811fdeab8eed396bcc71e5587ecf05b87ee0e4433a7560ee05c95430dd10537c4ac0223689d1dd4853437cb72962c1f02ba20f84c9c1b130f8b6cd94ae2e0caa14afb5e593c5ade5f5b2141edff9b20b5b0f4164b901d6ba3b39f50f196d10c0d1b16427e9fb1cfe3e5783655f2652250a9f3954a221cb0d234298696546e11fe17614c46889f9001803bc36bff7fcbb8296b0dc85a709fa45e36eeb384141acc84d5c53ca8afa019e8dbf01a8ad61f7992191c9b118d5de5fb927d131d01d1b3df0f92a159d1fdadcca86f6f8931d6a054d3daa7779f309f25f68e78023716135168a47f78a3ff6f4c9ea90d156eff03e1c03750e881547a04aba4988e40d7c8c8901d514255feeb83ecdd41a080c5d10d6453ecd971962662f23b00896c5ba0f06503e43ca24a2216cd7d3a419496fc17f1857509b401605d270a636336901c9fa45ae5cc0cd6b161c847dd1e98364b26f4aee02fc7da794045b5469fb6d9bb6274f83353a817564cff60646208ed3e49bf4a1165c789f04f9f20e345aba9ffefae3d411723c454c8d3ee572cd5ed3e38e0fb27243c2a1aa713ff2bfe";
char* D_hex = "0b4fb0edda5013ad77aaad54d178e0a2d6e0cc12ccd7d3e2930a3526ce8226d8451ae19f368c6d33674ab0464a174fd5924b7e2857995f6a4bae8d428d5d4c3a08f048e65c5341d337c285b51940c8ffa6a1ee425ba87b19b233706041a498fecff1fc4351150b8acf2de3dab67b6d2d412f2c835e4ed88d04f8633ac9bbcacddc50e4c82082b0920f5b1cd06ed6451de3de874ed4b0fc936c02b73d5af93a1414ad9dd79bd02268bd12edb9b67d92aa1d66fe15e66008e9c68ca212db997d043afcb9c5e40eb7907addb227bc6774bf12ceba99d7ae34351416b84c988b67d73ee15ebd2b77390c051d9c3cbe9e0f597aa6b48d2cce2634f5f26bb05062d42a07a782da97d5600ec26ba599c0e3a5dfe0add1bc725f733860a52cc7e18557d19aee8a49fabdd2ae45d7075a243fdffc7547f5c1a06dbbdfa2a23b2ee1bb1c3359a80d25ee2fced58e290d2957dba28ca52037d600e0579283238c15ba8c999b6681046ec4d8951fcd0f10b8b5ef1b26cb1a7779fd3de490199c615e3204c562bfc5be12a42cacacb8056a53aba01a152c2f29a35115f0df7fae445125276fb7438df010e295e8c99c7f14a16f4b90123017fe292b4d9fc5ed6703a58ed7224500191acc65ddd14c79e10780580e50f69b12a274a7d8dbaaa6781cef8711183adb7f7f0981e4bf3200d3a01e928425ccc063f32d29af8483078ee9639f4ca9cf";

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
        strcpy(buff, zero);
        strcat(buff, C);
        return buff;
    }
    else
        return C;
}

typedef struct
{
    PAILLIER_private_key paillier_priv;
    PAILLIER_public_key  paillier_pub, verifier_paillier_pub;
    PEDERSEN_PUB  pedersen_pub;
    Piaffg_COMMITS commits;
    Piaffg_SECRETS secrets;
    Piaffg_PROOFS proofs;
    Piaffg_PROOFS_OCT proofsOct;
    Piaffg_COMMITS_OCT commitsOct;
    octet x;
    octet y;
    octet rho;
    octet rho_x;
    octet rho_y;
    octet X;
    octet Y;
    octet C;
    octet D;
    octet e;

}  Prover;

typedef struct
{
    PAILLIER_private_key paillier_priv;
    PAILLIER_public_key  paillier_pub, prover_paillier_pub;
    PEDERSEN_PRIV pedersen_priv;
    PEDERSEN_PUB  pedersen_pub;
    Piaffg_COMMITS commits;
    Piaffg_PROOFS proofs;
    Piaffg_PROOFS_OCT proofsOct;
    Piaffg_COMMITS_OCT commitsOct;
    octet X;
    octet Y;
    octet C;
    octet D;
    octet e;

}  Verifier;


int main()
{
    Prover prover;
    Verifier verifier;

    int rc;
    ECP_SECP256K1 X;
    BIG_1024_58 xx[HFLEN_2048];

    char x_[MODBYTES_256_56];
    octet x1 = {0, sizeof(x_), x_};
    prover.x = x1;

    char y_[FS_2048];
    octet y1 = {0, sizeof(y_), y_};
    prover.y = y1;

    char rho_[FS_4096];
    octet rho1 = {0, sizeof(rho_), rho_};
    prover.rho = rho1;

    char rhoy_[FS_4096];
    octet rho_y1 = {0, sizeof(rhoy_), rhoy_};
    prover.rho_y = rho_y1;

    char X_[2*FS_2048];
    octet X1 = {0, sizeof(X_), X_};
    prover.X = X1;

    char Y_[2*FS_2048];
    octet Y1 = {0, sizeof(Y_), Y_};
    prover.Y = Y1;

    char C_[2*FS_2048];
    octet C1 = {0, sizeof(C_), C_};
    prover.C = C1;

    char D_[2*FS_2048];
    octet D1 = {0, sizeof(D_), D_};
    prover.D = D1;

    char pa[HFS_2048];
    octet Pa = {0, sizeof(pa), pa};

    char qa[HFS_2048];
    octet Qa = {0, sizeof(qa), qa};

    char pb[HFS_2048];
    octet Pb = {0, sizeof(pb), pb};

    char qb[HFS_2048];
    octet Qb = {0, sizeof(qb), qb};

    char t1[2 * FS_2048];
    octet A = {0, sizeof(t1), t1};
    prover.commitsOct.A = &A;

    char t2[FS_2048];
    octet Bx = {0, sizeof(t2), t2};
    prover.commitsOct.Bx = &Bx;

    char t3[2 * FS_2048];
    octet By = {0, sizeof(t3), t3};
    prover.commitsOct.By = &By;

    char oct1[FS_2048];
    octet E = {0, sizeof(oct1), oct1};
    prover.commitsOct.E = &E;

    char oct2[FS_2048];
    octet S = {0, sizeof(oct2), oct2};
    prover.commitsOct.S = &S;

    char oct3[FS_2048];
    octet F = {0, sizeof(oct3), oct3};
    prover.commitsOct.F = &F;

    char oct4[FS_2048];
    octet T = {0, sizeof(oct4), oct4};
    prover.commitsOct.T = &T;

    char oct5[FS_2048];
    octet z1 = {0, sizeof(oct5), oct5};
    prover.proofsOct.z1 = &z1;

    char oct6[FS_2048];
    octet z2 = {0, sizeof(oct6), oct6};
    prover.proofsOct.z2 = &z2;

    char oct61[FS_2048+HFS_2048];
    octet z3 = {0, sizeof(oct61), oct61};
    prover.proofsOct.z3 = &z3;

    char oct62[FS_2048+HFS_2048];
    octet z4 = {0, sizeof(oct62), oct62};
    prover.proofsOct.z4 = &z4;

    char oct7[FS_2048];
    octet w = {0, sizeof(oct7), oct7};
    prover.proofsOct.w = &w;

    char oct9[FS_2048];
    octet wy = {0, sizeof(oct9), oct9};
    prover.proofsOct.wy = &wy;

    char oct10[HFS_2048];
    octet alpha_oct = {0, sizeof(oct10), oct10};

    char e[EGS_SECP256K1];
    octet E1 = {0, sizeof(e), e};
    prover.e = E1;
    verifier.e = E1;

    char X2[FS_2048];
    octet X_oct = {0, sizeof(X2), X2};

    // Deterministic RNG for testing
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    char id[IDLEN];
    octet ID = {0, sizeof(id), id};

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

    // Pseudorandom ID and AD
    OCT_rand(&ID, &RNG, ID.len);

    /*
    -------------- LOAD INPUTS
    (x, y, rho, rho_y, C, D, X, Y) provided such that:
     X = xG
     Y = (1+N1)^y * rho_y^N1 mod N1^2
     D = C^x * (1+N0)^y * rho^N0 mod N0^2
    */

    // Compute X = xG
    OCT_fromHex(&alpha_oct, pad_string(x_hex));
    OCT_pad(&alpha_oct, HFS_2048);
    FF_2048_fromOctet(xx, &alpha_oct, HFLEN_2048);

    ECP_SECP256K1_generator(&X);
    ECP_mul_1024(&X, xx);
    ECP_SECP256K1_toOctet(&X_oct, &X, true);
    prover.X = X_oct;
    verifier.X = X_oct;

    // Load other inputs
    OCT_fromHex(&prover.x, pad_string(x_hex));
    OCT_fromHex(&prover.y, pad_string(y_hex));
    OCT_fromHex(&prover.rho, pad_string(rho_hex));
    OCT_fromHex(&prover.rho_y, pad_string(rho_y_hex));
    OCT_fromHex(&prover.Y, pad_string(Y_hex));
    OCT_fromHex(&prover.C, pad_string(C_hex));
    OCT_fromHex(&prover.D, pad_string(D_hex));
    verifier.Y = prover.Y;
    verifier.C = prover.C;
    verifier.D = prover.D;

    printf("\n\tInputs:\n");

    printf("\t\tVerifier:\n");
    printf("\t\t\tC = ");
    OCT_output(&prover.C);

    printf("\t\tProver:\n");
    printf("\t\t\tx = ");
    OCT_output(&prover.x);

    printf("\t\t\ty = ");
    OCT_output(&prover.y);

    printf("\t\t\trho = ");
    OCT_output(&prover.rho);

    printf("\t\t\trho_y = ");
    OCT_output(&prover.rho_y);

    printf("\n\t\t\tX = ");
    OCT_output(&prover.X);

    printf("\t\t\tY = ");
    OCT_output(&prover.Y);

    printf("\t\t\tD = ");
    OCT_output(&prover.D);

    // Load paillier key
    OCT_fromHex(&Pa, pad_string(P1_hex));
    OCT_fromHex(&Qa, pad_string(Q1_hex));

    OCT_fromHex(&Pb, pad_string(P2_hex));
    OCT_fromHex(&Qb, pad_string(Q2_hex));

    PAILLIER_KEY_PAIR(NULL, &Pa, &Qa, &verifier.paillier_pub, &verifier.paillier_priv);
    PAILLIER_KEY_PAIR(NULL, &Pb, &Qb, &prover.paillier_pub, &prover.paillier_priv);

    prover.verifier_paillier_pub = verifier.paillier_pub;
    verifier.prover_paillier_pub = prover.paillier_pub;

    printf("Run MTA Range Proof\nParameters:\n");
    printf("\tVerifier Paillier public key\n");
    printf("\t\tN0 = ");
    FF_4096_output(verifier.paillier_pub.n, HFLEN_4096);
    printf("\tProver Paillier public key\n");
    printf("\t\tN1 = ");
    FF_4096_output(prover.paillier_pub.n, HFLEN_4096);

    // Generate Ring-Pedersen parameters
    OCT_fromHex(&Pb, pad_string(P1_hex));
    OCT_fromHex(&Qb, pad_string(Q1_hex));
    ring_Pedersen_setup(&RNG, &verifier.pedersen_priv, &Pb, &Qb);

    Pedersen_get_public_param(&verifier.pedersen_pub, &verifier.pedersen_priv);
    prover.pedersen_pub = verifier.pedersen_pub;

    printf("\n\n\tVerifier's Pedersen parameters\n");
    printf("\t\tn = ");
    FF_2048_output(verifier.pedersen_pub.N, FFLEN_2048);
    printf("\n\t\ts = ");
    FF_2048_output(verifier.pedersen_pub.b0, FFLEN_2048);
    printf("\n\t\tt = ");
    FF_2048_output(verifier.pedersen_pub.b1, FFLEN_2048);

    //-------------- PROVER SAMPLES RANDOMS AND COMMITS
    rc = Piaffg_Sample_and_Commit(&RNG, &prover.paillier_priv, &prover.verifier_paillier_pub, &prover.pedersen_pub,
                             &prover.x, &prover.y, &prover.secrets, &prover.commits, &prover.commitsOct, &prover.C);
    if (rc != Piaffg_OK){
        printf("PiAffg_Sample_and_Commit failed!, %d", rc);
        exit(rc);
    }
    verifier.commitsOct = prover.commitsOct;

    printf("\n\n\t Prover's Secrets:");
    printf("\n\t\talpha = ");
    FF_2048_output(prover.secrets.alpha, HFLEN_2048);

    printf("\n\t\tbeta = ");
    FF_2048_output(prover.secrets.beta, FFLEN_2048);

    printf("\n\t\tr = ");
    FF_2048_output(prover.secrets.r, FFLEN_2048);

    printf("\n\t\try = ");
    FF_2048_output(prover.secrets.ry, FFLEN_2048);

    printf("\n\t\tgamma = ");
    FF_2048_output(prover.secrets.gamma, FFLEN_2048 + HFLEN_2048);

    printf("\n\t\tm = ");
    FF_2048_output(prover.secrets.m, FFLEN_2048 + HFLEN_2048);

    printf("\n\t\tdelta = ");
    FF_2048_output(prover.secrets.delta, FFLEN_2048 + HFLEN_2048);

    printf("\n\t\tmu = ");
    FF_2048_output(prover.secrets.mu, FFLEN_2048 + HFLEN_2048);

    printf("\n\n\t Prover's Commitments:");
    printf("\n\t\tA = ");
    FF_2048_output(prover.commits.A, 2 * FFLEN_2048);

    printf("\n\t\tBx= ");
    ECP_SECP256K1_output(&prover.commits.Bx);

    printf("\n\t\tBy= ");
    FF_2048_output(prover.commits.By, 2 * FFLEN_2048);

    printf("\n\t\tE = ");
    FF_2048_output(prover.commits.E, FFLEN_2048);

    printf("\n\t\tS = ");
    FF_2048_output(prover.commits.S, FFLEN_2048);

    printf("\n\t\tF = ");
    FF_2048_output(prover.commits.F, FFLEN_2048);

    printf("\n\t\tT = ");
    FF_2048_output(prover.commits.T, FFLEN_2048);

    //-------------- PROVER GENERATE A CHALLENGE
    Piaffg_Challenge_gen(&prover.verifier_paillier_pub, &prover.paillier_pub, &prover.pedersen_pub,
                         &prover.X, &prover.Y, &prover.C,
                         &prover.D, &prover.commits, &ssid, &prover.e);
    printf("\n\t\tchallenge e1 = ");
    OCT_output(&prover.e);

    //-------------- PROVER PROVES THE RANGES OF x AND y
    Piaffg_Prove(&prover.paillier_pub, &prover.verifier_paillier_pub, &prover.secrets, &prover.x, &prover.y,
                 &prover.rho, &prover.rho_y, &prover.e, &prover.proofs, &prover.proofsOct);
    verifier.proofsOct = prover.proofsOct;

    printf("\nz1=");
    OCT_output(prover.proofsOct.z1);
    printf("z2=");
    OCT_output(prover.proofsOct.z2);
    printf("z3=");
    OCT_output(prover.proofsOct.z3);
    printf("z4=");
    OCT_output(prover.proofsOct.z4);
    printf("w=");
    OCT_output(prover.proofsOct.w);
    printf("wy=");
    OCT_output(prover.proofsOct.wy);

    // Prover - clean random values
    Piaffg_Kill_secrets(&prover.secrets);

    //-------------- VERIFIER GENERATES THE CHALLENGE
    rc = Piaffg_commits_fromOctets(&verifier.commits, &verifier.commitsOct);
    if (rc != Piaffg_BX_OK) {
        printf("\n\t\tZK Range Proofs are INVALID! rc %d\n", rc);
    }

    Piaffg_proofs_fromOctets(&verifier.proofs, &verifier.proofsOct);

    Piaffg_Challenge_gen(&verifier.paillier_pub, &verifier.prover_paillier_pub, &verifier.pedersen_pub,
                         &verifier.X, &verifier.Y, &verifier.C,
                         &verifier.D, &verifier.commits,  &ssid, &verifier.e);
    printf("\n\t\tchallenge e1 = ");
    OCT_output(&verifier.e);

    //-------------- VERIFIER VALIDATES THE PROOFS
    rc = Piaffg_Verify(&verifier.paillier_priv, &verifier.prover_paillier_pub, &verifier.pedersen_priv,
                       &verifier.C, &verifier.D, &verifier.X, &verifier.Y, &verifier.commits, &verifier.e, &verifier.proofs);

    if (rc != Piaffg_OK)
        printf("\n\t\tZK Range Proofs are INVALID! rc %d\n", rc);
    else
        printf("\n\t\tZK Range Proofs are valid. rc %d", rc);
}
