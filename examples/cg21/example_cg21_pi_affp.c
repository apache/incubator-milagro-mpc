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
 This example refers to none-interactive pi^{aff-p} in CG21's,
 described in https://eprint.iacr.org/2021/060.pdf, page 64.
 */

#include "amcl/cg21/cg21_utilities.h"
#include "amcl/cg21/cg21_rp_pi_affp.h"


#define IDLEN 32

// Alice Paillier key
char *P1_hex = "C6C646679CD5B694841621AAD2FE7840E39B777C0BDEB36597594DA4FA0F07E4FC0B8E719F05203850FF8540A62394A8984E880C3AD0A407736BFE4631D7C501C43EB2463629CDF897BDA60664660FC5209BF73C6A33EF1FD2995C830C8A10339A5ED90EFD0698D470659C244CC927AAB4CD7D1F4D616A135EF250E9BB119673";
char *Q1_hex = "B6A1CED9AD6A84F36615652BB7794062911DFF67275F58F2F6C64356ABE8C1BBD4DB522C544071F15DC1704D0278731F2519EDD143B6F4065250CCB5625888DF1747470A83E515A7B3CCB71D20E661799C5CA21599EEF104989A5DC4399983FCD6ABD2B27802B1B790EEB0DBB8786167B5B41EB9D1EC65F3B4CE0F8129CC0635";

// Bob Paillier key
char *P2_hex = "f592ad30c88d719fd272095257c90395d16f6c613a3ccf1b556646a99c316275ce6bf0565f1f28e705342158c79e0d5614bcfeec3b02d60eb5bd490b930b04c64103b2b0257d73156715012c77f43872024488297b1f03d521200ffadeb3f85e86378837ed34c366b5f58e8dd042e320381d765a871f963f80fc4ac4bb4c096f";
char *Q2_hex = "c49346cef2c4249b7df76b93191e916db4582549697a526a6aa0094c09d83dc71be94598e64fba8e34f3b27c3a40090be0a44e1818b14c5513e0b9d9cdc9bb19398a29725fa851b08addaacb430ebe55128f6c43d611d2a35ddb7e7fba5edae177c9de0271912110709125ce18dd403be71ce96784ec856115e2fc4462ccd5d5";

// Alice - Safe primes for BC setup
char *PT_hex = "c2cc5ab59ecd22f46f0869dee3d9a99cd5bd131b07ca12b295a41a900c345ba41e3f25a251f080571058c74ca16f7949acc6c62737541562ac4fea45ad4db247a505675655efbdfd81cf8b78454ad466ee11e2ebadd884cc6f67ae2c5ab3fffb97f67198092c1bbc6d19cf456232b7e3bc39d1a5ebb77f120f09c58492f415b3";
char *QT_hex = "c6207e07c2e8b616d36b790d4ff127eb7d70b5e3b46d0acefc0a460ba544e03cf3a3d3c6e329aa2f5e0eb258bd0d7a140c5e9779ce0ec4e0f1982157ded95b3a48a1bbdffc1cec430dfbe535cc5b07ebb069e78c814f4f68ab6d5b2bd8e93a1aca4267fbe8d07b151c42393113d33deb21da82bf22e7fbfc1f64996bd1c52507";
char *b0_hex    = "86de86c3bddb35267dc93fbfa64e536380b262c22e0f4ec03603b65936e978d38f0ba33a9afc432aec5758d148666318d34a27e7f3aa7ed288a3d2034d48ea73d548b6a3dd6e781b4dd9e415a79dc7946a1fed16aadf03e8591135ce48ecc8416d25be1b96131cf1e709a1a371299d94bc62c7c72dd884f6ea89966bdf9356de7f029ce452ab3ff52408a6e75e6d061ee5279184c843cd5cbd9f43aa34ebb95a66b92219f8cdf0b9f597cf87fef979c701182affd720f0cd0120d5d9ff238a9dc9dae204823b18b6b706ddd0119481cc2e8126fde5eb4fc321604ca6004a6df1e80f687ac669cce59a5dd5b01ac15b0d8fcc02fb85df1356e0031995c6b87f05";
char *alpha_hex = "1041160a38b8282bd7c9cba6ab48f023ed06e532f0d8ae73cfa92a03a7c0f1f83a0e636a586fae00899f69f14dc0b1f01a834b83653dbb6b2fa280e92cfd521df584ce6374b57b8a23721dd7ca1d82c7830178f4c3115a5ed2cd4c42913576516432321e4753fbd3d4a07e42c7b4050822c9a9614e756bac681fad60e42c71c989556cb82b350f7b4af128d68a7dd9ad4782ac00e18391b393f0258da2b1d68334aa5ced92e45c695c47b6f7e8304e57f2c706720f7f590d1b556d0922bff60ff0efb24baf4bed77fa650343873056c9a08818a524465ad7e8ad4b3f94f415bb9549781f6c8eefa579ac31f7b083c5364ac5433fef912e454baf486935cfe7dc";

// Paillier ciphertext and plaintext
char* C_hex = "acbc3667355f321ce33ffbaabb3ad7c6df3fd1f15202cfa7592ea2882cb6656ceff0042647135e6976e3ba5e3918bd34d5bea345a7b080c34bbad1c5a439a8d6fa5d2ded180587118e71bf321a4576eb10e60e4b409c1f9aa9ecc0348d6fa18c48408c62840dbb65cb08b1648c800e9f843a25a4cdd1fff7b04440119b35541b5c6141af92c5d873a87c12d8e2ce19e91e9d60849c2659176dd582cf705de9287c3fc0c22353d1ed368dcb06d56060928bfd75ea1ec5e51d3a0a653900fc04254582d0741a164267a01db5669f96a2bf396ff649f843e15fe447b6f15b0b9dcf403bd0333fbe749233e38b43529e5d18238f808c205cb59d3098f02defa4d804c1217354511fe39c1cf3dbcd3dd59f6cd16351eefb4e333a490bc5da8f2da7e6b761af1c8737818672e3ed219779f25570e52b0bddf92183311a3738f946cfbfbb579d947383333eb5193c12ee636667028b4cb4006bee9c9cb242ef0d762d86b76e43833daca1afb7461718cded877a675c9ad7d3dd3de054c4a0c04539a6989026264bdb2a1e390951071d62ae255f54324eac37016dbe142adcfb3b77c126241b4cea7a01ef750dae2297ae3f14732b226b6baee5a954b48a5032532890a36bd485ba965fb06959aefd5c74fc0eee2bc43d209dd4b915c9ef50e73a51e44464a88c9b7ef7b615bc31cd87341c037f09770d674241037e1ea69393fdcc5a9";

char* x_hex = "944cbb2d943c6c51513932aba8c74d52d607299b23ee309fde20241e83ac6052";
char* y_hex = "8fc2c3d5929e72a06de0ae8bb1f316e932e3eea54f7d1a6d6d78f1060e33af09408dba353fe54b954994a3a8651c836ee0b867b2c671064d8dfcd699b2ec253c789cc8ed0913a2ee7fd5d07c53005cb8df4c1a26ff828fa9f8d477b8e24ce671da0eeb0dd46767d5647ae2cfa50fb9c571d5ee0ce9b88009e348741b53b5a68049a3f5f16f2a5172c2db58be17c2d9e962e0cd2b930d03eef2a92111cdbba523";

char* X_hex = "85dbd50844d0a6f7d0cdc315d50e676cfe8e3225b1b4a5ac82a6bfcfc1605276f5a5502ef83d0ae3a8885a4b982fe3d3a4e2114c325829369faa551622799da43291f10e212ccbb9d99eeb5b812c8c1b570fc0e2232445d8b5243365cbf6dad3326fd2e86d27ef02509aad9826f3d0743f92c394533fde2f7a9391bb5cf5fab4935fe3666580fa21c0f19d461f406dc4798263641377a28d68431cf8fada4c05a1686f2088f49f9b96a4f7e057510b350a9a4752aa595e95e5b9fe5c1f1fb5744cf590f0f893cfb76fddd7633c611ce051aabbeb4a96293c1fcd901823c46e7490b0e7ff89b0cc1c89fec4ade93438b489b7fe899f867f1a2867fd8b66d2fdd38838352590e20fab5e172e24f14b9f99be2ee8390caafc21fdd346da9be1efb2180557ef3f564635fc82806689d84153b11ffc70e0763facd1b3f3430d1f6c072d07768364937f6bae6d8f384c67254d45f741dfc8d97e0bec138ec37dd257ab2f0ad5a01a492f3ad08dc880da627eba9f30d17ff89de5db998358276e8cf804068ae35c9f04c1f278d2b2e9edf37d154a357efc7b6b76a5624261667c6c1cf9ca38989b8c6b0d738b4c2ed24916b73ba422b84da73b56cde199960d66feac1ddf21efa2b06828f04cee78268fc0eac540a88b41ff1fc3853894ca466e767998b7adce271ac7d3c2a2a77874b61ad47c2bcea3ad9c825532519b66197808a77b";
char* rho_x_hex = "21d1635dd26376ac14df60f8e04dc85dbda425e553597d3c73c01c7e8f9c006484e8431bbfe8c6099bdd002127689b8b02be2977707f5b1e4c6f4325f752c43323dd8b9406eaf8fb7f5cf8d9c8611581ba13c23063e8cdedbfb8bfb4790bbf91e7d68860e7008f8e2c5d887c561699665d5eb6fc25c7af1593c6c77d87666fe864e6f953e9e8b74bf79b2eb5a6a67378242d116456a9527620d1896429281e7221f249e17c3adc6cbf3ada3a925aa27dcafbe77a6fdd687a5b24e6dfea1aba6c9bed4b351dfed1dacf993fb0cc8237a2c0223b7226c4e25c28e9eeca0627dcc7b72fd8c9f3bdb7540aa1c4aef65d5c59979ab24892166c21ba5f22ec542bbef1";

char* Y_hex = "52386a6ec9db2fa17927dd97eb50545fcc5396d83f450565b78b539200b0f1482da1575a6c36a35ec705e3aee1586b86f7f3ccad1fde63c6d4dbd519726e02eb9e89898f1d292bdfd85eabe4beea5344d3fbf811b4a00c0ea483a782a81ae0f2f3ec47726ffb66afb2ea15460febffd21fbd6ef76da96d217670eb262b7b74d2f2352fd1e3f20551c57c0f84ca6dca908ed58164e5ff52aab35f1a00f0af7b1e806aadf446aa145e680272d4f071ec2d5081171a543254477aa994dbffc68066a06558b7ccb9e48f0de89b46b085234a79fa67c48e05445dc2175ad0dadc0b79f9317befc3a8b909b348ae14ee03db1eaf9c373bd19223be92595102446737b9106b4c8132ea20a38a80f71546136674d1854ad5383d9dbb55eed87f540e619bb50834aa687acbead61c73ba72efcd410badd02655925982a27bcda621be24bf1c9d946621855dde030913ee899aef60bc4526bf6320edec7444d5351ca78bee904ad0059c50359a74a5ba281354bebc2ee43c02c1dccb038fd869ab7710854adf3b1308885a1d99d58ab637133f3ce1bcc63d0c7324b3ea09e8e1ccdb00ce9c604dee3dea94abd8532c0b74104d1df640a3bf1c2591e0cc1b5f858c98a0b9eb202adacec694a7f111b38293cea5861dcf7e8ef7b13da647ea5fa58504722f43d8f3cfee12c526771007bb9be2b9648370bdd891facd256abc8dfa8d7101a8eb";
char* rho_y_hex = "8a196c1f57c5ad3f86f6c08c061912ab39b70eeb29680eb95abe5adfbd83632191e39a335f7a5d51bc0f2a17880bb54d1b2111faecc6c8ffb1ba4a584a475457fc2c6cc1f8cd4e5b1dea69b5f67531322098f67e4c085d598e260714e161cd45004b8cd2543b7d2949a903b916a7dd1af9c6adeca5190e0d715d0e7fbfb2df94da581665d4116bffa0ff238185ad7774392a89574ea299b8e30856704707ade1909deb8c69d68e670edd17ee66bd28cbe17d2179e7f4c2b6a3089f749c0ac6243e451096d1417d801783d816098296c7bea7d48f7a59a06270b26b7aef6f3a6592d317f8d4bd05f018c942c74cdf93bf2737c1504353e48ddbe64aa9e9002166";

char* D_hex = "3649699c3fc4fcf5503ff70f6f528c295e15dcc102ef8958ac68e5dde6ac7c6bfda5b8c5d3d582f2b6277c72066c02ee6d8ec25b98eafe28f78441ffc176675929387321fe05eaade23f26edd0dfeea6de79818627e81b936e39c6498f76b50c676d2b0cae6613662ee713f4086b80bdb5c819ac1267316eb06f75af34bfa4990810ce4b7b43fb7bbbc6698edf33e1121866ebbca8b96928be2659ab99be0d219811df2a6bb4a450f2b7b5183c7899af4a9410045126d0e8db1d00f66cc5a83630269a788c416c2c6bed84f794f23d3d08086d8ee880e04385b7b894b02c5add2eddbb269a11af1331182905f40f4ec2a59d0a2b837b9447b8340096c0d021ee29cb91ccd37db37ca17f080c1796ebecc46e89cb0e7fd4adf5a2897b673fde213dd45bc58491440ccb4d112458092ae6115870d8fbba64f0b436faa55097b541b2f5c56b0cd59c6b221c56cff5445d6097ac1b829040701407427ea98ddedb4608ad01c6a3b5ed0e528655400f7762f366f07ba646562e48b96b49a583d8aa057abeee0874118616a1104ce9d6b8e9bd802c2dc0f47c488c87886c0eea583940d3e6a1ef9b7a274c23108a982e3414247eda995416d732348d15e003a18ae1512960d818b9ad97628d4871fc36205c62b6f7ed3acc4af0f15ac59b546a79a3a1718e3b76c6ec3981851cc1bbf13ae09831c9c0ea13faa77f0efe2210ab8bb042";
char* rho_hex = "f7b448b7b6ed942c7e1756dbb5e3c1bc426c6ef74184b35cb9cfd8337dd509040bbb3038594e42938e269a010cb1be849f37b6d003206d9c75eaa40da02a24c49e7ada6289ab7146aa58e2cdd7d3972e0fc64c1894645dea300a5f6b8a9efe4266377b18dab7d7cbca95b7a067950c8a267b4be07b533d563a00fe0a4ac3c61e72eddb6ed0a9d02e73493ef7e8e86ea8e68beae60e24b9f2820bdf4ea09534a9bd57c529f20740f2cb6b490dca80e614dcf31b4928523b8c2bc15cef72ad0306887e0edfbf9c6940d91e25988b598b9b1f064f1dce64c7e73d08caaca8e07280002d43731696c32855b6cbf6cd631be818ac672a5498c6ee45056395cb18818";

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
    PAILLIER_private_key paillier_priv;
    PAILLIER_public_key  paillier_pub, verifier_paillier_pub;
    PEDERSEN_PUB  pedersen_pub;
    PiAffp_COMMITS commits;
    PiAffp_SECRETS secrets;
    PiAffp_PROOFS proofs;
    PiAffp_PROOFS_OCT proofsOct;
    PiAffp_COMMITS_OCT commitsOct;
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
    PiAffp_COMMITS commits;
    PiAffp_PROOFS proofs;
    PiAffp_PROOFS_OCT proofsOct;
    PiAffp_COMMITS_OCT commitsOct;
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

    char x_[MODBYTES_256_56];
    octet x1 = {0, sizeof(x_), x_};
    prover.x = x1;

    char y_[5*MODBYTES_256_56];
    octet y1 = {0, sizeof(y_), y_};
    prover.y = y1;

    char rho_[2*FS_2048];
    octet rho1 = {0, sizeof(rho_), rho_};
    prover.rho = rho1;

    char rhox_[2*FS_2048];
    octet rho_x1 = {0, sizeof(rhox_), rhox_};
    prover.rho_x = rho_x1;

    char rhoy_[2*FS_2048];
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

    char alpha_[HFS_2048];
    octet alpha = {0, sizeof(alpha_), alpha_};

    char b0_[FS_2048];
    octet b0 = {0, sizeof(b0_), b0_};

    char ad[IDLEN];
    octet AD = {0, sizeof(ad), ad};

    char t1[2 * FS_2048];
    octet A = {0, sizeof(t1), t1};
    prover.commitsOct.A = A;

    char t2[2 * FS_2048];
    octet Bx = {0, sizeof(t2), t2};
    prover.commitsOct.Bx = Bx;

    char t3[2 * FS_2048];
    octet By = {0, sizeof(t3), t3};
    prover.commitsOct.By = By;

    char oct1[FS_2048];
    octet E = {0, sizeof(oct1), oct1};
    prover.commitsOct.E = E;

    char oct2[FS_2048];
    octet S = {0, sizeof(oct2), oct2};
    prover.commitsOct.S = S;

    char oct3[FS_2048];
    octet F = {0, sizeof(oct3), oct3};
    prover.commitsOct.F = F;

    char oct4[FS_2048];
    octet T = {0, sizeof(oct4), oct4};
    prover.commitsOct.T = T;

    char oct5[FS_2048];
    octet z1 = {0, sizeof(oct5), oct5};
    prover.proofsOct.z1 = z1;

    char oct6[FS_2048];
    octet z2 = {0, sizeof(oct6), oct6};
    prover.proofsOct.z2 = z2;

    char oct61[FS_2048+HFS_2048];
    octet z3 = {0, sizeof(oct61), oct61};
    prover.proofsOct.z3 = z3;

    char oct62[FS_2048+HFS_2048];
    octet z4 = {0, sizeof(oct62), oct62};
    prover.proofsOct.z4 = z4;

    char oct7[FS_2048];
    octet w = {0, sizeof(oct7), oct7};
    prover.proofsOct.w = w;

    char oct8[FS_2048];
    octet wx = {0, sizeof(oct8), oct8};
    prover.proofsOct.wx = wx;

    char oct9[FS_2048];
    octet wy = {0, sizeof(oct9), oct9};
    prover.proofsOct.wy = wy;


    char e[EGS_SECP256K1];
    octet E1 = {0, sizeof(e), e};
    prover.e = E1;
    verifier.e = E1;

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

    // Deterministic RNG for testing
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, IDLEN, seed);

    // Pseudorandom ID and AD
    ID.len = IDLEN;
    AD.len = IDLEN;
    OCT_rand(&ID, &RNG, ID.len);
    OCT_rand(&AD, &RNG, AD.len);

    /*
    -------------- LOAD HARD-CODED INPUTS
    (x, y, rho, rho_x, rho_y, C, D, X, Y) provided such that:
     X = (1+N1)^x * rho_x^N1 mod N1^2
     Y = (1+N1)^y * rho_y^N1 mod N1^2
     D = C^x * (1+N0)^y * rho^N0 mod N0^2
    */
    OCT_fromHex(&prover.x, pad_string(x_hex));
    OCT_fromHex(&prover.y, pad_string(y_hex));
    OCT_fromHex(&prover.rho, pad_string(rho_hex));
    OCT_fromHex(&prover.rho_x, pad_string(rho_x_hex));
    OCT_fromHex(&prover.rho_y, pad_string(rho_y_hex));
    OCT_fromHex(&prover.X, pad_string(X_hex));
    OCT_fromHex(&prover.Y, pad_string(Y_hex));
    OCT_fromHex(&prover.C, pad_string(C_hex));
    OCT_fromHex(&prover.D, pad_string(D_hex));
    verifier.X = prover.X;
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

    printf("\t\t\trho_x = ");
    OCT_output(&prover.rho_x);

    printf("\t\t\trho_y = ");
    OCT_output(&prover.rho_y);

    printf("\t\t\tX = ");
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
    OCT_fromHex(&Pb, pad_string(PT_hex));
    OCT_fromHex(&Qb, pad_string(QT_hex));
    OCT_fromHex(&alpha, pad_string(alpha_hex));
    OCT_fromHex(&b0, pad_string(b0_hex));
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
    rc = PiAffp_Sample_and_Commit(&RNG, &prover.paillier_priv, &prover.verifier_paillier_pub,
                             &prover.pedersen_pub, &prover.x, &prover.y, &prover.secrets,
                             &prover.commits, &prover.commitsOct, &prover.C);

    if (rc!=PiAffp_OK){
        printf("PiAffp_Sample_and_Commit failed!, %d", rc);
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

    printf("\n\t\trx = ");
    FF_2048_output(prover.secrets.rx, FFLEN_2048);

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
    FF_2048_output(prover.commits.Bx, 2 * FFLEN_2048);

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
    PiAffp_Challenge_gen(&prover.verifier_paillier_pub, &prover.paillier_pub,
                         &prover.pedersen_pub, &prover.X, &prover.Y, &prover.C, &prover.D,
                         &prover.commits, &ssid, &prover.e);
    printf("\n\t\tchallenge e1 = ");
    OCT_output(&prover.e);

    //-------------- PROVER PROVES THE RANGES OF x AND y
    PiAffp_Prove(&prover.paillier_pub, &prover.verifier_paillier_pub, &prover.secrets,
                 &prover.x, &prover.y, &prover.rho, &prover.rho_x, &prover.rho_y,
                 &prover.e, &prover.proofs, &prover.proofsOct);
    verifier.proofsOct = prover.proofsOct;

    // Prover - clean random values
    PiAffp_Kill_secrets(&prover.secrets);

    //-------------- VERIFIER GENERATES THE CHALLENGE
    PiAffp_commits_fromOctets(&verifier.commits, &verifier.commitsOct);
    PiAffp_proofs_fromOctets(&verifier.proofs, &verifier.proofsOct);
    PiAffp_Challenge_gen(&verifier.paillier_pub, &verifier.prover_paillier_pub,
                         &verifier.pedersen_pub, &verifier.X, &verifier.Y, &verifier.C,
                         &verifier.D, &verifier.commits, &ssid, &verifier.e);

    //-------------- VERIFIER VALIDATES THE PROOFS
    rc = PiAffp_Verify(&verifier.paillier_priv, &verifier.prover_paillier_pub, &verifier.pedersen_priv, &verifier.C, &verifier.D, &verifier.X, &verifier.Y, &verifier.commits, &verifier.e, &verifier.proofs);

    if (rc != PiAffp_OK)
        printf("\n\t\tZK Range Proofs are INVALID! rc %d\n", rc);
    else
        printf("\n\t\tZK Range Proofs are valid. rc %d", rc);
}
