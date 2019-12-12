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

// Example of calculating s signature component

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <amcl/randapi.h>
#include <amcl/ecdh_SECP256K1.h>
#include <amcl/ecdh_support.h>
#include <amcl/paillier.h>
#include <amcl/mpc.h>

char* N1_hex = "59f668761d66864604a05a647ce112452830f0426d02e4141781c7431eb1845c2ed32ea93150fb3b8c17553629edc84fab77080e4200b815f338aaa58fa030a4b562f43d5f24a25d3dcb419ae75e281e37c8a1f0d2f47d733e040fcec7f45e293ef656c91d0045b6b97c64f72977c01ea85214e5847b425ea410a66b59cc2ef6d6fdf6509afe8d48eeb1335f58aaabf42799fe636a2f7653842cea779d0d1dc455c8d99b862ef5e96ae83626baf9d11aeecbf9cca683cb833ceeb09bd7e1bf7e63cf76d1d48d036cbcb05c185f08c72228ecd5ccffd9192443f007a3016249584504f7c0d483fb934365a58fbcf0df13a20d5864797245fe709abfee78a40a71";

char* G1_hex = "59f668761d66864604a05a647ce112452830f0426d02e4141781c7431eb1845c2ed32ea93150fb3b8c17553629edc84fab77080e4200b815f338aaa58fa030a4b562f43d5f24a25d3dcb419ae75e281e37c8a1f0d2f47d733e040fcec7f45e293ef656c91d0045b6b97c64f72977c01ea85214e5847b425ea410a66b59cc2ef6d6fdf6509afe8d48eeb1335f58aaabf42799fe636a2f7653842cea779d0d1dc455c8d99b862ef5e96ae83626baf9d11aeecbf9cca683cb833ceeb09bd7e1bf7e63cf76d1d48d036cbcb05c185f08c72228ecd5ccffd9192443f007a3016249584504f7c0d483fb934365a58fbcf0df13a20d5864797245fe709abfee78a40a72";

char* L1_hex = "59f668761d66864604a05a647ce112452830f0426d02e4141781c7431eb1845c2ed32ea93150fb3b8c17553629edc84fab77080e4200b815f338aaa58fa030a4b562f43d5f24a25d3dcb419ae75e281e37c8a1f0d2f47d733e040fcec7f45e293ef656c91d0045b6b97c64f72977c01ea85214e5847b425ea410a66b59cc2ef5a76c9540faee87fd45bcf109d92822af07d0771d943c69a3bc3232c573ebd9c4a6381c74a46b5d9bbe407db5c50dc37fc39de16501c4eca84f07c04511fe78d1ab5531809cf4f3706136c238df2511fc731f1bbc3be22e3efb3bef6d643a5df7ce17a93406ab8cc226c2459105cee6a3c224bc9348db96236b417f6d29a863f4";

char* M1_hex = "1ee3cbc99bde365d01286a216d15d331d82d3562fb8c53c08ed44fe45f8cc9e2d3e410b466de80dd4fb4f69e73e71232ff78e1dc7c68ce01f4d4307e05a0d4268c4fe711ae89a82bd601dbd2921db858f42ac7192ed5c37ccf35f68ab6b2bde63001f99582c34f54dfa687af2a225aa70b3fcb703ffa936ca6e4d9906cbb91f0abcb8799da2474ecdff45a7c8a5f7beee325ace997a692aee41ef423ea655747ed27f90ad330aafcc722eecc07adf5029ccf95df6e93ec773056c0e8fb2aac5d523bb0549e0d847590bb0645d662c07aef2ef3fd054c514b673516ba5aa0d2e96b04dc5bebac7727044675f94d89d990d63e118bbdf04303d566a8d5b439c77c";

char* K1_hex = "52b7fe8435a2532b79ee252e5444c6a7178757f29a7ff17176ed9098ad168883";

char* GAMMA2_hex = "2f595fbef2fa542fd1d20d07f02c7d4c50b4abb2d1f76b4952219edf59f3ccf7";

char* CA11_hex = "159a663e0aea1bcd6a9caf1a2a6d2b868459cb65081f133d510b46863d1658894cdd93c0b325252f2c681c15acbad6a30eef0a05babe6bc1d9267f3268d84387c13348afa0bce0a9795008cf1d81a39ab8483cebacf4ae9bb617bdcce3b3864a36838a88357b74ea38cad34650d0d3fea2bfdd2949ee9bd58f529b2c0b717c3ced1c9ddcfa85abeaffc78b5ed6a8dd54aef7cfb9dabaa78d0c3dbc2b58fc682a52ada4628c3c3e004f2fdc9b8f15392c6d4acaa93b6eb1f7a0807e3ce905ea58ff7ba778737c001765117367723626a82c8f3c89deed8157a13ec30adeb8eba000ca5e7a72ffa045de558a15151b514c1a3b0221ab74ff40034c1e992ae613aef9138170fb123fd5ad2afe3969b9126c37b5750a540140da3336064cfe285ae48414a997c38927408b2f61c33fbad461352cc231254c4142168c09b1b876d362a3683b9fc81440fb9075d32657cc38bf6128dd9fdcb4206c9d37bf0c92d1014a3464f4a2b4906fcdc3e33c812a30fbcbfc93a43f04ee2eae6e46af91332ec8281723a45ea0b571326df7e1172c87652494e2db26d262d741c8b541009c174d39054dcda218739a083a1cc089cf5f06cb985a145d0ef32813887d3e46c16203f98aff92d2cf2e392d767c16b0211047548ed8f5d8eb161c9729a424964c7cffc9927c4974658e9388a0f137a1f81ad88a3d07ab119736e35b040a945d9b4e5730";

char* R11_hex = "980dcee14556e2c40472c3544d46a6e34652ff1a4d9f99fdd7e8823aa39e332050431361bf618e5cfd248cd3ff3f03a32f8021eaf0d0b6d34bc3506f99e86a21dcc8237f66cd7d7aab0a1aad359da6580ea51b5c722d548e340617d512945c105a7a01756ffbcce91611bb8e3be4e36c24aa2c356fa7370515e359b5fd1075aa8628e07fcdb205e510dc1d464ced3805fd834d1ab82cd9086a5fe92bebef8900d5ca7269c9da58d732b7dda821c35cca5ce0a31c1ddb3f3d0b62e1117cd00bb54c3c03fd533a4d0148852703f83293def0f5c42a68b6deab4762ca6a7c448cbcf8a5156450d5441f961121f0220cae9af7844f9923fa4be52b3abbf3100a9dee";

char* CB12_hex = "1d7a81d4c53465b04668d95e16c75382fefa7942b7142c2758c9f386d6611151b9740d2c3402c3637c89a49b4166c5c16448f04bd1a6c06558e96bccabd322d6990e03ce0c0d78228af32ec185c281a1eae026d332690b49e5182db4a70df419cb57bdf29055e6242d3ba49e494ab60690c314aa0f1e4b4683344fed6080464733afe19e65565f569be80343b23b7d22e7ab157c311ed601e03ac480b0a6d1eacea71ecc1f6290a7ecd3b3b7de1b50174c5ca9f9d27e2c8fd5017ff72e9e4ca44725cecd2ee6ced380655d0e9febdee53c61a25322a217ad61b1486600791d3952dbf3f33cb762ce04a3653e82f4dd7d150f34d2d851705983ee064f556fedbd444dcf26fb33361c7565d79cc2a937a0d5e3df6f96691df6d7c2d03860c1688a7d481a23b1595b9de8ee87ea92ff54db673b16491ddd93c4aaf466437df591009171e301813851de05625093d0e75fccd5c31482243893c8a86a3ea8405ab06ebbb82ff3904e07a1a8e28f23f55cba1ce8dd40e4af7d070af859f619a8ac14d6b1ce22a44752b467384d1652d98d5b8d65b7108187761154b302aa47d6ae88754f4033289f62911b99518ecc7435005fdaa52e265d21a0e58f6a5d8420bc317876fe2dc2c21f8d22fb72622a943600b277b66630319891be1cdd64ce4d40b57d9dde40d2638d5debe2ceb23c4758a9e78e27bb1073c469f4caea94044bee74a0";

char* R12_hex = "8a0a6634ed02a76e647cb5a44636c4960e961cd3e11a1b32b42e51418e5738fe67aa182e617968c0a811bc5fe96623070d4e853c567710f468f5698610cc2cd1cccdad807e0011d607e7617977a5468ccd0a7a514ee60d7910297dfc17fe2b42a623eed640416e0cb9ed67ce9b79cf33174037a5e5a7bab4b367bf9ae62a5e2f6b6d51247fd2c39ea97f21afa2f010123486f8f26f3df92d59588ea8cebf617cd1e8fc2f7206f44eafdadde28e44aa27744bcef25b075451e930a1e1377943805b90780506bd7e86092e47fa892bd252f7eba090642501e28148540047d2f264a0b4855f48ab43ca4f75d728ba19585da77d7dcb402f5f3d040b8718faa0f361";

char* Z12_hex = "0207c724d58036400bcb7d99286aeb835745711fcf18c124fedb14bb252870bc";

char* BETA2_hex = "fdf838db2a7fc9bff4348266d795147b63696bc6e02fdf16c0f749d1ab0dd085";

char* ALPHA1_hex = "a43803ffcc7aa295dff0ede560973c151ef9f9c8160500bbcda7e18d0c2eac03";

char* A1B2_hex = "a2303cdaf6fa6c55d425704c382c5091c7b488a846ec3f96ceccccd1e7063b47";

char* N2_hex = "af5169183de9018407c5da24e23310f1caa6408e2f0a0bc0eb12d16d474cb9d36388a436cabce4ec6bc82244ef082eb84fa6319437b8b930c4ef643d36d572a9b0ac41e82cd1972c5bdca69178683d0f9c9ab91a996b52a0694a8618d1f5c0c1c57f94c1f87d0296d695c17fc5404b8b9ac725c10a1d3e49e38af4d141e943ed48d1700d826fa23fee890860d6811f417c19faca2197bbc000edc73bfe00c34e6d540912e67e3e4b921797510cafd2e28d3274937819c152e9c081e6170f803e2e5db9bc22271b923d84432a4f15f5ee3ec9164836a20969424adf8de3fa9fc5a8b95ea0488247a1026c17f5bf964d8bc606be03d2b127168b7dbc87b9a2d711";

char* G2_hex = "af5169183de9018407c5da24e23310f1caa6408e2f0a0bc0eb12d16d474cb9d36388a436cabce4ec6bc82244ef082eb84fa6319437b8b930c4ef643d36d572a9b0ac41e82cd1972c5bdca69178683d0f9c9ab91a996b52a0694a8618d1f5c0c1c57f94c1f87d0296d695c17fc5404b8b9ac725c10a1d3e49e38af4d141e943ed48d1700d826fa23fee890860d6811f417c19faca2197bbc000edc73bfe00c34e6d540912e67e3e4b921797510cafd2e28d3274937819c152e9c081e6170f803e2e5db9bc22271b923d84432a4f15f5ee3ec9164836a20969424adf8de3fa9fc5a8b95ea0488247a1026c17f5bf964d8bc606be03d2b127168b7dbc87b9a2d712";

char* L2_hex = "af5169183de9018407c5da24e23310f1caa6408e2f0a0bc0eb12d16d474cb9d36388a436cabce4ec6bc82244ef082eb84fa6319437b8b930c4ef643d36d572a9b0ac41e82cd1972c5bdca69178683d0f9c9ab91a996b52a0694a8618d1f5c0c1c57f94c1f87d0296d695c17fc5404b8b9ac725c10a1d3e49e38af4d141e943eb9f8014508a8531066b5781d870e672a6e43799eee2ec527d8c4ce1d18f498e0694a04c78ca539584454a0bde84a0e9acaa575d1e45b8af338a80606b61ee78103326b1794ea9863416c5b7c9f79064cd54e10da84bf03cfce449b9a38f5727b9d84e46d5717eba7655def6f5bea3ddec9527f8047892f8b4a1e400e4da437a24";

char* M2_hex = "5a29cdae1de7e38a7382d07f7db169a783fd24a349d2abc09bb53ca4803d361fa2cc777c7e7a00d94b67ef283a5e9a008c8bc1cd586e12b0461cc09c8c53280835a4979af3b1d03e29fecc2b6469f63ba5efad3a077f474326cb58ed66bca98ee7edf102241b13c86ef2c758d2c9db49dff1e1515e4be90f8e1f1d7630aa520223184e4e111bee754b78805a3a29693aba680aae58212b0a91238066f0cb1b4f4d46f22ebefb5bcd98213fc5a169a7e189414966deb02ace640a0c26120df02228c8cc2116953a39643585f85851e10ffbc78fdb2d67f126fff39873de41a204ed9bc88ae3d449a786a5f80d8a666b7d9ce4f7e3958183bede6741d3ae9fc8e1";

char* K2_hex = "6f6aa64cdf2f28bb081ec019b3a8e2eed89052441626172daf106f523b0b44cc";

char* GAMMA1_hex = "0f757744e20d00dce6763b71ecb95f9fa9d4e788cfb9e39775d133e5e350ea93";

char* CA22_hex = "3192b9daade647a4d17b5e2e0f08e6e3d0666fac576ff8e20be4a1072b23e0202195cb9738bf7d4f5784577d23071bec7c326b6ddf25bb2f4a415cb5a95b89c5a42d4d31a740f72576d798746d30078e15ba1a91d1687563bee2af7b4eceac2f0f13184df619a5ecde5caf9e88b123438afe73d4cc9c2c50ffde42f713cd9384b5cba6cda395d03383e7f8335ac61852fd18ea7012480c49aafc27f035045303f46d0a40fe4e7fce17facbc16e55a418c18256bb30216613a2590edcc0fbe1b18d0f6507273def2e2b740b04a880648d9dc5a5225884fc07bcdaec34d91b6f84ada7c274ba960f316c04765d0e4abab76f15801dce47381d69ed3205c0398d04a71637220420f708b591af0669d35c586d888c90f8ad82e5c421e2b0474c6dca65dd70f128398489e39f886f1de11b8537ba7d3c9653a21371f90df104d6000ac1e232b07e838204767dcfdf7088e1dbbc9d9b315876ecf9fda14c5ea85bf6a63ee7b8884fd23361350574c89cbc11439648a97ae74b6da2a08763926015628909b9ca8def2734df5ec720caafa274abff2dcb29a310911ebd6ccfab67c4f98aa5b2a48e7e76443a5deb3ab4fd57df9847a19c004d0529e25d0a78f5d732c90aa68025ab7885c23ac5268794c6325398e0f63511a24b90f6e09476d37aecb64cd98c2b780e0b32810341cc892fccccdc8a1396a5d3019eafb163190f63807868";

char* R22_hex = "8a0a6634ed02a76e647cb5a44636c4960e961cd3e11a1b32b42e51418e5738fe67aa182e617968c0a811bc5fe96623070d4e853c567710f468f5698610cc2cd1cccdad807e0011d607e7617977a5468ccd0a7a514ee60d7910297dfc17fe2b42a623eed640416e0cb9ed67ce9b79cf33174037a5e5a7bab4b367bf9ae62a5e2f6b6d51247fd2c39ea97f21afa2f010123486f8f26f3df92d59588ea8cebf617cd1e8fc2f7206f44eafdadde28e44aa27744bcef25b075451e930a1e1377943805b90780506bd7e86092e47fa892bd252f7eba090642501e28148540047d2f264a0b4855f48ab43ca4f75d728ba19585da77d7dcb402f5f3d040b8718faa0f361";

char* CB21_hex = "17b2dfb8b37675e4551f557c807a5f94950a0902b8627bb7840c37a054070da1028089b822e55df859dd2d95cd790691e2c27c08603d17bbb016fa159023776651befd64bc7e28bcdfcbeaf6b524fdaf8787217764b4d9385c922c76fd54118fbc7a897a7fc3288c813302f91424b7671b223aa9958f42dbc3dd3b600b57aa76998c68ef668af138bce9332d2983cffb25add049fc4a1be85410bcd17c9ba001c817a2a03802b85d7583a386650ea65fcbf243d8e5a66f2e79afbfaa2e42abcf8200f8f74a9aed2628bdb5c3dd3dcfe3a3f2f4dc7c23a12981e9637c5237c826bd445a3265b775e3c8d0e738f7e1a23fe3051ec5d992b915e6c0edc27f0138d6c42a0c872076b37c67ff9928e00e94887868d46003c29bbd406211b162b7e8ed33dd9967543c2698a2e1224e0441ed2ea25877a34d55172209275a3684308e3330987a6a501aac9bbd374e8d7637b0e7bbb2209782b32dc99e2debe9a1ab9956a4bcfd0da856593de4fdb1cf94059afe2e440ddbd499e92b386629e695577e28366052f19a33da1d4e14260f2f14c14fffbf6cae8e378abf8918d842a3d41110c1d1a033c3c12682a6a25de1f52d7ea9295ce483846b125998dc1c9790c4f4bf2ca1483eb7b807ca202cd928dfc14e71cbfd470dbe41d983330adbe95439b9770a0d1f3aed89b4ef1a50d02c7e60f671b3358d06548826cf7b78efb9f671edbd";

char* R21_hex = "980dcee14556e2c40472c3544d46a6e34652ff1a4d9f99fdd7e8823aa39e332050431361bf618e5cfd248cd3ff3f03a32f8021eaf0d0b6d34bc3506f99e86a21dcc8237f66cd7d7aab0a1aad359da6580ea51b5c722d548e340617d512945c105a7a01756ffbcce91611bb8e3be4e36c24aa2c356fa7370515e359b5fd1075aa8628e07fcdb205e510dc1d464ced3805fd834d1ab82cd9086a5fe92bebef8900d5ca7269c9da58d732b7dda821c35cca5ce0a31c1ddb3f3d0b62e1117cd00bb54c3c03fd533a4d0148852703f83293def0f5c42a68b6deab4762ca6a7c448cbcf8a5156450d5441f961121f0220cae9af7844f9923fa4be52b3abbf3100a9dee";

char* Z21_hex = "101c7abf2665c3f311a11c988798476216b28d576657fe0e7795e7024086051a";

char* BETA1_hex = "efe38540d99a3c0cee5ee3677867b89ca3fc4f8f48f0a22d483c778a8fb03c27";

char* ALPHA2_hex = "945a07ddc50b23d9421aca78b7192d5647856a7e9c3cf951f149d3431273b5ff";

char* A2B1_hex = "843d8d1e9ea55fe63079ade02f80e5f430d2dd2735e4fb4379b3ec40d1edb0e5";

char* SUM1_hex = "7d8436ceb1b37b1eb9829968350c721c70f3aa2eeee57c35442dc41c9a519abe";

char* SUM2_hex = "c2cce80b56c443c5ead466b586e67bf490214bba39a3f484327d7d1de9bbc6d8";

char* KGAMME_hex = "40511eda0877bee4a457001dbbf2ee12466619027940d07db6d8e2adb3d72055";

char* INVKGAMMA_hex = "f9419b11580cdc098cbcbfd3ac06e70d2d4827447353f64bd97daa5667b34ef9";

char* GAMMAPT1_hex = "04206b7c7ae7ecf8fe79ac581d8de90b9a12a27f79732268649fb0ae109faade73385833cafe293b42e33097a79397c77c94a7d12a32304514a890a0c2d747a40d";

char* GAMMAPT2_hex = "04fc86f69384e2b0cc3d563dc24ebb3a7ca0ac12dfa671e4cda4abdec35f33ed326fdc2404c8e236d5bea82bcbe4aeeb7545c8b5d0a19a39e00bacf8a7143800a9";

char* SUMGAMMAPT_hex = "04b46da316359aead5e06c983407b199465bad193dc661334aafb1d7d94bafe721e671defdf3eedef2b6f298f7cdc673a740e88dbb313f2afdb294ee6527e325c1";

char* RPT_hex = "048adf50a4f51443cac2b4d488092ab49925da09e3feb57a1fc03b5b917ca6de9fdefc78277d8cb4865e3e4b17c2821017316d9b21e648e733a207aee22ec91b3c";

char* SIG_R_hex = "8adf50a4f51443cac2b4d488092ab49925da09e3feb57a1fc03b5b917ca6de9f";



int main()
{
    int rc;

    char n1[FS_2048] = {0};
    octet N1 = {0,sizeof(n1),n1};

    char g1[FS_2048];
    octet G1 = {0,sizeof(g1),g1};

    char l1[FS_2048] = {0};
    octet L1 = {0,sizeof(l1),l1};

    char m1[FS_2048] = {0};
    octet M1 = {0,sizeof(m1),m1};

    char k1[EGS_SECP256K1];
    octet K1 = {0,sizeof(k1),k1};

    char gamma2[EGS_SECP256K1];
    octet GAMMA2 = {0,sizeof(gamma2),gamma2};

    char ca11[FS_4096];
    octet CA11 = {0,sizeof(ca11),ca11};

    char ca11golden[FS_4096];
    octet CA11GOLDEN = {0,sizeof(ca11golden),ca11golden};

    char r11[FS_2048];
    octet R11 = {0,sizeof(r11),r11};

    char cb12[FS_4096];
    octet CB12 = {0,sizeof(cb12),cb12};

    char cb12golden[FS_4096];
    octet CB12GOLDEN = {0,sizeof(cb12golden),cb12golden};

    char r12[FS_2048];
    octet R12 = {0,sizeof(r12),r12};

    char z12[EGS_SECP256K1];
    octet Z12 = {0,sizeof(z12),z12};

    char beta2[EGS_SECP256K1];
    octet BETA2 = {0,sizeof(beta2),beta2};

    char beta2golden[EGS_SECP256K1];
    octet BETA2GOLDEN = {0,sizeof(beta2golden),beta2golden};

    char alpha1[EGS_SECP256K1];
    octet ALPHA1 = {0,sizeof(alpha1),alpha1};

    char alpha1golden[EGS_SECP256K1];
    octet ALPHA1GOLDEN = {0,sizeof(alpha1golden),alpha1golden};

    char n2[FS_2048] = {0};
    octet N2 = {0,sizeof(n2),n2};

    char g2[FS_2048];
    octet G2 = {0,sizeof(g2),g2};

    char l2[FS_2048] = {0};
    octet L2 = {0,sizeof(l2),l2};

    char m2[FS_2048] = {0};
    octet M2 = {0,sizeof(m2),m2};

    char k2[EGS_SECP256K1];
    octet K2 = {0,sizeof(k2),k2};

    char gamma1[EGS_SECP256K1];
    octet GAMMA1 = {0,sizeof(gamma1),gamma1};

    char ca22[FS_4096];
    octet CA22 = {0,sizeof(ca22),ca22};

    char ca22golden[FS_4096];
    octet CA22GOLDEN = {0,sizeof(ca22golden),ca22golden};

    char r22[FS_2048];
    octet R22 = {0,sizeof(r22),r22};

    char cb21[FS_4096];
    octet CB21 = {0,sizeof(cb21),cb21};

    char cb21golden[FS_4096];
    octet CB21GOLDEN = {0,sizeof(cb21golden),cb21golden};

    char r21[FS_2048];
    octet R21 = {0,sizeof(r21),r21};

    char z21[EGS_SECP256K1];
    octet Z21 = {0,sizeof(z21),z21};

    char beta1[EGS_SECP256K1];
    octet BETA1 = {0,sizeof(beta1),beta1};

    char beta1golden[EGS_SECP256K1];
    octet BETA1GOLDEN = {0,sizeof(beta1golden),beta1golden};

    char alpha2[EGS_SECP256K1];
    octet ALPHA2 = {0,sizeof(alpha2),alpha2};

    char alpha2golden[EGS_SECP256K1];
    octet ALPHA2GOLDEN = {0,sizeof(alpha2golden),alpha2golden};

    char sum1[EGS_SECP256K1];
    octet SUM1 = {0,sizeof(sum1),sum1};

    char sum1golden[EGS_SECP256K1];
    octet SUM1GOLDEN = {0,sizeof(sum1golden),sum1golden};

    char sum2[EGS_SECP256K1];
    octet SUM2 = {0,sizeof(sum2),sum2};

    char sum2golden[EGS_SECP256K1];
    octet SUM2GOLDEN = {0,sizeof(sum2golden),sum2golden};

    char invkgamma[EGS_SECP256K1];
    octet INVKGAMMA = {0,sizeof(invkgamma),invkgamma};

    char invkgammagolden[EGS_SECP256K1];
    octet INVKGAMMAGOLDEN = {0,sizeof(invkgammagolden),invkgammagolden};

    char gammapt1[2*EFS_SECP256K1+1];
    octet GAMMAPT1 = {0,sizeof(gammapt1),gammapt1};

    char gammapt2[2*EFS_SECP256K1+1];
    octet GAMMAPT2 = {0,sizeof(gammapt2),gammapt2};

    char sig_rgolden[EGS_SECP256K1];
    octet SIG_RGOLDEN = {0,sizeof(sig_rgolden),sig_rgolden};

    char sig_r[EGS_SECP256K1];
    octet SIG_R = {0,sizeof(sig_r),sig_r};

    // Load values
    OCT_fromHex(&N1,N1_hex);
    printf("N1: ");
    OCT_output(&N1);

    OCT_fromHex(&G1,G1_hex);
    printf("G1: ");
    OCT_output(&G1);

    OCT_fromHex(&L1,L1_hex);
    printf("L1: ");
    OCT_output(&L1);

    OCT_fromHex(&M1,M1_hex);
    printf("M1: ");
    OCT_output(&M1);

    OCT_fromHex(&K1,K1_hex);
    printf("K1: ");
    OCT_output(&K1);

    OCT_fromHex(&GAMMA2,GAMMA2_hex);
    printf("GAMMA2: ");
    OCT_output(&GAMMA2);

    OCT_fromHex(&CA11GOLDEN,CA11_hex);
    printf("CA11GOLDEN: ");
    OCT_output(&CA11GOLDEN);

    OCT_fromHex(&R11,R11_hex);
    printf("R11: ");
    OCT_output(&R11);

    OCT_fromHex(&CB12GOLDEN,CB12_hex);
    printf("CB12GOLDEN: ");
    OCT_output(&CB12GOLDEN);

    OCT_fromHex(&R12,R12_hex);
    printf("R12: ");
    OCT_output(&R12);

    OCT_fromHex(&Z12,Z12_hex);
    printf("Z12: ");
    OCT_output(&Z12);

    OCT_fromHex(&BETA2GOLDEN,BETA2_hex);
    printf("BETA2GOLDEN: ");
    OCT_output(&BETA2GOLDEN);

    OCT_fromHex(&ALPHA1GOLDEN,ALPHA1_hex);
    printf("ALPHA1GOLDEN: ");
    OCT_output(&ALPHA1GOLDEN);

    OCT_fromHex(&N2,N2_hex);
    printf("N2: ");
    OCT_output(&N2);

    OCT_fromHex(&G2,G2_hex);
    printf("G2: ");
    OCT_output(&G2);

    OCT_fromHex(&L2,L2_hex);
    printf("L2: ");
    OCT_output(&L2);

    OCT_fromHex(&M2,M2_hex);
    printf("M2: ");
    OCT_output(&M2);

    OCT_fromHex(&K2,K2_hex);
    printf("K2: ");
    OCT_output(&K2);

    OCT_fromHex(&GAMMA1,GAMMA1_hex);
    printf("GAMMA1: ");
    OCT_output(&GAMMA1);

    OCT_fromHex(&CA22GOLDEN,CA22_hex);
    printf("CA22GOLDEN: ");
    OCT_output(&CA22GOLDEN);

    OCT_fromHex(&R22,R22_hex);
    printf("R22: ");
    OCT_output(&R22);

    OCT_fromHex(&CB21GOLDEN,CB21_hex);
    printf("CB21GOLDEN: ");
    OCT_output(&CB21GOLDEN);

    OCT_fromHex(&R21,R21_hex);
    printf("R21: ");
    OCT_output(&R21);

    OCT_fromHex(&Z21,Z21_hex);
    printf("Z21: ");
    OCT_output(&Z21);

    OCT_fromHex(&BETA1GOLDEN,BETA1_hex);
    printf("BETA1GOLDEN: ");
    OCT_output(&BETA1GOLDEN);

    OCT_fromHex(&ALPHA2GOLDEN,ALPHA2_hex);
    printf("ALPHA2GOLDEN: ");
    OCT_output(&ALPHA2GOLDEN);

    OCT_fromHex(&SUM1GOLDEN,SUM1_hex);
    printf("SUM1GOLDEN: ");
    OCT_output(&SUM1GOLDEN);

    OCT_fromHex(&SUM2GOLDEN,SUM2_hex);
    printf("SUM2GOLDEN: ");
    OCT_output(&SUM2GOLDEN);

    OCT_fromHex(&INVKGAMMAGOLDEN,INVKGAMMA_hex);
    printf("INVKGAMMAGOLDEN: ");
    OCT_output(&INVKGAMMAGOLDEN);

    OCT_fromHex(&GAMMAPT1,GAMMAPT1_hex);
    printf("GAMMAPT1: ");
    OCT_output(&GAMMAPT1);

    OCT_fromHex(&GAMMAPT2,GAMMAPT2_hex);
    printf("GAMMAPT2: ");
    OCT_output(&GAMMAPT2);

    OCT_fromHex(&SIG_RGOLDEN,SIG_R_hex);
    printf("SIG_RGOLDEN: ");
    OCT_output(&SIG_RGOLDEN);

    // ALPHA1 + BETA2 = K1 * GAMMA2
    rc = MPC_MTA_CLIENT1(NULL, &N1, &G1, &K1, &CA11, &R11);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_MTA_CLIENT1 rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("CA11: ");
    OCT_output(&CA11);
    printf("\n");

    rc = OCT_comp(&CA11GOLDEN,&CA11);
    if(!rc)
    {
        fprintf(stderr, "FAILURE CA11 != CA11GOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    rc = MPC_MTA_SERVER(NULL,  &N1, &G1, &GAMMA2, &CA11, &Z12, &R12, &CB12, &BETA2);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_MTA_SERVER rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("CB12: ");
    OCT_output(&CB12);
    printf("\n");

    printf("BETA2: ");
    OCT_output(&BETA2);
    printf("\n");

    rc = OCT_comp(&CB12GOLDEN,&CB12);
    if(!rc)
    {
        fprintf(stderr, "FAILURE CB12 != CB12GOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    rc = OCT_comp(&BETA2GOLDEN,&BETA2);
    if(!rc)
    {
        fprintf(stderr, "FAILURE BETA2 != BETA2GOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    rc = MPC_MTA_CLIENT2(&N1, &L1, &M1, &CB12, &ALPHA1);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_MTA_CLIENT2 rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("ALPHA1: ");
    OCT_output(&ALPHA1);
    printf("\n");

    rc = OCT_comp(&ALPHA1,&ALPHA1GOLDEN);
    if(!rc)
    {
        fprintf(stderr, "FAILURE ALPHA1 != ALPHA1GOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    // ALPHA2 + BETA1 = K2 * GAMMA1
    rc = MPC_MTA_CLIENT1(NULL, &N2, &G2, &K2, &CA22, &R22);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_MTA_CLIENT1 rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("CA22: ");
    OCT_output(&CA22);
    printf("\n");

    rc = OCT_comp(&CA22GOLDEN,&CA22);
    if(!rc)
    {
        fprintf(stderr, "FAILURE CA22 != CA22GOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    rc = MPC_MTA_SERVER(NULL,  &N2, &G2, &GAMMA1, &CA22, &Z21, &R21, &CB21, &BETA1);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_MTA_SERVER rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("CB21: ");
    OCT_output(&CB21);
    printf("\n");

    printf("BETA1: ");
    OCT_output(&BETA1);
    printf("\n");

    rc = OCT_comp(&CB21GOLDEN,&CB21);
    if(!rc)
    {
        fprintf(stderr, "FAILURE CB21 != CB21GOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    rc = OCT_comp(&BETA1GOLDEN,&BETA1);
    if(!rc)
    {
        fprintf(stderr, "FAILURE BETA1 != BETA1GOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }


    rc = MPC_MTA_CLIENT2(&N2, &L2, &M2, &CB21, &ALPHA2);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_MTA_CLIENT2 rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("ALPHA2: ");
    OCT_output(&ALPHA2);
    printf("\n");

    rc = OCT_comp(&ALPHA2,&ALPHA2GOLDEN);
    if(!rc)
    {
        fprintf(stderr, "FAILURE ALPHA2 != ALPHA2GOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    // sum = K1.GAMMA1 + alpha1  + beta1
    rc = MPC_SUM_MTA(&K1, &GAMMA1, &ALPHA1, &BETA1, NULL, NULL, &SUM1);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_SUM_MTA rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("SUM1: ");
    OCT_output(&SUM1);
    printf("\n");

    rc = OCT_comp(&SUM1,&SUM1GOLDEN);
    if(!rc)
    {
        fprintf(stderr, "FAILURE SUM1 != SUM1GOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    // sum = K2.GAMMA2 + alpha2  + beta2
    rc = MPC_SUM_MTA(&K2, &GAMMA2, &ALPHA2, &BETA2, NULL, NULL, &SUM2);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_SUM_MTA rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("SUM2: ");
    OCT_output(&SUM2);
    printf("\n");

    rc = OCT_comp(&SUM2,&SUM2GOLDEN);
    if(!rc)
    {
        fprintf(stderr, "FAILURE SUM2 != SUM2GOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    // Calculate the inverse of kgamma
    rc = MPC_INVKGAMMA(&SUM1, &SUM2, NULL, &INVKGAMMA);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_INVKGAMMA rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("INVKGAMMA: ");
    OCT_output(&INVKGAMMA);
    printf("\n");

    rc = OCT_comp(&INVKGAMMA,&INVKGAMMAGOLDEN);
    if(!rc)
    {
        fprintf(stderr, "FAILURE INVKGAMMA != INVKGAMMAGOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    // Calculate the R signature component
    rc = MPC_R(&INVKGAMMA, &GAMMAPT1, &GAMMAPT2, NULL, &SIG_R);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_R rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("SIG_R: ");
    OCT_output(&SIG_R);
    printf("\n");

    rc = OCT_comp(&SIG_R,&SIG_RGOLDEN);
    if(!rc)
    {
        fprintf(stderr, "FAILURE SIG_R != SIG_RGOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
