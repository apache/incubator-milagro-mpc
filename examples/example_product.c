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
   Example of using MtA
 */

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

char* A1_hex = "0000000000000000000000000000000000000000000000000000000000000002";

char* B2_hex = "0000000000000000000000000000000000000000000000000000000000000003";

char* CA11_hex = "19c8b725dbd74b7dcaf72bd9ff2cd207b47cb1095393685906171af9e2f2959e7f68729e0e40f97a22bbca93373d618ad51dd077c0d102938598a8ecc8a656e978ebd14007da99db8e691d85fc18a428097ee8a63dcf95b84b660294474a20ed2edcf2b1b4f305c1cc25860a08d1348c2a4d24cc1a97b51f920e2985b8108b3392a5eafc443cf3449e288eb49dbde2228a56233afa5a6643e5ae6ec6aa8937a666ef74a30625c35bb22c3cc57b700f8eae7690f8d37edbfd27ccb2e882f70d0d85e0cc825347453a28e98e877ab1eeaa6efa09f034bc8976bffb86420106978066ff52221b315f71eb32cbf608d2b72cfa4c88e43282598f175b48ba3b5c14d72b2d90baabc00025450740ac89fc0dcd7d2f80cf12c721b6ec493c2025d7adc683b78f1d711b639a1b0dd043b9defa7ff928e257599dd95525bc8b45e1b88470311e11feb72749e5fc98f69051ddd1101b1bcc92f649681bd7ae316575444625d9d73d3684789142650951321e17f6b2f92103f36dbbd004cd66cda366e80faa4f57b71b9abb042f6cc932716fa3e6fdf50674e3d1e6d871f723d3f4f672c1270b41e7cdd5930a2572ddfc8ce370576a7a75ee6924f53122d717146c74eb6167811a2488bb899cc2da9dc2e29df66b5a03ed986fdad6ef177151ddd2698055050709c475b4ed5a2ab0be00c8b03e24193fb79f91cfd81fbcb838e45c25f8ba05";

char* R11_hex = "18c5947fda2edea04c1f87c207e0bab17aff5f77ac21d04cb194631efd1f7256dc37de9473fc86009df36206974859c09023ac8179b02aacea8d89a01f4de161db955d450cef55ce959897636973b952371e349778e67c61ef6fae5f73fd728d423a594b6a76d5faca97d59d6ae40c53f3bd42dfccc93183e355422ba7af308a87d32c0352d478156275f98bc74e9ed4f2c7a9853c9f35b996fafe765b56c7f2e83771c6b676b75436e5c1697b838b3908aee92001cbccf3bf6cfb7aaea27a358a12cfe1ddde886b975ae14517e5912eba3ff9792e46403a998edd371020bbc5fbd6a705e669383303030ef79653ce16e13122233c626bb101ee8dd27bf4ff86";

char* CB12_hex = "1f1f087e749c85aacdacaace8659a33b53baad5eec1e56628435d335a8b150f96865d6e090f53146e120e7089b6f4a91c762622b24d0d2fba0e703301170a0b826a1336d4d6bb83dccd29ad9ef0936614bf14e992ea4daa202c63ace9bd3f95b9a8a6edd7949e89ec165541e7c01bd41395baf3e2fe7f3a9611af8b5ed8639c02a2bfc236c17a136bef6d09f966db718f3df9d6f4f40b618b4b6058b4e4ec241e6c2424404d0aee0ef5cd666e5c4253a62ae9deb09289fb84657109e0b933f58871ba7ea77190d6ea45a04be68360478adf43a85851cf583c5575543578635996d2dcd020aeceabf18be6ff8b45e4ecd63c899cbfe353bc6be246aa421f54bb1f6aad797b36e435e2f33a3a049aeab894b851c5ce1076aa6e19316e3da6f539197e00e17e7a3025b53490a9d1210b900c1cac32a3bdc31d4c4866e7499a2858942e057be2840cf8ad4b1dcd914c64ac7d4b89e3f1b1a010096ecb62bb5837d9e79018870002962838bc46d7a70c23494985c300b4f8a7352a412bfc4134378d23343b3c8a77f65c234c8586e5fb0731881cb756e994c82773261f2a2321e45df45a08830e67b6c983e3f01a464b9ca6cc78ec7f170782748d114889656377e86a1e3b3c28616f3b4b73693867fefd7459fe99e9892435f0902ad74ceebac99c4f67340344f128b1f55fdb85acdc64891b77d9961653361f5264d5f1e0b67173b";

char* R12_hex = "18c5947fda2edea04c1f87c207e0bab17aff5f77ac21d04cb194631efd1f7256dc37de9473fc86009df36206974859c09023ac8179b02aacea8d89a01f4de161db955d450cef55ce959897636973b952371e349778e67c61ef6fae5f73fd728d423a594b6a76d5faca97d59d6ae40c53f3bd42dfccc93183e355422ba7af308a87d32c0352d478156275f98bc74e9ed4f2c7a9853c9f35b996fafe765b56c7f2e83771c6b676b75436e5c1697b838b3908aee92001cbccf3bf6cfb7aaea27a358a12cfe1ddde886b975ae14517e5912eba3ff9792e46403a998edd371020bbc5fbd6a705e669383303030ef79653ce16e13122233c626bb101ee8dd27bf4ff86";

char* Z12_hex = "0000000000000000000000000000000000000000000000000000000000000004";

char* BETA2_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413d";

char* ALPHA1_hex = "000000000000000000000000000000000000000000000000000000000000000a";

char* A1B2_hex = "0000000000000000000000000000000000000000000000000000000000000006";

char* N2_hex = "af5169183de9018407c5da24e23310f1caa6408e2f0a0bc0eb12d16d474cb9d36388a436cabce4ec6bc82244ef082eb84fa6319437b8b930c4ef643d36d572a9b0ac41e82cd1972c5bdca69178683d0f9c9ab91a996b52a0694a8618d1f5c0c1c57f94c1f87d0296d695c17fc5404b8b9ac725c10a1d3e49e38af4d141e943ed48d1700d826fa23fee890860d6811f417c19faca2197bbc000edc73bfe00c34e6d540912e67e3e4b921797510cafd2e28d3274937819c152e9c081e6170f803e2e5db9bc22271b923d84432a4f15f5ee3ec9164836a20969424adf8de3fa9fc5a8b95ea0488247a1026c17f5bf964d8bc606be03d2b127168b7dbc87b9a2d711";

char* G2_hex = "af5169183de9018407c5da24e23310f1caa6408e2f0a0bc0eb12d16d474cb9d36388a436cabce4ec6bc82244ef082eb84fa6319437b8b930c4ef643d36d572a9b0ac41e82cd1972c5bdca69178683d0f9c9ab91a996b52a0694a8618d1f5c0c1c57f94c1f87d0296d695c17fc5404b8b9ac725c10a1d3e49e38af4d141e943ed48d1700d826fa23fee890860d6811f417c19faca2197bbc000edc73bfe00c34e6d540912e67e3e4b921797510cafd2e28d3274937819c152e9c081e6170f803e2e5db9bc22271b923d84432a4f15f5ee3ec9164836a20969424adf8de3fa9fc5a8b95ea0488247a1026c17f5bf964d8bc606be03d2b127168b7dbc87b9a2d712";

char* L2_hex = "af5169183de9018407c5da24e23310f1caa6408e2f0a0bc0eb12d16d474cb9d36388a436cabce4ec6bc82244ef082eb84fa6319437b8b930c4ef643d36d572a9b0ac41e82cd1972c5bdca69178683d0f9c9ab91a996b52a0694a8618d1f5c0c1c57f94c1f87d0296d695c17fc5404b8b9ac725c10a1d3e49e38af4d141e943eb9f8014508a8531066b5781d870e672a6e43799eee2ec527d8c4ce1d18f498e0694a04c78ca539584454a0bde84a0e9acaa575d1e45b8af338a80606b61ee78103326b1794ea9863416c5b7c9f79064cd54e10da84bf03cfce449b9a38f5727b9d84e46d5717eba7655def6f5bea3ddec9527f8047892f8b4a1e400e4da437a24";

char* M2_hex = "5a29cdae1de7e38a7382d07f7db169a783fd24a349d2abc09bb53ca4803d361fa2cc777c7e7a00d94b67ef283a5e9a008c8bc1cd586e12b0461cc09c8c53280835a4979af3b1d03e29fecc2b6469f63ba5efad3a077f474326cb58ed66bca98ee7edf102241b13c86ef2c758d2c9db49dff1e1515e4be90f8e1f1d7630aa520223184e4e111bee754b78805a3a29693aba680aae58212b0a91238066f0cb1b4f4d46f22ebefb5bcd98213fc5a169a7e189414966deb02ace640a0c26120df02228c8cc2116953a39643585f85851e10ffbc78fdb2d67f126fff39873de41a204ed9bc88ae3d449a786a5f80d8a666b7d9ce4f7e3958183bede6741d3ae9fc8e1";

char* A2_hex = "0000000000000000000000000000000000000000000000000000000000000004";

char* B1_hex = "0000000000000000000000000000000000000000000000000000000000000005";

char* CA22_hex = "2f491b6f65767dd5a31c80c0caf50415b493d3b775515ce79afad3e8422c4befa2b56937486faaa3016226d3e6c9246363a17709a835d3d33358b4ea9393d4815244f758762595ca71b4c7940d3dd34eb1aac1c613edc3d66ddb0b9150284929a03e8f2aa00687fa03916e4578755ecfb802cac3cd4f3f233ab18e2247420af6c8b3093feb92b1f77eeed12af72c6880a28c31a656594000c67743d5d089ccde3a0aafa34f717391594dc7663e0faf405568b32c750189afd0b769fc0f9ae148c074d8ad52fd8ecc094f881563d94da8e71e9b44cde4a345e13feab9eadacf722a917ca47e0e4042d39049858052b898954bd41b44e7bc4e7baa80a738d644a8c476201a50a12af6fb8038918b992b81f69d1db0a97de313b965461f2696e6b9dbec8e94fefc4ff768cf7a600ad678de69b5458d36e17b2d3b45d7487370405a472d37ada7fbe16f4d674246215d8d4b597221e4619cfc789b1440008330b6921215722f83d2d60e2230dd84ca5231d23967ede602ec0815d49f28f8aac1949913b6b112c8f8e81e7f58621f07caa209a6a00e53a4427b36f6ac467ac4c9f0e323804797a20a57777fc51cd140a5ce8f691f9442adb9a3ab4cab34fd6828644e490332a893804daaa1e1cd989fb20b9abe9c58b08f465bbc1078715920b8f3e6d27e60dc818ea1a501a4d0bf6ec275ee585371b224ac5cd1411d37ed07616ef7";

char* R22_hex = "18c5947fda2edea04c1f87c207e0bab17aff5f77ac21d04cb194631efd1f7256dc37de9473fc86009df36206974859c09023ac8179b02aacea8d89a01f4de161db955d450cef55ce959897636973b952371e349778e67c61ef6fae5f73fd728d423a594b6a76d5faca97d59d6ae40c53f3bd42dfccc93183e355422ba7af308a87d32c0352d478156275f98bc74e9ed4f2c7a9853c9f35b996fafe765b56c7f2e83771c6b676b75436e5c1697b838b3908aee92001cbccf3bf6cfb7aaea27a358a12cfe1ddde886b975ae14517e5912eba3ff9792e46403a998edd371020bbc5fbd6a705e669383303030ef79653ce16e13122233c626bb101ee8dd27bf4ff86";

char* CB21_hex = "0f86922b01e56e662aeaa97a924740815d72672be93f9cc1a425b58bb2a8c1a7ccd67d1bb0ac2a5041603ec5cf0434fa32c15244e98f89039b2b165e9077d574fce21672dbc378b2d60a9c7086ca95ccf7bf33cfd6a7f27e2dc442ad29adc5d96986b102cd2dcf727db53705592803694bc2293f159fb3a1a2b874633d478e20af95c8ffc4b36a999b397c0e1ca0b29ec6aad5fc0e07e73c61cd7120e388bd9746120638155204be2bc532a61c2b197ab0437f179b03a1c90966299c1e8c7f7121c8c842254ec44beeac7e0eae11dc481ec44f8c9578ca06eb3dfc346c53170b18bb25174eae3f5091c22f5d784bbf99108653669855b1d649d21b990b5e3dbaa8f518377949ce445ee11b772e3075f1b6b85133c964301c29e286972178c2f9ede3e15eb9c6163b8ccad30bed128d05e794a5a69a32ce37a8d3da40d9b2ff6874e686e1e585535f55a0b6d251931bd76dc72eb605b245e0e8c44ac7d853ecb0dc6df79049143f23ed0141a469846d31df3d881a8236383aa9f4dfe5d0b65452db20ce49abcdd6410b3dab279d1c346514edeafed65039af68eb5935758bd8482eddc66800a38cde576050861d43b568780945c4ceebd5a9fa75224a4c217be72930262053f2e0ef93e39d48eac2fc98db30c90bb0966ce046c98780d5dcacb4d26870b02294094d221f52451e36f045c3cc83973e48f445e64e0cc11dd91fab";

char* R21_hex = "18c5947fda2edea04c1f87c207e0bab17aff5f77ac21d04cb194631efd1f7256dc37de9473fc86009df36206974859c09023ac8179b02aacea8d89a01f4de161db955d450cef55ce959897636973b952371e349778e67c61ef6fae5f73fd728d423a594b6a76d5faca97d59d6ae40c53f3bd42dfccc93183e355422ba7af308a87d32c0352d478156275f98bc74e9ed4f2c7a9853c9f35b996fafe765b56c7f2e83771c6b676b75436e5c1697b838b3908aee92001cbccf3bf6cfb7aaea27a358a12cfe1ddde886b975ae14517e5912eba3ff9792e46403a998edd371020bbc5fbd6a705e669383303030ef79653ce16e13122233c626bb101ee8dd27bf4ff86";

char* Z21_hex = "0000000000000000000000000000000000000000000000000000000000000004";

char* BETA1_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413d";

char* ALPHA2_hex = "0000000000000000000000000000000000000000000000000000000000000018";

char* A2B1_hex = "0000000000000000000000000000000000000000000000000000000000000014";

char* SUM1_hex = "0000000000000000000000000000000000000000000000000000000000000010";

char* SUM2_hex = "0000000000000000000000000000000000000000000000000000000000000020";

char* AB_hex = "0000000000000000000000000000000000000000000000000000000000000030";

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

    char a1[EGS_SECP256K1];
    octet A1 = {0,sizeof(a1),a1};

    char b2[EGS_SECP256K1];
    octet B2 = {0,sizeof(b2),b2};

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

    char a2[EGS_SECP256K1];
    octet A2 = {0,sizeof(a2),a2};

    char b1[EGS_SECP256K1];
    octet B1 = {0,sizeof(b1),b1};

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

    OCT_fromHex(&A1,A1_hex);
    printf("A1: ");
    OCT_output(&A1);

    OCT_fromHex(&B2,B2_hex);
    printf("B2: ");
    OCT_output(&B2);

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

    OCT_fromHex(&A2,A2_hex);
    printf("A2: ");
    OCT_output(&A2);

    OCT_fromHex(&B1,B1_hex);
    printf("B1: ");
    OCT_output(&B1);

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

    // ALPHA1 + BETA2 = A1 * B2
    rc = MPC_MTA_CLIENT1(NULL, &N1, &G1, &A1, &CA11, &R11);
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

    rc = MPC_MTA_SERVER(NULL,  &N1, &G1, &B2, &CA11, &Z12, &R12, &CB12, &BETA2);
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

    // ALPHA2 + BETA1 = A2 * B1
    rc = MPC_MTA_CLIENT1(NULL, &N2, &G2, &A2, &CA22, &R22);
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

    rc = MPC_MTA_SERVER(NULL,  &N2, &G2, &B1, &CA22, &Z21, &R21, &CB21, &BETA1);
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

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
