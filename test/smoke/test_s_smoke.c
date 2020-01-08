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

// Calculation of S smoke test

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

char* W2_hex = "0aec8feb32fd8bbb4526b6d5af6681519e195874ada7474255c89926efe53291";

char* CA11_hex = "159a663e0aea1bcd6a9caf1a2a6d2b868459cb65081f133d510b46863d1658894cdd93c0b325252f2c681c15acbad6a30eef0a05babe6bc1d9267f3268d84387c13348afa0bce0a9795008cf1d81a39ab8483cebacf4ae9bb617bdcce3b3864a36838a88357b74ea38cad34650d0d3fea2bfdd2949ee9bd58f529b2c0b717c3ced1c9ddcfa85abeaffc78b5ed6a8dd54aef7cfb9dabaa78d0c3dbc2b58fc682a52ada4628c3c3e004f2fdc9b8f15392c6d4acaa93b6eb1f7a0807e3ce905ea58ff7ba778737c001765117367723626a82c8f3c89deed8157a13ec30adeb8eba000ca5e7a72ffa045de558a15151b514c1a3b0221ab74ff40034c1e992ae613aef9138170fb123fd5ad2afe3969b9126c37b5750a540140da3336064cfe285ae48414a997c38927408b2f61c33fbad461352cc231254c4142168c09b1b876d362a3683b9fc81440fb9075d32657cc38bf6128dd9fdcb4206c9d37bf0c92d1014a3464f4a2b4906fcdc3e33c812a30fbcbfc93a43f04ee2eae6e46af91332ec8281723a45ea0b571326df7e1172c87652494e2db26d262d741c8b541009c174d39054dcda218739a083a1cc089cf5f06cb985a145d0ef32813887d3e46c16203f98aff92d2cf2e392d767c16b0211047548ed8f5d8eb161c9729a424964c7cffc9927c4974658e9388a0f137a1f81ad88a3d07ab119736e35b040a945d9b4e5730";

char* R11_hex = "980dcee14556e2c40472c3544d46a6e34652ff1a4d9f99fdd7e8823aa39e332050431361bf618e5cfd248cd3ff3f03a32f8021eaf0d0b6d34bc3506f99e86a21dcc8237f66cd7d7aab0a1aad359da6580ea51b5c722d548e340617d512945c105a7a01756ffbcce91611bb8e3be4e36c24aa2c356fa7370515e359b5fd1075aa8628e07fcdb205e510dc1d464ced3805fd834d1ab82cd9086a5fe92bebef8900d5ca7269c9da58d732b7dda821c35cca5ce0a31c1ddb3f3d0b62e1117cd00bb54c3c03fd533a4d0148852703f83293def0f5c42a68b6deab4762ca6a7c448cbcf8a5156450d5441f961121f0220cae9af7844f9923fa4be52b3abbf3100a9dee";

char* CB12_hex = "09c9e0fe1ba09663cafa368daa6b404df6e719646a7d4ade95909e7513086cc947e3d5dfc14e22d3cdf842df917617e6a79997b5cca3c0d45894e3d6aeef854d8c10ed5abaeb40c9e35142cb4acdbcbfc51e72d259cb5a26efe77626ba21922d6a09897c8ac3eb080de36f7b622f09c4d70a6315bbed69fff3aa7406358f6c588cd01fc1c5abf9899e76ed8da9fda4d323687d9746ff35e46cc64947b25f25f6d9ae9365cb8a019d508ef76f02673a6dee9376a8ac2aef9c1045966e856e5e08de3f93aeb7ea1fa2fe9adf2587ea5e12f245cb30859293c36eb27e41c35db18df8743fd14f76e581c518add32194161896ef43fa53d8430add75059358f7a6fb27f068165a7de58dbc263da92cc4d69120a87c12a3ad5b6440de9086bf6905fb930c9a7f697740c10ba8745178e8e584987b2b909611d9504572ca3dcd3cf5305f9da73024b45365467d2f1a69dee7daba9ccc08ce2f37eb2c477874d14c950aa8c8fa6a62c743df0b1c8d090b680db11435ed5c1c2f601e50d2a21f78a250d9436f6317e8a7bf83023742cc53f8fef27c878dd6faf4d10a0a511c54ea4c0167ec28039d290b7192f34ddf5a09c199c777bd888280158e3a0f74d16eca7447fe76eeeddbfb0c2041085527b390678d489fdcc9951cf383807fe516149652e6aaeb9166d07635cfc1da17f4c7fe1edbc55b292eb1a34b434e84bdcf07c2e6601f";

char* R12_hex = "8a0a6634ed02a76e647cb5a44636c4960e961cd3e11a1b32b42e51418e5738fe67aa182e617968c0a811bc5fe96623070d4e853c567710f468f5698610cc2cd1cccdad807e0011d607e7617977a5468ccd0a7a514ee60d7910297dfc17fe2b42a623eed640416e0cb9ed67ce9b79cf33174037a5e5a7bab4b367bf9ae62a5e2f6b6d51247fd2c39ea97f21afa2f010123486f8f26f3df92d59588ea8cebf617cd1e8fc2f7206f44eafdadde28e44aa27744bcef25b075451e930a1e1377943805b90780506bd7e86092e47fa892bd252f7eba090642501e28148540047d2f264a0b4855f48ab43ca4f75d728ba19585da77d7dcb402f5f3d040b8718faa0f361";

char* Z12_hex = "0207c724d58036400bcb7d99286aeb835745711fcf18c124fedb14bb252870bc";

char* BETA2_hex = "fdf838db2a7fc9bff4348266d795147b63696bc6e02fdf16c0f749d1ab0dd085";

char* ALPHA1_hex = "a0e312daab26f391796f16c358dba05ca8da9dad5ecaeccbb0433a95049bd390";

char* N2_hex = "af5169183de9018407c5da24e23310f1caa6408e2f0a0bc0eb12d16d474cb9d36388a436cabce4ec6bc82244ef082eb84fa6319437b8b930c4ef643d36d572a9b0ac41e82cd1972c5bdca69178683d0f9c9ab91a996b52a0694a8618d1f5c0c1c57f94c1f87d0296d695c17fc5404b8b9ac725c10a1d3e49e38af4d141e943ed48d1700d826fa23fee890860d6811f417c19faca2197bbc000edc73bfe00c34e6d540912e67e3e4b921797510cafd2e28d3274937819c152e9c081e6170f803e2e5db9bc22271b923d84432a4f15f5ee3ec9164836a20969424adf8de3fa9fc5a8b95ea0488247a1026c17f5bf964d8bc606be03d2b127168b7dbc87b9a2d711";

char* G2_hex = "af5169183de9018407c5da24e23310f1caa6408e2f0a0bc0eb12d16d474cb9d36388a436cabce4ec6bc82244ef082eb84fa6319437b8b930c4ef643d36d572a9b0ac41e82cd1972c5bdca69178683d0f9c9ab91a996b52a0694a8618d1f5c0c1c57f94c1f87d0296d695c17fc5404b8b9ac725c10a1d3e49e38af4d141e943ed48d1700d826fa23fee890860d6811f417c19faca2197bbc000edc73bfe00c34e6d540912e67e3e4b921797510cafd2e28d3274937819c152e9c081e6170f803e2e5db9bc22271b923d84432a4f15f5ee3ec9164836a20969424adf8de3fa9fc5a8b95ea0488247a1026c17f5bf964d8bc606be03d2b127168b7dbc87b9a2d712";

char* L2_hex = "af5169183de9018407c5da24e23310f1caa6408e2f0a0bc0eb12d16d474cb9d36388a436cabce4ec6bc82244ef082eb84fa6319437b8b930c4ef643d36d572a9b0ac41e82cd1972c5bdca69178683d0f9c9ab91a996b52a0694a8618d1f5c0c1c57f94c1f87d0296d695c17fc5404b8b9ac725c10a1d3e49e38af4d141e943eb9f8014508a8531066b5781d870e672a6e43799eee2ec527d8c4ce1d18f498e0694a04c78ca539584454a0bde84a0e9acaa575d1e45b8af338a80606b61ee78103326b1794ea9863416c5b7c9f79064cd54e10da84bf03cfce449b9a38f5727b9d84e46d5717eba7655def6f5bea3ddec9527f8047892f8b4a1e400e4da437a24";

char* M2_hex = "5a29cdae1de7e38a7382d07f7db169a783fd24a349d2abc09bb53ca4803d361fa2cc777c7e7a00d94b67ef283a5e9a008c8bc1cd586e12b0461cc09c8c53280835a4979af3b1d03e29fecc2b6469f63ba5efad3a077f474326cb58ed66bca98ee7edf102241b13c86ef2c758d2c9db49dff1e1515e4be90f8e1f1d7630aa520223184e4e111bee754b78805a3a29693aba680aae58212b0a91238066f0cb1b4f4d46f22ebefb5bcd98213fc5a169a7e189414966deb02ace640a0c26120df02228c8cc2116953a39643585f85851e10ffbc78fdb2d67f126fff39873de41a204ed9bc88ae3d449a786a5f80d8a666b7d9ce4f7e3958183bede6741d3ae9fc8e1";

char* K2_hex = "6f6aa64cdf2f28bb081ec019b3a8e2eed89052441626172daf106f523b0b44cc";

char* W1_hex = "248ea4e0ce968bdd1febd48e2d246f7268070eb468eca0c1e911cc1642bd8041";

char* CA22_hex = "3192b9daade647a4d17b5e2e0f08e6e3d0666fac576ff8e20be4a1072b23e0202195cb9738bf7d4f5784577d23071bec7c326b6ddf25bb2f4a415cb5a95b89c5a42d4d31a740f72576d798746d30078e15ba1a91d1687563bee2af7b4eceac2f0f13184df619a5ecde5caf9e88b123438afe73d4cc9c2c50ffde42f713cd9384b5cba6cda395d03383e7f8335ac61852fd18ea7012480c49aafc27f035045303f46d0a40fe4e7fce17facbc16e55a418c18256bb30216613a2590edcc0fbe1b18d0f6507273def2e2b740b04a880648d9dc5a5225884fc07bcdaec34d91b6f84ada7c274ba960f316c04765d0e4abab76f15801dce47381d69ed3205c0398d04a71637220420f708b591af0669d35c586d888c90f8ad82e5c421e2b0474c6dca65dd70f128398489e39f886f1de11b8537ba7d3c9653a21371f90df104d6000ac1e232b07e838204767dcfdf7088e1dbbc9d9b315876ecf9fda14c5ea85bf6a63ee7b8884fd23361350574c89cbc11439648a97ae74b6da2a08763926015628909b9ca8def2734df5ec720caafa274abff2dcb29a310911ebd6ccfab67c4f98aa5b2a48e7e76443a5deb3ab4fd57df9847a19c004d0529e25d0a78f5d732c90aa68025ab7885c23ac5268794c6325398e0f63511a24b90f6e09476d37aecb64cd98c2b780e0b32810341cc892fccccdc8a1396a5d3019eafb163190f63807868";

char* R22_hex = "8a0a6634ed02a76e647cb5a44636c4960e961cd3e11a1b32b42e51418e5738fe67aa182e617968c0a811bc5fe96623070d4e853c567710f468f5698610cc2cd1cccdad807e0011d607e7617977a5468ccd0a7a514ee60d7910297dfc17fe2b42a623eed640416e0cb9ed67ce9b79cf33174037a5e5a7bab4b367bf9ae62a5e2f6b6d51247fd2c39ea97f21afa2f010123486f8f26f3df92d59588ea8cebf617cd1e8fc2f7206f44eafdadde28e44aa27744bcef25b075451e930a1e1377943805b90780506bd7e86092e47fa892bd252f7eba090642501e28148540047d2f264a0b4855f48ab43ca4f75d728ba19585da77d7dcb402f5f3d040b8718faa0f361";

char* CB21_hex = "195a0cb5a5677bd8b22606346aa2c80e42be21442119079d56ee169eb6ee84b54e8f8c5b1196edc133520c9b60f6735ea444880e9c47eabe41b409cf3a1ac9e51e1b48e855e47f92c7395f825ad2c82648c0b4e303d02345130b6c7df80fe8da0df632ea61bfb4b2373587cc59c37810eee25ec4e74db801729b32134e03e9df04edbc354c42ee9bee52f5939f12783854ed221bcb7e3ce366843c3b40b7396574bffdd2e5ad6d85487f95e62858cedf91e14fe31e922603303a4da6190f1940243539bdfd833920071aaefe5e719310bf4e99bff85154a19dac944a395ad0c820bfe8ead7a3a80aa32cd2a60119c27cf148223ba2354467eb5be12e4bc67e6faa7b505ac1ea154443f99d59bf0141621f2495a653d66d490d2756a37223b4a4053fead8580c7c789a79ffd71817bc4c67efa39411c34a8cb18e13498581faa3e74a5fdcd220ff74497a70298fc74326cc1cd6045ee92784143ce5f985155941ad3777ae6e875491dc7caf00b5181d08e16054c73e28085c9f78fb1dbbb44e8558c77ebf960803ee9a9fce4e9bf00c9c8c3dfe02fe7780a91eb26b79860fa516ac12ac05d3a994431718c147bfad8486de3ea053134f78ac9dbbc4aa2f1dce1f409d7371cbb40e2b81c59e8cd514d2e6e6d5c8965764e643f3d890151662d1f9bac07fac7f1320d0df476412f2b26c34bc3b1baf9b5272636830e73793925bc6";

char* R21_hex = "980dcee14556e2c40472c3544d46a6e34652ff1a4d9f99fdd7e8823aa39e332050431361bf618e5cfd248cd3ff3f03a32f8021eaf0d0b6d34bc3506f99e86a21dcc8237f66cd7d7aab0a1aad359da6580ea51b5c722d548e340617d512945c105a7a01756ffbcce91611bb8e3be4e36c24aa2c356fa7370515e359b5fd1075aa8628e07fcdb205e510dc1d464ced3805fd834d1ab82cd9086a5fe92bebef8900d5ca7269c9da58d732b7dda821c35cca5ce0a31c1ddb3f3d0b62e1117cd00bb54c3c03fd533a4d0148852703f83293def0f5c42a68b6deab4762ca6a7c448cbcf8a5156450d5441f961121f0220cae9af7844f9923fa4be52b3abbf3100a9dee";

char* Z21_hex = "101c7abf2665c3f311a11c988798476216b28d576657fe0e7795e7024086051a";

char* BETA1_hex = "efe38540d99a3c0cee5ee3677867b89ca3fc4f8f48f0a22d483c778a8fb03c27";

char* ALPHA2_hex = "75cf36d1b9c257313412185bc75b86f158dfd7d09c8584a98aa3a3ee852f512e";

char* SUM1_hex = "68891b7166cf16ec847db1ce65c472d8978dbdb1fc01089330e151f4face11b4";

char* SUM2_hex = "3231b07d70de00c4e250f7b545bfbfebe19f71f6a7e85ffefc2dc19b8ba4aeee";

char* SIG_R_hex = "8adf50a4f51443cac2b4d488092ab49925da09e3feb57a1fc03b5b917ca6de9f";

char* M_hex = "74657374206d657373616765";

char* SIG_S1_hex = "d14b16fbbd346f5a9f184a064c351eca2d516a2e88ed3aab5713fea9766aa2b1";

char* SIG_S2_hex = "44548a9ba59d1459a047a7ae5095b0cc70f7d1de6cd5730730cdd762619d8c9a";

char* SIG_S_hex = "159fa19762d183b43f5ff1b49ccacf97e39a5f26467a0d76c80f777f07d1ee0a";

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

    char w2[EGS_SECP256K1];
    octet W2 = {0,sizeof(w2),w2};

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

    char w1[EGS_SECP256K1];
    octet W1 = {0,sizeof(w1),w1};

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

    char sig_r[EGS_SECP256K1];
    octet SIG_R = {0,sizeof(sig_r),sig_r};

    char sig_s1[EGS_SECP256K1];
    octet SIG_S1 = {0,sizeof(sig_s1),sig_s1};

    char sig_s1golden[EGS_SECP256K1];
    octet SIG_S1GOLDEN = {0,sizeof(sig_s1golden),sig_s1golden};

    char sig_s2[EGS_SECP256K1];
    octet SIG_S2 = {0,sizeof(sig_s2),sig_s2};

    char sig_s2golden[EGS_SECP256K1];
    octet SIG_S2GOLDEN = {0,sizeof(sig_s2golden),sig_s2golden};

    char sig_s[EGS_SECP256K1];
    octet SIG_S = {0,sizeof(sig_s),sig_s};

    char sig_sgolden[EGS_SECP256K1];
    octet SIG_SGOLDEN = {0,sizeof(sig_sgolden),sig_sgolden};

    char m[2000];
    octet M = {0,sizeof(m),m};

    char hm[32];
    octet HM = {0,sizeof(hm),hm};

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

    OCT_fromHex(&W2,W2_hex);
    printf("W2: ");
    OCT_output(&W2);

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

    OCT_fromHex(&W1,W1_hex);
    printf("W1: ");
    OCT_output(&W1);

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

    OCT_fromHex(&SIG_S1GOLDEN,SIG_S1_hex);
    printf("SIG_S1GOLDEN: ");
    OCT_output(&SIG_S1GOLDEN);

    OCT_fromHex(&SIG_S2GOLDEN,SIG_S2_hex);
    printf("SIG_S2GOLDEN: ");
    OCT_output(&SIG_S2GOLDEN);

    OCT_fromHex(&SIG_SGOLDEN,SIG_S_hex);
    printf("SIG_SGOLDEN: ");
    OCT_output(&SIG_SGOLDEN);

    OCT_fromHex(&SIG_R,SIG_R_hex);
    printf("SIG_R: ");
    OCT_output(&SIG_R);

    OCT_fromHex(&M,M_hex);
    printf("M: ");
    OCT_output(&M);

    // ALPHA1 + BETA2 = K1 * W2
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

    rc = MPC_MTA_SERVER(NULL,  &N1, &G1, &W2, &CA11, &Z12, &R12, &CB12, &BETA2);
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

    // ALPHA2 + BETA1 = K2 * W1
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

    rc = MPC_MTA_SERVER(NULL,  &N2, &G2, &W1, &CA22, &Z21, &R21, &CB21, &BETA1);
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

    // sum = K1.W1 + alpha1  + beta1
    rc = MPC_SUM_MTA(&K1, &W1, &ALPHA1, &BETA1, &SUM1);
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

    // sum = K2.W2 + alpha2  + beta2
    rc = MPC_SUM_MTA(&K2, &W2, &ALPHA2, &BETA2, &SUM2);
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

    // Calculate the message hash
    rc = MPC_HASH(HASH_TYPE_SECP256K1, &M, &HM);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_HASH rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    // Calculate the S1 signature component
    rc = MPC_S(&HM, &SIG_R, &K1, &SUM1, &SIG_S1);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_S rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("SIG_S1: ");
    OCT_output(&SIG_S1);
    printf("\n");

    rc = OCT_comp(&SIG_S1,&SIG_S1GOLDEN);
    if(!rc)
    {
        fprintf(stderr, "FAILURE SIG_S1 != SIG_S1GOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    // Calculate the S2 signature component
    rc = MPC_S(&HM, &SIG_R, &K2, &SUM2, &SIG_S2);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_S rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("SIG_S2: ");
    OCT_output(&SIG_S2);
    printf("\n");

    rc = OCT_comp(&SIG_S2,&SIG_S2GOLDEN);
    if(!rc)
    {
        fprintf(stderr, "FAILURE SIG_S2 != SIG_S2GOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    // Sum S signature component
    rc = MPC_SUM_S(&SIG_S1, &SIG_S2, &SIG_S);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_SUM_S rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("SIG_S: ");
    OCT_output(&SIG_S);
    printf("\n");

    rc = OCT_comp(&SIG_S,&SIG_SGOLDEN);
    if(!rc)
    {
        fprintf(stderr, "FAILURE SIG_S != SIG_SGOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
