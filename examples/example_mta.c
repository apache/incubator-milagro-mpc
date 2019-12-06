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

char* N_hex = "59f668761d66864604a05a647ce112452830f0426d02e4141781c7431eb1845c2ed32ea93150fb3b8c17553629edc84fab77080e4200b815f338aaa58fa030a4b562f43d5f24a25d3dcb419ae75e281e37c8a1f0d2f47d733e040fcec7f45e293ef656c91d0045b6b97c64f72977c01ea85214e5847b425ea410a66b59cc2ef6d6fdf6509afe8d48eeb1335f58aaabf42799fe636a2f7653842cea779d0d1dc455c8d99b862ef5e96ae83626baf9d11aeecbf9cca683cb833ceeb09bd7e1bf7e63cf76d1d48d036cbcb05c185f08c72228ecd5ccffd9192443f007a3016249584504f7c0d483fb934365a58fbcf0df13a20d5864797245fe709abfee78a40a71";

char* G_hex = "59f668761d66864604a05a647ce112452830f0426d02e4141781c7431eb1845c2ed32ea93150fb3b8c17553629edc84fab77080e4200b815f338aaa58fa030a4b562f43d5f24a25d3dcb419ae75e281e37c8a1f0d2f47d733e040fcec7f45e293ef656c91d0045b6b97c64f72977c01ea85214e5847b425ea410a66b59cc2ef6d6fdf6509afe8d48eeb1335f58aaabf42799fe636a2f7653842cea779d0d1dc455c8d99b862ef5e96ae83626baf9d11aeecbf9cca683cb833ceeb09bd7e1bf7e63cf76d1d48d036cbcb05c185f08c72228ecd5ccffd9192443f007a3016249584504f7c0d483fb934365a58fbcf0df13a20d5864797245fe709abfee78a40a72";

char* L_hex = "59f668761d66864604a05a647ce112452830f0426d02e4141781c7431eb1845c2ed32ea93150fb3b8c17553629edc84fab77080e4200b815f338aaa58fa030a4b562f43d5f24a25d3dcb419ae75e281e37c8a1f0d2f47d733e040fcec7f45e293ef656c91d0045b6b97c64f72977c01ea85214e5847b425ea410a66b59cc2ef5a76c9540faee87fd45bcf109d92822af07d0771d943c69a3bc3232c573ebd9c4a6381c74a46b5d9bbe407db5c50dc37fc39de16501c4eca84f07c04511fe78d1ab5531809cf4f3706136c238df2511fc731f1bbc3be22e3efb3bef6d643a5df7ce17a93406ab8cc226c2459105cee6a3c224bc9348db96236b417f6d29a863f4";

char* M_hex = "1ee3cbc99bde365d01286a216d15d331d82d3562fb8c53c08ed44fe45f8cc9e2d3e410b466de80dd4fb4f69e73e71232ff78e1dc7c68ce01f4d4307e05a0d4268c4fe711ae89a82bd601dbd2921db858f42ac7192ed5c37ccf35f68ab6b2bde63001f99582c34f54dfa687af2a225aa70b3fcb703ffa936ca6e4d9906cbb91f0abcb8799da2474ecdff45a7c8a5f7beee325ace997a692aee41ef423ea655747ed27f90ad330aafcc722eecc07adf5029ccf95df6e93ec773056c0e8fb2aac5d523bb0549e0d847590bb0645d662c07aef2ef3fd054c514b673516ba5aa0d2e96b04dc5bebac7727044675f94d89d990d63e118bbdf04303d566a8d5b439c77c";

char* a_hex = "0000000000000000000000000000000000000000000000000000000000000002";

char* b_hex = "0000000000000000000000000000000000000000000000000000000000000003";

char* ca_hex = "19c8b725dbd74b7dcaf72bd9ff2cd207b47cb1095393685906171af9e2f2959e7f68729e0e40f97a22bbca93373d618ad51dd077c0d102938598a8ecc8a656e978ebd14007da99db8e691d85fc18a428097ee8a63dcf95b84b660294474a20ed2edcf2b1b4f305c1cc25860a08d1348c2a4d24cc1a97b51f920e2985b8108b3392a5eafc443cf3449e288eb49dbde2228a56233afa5a6643e5ae6ec6aa8937a666ef74a30625c35bb22c3cc57b700f8eae7690f8d37edbfd27ccb2e882f70d0d85e0cc825347453a28e98e877ab1eeaa6efa09f034bc8976bffb86420106978066ff52221b315f71eb32cbf608d2b72cfa4c88e43282598f175b48ba3b5c14d72b2d90baabc00025450740ac89fc0dcd7d2f80cf12c721b6ec493c2025d7adc683b78f1d711b639a1b0dd043b9defa7ff928e257599dd95525bc8b45e1b88470311e11feb72749e5fc98f69051ddd1101b1bcc92f649681bd7ae316575444625d9d73d3684789142650951321e17f6b2f92103f36dbbd004cd66cda366e80faa4f57b71b9abb042f6cc932716fa3e6fdf50674e3d1e6d871f723d3f4f672c1270b41e7cdd5930a2572ddfc8ce370576a7a75ee6924f53122d717146c74eb6167811a2488bb899cc2da9dc2e29df66b5a03ed986fdad6ef177151ddd2698055050709c475b4ed5a2ab0be00c8b03e24193fb79f91cfd81fbcb838e45c25f8ba05";

char* R_hex = "18c5947fda2edea04c1f87c207e0bab17aff5f77ac21d04cb194631efd1f7256dc37de9473fc86009df36206974859c09023ac8179b02aacea8d89a01f4de161db955d450cef55ce959897636973b952371e349778e67c61ef6fae5f73fd728d423a594b6a76d5faca97d59d6ae40c53f3bd42dfccc93183e355422ba7af308a87d32c0352d478156275f98bc74e9ed4f2c7a9853c9f35b996fafe765b56c7f2e83771c6b676b75436e5c1697b838b3908aee92001cbccf3bf6cfb7aaea27a358a12cfe1ddde886b975ae14517e5912eba3ff9792e46403a998edd371020bbc5fbd6a705e669383303030ef79653ce16e13122233c626bb101ee8dd27bf4ff86";

char* cb_hex = "1f1f087e749c85aacdacaace8659a33b53baad5eec1e56628435d335a8b150f96865d6e090f53146e120e7089b6f4a91c762622b24d0d2fba0e703301170a0b826a1336d4d6bb83dccd29ad9ef0936614bf14e992ea4daa202c63ace9bd3f95b9a8a6edd7949e89ec165541e7c01bd41395baf3e2fe7f3a9611af8b5ed8639c02a2bfc236c17a136bef6d09f966db718f3df9d6f4f40b618b4b6058b4e4ec241e6c2424404d0aee0ef5cd666e5c4253a62ae9deb09289fb84657109e0b933f58871ba7ea77190d6ea45a04be68360478adf43a85851cf583c5575543578635996d2dcd020aeceabf18be6ff8b45e4ecd63c899cbfe353bc6be246aa421f54bb1f6aad797b36e435e2f33a3a049aeab894b851c5ce1076aa6e19316e3da6f539197e00e17e7a3025b53490a9d1210b900c1cac32a3bdc31d4c4866e7499a2858942e057be2840cf8ad4b1dcd914c64ac7d4b89e3f1b1a010096ecb62bb5837d9e79018870002962838bc46d7a70c23494985c300b4f8a7352a412bfc4134378d23343b3c8a77f65c234c8586e5fb0731881cb756e994c82773261f2a2321e45df45a08830e67b6c983e3f01a464b9ca6cc78ec7f170782748d114889656377e86a1e3b3c28616f3b4b73693867fefd7459fe99e9892435f0902ad74ceebac99c4f67340344f128b1f55fdb85acdc64891b77d9961653361f5264d5f1e0b67173b";

char* z_hex = "0000000000000000000000000000000000000000000000000000000000000004";

char* beta_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413d";

char* alpha_hex = "000000000000000000000000000000000000000000000000000000000000000a";

int main()
{
    int rc;

    char n[FS_2048] = {0};
    octet N = {0,sizeof(n),n};

    char g[FS_2048];
    octet G = {0,sizeof(g),g};

    char l[FS_2048] = {0};
    octet L = {0,sizeof(l),l};

    char m[FS_2048] = {0};
    octet M = {0,sizeof(m),m};

    char a[EGS_SECP256K1];
    octet A = {0,sizeof(a),a};

    char b[EGS_SECP256K1];
    octet B = {0,sizeof(b),b};

    char z[EGS_SECP256K1];
    octet Z = {0,sizeof(z),z};

    char r[FS_2048];
    octet R = {0,sizeof(r),r};

    char ca[FS_4096];
    octet CA = {0,sizeof(ca),ca};

    char cb[FS_4096];
    octet CB = {0,sizeof(cb),cb};

    char alpha[EGS_SECP256K1];
    octet ALPHA = {0,sizeof(alpha),alpha};

    char beta[EGS_SECP256K1];
    octet BETA = {0,sizeof(beta),beta};

    char cagolden[FS_4096];
    octet CAGOLDEN = {0,sizeof(cagolden),cagolden};

    char cbgolden[FS_4096];
    octet CBGOLDEN = {0,sizeof(cbgolden),cbgolden};

    char alphagolden[EGS_SECP256K1];
    octet ALPHAGOLDEN = {0,sizeof(alphagolden),alphagolden};

    char betagolden[EGS_SECP256K1];
    octet BETAGOLDEN = {0,sizeof(betagolden),betagolden};

    // Load values
    OCT_fromHex(&N,N_hex);
    printf("N: ");
    OCT_output(&N);

    OCT_fromHex(&G,G_hex);
    printf("G: ");
    OCT_output(&G);

    OCT_fromHex(&L,L_hex);
    printf("L: ");
    OCT_output(&L);

    OCT_fromHex(&M,M_hex);
    printf("M: ");
    OCT_output(&M);

    OCT_fromHex(&A,a_hex);
    printf("A: ");
    OCT_output(&A);

    OCT_fromHex(&B,b_hex);
    printf("B: ");
    OCT_output(&B);

    OCT_fromHex(&Z,z_hex);
    printf("Z: ");
    OCT_output(&Z);

    OCT_fromHex(&R,R_hex);
    printf("R: ");
    OCT_output(&R);

    OCT_fromHex(&CAGOLDEN,ca_hex);
    printf("CAGOLDEN: ");
    OCT_output(&CAGOLDEN);

    OCT_fromHex(&CBGOLDEN,cb_hex);
    printf("CBGOLDEN: ");
    OCT_output(&CBGOLDEN);

    OCT_fromHex(&ALPHAGOLDEN,alpha_hex);
    printf("ALPHAGOLDEN: ");
    OCT_output(&ALPHAGOLDEN);

    OCT_fromHex(&BETAGOLDEN,beta_hex);
    printf("BETAGOLDEN: ");
    OCT_output(&BETAGOLDEN);

    rc = MPC_MTA_CLIENT1(NULL, &N, &G, &A, &CA, &R);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_MTA_CLIENT1 rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("CA: ");
    OCT_output(&CA);
    printf("\n");

    rc = OCT_comp(&CAGOLDEN,&CA);
    if(!rc)
    {
        fprintf(stderr, "FAILURE CA != CAGOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    
    rc = MPC_MTA_SERVER(NULL,  &N, &G, &B, &CA, &Z, &R, &CB, &BETA);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_MTA_SERVER rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("CB: ");
    OCT_output(&CB);
    printf("\n");

    printf("BETA: ");
    OCT_output(&BETA);
    printf("\n");

    printf("ZOUT: ");
    OCT_output(&Z);
    printf("\n");
    
    rc = OCT_comp(&BETAGOLDEN,&BETA);
    if(!rc)
    {
        fprintf(stderr, "FAILURE BETA != BETAGOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    rc = OCT_comp(&CBGOLDEN,&CB);
    if(!rc)
    {
        fprintf(stderr, "FAILURE CB != CBGOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("ALPHAGOLDEN: ");
    OCT_output(&ALPHAGOLDEN);
    printf("\n");
    
    rc = MPC_MTA_CLIENT2(&N, &L, &M, &CB, &ALPHA);
    if (rc)
    {
        fprintf(stderr, "FAILURE MPC_MTA_CLIENT2 rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("ALPHA: ");
    OCT_output(&ALPHA);
    printf("\n");
    printf("ALPHAGOLDEN: ");
    OCT_output(&ALPHAGOLDEN);
    printf("\n");

    rc = OCT_comp(&ALPHA,&ALPHAGOLDEN);
    if(!rc)
    {
        fprintf(stderr, "FAILURE ALPHA != ALPHAGOLDEN rc: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
