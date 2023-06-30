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

    This example is for the implementation of CG21:PI_PRM, eprint, page:37, figure:17
    For checking the original paper refer to F097 ( Statistical zero knowledge protocols
    to prove modular polynomial relations)
    https://link.springer.com/chapter/10.1007/BFb0052225, page:4, section 3.1

    Note that in CGG21, Algorithm M in page 5 is selected to generating Pedersen params; however,
    in this implementation of follow the main protocol for params generation to enjoy full security
    features at the cost of more computational and communication costs.

 */

#include <stdlib.h>
#include <amcl/amcl.h>
#include "amcl/cg21/cg21_pi_prm.h"
#include <amcl/paillier.h>
#include <amcl/ecdh_SECP256K1.h>
#include <amcl/randapi.h>
#include "amcl/schnorr.h"
#include "amcl/cg21/cg21_utilities.h"



char* P_hex = "ffa0ec8cec4d2ffbef2a251111a361ad0199133f0aaa715df5ef052ad1efee2efda77a9349a74743e394ecef4da268c63171b8a896df79ec940f0c11d5de4a90d66628646f21f1ac0ac5f13adf45d2fd1d795c766dff1f656c91c3650ac2b59734efd3431332d691815da465b0d6f65b1620f4b1c7b9c18b38f63f478c06ca67";
char* Q_hex = "e4d2fcd44d6bda22588e7f64e47fb32b1783cdc6ea43df8618cd27ae50e38a7d2ff1a252aec54625ab497f3cfe5860547ee0c66cb4ca0e29ccb1098fa3c04cee2565a20510596f5e0c8e4e2adde5aedcbb1803250f3465941880055798f1e36f5ba60e8878328132c070c6fad3c8ad2c155fd4cc88927f4410d498a5a5e40d8b";

char* rid_hex = "fe3d9b2809ea3595990283e7baf121910ec681e70a83255c05761008d42dce95";
char* rho_hex = "b40a06d473a944f6100d16f4900291eb929325339f52b9a058584be26f934ca2";
char* X_packed_hex = "03868dccba08f5021b5f9bf59e7834ba093ed7ca6381c6e8122207d9cdd67aa07a03bba617c6a6c6d6f76d4ea64b58bc66fb02a00de037d47fbf4852003374b9983303bc549c825221baeaa606d875e7ae28afd1785e170388c6e1d1defca48d4b3c2a";
char* j_packed_hex = "000100020003";
int n = 3; // number of players in the network and the octets in the packages generated in key re-sharing protocol

int main() {

    // Deterministic RNG for debugging
    const char* seedHex = "78d0fb6705ce77dee47d03eb5b9c5d30";
    char seed[16] = {0};
    octet SEED = {sizeof(seed),sizeof(seed),seed};

    // CSPRNG
    csprng RNG;

    // fake random source
    OCT_fromHex(&SEED,seedHex);
    printf("SEED: ");
    OCT_output(&SEED);

    // initialise RNG
    CREATE_CSPRNG(&RNG,&SEED);

    char p[FS_2048] = {0};
    octet P = {0,sizeof(p),p};

    char qq[FS_2048];
    octet Q = {0,sizeof(qq),qq};

    char rid[EGS_SECP256K1];
    octet RID = {0,sizeof(rid),rid};

    char rho[EGS_SECP256K1];
    octet RHO = {0,sizeof(rho),rho};

    char x_packed[n * (EFS_SECP256K1 + 1)];
    octet X_Packed = {0,n * (EFS_SECP256K1 + 1),x_packed};

    char j_packed[n * 4 + 1];
    octet J_Packed = {0,n * 4 + 1,j_packed};

    // Load values
    OCT_fromHex(&P,P_hex);
    OCT_fromHex(&Q,Q_hex);

    OCT_fromHex(&RID,rid_hex);
    OCT_fromHex(&RHO,rho_hex);
    OCT_fromHex(&X_Packed,X_packed_hex);
    OCT_fromHex(&J_Packed,j_packed_hex);

    CG21_SSID ssid;
    ssid.rid = &RID;
    ssid.j_set_packed = &J_Packed;
    ssid.rho = &RHO;
    ssid.X_set_packed = &X_Packed;
    ssid.n1 = &n;


    char rr1[HDLOG_VALUES_SIZE];
    octet rho_oct = {0, sizeof(rr1), rr1};

    char rr2[HDLOG_VALUES_SIZE];
    octet irho_oct = {0, sizeof(rr2), rr2};

    char rr3[HDLOG_VALUES_SIZE];
    octet t_oct = {0, sizeof(rr3), rr3};

    char rr4[HDLOG_VALUES_SIZE];
    octet it_oct = {0, sizeof(rr4), rr4};

    CG21_PIPRM_PROOF_OCT proofOct;
    proofOct.rho = &rho_oct;
    proofOct.irho = &irho_oct;
    proofOct.t = &t_oct;
    proofOct.it = &it_oct;

    CG21_PEDERSEN_KEYS pedersenKeys;

    // Using externally generated primes
    ring_Pedersen_setup(&RNG, &pedersenKeys.pedersenPriv, &P,&Q);

    // Prove b0, b1, n have correct form
    printf("\nProve the generated parameters are well formed ...");

    int rc = CG21_PI_PRM_PROVE(&RNG, &pedersenKeys.pedersenPriv, &ssid, &proofOct);
    if (rc != CG21_OK){
        printf("\nProve failed!, %d", rc);
        exit(1);
    }

    printf("\nDone.");

    printf("\n\nVerify the proof ...\n");

    // copy public params to another structure
    Pedersen_get_public_param(&pedersenKeys.pedersenPub, &pedersenKeys.pedersenPriv);

    rc = CG21_PI_PRM_VERIFY(&pedersenKeys.pedersenPub, &ssid, &proofOct, n);

    if (rc != CG21_OK)
    {
        printf("Failure! RC %d\n", rc);
        exit(0);
    }
    else
    {
        printf("Success!\n");
        exit(rc);
    }

}