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

    This example is for the implementation of CG21:PI_MOD, eprint, page:36, figure:16
    For checking validity of Paillier N visit
    https://dl.acm.org/doi/abs/10.1145/3372297.3423367, page:1779, figure:5

 */

#include <stdlib.h>
#include <amcl/amcl.h>
#include "amcl/cg21/cg21_pi_mod.h"
#include <amcl/paillier.h>
#include <amcl/ecdh_SECP256K1.h>
#include <amcl/randapi.h>
#include "amcl/schnorr.h"

bool Debug = false;


void dec_to_octet(int decimal_Number, octet *O)
{
    BIG_256_56 temp;

    BIG_256_56_zero(temp);
    BIG_256_56_inc(temp, decimal_Number);
    OCT_pad(O, iLEN);
    BIG_256_56_toBytes(O->val,temp);
}

void init_octets(char* mem, octet *OCTETS, int max, int n)
{
    for (int i = 0; i < n; i++)
    {
        OCTETS[i].val = mem + (i*max);
        OCTETS[i].len = 0;
        OCTETS[i].max = max;
    }
}

char* P_hex = "ffa0ec8cec4d2ffbef2a251111a361ad0199133f0aaa715df5ef052ad1efee2efda77a9349a74743e394ecef4da268c63171b8a896df79ec940f0c11d5de4a90d66628646f21f1ac0ac5f13adf45d2fd1d795c766dff1f656c91c3650ac2b59734efd3431332d691815da465b0d6f65b1620f4b1c7b9c18b38f63f478c06ca67";
char* Q_hex = "e4d2fcd44d6bda22588e7f64e47fb32b1783cdc6ea43df8618cd27ae50e38a7d2ff1a252aec54625ab497f3cfe5860547ee0c66cb4ca0e29ccb1098fa3c04cee2565a20510596f5e0c8e4e2adde5aedcbb1803250f3465941880055798f1e36f5ba60e8878328132c070c6fad3c8ad2c155fd4cc88927f4410d498a5a5e40d8b";

char* rid_hex = "fe3d9b2809ea3595990283e7baf121910ec681e70a83255c05761008d42dce95";
char* rho_hex = "b40a06d473a944f6100d16f4900291eb929325339f52b9a058584be26f934ca2";
char* X_packed_hex = "03868dccba08f5021b5f9bf59e7834ba093ed7ca6381c6e8122207d9cdd67aa07a03bba617c6a6c6d6f76d4ea64b58bc66fb02a00de037d47fbf4852003374b9983303bc549c825221baeaa606d875e7ae28afd1785e170388c6e1d1defca48d4b3c2a";
char* j_packed_hex = "000100020003";
int n = 3; // number of players in the network

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

    CG21_PAILLIER_KEYS paillierKeys;

    PAILLIER_KEY_PAIR(NULL, &P, &Q, &paillierKeys.paillier_pk, &paillierKeys.paillier_sk);

    BIG_256_56 q;
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    // define variables
    char xoct[CG21_PAILLIER_PROOF_SIZE];
    octet Xoct = {0, sizeof(xoct), xoct};

    char zoct[CG21_PAILLIER_PROOF_SIZE];
    octet Zoct = {0, sizeof(zoct), zoct};

    char ab[CG21_PAILLIER_PROOF_ITERS*4];
    octet AB = {0,sizeof(ab),ab};

    char w[HFS_4096];
    octet W = {0, sizeof(w), w};

    CG21_SSID ssid;
    ssid.rid = &RID;
    ssid.j_set_packed = &J_Packed;
    ssid.rho = &RHO;
    ssid.X_set_packed = &X_Packed;

    CG21_PIMOD_PROOF_OCT paillierProof;
    paillierProof.w = &W;
    paillierProof.x = &Xoct;
    paillierProof.z = &Zoct;
    paillierProof.ab = &AB;

    // generate proofs for the correctness of Paillier Pk
    int rc = CG21_PI_MOD_PROVE(&RNG, paillierKeys,&ssid, &paillierProof, n);
    if (rc != CG21_OK){
        exit(rc);
    }

    // verify the proofs
    rc = CG21_PI_MOD_VERIFY(&paillierProof, &ssid, paillierKeys.paillier_pk, n);
    if (rc == CG21_OK){
        printf("SUCCESS\n");
        exit(0);
    }
    printf("FAILURE\n");
    exit(1);
}