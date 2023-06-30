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

    This example is for the implementation of CG21:PI_FAC, eprint, page:66, figure:28

 */

#include <stdlib.h>
#include <amcl/amcl.h>
#include "amcl/cg21/cg21_pi_factor.h"
#include <amcl/paillier.h>
#include <amcl/ecdh_SECP256K1.h>
#include <amcl/randapi.h>
#include "amcl/schnorr.h"

bool Debug = false;




void init_octets(char* mem, octet *OCTETS, int max, int n)
{
    for (int i = 0; i < n; i++)
    {
        OCTETS[i].val = mem + (i*max);
        OCTETS[i].len = 0;
        OCTETS[i].max = max;
    }
}

char* P_hex = "3CB0AA89110ADCFC0ED38B894C782BFE344215AF18504AD9D32712806961969062160778569AE82341B17B54944725645D778228C5E1518F8EE54FF56A874B35EF40F8D20D";
char* Q_hex = "03D282594E25896A82F1C9BD48486A40A9D240ED670C158226489EDB764D02601255E2FD3F79A9C865AECBD1610300426DDF6FF04EFD975B8CBE890CA0960D6D6E1B5AA15846C7C2774A6BAA7E3CDFEB4A3E8154BB7333A3BAFC9A854C0D38998742D3E321426DA2DE6732814D5EA2CA605594F946A8BA89260176611BD4D94DE8B6E80D51E987D45242D60EA4CA9FC18A2DA28AC8EA2490D60CAF0EE5626E8B917385AFD080DB301FA3DBD2C84DDD50105F3151CD20107C162EE995";

// Verifier's Ring-Pedersen parameters
char *PT_hex = "CA5F37B7C0DDF6530B30A41116588218DE95F1F36B807FD7C28E4C467EE3F35967BC01D28B71F8A627A353675A81C86A1FF03DCECAF1686891183FA317BA34A4A1148D40A89F1F3AC0C200511C6CFE02342CD75354C25A2E069886DD4FB73BD365660D163F1282B143119AB8F375A73875EC16B634F52593B73BC6D875F2D3EF";
char *QT_hex = "C2FC545C1C803F6C7625FBC4ECF9355734D6B6058FD714816D3ECFB93F1F705C9CE90D4F8796A05148AB5ABC201F90889231CC6BF5F68ED15EE4D901F603930A280EEABF10C613BFCB67A816363C839EB902B02607EB48AB8325E2B72620D4D294A232803217090DFB50AF8C620D4679E77CE3053437ED518F4F68840DCF1AA3";

char* rid_hex = "fe3d9b2809ea3595990283e7baf121910ec681e70a83255c05761008d42dce95";
char* rho_hex = "b40a06d473a944f6100d16f4900291eb929325339f52b9a058584be26f934ca2";
char* X_packed_hex = "03868dccba08f5021b5f9bf59e7834ba093ed7ca6381c6e8122207d9cdd67aa07a03bba617c6a6c6d6f76d4ea64b58bc66fb02a00de037d47fbf4852003374b9983303bc549c825221baeaa606d875e7ae28afd1785e170388c6e1d1defca48d4b3c2a";
char* j_packed_hex = "000100020003";
int n = 3; // number of players in the network

typedef struct
{
    PAILLIER_public_key  paillier_pub_key;
    PAILLIER_private_key paillier_priv_key;
    PEDERSEN_PUB Pedersen_pub;
}  Prover;

typedef struct
{
    PAILLIER_public_key  paillier_pub_key;
    PEDERSEN_PUB Pedersen_pub;
    PEDERSEN_PRIV Pedersen_priv;

}  Verifier;

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

    char p[HFS_2048] = {0};
    octet P = {0,sizeof(p),p};

    char qq[HFS_2048];
    octet Q = {0,sizeof(qq),qq};

    char p2[HFS_2048] = {0};
    octet P2 = {0,sizeof(p2),p2};

    char qq2[HFS_2048];
    octet Q2 = {0,sizeof(qq2),qq2};

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
    OCT_fromHex(&P2,PT_hex);
    OCT_fromHex(&Q2,QT_hex);

    OCT_fromHex(&RID,rid_hex);
    OCT_fromHex(&RHO,rho_hex);
    OCT_fromHex(&X_Packed,X_packed_hex);
    OCT_fromHex(&J_Packed,j_packed_hex);

    BIG_1024_58 pF[FFLEN_2048];
    BIG_1024_58 qF[FFLEN_2048];
    BIG_1024_58 t1[2*FFLEN_2048];
    BIG_1024_58 t2[FFLEN_2048];

    char nt[FS_2048];
    octet N_Oct = {0, sizeof(nt), nt};

    char t20[FS_2048];
    octet p_ = {0,sizeof(t20),t20};

    char t21[FS_2048];
    octet q_ = {0,sizeof(t21),t21};

    OCT_copy(&p_, &P);
    OCT_copy(&q_, &Q);
    OCT_pad(&p_, FS_2048);
    OCT_pad(&q_, FS_2048);
    FF_2048_fromOctet(pF, &p_, FFLEN_2048);
    FF_2048_fromOctet(qF, &q_, FFLEN_2048);

    FF_2048_mul(t1, pF, qF, FFLEN_2048);
    FF_2048_copy(t2, t1, FFLEN_2048);
    FF_2048_toOctet(&N_Oct,t2,FFLEN_2048);

    // initialize Paillier and Pedersen
    Prover prover;
    Verifier verifier;

    ring_Pedersen_setup(&RNG, &verifier.Pedersen_priv, &P2, &Q2);
    Pedersen_get_public_param(&verifier.Pedersen_pub, &verifier.Pedersen_priv);

    verifier.paillier_pub_key = prover.paillier_pub_key;
    prover.Pedersen_pub = verifier.Pedersen_pub;

    CG21_SSID ssid;
    ssid.rid = &RID;
    ssid.j_set_packed = &J_Packed;
    ssid.rho = &RHO;
    ssid.X_set_packed = &X_Packed;

    char t5[2*FS_2048+HFS_2048];
    octet sigma = {0, sizeof(t5), t5};

    char t9[FS_2048];
    octet P_ = {0, sizeof(t9), t9};

    char t10[FS_2048];
    octet Q_ = {0, sizeof(t10), t10};

    char t11[FS_2048];
    octet A = {0, sizeof(t11), t11};

    char t12[FS_2048];
    octet B = {0, sizeof(t12), t12};

    char t13[FS_2048];
    octet T = {0, sizeof(t13), t13};

    char t14[FS_2048 + HFS_2048];
    octet z1 = {0, sizeof(t14), t14};

    char t15[FS_2048 + HFS_2048];
    octet z2 = {0, sizeof(t15), t15};

    char t16[FS_2048 + HFS_2048];
    octet w1 = {0, sizeof(t16), t16};

    char t17[FS_2048 + HFS_2048];
    octet w2 = {0, sizeof(t17), t17};

    char t18[2*FS_2048 + HFS_2048];
    octet v = {0, sizeof(t18), t18};

    CG21_PiFACTOR_COMMIT commit;
    commit.sigma = &sigma;
    commit.P = &P_;
    commit.Q = &Q_;
    commit.A = &A;
    commit.B = &B;
    commit.T = &T;



    CG21_PiFACTOR_PROOF proof;
    proof.v = &v;
    proof.w1 = &w1;
    proof.w2 = &w2;
    proof.z1 = &z1;
    proof.z2 = &z2;

    CG21_PI_FACTOR_COMMIT_PROVE(&RNG, &ssid,&prover.Pedersen_pub,&commit,&proof,&P, &Q,n);

    int rc = CG21_PI_FACTOR_VERIFY(&commit,&proof,&N_Oct,&verifier.Pedersen_priv,&ssid, n);
    if (rc == CG21_OK){
        printf("SUCCESS\n");
        exit(0);
    }

    printf("FAILURE\n");
    exit(1);
}