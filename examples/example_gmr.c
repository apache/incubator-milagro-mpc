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

/* Example of the GMR ZKP of Square Freeness*/

#include "amcl/gmr.h"

char *P_hex = "e008507e09c24d756280f3d94912fb9ac16c0a8a1757ee01a350736acfc7f65880f87eca55d6680253383fc546d03fd9ebab7d8fa746455180888cb7c17edf58d3327296468e5ab736374bc9a0fa02606ed5d3a4a5fb1677891f87fbf3c655c3e0549a86b17b7ddce07c8f73e253105e59f5d3ed2c7ba5bdf8495df40ae71a7f";
char *Q_hex = "d344c02d8379387e773ab6fa6de6b92b395d5b7f0c41660778766a1ec4740468203bff2d05f263ff6f22740d4b2e799fd1fd2e2339e328c62d31eeecba30fd4892e0c1637e0f62b4de34f5d778a7dfd181b94464f3669751264a0058708a360552535653efc75e3035485e966df30a17146d692747e20b2f04f3877dd1f56dcf";

int main()
{
    int rc;

    char id[32];
    octet ID = {0, sizeof(id), id};

    char ad[32];
    octet AD = {0, sizeof(ad), ad};

    char p[HFS_2048] = {0};
    octet P = {0, sizeof(p), p};

    char q[HFS_2048];
    octet Q = {0, sizeof(q), q};

    char n[FS_2048];
    octet N = {0, sizeof(n), n};

    MODULUS_priv m;

    GMR_proof Y;

    char yoct[GMR_PROOF_SIZE];
    octet Yoct = {0, sizeof(yoct), yoct};

    // Deterministic RNG for testing
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    // Pseudorandom ID and AD
    OCT_rand(&ID, &RNG, ID.len);
    OCT_rand(&AD, &RNG, AD.len);

    // Load RSA modulus
    OCT_fromHex(&P, P_hex);
    OCT_fromHex(&Q, Q_hex);

    MODULUS_fromOctets(&m, &P, &Q);

    FF_2048_toOctet(&N, m.n, FFLEN_2048);

    printf("Prove Square Freeness for");
    printf("\n\tP  = ");
    FF_2048_output(m.p, HFLEN_2048);
    printf("\n\tQ  = ");
    FF_2048_output(m.q, HFLEN_2048);
    printf("\n\tN  = ");
    FF_2048_output(m.n, FFLEN_2048);
    printf("\n\tID = ");
    OCT_output(&ID);
    printf("\tAD = ");
    OCT_output(&AD);

    // ZK Proof
    GMR_prove(&m, &ID, &AD, Y);
    GMR_proof_toOctet(&Yoct, Y);

    printf("\nGenerate GMR Proof of Square Freeness\n");
    printf("and encode it into an octet\n");
    printf("Y = ");
    OCT_output(&Yoct);

    // Clear memory once the proof is generated
    MODULUS_kill(&m);

    // ZK Verify
    printf("\nVerification\n");
    printf("\tDecode the Proof from the octet:\n");

    rc = GMR_proof_fromOctet(Y, &Yoct);
    if (rc == GMR_OK)
    {
        printf("\t\tSuccess!\n");
    }
    else
    {
        printf("\t\tFailure!\n");
        exit(EXIT_FAILURE);
    }

    printf("\tVerify the Proof:\n");

    rc = GMR_verify(&N, Y, &ID, &AD);
    if (rc == GMR_OK)
    {
        printf("\t\tSuccess!\n");
    }
    else
    {
        printf("\t\tFailure!\n");
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}