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

/* ZKPoK of DLOG over a hidden order group smoke test */

#include "amcl/hidden_dlog.h"

// Safe primes P = 2p+1, Q = 2q+1
char *Phex  = "e41615620cb68a9ea8df28551b27f333cf65c770c7e959435786d4b510fe360a304fd2bf437431e790dc4c54da6db03119e75ef0b3f47436acf78a9e7b2276ebdd864e49d3bf450c496b10471f024dc4ae1f659c41aacdfb8ee6d52ba46a82d41f79a14277a61474a6473b7e4ab82528383d6400dc71278941e16c138d74d5bb";
char *Qhex  = "d344c02d8379387e773ab6fa6de6b92b395d5b7f0c41660778766a1ec4740468203bff2d05f263ff6f22740d4b2e799fd1fd2e2339e328c62d31eeecba30fd4892e0c1637e0f62b4de34f5d778a7dfd181b94464f3669751264a0058708a360552535653efc75e3035485e966df30a17146d692747e20b2f04f3877dd1f56dcf";

// B1 = B0 ^ A mod PQ with B0 generator of G_pq
char *Ahex  = "2545cf613d4a6fa16bec6ec4dfc0c512bb6b8ea31250414f01f466776d30ca080e323392759180cf0e853a9168b59cf32589f84c1380c3a1482c031cb3b32b5e2dc062dde861fe09dd57afb1c2b8674a35dfe016368e2345592fd90e76060532ce61cbec50a49c67c5ab3f3b433aaa8d0480f79123b14a375f6a8f8ebc91cabd8e5fe5428a37f11caee1f7833418d60c2a757304ca1f12e2a63a366e7ec3007a4c62b068b6207aa2ce2ea287fbdeff973f4a725da10df44134a8f981f22157ee932a3b3565ec723af666553c668fcd31cf342712b4dff9bb5e95dc0d6cc23cfb31b9fdd92f00a35a200c2656054bbcddea10284027667da8598f650083a23fd6";
char *B0hex = "5e712c49e4648060d2a1f4487aa56496f75106571e4f6fedebf0150fa628d968e8694919d151e21a521c3e80309e5830b4c284f0e00e084fbac1defffbbf2f4f467b2ba14b7ca796fab4574310bf5afead953bfaf01750f0dd8f771df7bc6cfa64b9a108648d8a180a361f5faa9549a56afae8b2bd0563b5591a20439e0781babb280ab30f2b5b6abe4e35b600403f9e86564197fd7a5da724f3fb265600c619645b50cad7ed2597c189b082a18f641dbbf79c28a75add4915ce0ff19ef229a4d03e11cdc1b37d42df20c25b6cd991ab8b31d82051bcb7c3848ca1eac18cb9bab5eaf36390f90bf7e34aace31279cad4fd55aec4689881c49b7bf7cf4939ebb4";
char *B1hex = "199540bcefff1aa1af7d665e5fb401a57a0962004fd0f6c4e7ec1543daf9a57c4e758b7e3bb8e9bb9528699cddd5ae23522decee78a67da3a872e1b2fcbc3be354674fd4c037639da2ace925805471bf960d6679bfdac6b722bd1f607f314e05c2c2b7f5af9d85c49c82a40a91b217806f8e18fc1b3746f380b0512458fc7f81e58a052afadcd9fe448e61ce846ab729344b9c845dd4590888ee25abc695ef04efdd9f02a35e89bb563a68cb54ed8a7fba6de284385b8e065372082b10b00499f62dd522ad51d0a4f44f509876b6b3a9e824e172550ef09f5d07183b6ab87671fda390a5a080f50e88d987c5d0ea64f77149beba2b0e5a77c6ee0cff08854fc6";

int main()
{
    int i, rc;

    char p[HFS_2048];
    octet P = {0, sizeof(p), p};

    char q[HFS_2048];
    octet Q = {0, sizeof(q), q};

    char w[FS_2048];
    octet W = {0, sizeof(w), w};

    MODULUS_priv m;

    BIG_1024_58 ord[FFLEN_2048];

    BIG_1024_58 alpha[FFLEN_2048];
    BIG_1024_58 b0[FFLEN_2048];
    BIG_1024_58 b1[FFLEN_2048];

    BIG_1024_58 ws1[HFLEN_2048];
    BIG_1024_58 ws2[HFLEN_2048];

    HDLOG_iter_values r;
    HDLOG_iter_values rho;
    HDLOG_iter_values t;

    char id[32];
    octet ID = {0, sizeof(id), id};

    char ad[32];
    octet AD = {0, sizeof(ad), ad};

    char e[HDLOG_CHALLENGE_SIZE];
    octet E = {0, sizeof(e), e};

    // Deterministic RNG for testing
    char seed[32] = {0};
    csprng RNG;
    RAND_seed(&RNG, 32, seed);

    // Pseudorandom ID and AD
    OCT_rand(&ID, &RNG, ID.len);
    OCT_rand(&AD, &RNG, AD.len);

    // Load values
    OCT_fromHex(&P, Phex);
    OCT_fromHex(&Q, Qhex);

    MODULUS_fromOctets(&m, &P, &Q);

    OCT_fromHex(&W, Ahex);
    FF_2048_fromOctet(alpha, &W, FFLEN_2048);

    OCT_fromHex(&W, B0hex);
    FF_2048_fromOctet(b0, &W, FFLEN_2048);

    OCT_fromHex(&W, B1hex);
    FF_2048_fromOctet(b1, &W, FFLEN_2048);

    // Compute order of B0
    FF_2048_copy(ws1, m.p, HFLEN_2048);
    FF_2048_copy(ws2, m.q, HFLEN_2048);

    FF_2048_shr(ws1, HFLEN_2048);
    FF_2048_shr(ws2, HFLEN_2048);

    FF_2048_mul(ord, ws1, ws2, HFLEN_2048);

    // Smoke test
    HDLOG_commit(&RNG, &m, ord, b0, r, rho);

    HDLOG_challenge(m.n, b0, b1, rho, &ID, &AD, &E);

    HDLOG_prove(ord, alpha, r, &E, t);

    rc = HDLOG_verify(m.n, b0, b1, rho, &E, t);
    if (rc != HDLOG_OK)
    {
        fprintf(stderr, "FAILURE HDLOG_verify failed");
        exit(EXIT_FAILURE);
    }

    HDLOG_iter_values_kill(r);

    for (i = 0; i < HDLOG_PROOF_ITERS; i++)
    {
        if (!FF_2048_iszilch(r[i], FFLEN_2048))
        {
            printf("FAILURE HDLOG_iter_values_kill at %d\n", i);
            exit(EXIT_FAILURE);
        }
    }

    MODULUS_kill(&m);
    FF_2048_zero(ws1, FFLEN_2048);
    FF_2048_zero(ws2, FFLEN_2048);
    FF_2048_zero(ord, FFLEN_2048);
    FF_2048_zero(alpha, FFLEN_2048);

    OCT_clear(&P);
    OCT_clear(&Q);

    printf("SUCCESS\n");
    exit(EXIT_SUCCESS);
}
