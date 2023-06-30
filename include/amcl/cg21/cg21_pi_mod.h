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



#include <amcl/amcl.h>
#include <amcl/big_512_60.h>
#include <amcl/ff_4096.h>
#include <amcl/paillier.h>
#include "cg21_utilities.h"
#include "amcl/shamir.h"
#include "amcl/modulus.h"

typedef struct
{
    BIG_1024_58 yi[CG21_PAILLIER_PROOF_ITERS][FFLEN_2048];
    BIG_1024_58 xi[CG21_PAILLIER_PROOF_ITERS][FFLEN_2048];
    BIG_1024_58 zi[CG21_PAILLIER_PROOF_ITERS][FFLEN_2048];
    BIG_512_60 w[HFLEN_4096];
    bool ab[CG21_PAILLIER_PROOF_ITERS][2];
} CG21_PIMOD_PROOF;

typedef struct
{
    octet *w;
    octet *x;
    octet *z;
    octet *ab;
} CG21_PIMOD_PROOF_OCT;

#define iLEN 32

/**	@brief Generate proof that N is a Paillier-Blum modulus
*
*  1: choose random w ← ZN of Jacobi symbol −1
*  2: generate (ai,bi,xi)
*  3: generate zi
*
*  @param RNG               is a pointer to a cryptographically secure random number generator
*  @param paillierKeys
*  @param ssid              system-wide session-ID, refers to the same notation as in CG21
*  @param paillierProof     generated proof
*  @param n                 size of packed elements in SSID
*/
extern int CG21_PI_MOD_PROVE(csprng *RNG, CG21_PAILLIER_KEYS paillierKeys, const CG21_SSID *ssid,
                             CG21_PIMOD_PROOF_OCT *paillierProof, int n);

/**	@brief Validate proofs that N is a Paillier-Blum modulus
*
*  1: check N is an odd composite number
*  2: generate yi and validate zi
*  3: validate (xi,a,b)
*
*  @param paillierProof     generated proof
*  @param ssid              system-wide session-ID, refers to the same notation as in CG21
*  @param pk                Paillier public key
*  @param n                 size of packed elements in SSID
*/
extern int CG21_PI_MOD_VERIFY(CG21_PIMOD_PROOF_OCT *paillierProof, const CG21_SSID *ssid,
                              PAILLIER_public_key pk, int n);