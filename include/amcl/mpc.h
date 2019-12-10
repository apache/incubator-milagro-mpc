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

/**
 * @file mpc.h
 * @brief MPC declarations
 *
 */

#ifndef MPC_H
#define MPC_H

#include <amcl/amcl.h>

#ifdef __cplusplus
extern "C" {
#endif


/*! \brief Truncates an octet string
 *
 *  Add the top x->len bytes of y to x
 *
 *  @param  y       Output octet
 *  @param  x       Input octet
 *  @return         Returns 0 or else error code
 */
void OCT_truncate(octet *y,octet *x);

/** \brief ECDSA Signature
 *
 *  Generate the ECDSA signature on message, M, with outputs (R,S)
 *
 *  <ol>
 *  <li> Choose a random non-zero value \f$ k \in  F_q \f$ where \f$q\f$ is the curve order
 *  <li> \f$ r_x, r_y = k^{-1}G \f$ where G is the group generator
 *  <li> \f$ r = rx \text{ }\mathrm{mod}\text{ }q \f$
 *  <li> \f$ z = hash(message) \f$
 *  <li> \f$ s = k.(z + r.sk) \text{ }\mathrm{mod}\text{ }q \f$ where \f$ sk \f$ is the ECDSA secret key
 *  </ol>
 *
 *  @param sha is the hash type
 *  @param K Ephemeral key.
 *  @param SK the input private signing key
 *  @param M the input message to be signed
 *  @param R component of the signature
 *  @param D component of the signature
 */
int MPC_ECDSA_SIGN(int sha, octet *K, octet *SK, octet *M, octet *R, octet *S);

/*! \brief Client MTA first pass
 *
 *  Encrypt multplicative share, \f$ a \f$, of secret \f$ s = a.b \f$
 *
 *  @param  RNG              Pointer to a cryptographically secure random number generator
 *  @param  N                Public key
 *  @param  G                Public key
 *  @param  A                Multiplicative share of secret
 *  @param  CA               Ciphertext
 *  @param  R                R value for testing. If RNG is NULL then this value is read.
 *  @return                  Returns 0 or else error code
 */
int MPC_MTA_CLIENT1(csprng *RNG, octet* N, octet* G, octet* A, octet* CA, octet* R);

/*! \brief Client MtA second pass
 *
 *  Calculate additive share, \f$ \alpha \f$, of secret \f$ s = a.b \f$
 *
 *  <ol>
 *  <li> Choose a random non-zero value \f$ z \in  F_q \f$ where \f$q\f$ is the curve order
 *  <li> \f$ \alpha = D_A(cb) = D_A(E_A(ab + z)) = ab + z \text{ }\mathrm{mod}\text{ }q \f$
 *  </ol>
 *
 *  @param   N                Public key
 *  @param   L                Private key
 *  @param   M                Private key
 *  @param   CB               Ciphertext
 *  @param   ALPHA            Additive share of secret
 *  @return                   Returns 0 or else error code
 */
int MPC_MTA_CLIENT2(octet* N, octet* L, octet* M, octet* CB, octet* ALPHA);

/*! \brief Server MtA
 *
 *  Calculate additive share, \f$ \beta \f$, of secret \f$ s = a.b \f$ and
 *  ciphertext allowing client to calculate their additive share.
 *
 *  <ol>
 *  <li> Choose a random non-zero value \f$ z \in  F_q \f$ where \f$q\f$ is the curve order
 *  <li> \f$ \beta = -z\text{ }\mathrm{mod}\text{ }q \f$
 *  <li> \f$ cb = ca \otimes{} b \oplus{} z = E_A(ab + z) \f$
 *  </ol>
 *
 *  @param   RNG              Pointer to a cryptographically secure random number generator
 *  @param   N                Public key
 *  @param   G                Public key
 *  @param   B                Multiplicative share of secret
 *  @param   CA               Ciphertext of client's additive share of secret
 *  @param   Z                Plaintext z value (see above)
 *  @param   R                R value for testing. If RNG is NULL then this value is read.
 *  @param   CB               Ciphertext
 *  @param   BETA             Additive share of secret (see above)
 *  @return                   Returns 0 or else error code
 */
int MPC_MTA_SERVER(csprng *RNG, octet* N, octet* G, octet* B, octet* CA, octet* Z, octet* R, octet* CB, octet* BETA);

/** \brief Sum of secret shares
 *
 *  Sum of secret shares
 *
 *  <ol>
 *  <li> \f$ sum  = a.b + \alpha{}1 + \beta{}1 + \alpha{}2 + \beta{}2 \text{ }\mathrm{mod}\text{ }q \f$
 *  </ol>
 *
 *  @param A                  A1 value
 *  @param B                  B1 value
 *  @param ALPHA1             Additive share of A1.B2
 *  @param BETA1              Additive share of A2.B1
 *  @param ALPHA2             Additive share of A1.B3
 *  @param BETA2              Additive share of A3.B1
 *  @param SUM                The sum of all values
 *  @return                   Returns 0 or else error code
 */
int MPC_SUM(octet *A, octet *B, octet *ALPHA1, octet *BETA1, octet *ALPHA2, octet *BETA2, octet *SUM);

/** \brief Calculate the inverse of the sum of kgamma values
 *
 *  Calculate the inverse of the sum of kgamma values
 *
 *  <ol>
 *  <li> \f$ invkgamma = (kgamma1 + kgamma2 + kgamma3)^{-1} \text{ }\mathrm{mod}\text{ }q \f$
 *  </ol>
 *
 *  @param KGAMMA1            Actor 1 additive share
 *  @param KGAMMA2            Actor 2 additive share
 *  @param KGAMMA3            Actor 3 additive share
 *  @param INVKGAMMA          Inverse of the sum of the additive shares
 *  @return                   Returns 0 or else error code
 */
int MPC_INVKGAMMA(octet *KGAMMA1, octet *KGAMMA2, octet *KGAMMA3, octet *INVKGAMMA);

/** \brief R component
 *
 *  Generate the ECDSA signature R component
 *
 *  <ol>
 *  <li> \f$ r_x, r_y = k^{-1}G \f$ where G is the group generator
 *  <li> \f$ r = rx \text{ }\mathrm{mod}\text{ }q \f$
 *  </ol>
 *
 *  @param                    Inverse of k times gamma
 *  @param                    Actor 1 gamma point
 *  @param                    Actor 2 gamma point
 *  @param                    Actor 3 gamma point
 *  @param                    R component of the signature
 *  @return                   Returns 0 or else error code
 */
int MPC_R(octet *INVKGAMMA, octet *GAMMAPT1, octet *GAMMAPT2, octet *GAMMAPT3, octet *R);

#ifdef __cplusplus
}
#endif

#endif
