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
 * @file hash_utils.h
 * @brief Hash utility functions for pseudorandom challenge generation
 *
 */

#ifndef HASH_UTILS
#define HASH_UTILS

#include "amcl/amcl.h"
#include "amcl/big_256_56.h"
#include "amcl/modulus.h"

#ifdef __cplusplus
extern "C"
{
#endif

/** \brief Copy the internal state of an hash function
 *
 *  @param  dst         Destination hash function. It does not need to be initialised
 *  @param  src         Source hash function
 */
extern void HASH_UTILS_hash_copy(hash256 *dst, const hash256 *src);

/** \brief Process an octet into an hash function
 *
 *  @param  sha         Hash function. Must be initialised
 *  @param  O           Octet to process
 */
extern void HASH_UTILS_hash_oct(hash256 *sha, const octet *O);

/** \brief Process a 4 bytes integer into an hash function
 *
 *  Convert i as a 4 bytes integer using PKCS#1 I2OSP [RFC2437 # Section 4.1]
 *  Process the resulting bytes into the provided hash function
 *
 *  @param  sha         Hash function. Must be initialised
 *  @param  i           Integer to process
 */
extern void HASH_UTILS_hash_i2osp4(hash256 *sha, const int i);

/** \brief Sample a pseudorandom FF_2048 from a given hash function
 *
 *  Use the provided function to produce 4096 pseudorandom bits
 *  using PKCS#1 MGF1 [RFC2437 # Section 10.2.1]
 *  Reduce the resulting integer moduls an FF_2048 element.
 *  The extra random data is produced to make the bias in the
 *  resulting distribution negligible.
 *
 *  @param  sha         Hash function. Must be initialised
 *  @param  n           Modulo for the reduction. FF_2048 element.
 *  @param  x           Sampled FF_2048 element
 */
extern void HASH_UTILS_sample_mod_FF(const hash256 *sha, BIG_1024_58 *n, BIG_1024_58 *x);

/** \brief Sample a pseudorandom FP_256 from a given hash function
 *
 *  Produce 256 bit of pseudorandom dqata using the hash function
 *  Reduce the resulting integer moduls an FP_256 element.
 *  The integer is sampled using rejection sampling to remove bias.
 *
 *  @param  sha         Hash function. Must be initialised
 *  @param  q           Modulo for the reduction. FP_256 element.
 *  @param  x           Sampled FP_256 element
 */
extern void HASH_UTILS_rejection_sample_mod_BIG(const hash256 *sha, const BIG_256_56 q, BIG_256_56 x);

#ifdef __cplusplus
}
#endif

#endif
