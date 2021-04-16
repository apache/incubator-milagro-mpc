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
 * @file modulus.h
 * @brief Declarations for a modulus N = PQ
 *
 */

#ifndef MODULUS_H
#define MODULUS_H

#include "amcl/amcl.h"
#include "amcl/big_1024_58.h"
#include "amcl/ff_2048.h"

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef FS_2048
#define FS_2048 MODBYTES_1024_58 * FFLEN_2048  /**< 2048 field size in bytes */
#endif

#ifndef HFS_2048
#define HFS_2048 MODBYTES_1024_58 * HFLEN_2048 /**< Half 2048 field size in bytes */
#endif

/*! \brief Modulus and precomputed values for CRT */
typedef struct
{
    BIG_1024_58 p[HFLEN_2048];     /**< First factor of the modulus */
    BIG_1024_58 q[HFLEN_2048];     /**< Second factor of the modulus */
    BIG_1024_58 invpq[HFLEN_2048]; /**< Precomputed inverse for CRT */
    BIG_1024_58 n[FFLEN_2048];     /**< Modulus */
} MODULUS_priv;

/** \brief Read a modulus from octets
 *
 *  @param  m           The destination modulus
 *  @param  P           The first factor of the modulus
 *  @param  Q           The second factor of the modulus
 */
void MODULUS_fromOctets(MODULUS_priv *m, octet *P, octet *Q);

/** \brief Write a modulus to octets
 *
 *  @param  P           The destination first factor of the modulus
 *  @param  Q           The destination second factor of the modulus
 *  @param  m           The source modulus
 */
void MODULUS_toOctets(octet *P, octet *Q, MODULUS_priv *m);

/** \brief Clean memory associated to a modulus
 *
 *  @param  m           The modulus to clean
 */
void MODULUS_kill(MODULUS_priv *m);

#ifdef __cplusplus
}
#endif

#endif
