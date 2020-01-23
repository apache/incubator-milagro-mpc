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
 * @file commitments.h
 * @brief Commitment schemes declarations
 *
 */

#ifndef COMMITMENTS
#define COMMITMENTS

#include "amcl/amcl.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* NM Commitment Scheme API */

/*! \brief Generate a commitment for the value X
 *
 * @param RNG   CSPRNG to use for commitment
 * @param X     Value to commit to
 * @param R     Decommitment value. If RNG is null then this value is read and must be 256 bit long
 * @param C     Commitment value
 */
extern void COMMITMENTS_NM_commit(csprng *RNG, octet *X, octet *R, octet *C);

/*! \brief Decommit the value X
 *
 * @param X     Committed value
 * @param R     Decommitment value. Must be 256 bit long
 * @param C     Commitment value
 * @return      Returns 1 for a valid decommitment, 0 otherwise
 */
extern int COMMITMENTS_NM_decommit(octet* X, octet* R, octet* C);

#ifdef __cplusplus
}
#endif

#endif
