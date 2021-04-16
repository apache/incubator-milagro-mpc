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

/*
 * Test utilities declarations
 */

#ifndef TEST_H
#define TEST_H

#include "amcl/amcl.h"
#include "amcl/big_256_56.h"
#include "amcl/ff_2048.h"
#include "amcl/ff_4096.h"
#include "amcl/ecp_SECP256K1.h"
#include "amcl/hidden_dlog.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*! \brief Read string into an octet
 *
 *  @param  fp      TV file pointer to close in case of error
 *  @param  OCT     Output octet
 *  @param  string  Input string
 */
extern void read_OCTET(FILE *fp, octet *OCT, char *string);

/*! \brief Read string into an octet array
 *
 *  @param  fp        TV file pointer to close in case of error
 *  @param  OCT_ARRAY Output octet
 *  @param  string    Input string
 *  @param  n         Length of the array to read
 */
extern void read_OCTET_ARRAY(FILE *fp, octet *OCT_ARRAY, char *string, int n);

/*! \brief Read string into a big_256_56
 *
 *  @param  fp      TV file pointer to close in case of error
 *  @param  x       Output big
 *  @param  string  Input string
 */
extern void read_BIG_256_56(FILE *fp, BIG_256_56 x, char *string);

/*! \brief Read string into an ff_2048
 *
 *  @param  fp      TV file pointer to close in case of error
 *  @param  x       Output ff element
 *  @param  string  Input string
 *  @param  n       Length of x in BIGs
 */
extern void read_FF_2048(FILE *fp, BIG_1024_58 *x, char *string, int n);

/*! \brief Read string into an ff_4096
 *
 *  @param  fp      TV file pointer to close in case of error
 *  @param  x       Output ff element
 *  @param  string  Input string
 *  @param  n       Length of x in BIGs
 */
extern void read_FF_4096(FILE *fp, BIG_512_60 *x, char *string, int n);

/*! \brief Read string into an ECP_SECP256K1
 *
 *  @param  fp      TV file pointer to close in case of error
 *  @param  P       Output ECP
 *  @param  string  Input string
 */
extern void read_ECP_SECP256K1(FILE *fp, ECP_SECP256K1 *P, char *string);

/*! \brief Read string into an HDLOG_iter_values
 *
 *  @param  fp      TV file pointer to close in case of error
 *  @param  V       Output values
 *  @param  string  Input string
 */
extern void read_HDLOG_iv(FILE *fp, HDLOG_iter_values V, char *string);

/*! \brief Read integer if the line has the correct prefix
 *
 *  @param  v       Output integer
 *  @param  line    TV line
 *  @param  prefix  Line prefix for the integer to read
 */
extern void scan_int(int *v, char *line, const char *prefix);

/*! \brief Read octet if the line has the correct prefix
 *
 *  @param  fp      TV file pointer to close in case of error
 *  @param  OCT     Output octet
 *  @param  line    TV line
 *  @param  prefix  Line prefix for the octet to read
 */
extern void scan_OCTET(FILE *fp, octet *OCT, char *line, const char *prefix);

/*! \brief Read octet array if the line has the correct prefix
 *
 *  @param  fp        TV file pointer to close in case of error
 *  @param  OCT_ARRAY Output octet array
 *  @param  line      TV line
 *  @param  prefix    Line prefix for the octet to read
 *  @param  n         Length of the array to read
 */
extern void scan_OCTET_ARRAY(FILE *fp, octet *OCT_ARRAY, char *line, const char *prefix, int n);

/*! \brief Read big_256_56 if the line has the correct prefix
 *
 *  @param  fp      TV file pointer to close in case of error
 *  @param  x       Output big
 *  @param  line    TV line
 *  @param  prefix  Line prefix for the element to read
 */
extern void scan_BIG_256_56(FILE *fp, BIG_256_56 x, char *line, const char *prefix);

/*! \brief Read ff_2048 element if the line has the correct prefix
 *
 *  @param  fp      TV file pointer to close in case of error
 *  @param  x       Output ff element
 *  @param  line    TV line
 *  @param  prefix  Line prefix for the element to read
 *  @param  n       Length of x in BIGs
 */
extern void scan_FF_2048(FILE *fp, BIG_1024_58 *x, char *line, const char *prefix, int n);

/*! \brief Read ff_4096 element if the line has the correct prefix
 *
 *  @param  fp      TV file pointer to close in case of error
 *  @param  x       Output ff element
 *  @param  line    TV line
 *  @param  prefix  Line prefix for the element to read
 *  @param  n       Length of x in BIGs
 */
extern void scan_FF_4096(FILE *fp, BIG_512_60 *x, char *line, const char *prefix, int n);

/*! \brief Read string into an ECP_SECP256K1
 *
 *  @param  fp      TV file pointer to close in case of error
 *  @param  P       Output ECP
 *  @param  line    TV line
 *  @param  prefix  Line prefix for the element to read
 */
extern void scan_ECP_SECP256K1(FILE *fp, ECP_SECP256K1 *P, char *line, const char *prefix);

/*! \brief Read string into an HDLOG_iter_values
 *
 *  @param  fp      TV file pointer to close in case of error
 *  @param  V       Output values
 *  @param  line    TV line
 *  @param  prefix  Line prefix for the element to read
 */
extern void scan_HDLOG_iv(FILE *fp, HDLOG_iter_values V, char *line, const char *prefix);

/* Assertion utilities */

/*! \brief Compare two octets
 *
 *  Compare two octets and fail the test if they are not equal
 *
 *  @param  fp      TV file pointer to close in case of failure
 *  @param  testNo  Test Vector identifier
 *  @param  name    Descriptor for the elements compared
 *  @param  X       First octet to compare
 *  @param  Y       Second octet to compare
 */
extern void compare_OCT(FILE *fp, int testNo, char *name, octet *X, octet *Y);

/*! \brief Compare two big_256_56 elements
 *
 *  Compare two big_s and fail the test if they are not equal
 *
 *  @param  fp      TV file pointer to close in case of failure
 *  @param  testNo  Test Vector identifier
 *  @param  name    Descriptor for the elements compared
 *  @param  x       First element to compare
 *  @param  y       Second element to compare
 */
extern void compare_BIG_256_56(FILE *fp, int testNo, char* name, BIG_256_56 x, BIG_256_56 y);

/*! \brief Compare two ff_2048 elements
 *
 *  Compare two ff_2048 elements and fail the test if they are not equal
 *
 *  @param  fp      TV file pointer to close in case of failure
 *  @param  testNo  Test Vector identifier
 *  @param  name    Descriptor for the elements compared
 *  @param  X       First element to compare
 *  @param  Y       Second element to compare
 *  @param  n       Length of x, y in BIGs
 */
extern void compare_FF_2048(FILE *fp, int testNo, char* name, BIG_1024_58 *x, BIG_1024_58 *y, int n);

/*! \brief Compare two ff_4096 elements
 *
 *  Compare two ff_4096 elements and fail the test if they are not equal
 *
 *  @param  fp      TV file pointer to close in case of failure
 *  @param  testNo  Test Vector identifier
 *  @param  name    Descriptor for the elements compared
 *  @param  X       First element to compare
 *  @param  Y       Second element to compare
 *  @param  n       Length of x, y in BIGs
 */
extern void compare_FF_4096(FILE *fp, int testNo, char* name, BIG_512_60 *x, BIG_512_60 *y, int n);

/*! \brief Compare two ECP_SECP256K1 elements
 *
 *  Compare two ECP and fail the test if they are not equal
 *
 *  @param  fp      TV file pointer to close in case of failure
 *  @param  testNo  Test Vector identifier
 *  @param  name    Descriptor for the elements compared
 *  @param  P       First element to compare
 *  @param  Q       Second element to compare
 */
extern void compare_ECP_SECP256K1(FILE *fp, int testNo, char* name, ECP_SECP256K1 *P, ECP_SECP256K1 *Q);

/*! \brief Compare two HDLOG_iter_values
 *
 *  @param  fp      TV file pointer to close in case of error
 *  @param  testNo  Test Vector identifier
 *  @param  name    Descriptor for the elements compared
 *  @param  V       First element to compare
 *  @param  R       Second element to compare
 */
extern void compare_HDLOG_iv(FILE *fp, int testNo, char* name, HDLOG_iter_values V, HDLOG_iter_values R);

/*! \brief Assert boolean statement
 *
 *  Assert boolean statement and fail the test if does not hold
 *
 *  @param  fp              TV file pointer to close in case of failure
 *  @param  msg             Error message in case of failure
 *  @param  statement       Boolean statement to assert
 */
extern void assert(FILE *fp, char *msg, int statement);

/*! \brief Assert boolean statement associated to a TV
 *
 *  Assert boolean statement and fail the test if does not hold
 *
 *  @param  fp              TV file pointer to close in case of failure
 *  @param  testNo          Test Vector identifier
 *  @param  name            Descriptor for the statement asserted
 *  @param  statement       Boolean statement to assert
 */
extern void assert_tv(FILE *fp, int testNo, char* name, int statement);

#ifdef __cplusplus
}
#endif

#endif
