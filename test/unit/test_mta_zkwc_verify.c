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

#include <string.h>
#include "test.h"
#include "amcl/mta.h"

/* MTA Receiver ZK Proof with check verification unit tests */

#define LINE_LEN 2048

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_mta_zkwc_verify [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int rc;
    int test_run = 0;

    char err_msg[128];

    FILE *fp;
    char line[LINE_LEN] = {0};

    const char *TESTline = "TEST = ";
    int testNo = 0;

    MTA_ZKWC_commitment c;
    const char *Uline  = "U = ";
    const char *Zline  = "Z = ";
    const char *Z1line = "Z1 = ";
    const char *Tline  = "T = ";
    const char *Vline  = "V = ";
    const char *Wline  = "W = ";

    COMMITMENTS_BC_priv_modulus mod;
    const char *PTline = "PT = ";
    const char *QTline = "QT = ";
    const char *H1line = "H1 = ";
    const char *H2line = "H2 = ";

    MTA_ZKWC_proof proof;
    const char *Sline  = "S = ";
    const char *S1line = "S1 = ";
    const char *S2line = "S2 = ";
    const char *T1line = "T1 = ";
    const char *T2line = "T2 = ";

    char x[EGS_SECP256K1 + 1];
    octet X = {0, sizeof(x), x};
    const char *Xline = "ECPX = ";

    char c1[2*FS_2048];
    octet C1 = {0, sizeof(c1), c1};
    const char *C1line = "C1 = ";

    char c2[2*FS_2048];
    octet C2 = {0, sizeof(c2), c2};
    const char *C2line = "C2 = ";

    char e[MODBYTES_256_56];
    octet E = {0, sizeof(e), e};
    const char *Eline = "E = ";

    char p[HFS_2048];
    octet P = {0, sizeof(p), p};
    const char *Pline = "P = ";

    char q[HFS_2048];
    octet Q = {0, sizeof(q), q};
    const char *Qline = "Q = ";

    PAILLIER_private_key priv;
    PAILLIER_public_key pub;

    MTA_ZKWC_proof tmp;
    ECP_SECP256K1 G;

    // Make sure proof is properly zeroed before starting test
    FF_2048_zero(proof.s1, FFLEN_2048);

    // Line terminating a test vector
    const char *last_line = Uline;

    /* Test happy path using test vectors */
    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        scan_int(&testNo, line, TESTline);

        // Read inputs
        scan_OCTET(fp, &C1, line, C1line);
        scan_OCTET(fp, &C2, line, C2line);
        scan_OCTET(fp, &X,  line, Xline);
        scan_OCTET(fp, &E,  line, Eline);
        scan_OCTET(fp, &P,  line, Pline);
        scan_OCTET(fp, &Q,  line, Qline);

        scan_FF_2048(fp, mod.b0, line, H1line, FFLEN_2048);
        scan_FF_2048(fp, mod.b1, line, H2line, FFLEN_2048);
        scan_FF_2048(fp, mod.P, line, PTline, HFLEN_2048);
        scan_FF_2048(fp, mod.Q, line, QTline, HFLEN_2048);

        scan_FF_2048(fp, c.zkc.z,  line, Zline,  FFLEN_2048);
        scan_FF_2048(fp, c.zkc.z1, line, Z1line, FFLEN_2048);
        scan_FF_2048(fp, c.zkc.t,  line, Tline,  FFLEN_2048);
        scan_FF_2048(fp, c.zkc.v,  line, Vline,  2 * FFLEN_2048);
        scan_FF_2048(fp, c.zkc.w,  line, Wline,  FFLEN_2048);

        scan_ECP_SECP256K1(fp, &(c.U), line, Uline);

        scan_FF_2048(fp, proof.s,  line, Sline,  FFLEN_2048);
        scan_FF_2048(fp, proof.s1, line, S1line, HFLEN_2048);
        scan_FF_2048(fp, proof.s2, line, S2line, FFLEN_2048 + HFLEN_2048);
        scan_FF_2048(fp, proof.t1, line, T1line, FFLEN_2048);
        scan_FF_2048(fp, proof.t2, line, T2line, FFLEN_2048 + HFLEN_2048);

        if (!strncmp(line, last_line, strlen(last_line)))
        {
            PAILLIER_KEY_PAIR(NULL, &P, &Q, &pub, &priv);

            rc = MTA_ZKWC_verify(&priv, &mod, &C1, &C2, &X, &E, &c, &proof);

            sprintf(err_msg, "MTA_ZKWC_verify OK. rc %d", rc);
            assert_tv(fp, testNo, err_msg, rc == MTA_OK);

            // Mark that at least one test vector was executed
            test_run = 1;
        }
    }

    fclose(fp);

    if (test_run == 0)
    {
        printf("ERROR no test vector was executed\n");
        exit(EXIT_FAILURE);
    }

    /* Test unhappy paths */

    FF_2048_copy(tmp.s,  proof.s,  FFLEN_2048);
    FF_2048_copy(tmp.s1, proof.s1, FFLEN_2048);
    FF_2048_copy(tmp.s2, proof.s2, FFLEN_2048 + HFLEN_2048);
    FF_2048_copy(tmp.t1, proof.t1, FFLEN_2048);
    FF_2048_copy(tmp.t2, proof.t2, FFLEN_2048 + HFLEN_2048);

    rc = MTA_ZKWC_verify(&priv, &mod, &C1, &C2, &X, &E, &c, &tmp);
    assert(NULL, "ERROR copying proof for unhappy path test\n", rc == MTA_OK);

    // Test wrong Base proof
    FF_2048_copy(tmp.s1, tmp.s2, FFLEN_2048);

    rc = MTA_ZKWC_verify(&priv, &mod, &C1, &C2, &X, &E, &c, &tmp);
    sprintf(err_msg, "FAILURE MTA_ZKWC_verify s1 too long. rc %d\n", rc);
    assert(NULL, err_msg, rc == MTA_FAIL);

    // Test X invalid ECP
    rc = MTA_ZKWC_verify(&priv, &mod, &C1, &C2, &E, &E, &c, &proof);
    sprintf(err_msg, "FAILURE MTA_ZKWC_verify X invalid ECP. rc %d\n", rc);
    assert(NULL, err_msg, rc == MTA_INVALID_ECP);

    // Test X invalid value
    ECP_SECP256K1_generator(&G);
    ECP_SECP256K1_toOctet(&X, &G, 1);

    rc = MTA_ZKWC_verify(&priv, &mod, &C1, &C2, &X, &E, &c, &proof);
    sprintf(err_msg, "FAILURE MTA_ZKWC_verify X invalid value. rc %d\n", rc);
    assert(NULL, err_msg, rc == MTA_FAIL);

    printf("SUCCESS");
    exit(EXIT_SUCCESS);
}
