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

#include "amcl/cg21/cg21_pi_prm.h"

static void CG21_PI_PRM_PROOF_to_OCT(CG21_PIPRM_PROOF *proof, CG21_PIPRM_PROOF_OCT *proofOct){
    HDLOG_iter_values_toOctet(proofOct->rho, proof->rho);
    HDLOG_iter_values_toOctet(proofOct->irho, proof->irho);
    HDLOG_iter_values_toOctet(proofOct->t,    proof->t);
    HDLOG_iter_values_toOctet(proofOct->it,   proof->it);
}

int CG21_PI_PRM_PROVE(csprng *RNG, PEDERSEN_PRIV *priv, const CG21_SSID *ssid, CG21_PIPRM_PROOF_OCT *proofOct){

    CG21_PIPRM_PROOF proof;
    HDLOG_iter_values R;

    char e[HDLOG_CHALLENGE_SIZE];
    octet E = {0, sizeof(e), e};

    int n = *ssid->n1;

    /* generate proof for both alpha and ialpha based on FO97:section3.1:setup procedure (step5) */
    // Prove b1 = b0^alpha
    HDLOG_commit(RNG, &priv->mod, priv->pq, priv->b0, R, proof.rho);
    int rc = HDLOG_challenge_CG21(priv->mod.n, priv->b0, priv->b1, proof.rho, (const HDLOG_SSID *) ssid, &E, n);
    if (rc != HDLOG_OK)
    {
        return rc;
    }
    HDLOG_prove(priv->pq, priv->alpha, R, &E, proof.t);

    // Prove b0 = b1 ^ ialpha
    HDLOG_commit(RNG, &priv->mod, priv->pq, priv->b1, R, proof.irho);
    rc = HDLOG_challenge_CG21(priv->mod.n, priv->b1, priv->b0, proof.irho, (const HDLOG_SSID *) ssid, &E, n);
    if (rc != HDLOG_OK)
    {
        return rc;
    }
    HDLOG_prove(priv->pq, priv->ialpha, R, &E, proof.it);

    // Clean memory
    HDLOG_iter_values_kill(R);

    // convert proof to octet
    CG21_PI_PRM_PROOF_to_OCT(&proof, proofOct);

    return CG21_OK;
}

int CG21_PI_PRM_OCT_to_PROOF(CG21_PIPRM_PROOF *proof, CG21_PIPRM_PROOF_OCT *proofOct)
{
    if (HDLOG_iter_values_fromOctet(proof->rho, proofOct->rho) != HDLOG_OK)
    {
        return CG21_PI_PRM_INVALID_FORMAT;
    }

    if (HDLOG_iter_values_fromOctet(proof->irho, proofOct->irho) != HDLOG_OK)
    {
        return CG21_PI_PRM_INVALID_FORMAT;
    }

    if (HDLOG_iter_values_fromOctet(proof->t, proofOct->t) != HDLOG_OK)
    {
        return CG21_PI_PRM_INVALID_FORMAT;
    }

    if (HDLOG_iter_values_fromOctet(proof->it, proofOct->it) != HDLOG_OK)
    {
        return CG21_PI_PRM_INVALID_FORMAT;
    }

    return CG21_OK;
}

int CG21_PI_PRM_VERIFY(PEDERSEN_PUB *pub, const CG21_SSID *ssid, CG21_PIPRM_PROOF_OCT *proofOct, int n){

    CG21_PIPRM_PROOF proof;

    char e[HDLOG_CHALLENGE_SIZE];
    octet E = {0, sizeof(e), e};

    // load proof from octet
    CG21_PI_PRM_OCT_to_PROOF(&proof, proofOct);

    // Verify knowledge of DLOG of b1
    HDLOG_challenge_CG21(pub->N, pub->b0, pub->b1, proof.rho, (const HDLOG_SSID *) ssid, &E, n);
    int rc = HDLOG_verify(pub->N, pub->b0, pub->b1, proof.rho, &E, proof.t);
    if (rc != HDLOG_OK)
    {
        return CG21_PI_PRM_INVALID_PROOF;
    }

    // Verify knowledge of DLOG of b1
    HDLOG_challenge_CG21(pub->N, pub->b1, pub->b0, proof.irho, (const HDLOG_SSID *) ssid, &E, n);
    rc = HDLOG_verify(pub->N, pub->b1, pub->b0, proof.irho, &E, proof.it);
    if (rc != HDLOG_OK)
    {
        return CG21_PI_PRM_INVALID_PROOF;
    }

    return CG21_OK;
}
