#!/usr/bin/env python3

"""
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
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from amcl import core_utils, mpc, schnorr, factoring_zk, commitments

seed_hex = "78d0fb6705ce77dee47d03eb5b9c5d30"


def generate_key_material(rng, player):
    """ Generate Paillier and ECDSA Key Pairs

    Generate key material and commitment to the ECDSA PK.
    The key material dictionary has keys:
     * paillier_sk
     * paillier_pk
     * ecdsa_sk
     * ecdsa_pk

    Args::

        rng: pointer to CSPRNG

    Returns::

        key_material: dictionary with the generated key material

    """
    # Paillier keys
    paillier_pk, paillier_sk = mpc.paillier_key_pair(rng)

    # ECDSA keys
    ecdsa_pk, ecdsa_sk = mpc.mpc_ecdsa_key_pair_generate(rng)
    rc = mpc.ecp_secp256k1_public_key_validate(ecdsa_pk)
    assert rc == 0, f"[{player}] Invalid ECDSA public key. rc {rc}"

    key_material = {
        'paillier_pk' : paillier_pk,
        'paillier_sk' : paillier_sk,
        'ecdsa_pk'    : ecdsa_pk,
        'ecdsa_sk'    : ecdsa_sk
    }

    return key_material


def generate_key_material_zkp(rng, key_material):
    """ Generate ZK Proofs for key material

    Generate a commitment to the ECDSA PK, a Schnorr's
    Proof for the ECDSA PK and a factoring Proof for the
    Paillier PK
    The key material dictionary must have keys:
     * paillier_sk
     * paillier_pk
     * ecdsa_sk
     * ecdsa_pk

    Args::

        rng: pointer to CSPRNG
        key_material: dictionary with the key material

    Returns::

        r:  secret value for the ECDSA PK commitment
        c:  commitment for the ECDSA PK
        sc: commitment for the Schnorr's Proof
        sp: Schnorr's Proof
        fe: Factoring Proof. First component
        fy: Factoring Proof. Second component

    """
    # Commit to ECDSA PK
    r, c = commitments.nm_commit(rng, key_material['ecdsa_pk'])

    # Generate Schnorr's proof for ECDSA PK
    sr, sc = schnorr.commit(rng)
    e = schnorr.challenge(key_material['ecdsa_pk'], sc)
    sp = schnorr.prove(sr, e, key_material['ecdsa_sk'])

    # Generate ZKP of knowledge of factorization for
    # Paillier key pair
    psk_p, psk_q = mpc.mpc_dump_paillier_sk(key_material['paillier_sk'])

    fe, fy = factoring_zk.prove(rng, psk_p, psk_q)

    return r, c, sc, sp, fe, fy


def verify_key_material(key_material, r, c, sc, sp, fe, fy, player):
    """ Verify key material

    Verify the conunterparty key material using the
    proof received
    The key material dictionary must have keys:
     * paillier_pk
     * ecdsa_pk

    Args::

        key_material: dictionary with the key material
        r:  secret value for the ECDSA PK commitment
        c:  commitment for the ECDSA PK
        sc: commitment for the Schnorr's Proof
        sp: Schnorr's Proof
        fe: Factoring Proof. First component
        fy: Factoring Proof. Second component

    Returns::

    """
    # Decommit ECDSA PK
    rc = commitments.nm_decommit(key_material['ecdsa_pk'], r, c)
    assert rc == commitments.OK, f"[{player}] Failure decommitting ecdsa_pk. rc {rc}"

    # Verify ECDSA PK Schnorr's proof
    e = schnorr.challenge(key_material['ecdsa_pk'], sc)
    rc = schnorr.verify(key_material['ecdsa_pk'], sc, e, sp)
    assert rc == schnorr.OK, f"[{player}] Invalid ECDSA PK Schnorr Proof. rc {rc}"

    # Verify factoring ZKP
    n = mpc.paillier_pk_to_octet(key_material['paillier_pk'])
    rc = factoring_zk.verify(n, fe, fy)
    assert rc == factoring_zk.OK, f"[{player}] Invalid Factoring ZKP. rc {rc}"


if __name__ == "__main__":
    seed = bytes.fromhex(seed_hex)
    rng = core_utils.create_csprng(seed)


    ### Key setup ###

    print("Setup Key Material\n")

    # Generate key material
    key_material1 = generate_key_material(rng, "Alice")
    key_material2 = generate_key_material(rng, "Bob")

    print("[Alice] Generate ECDSA and Paillier key pairs")
    print("[Bob] Generate ECDSA and Paillier key pairs")

    # Generate key material ZKP
    r1, c1, sc1, sp1, fe1, fy1 = generate_key_material_zkp(rng, key_material1)
    r2, c2, sc2, sp2, fe2, fy2 = generate_key_material_zkp(rng, key_material2)

    print("[Alice] Generate commitment to ECDSA PK and ZKPs")
    print("[Bob] Generate commitment to ECDSA PK and ZKPs")

    # Commit to ECDSA PK by transmitting c
    print("[Alice] Commit to ECDSA PK. Transmit c")
    print("[Bob] Commit to ECDSA PK. Transmit c")

    # Transmit decommitment and ZKP
    print("[Alice] Transmit decommitment for ECDSA PK and ZKPs")
    print("[Bob] Transmit decommitment for ECDSA PK and ZKPs")

    # Verify decommitment and ZKP
    c_key_material1 = {
        'paillier_pk' : key_material2['paillier_pk'],
        'ecdsa_pk'    : key_material2['ecdsa_pk'],
    }

    c_key_material2 = {
        'paillier_pk' : key_material1['paillier_pk'],
        'ecdsa_pk'    : key_material1['ecdsa_pk'],
    }

    print("[Alice] Verify ZKP")
    verify_key_material(c_key_material1, r2, c2, sc2, sp2, fe2, fy2, "Alice")

    print("[Bob] Verify ZKP")
    verify_key_material(c_key_material2, r1, c1, sc1, sp1, fe1, fy1, "Bob")

    # Recombine full ECDSA PK
    rc, ecdsa_full_pk1 = mpc.mpc_sum_pk(key_material1['ecdsa_pk'], c_key_material1['ecdsa_pk'])
    assert rc == 0, '[Alice] Error recombining full ECDSA PK'

    rc, ecdsa_full_pk2 = mpc.mpc_sum_pk(key_material2['ecdsa_pk'], c_key_material2['ecdsa_pk'])
    assert rc == 0, '[Bob] Error recombining full ECDSA PK'


    ### Signature ###

    # Message
    M = b'test message'

    print(f"\nSign message '{M.encode('utf-8')}'")

    # Generate k, gamma and gamma.G
    print("[Alice] Generate k, gamma and gamma.G")
    GAMMA1, gamma1 = mpc.mpc_ecdsa_key_pair_generate(rng)
    k1 = mpc.mpc_k_generate(rng)

    print("[Bob] Generate k, gamma and gamma.G")
    GAMMA2, gamma2 = mpc.mpc_ecdsa_key_pair_generate(rng)
    k2 = mpc.mpc_k_generate(rng)

    ## Commit to GAMMA1, GAMMA2
    print("[Alice] Commit to GAMMA1")
    GAMMAR1, GAMMAC1 = commitments.nm_commit(rng, GAMMA1)

    print("[Bob] Commit to GAMMA2")
    GAMMAR2, GAMMAC2 = commitments.nm_commit(rng, GAMMA2)

    ## Engage in MTA with k_i, gamma_j

    # k1, gamma2
    print("[Alice] Engage in MTA with shares k1, gamma2")

    ca = mpc.mpc_mta_client1(rng, key_material1['paillier_pk'], k1)
    cb, beta2 = mpc.mpc_mta_server(rng, c_key_material2['paillier_pk'], gamma2, ca)
    alpha1 = mpc.mpc_mta_client2(key_material1['paillier_sk'], cb)

    # k2, gamma1
    print("[Bob] Engage in MTA with shares k2, gamma1")

    ca = mpc.mpc_mta_client1(rng, key_material2['paillier_pk'], k2)
    cb, beta1 = mpc.mpc_mta_server(rng, c_key_material1['paillier_pk'], gamma1, ca)
    alpha2 = mpc.mpc_mta_client2(key_material2['paillier_sk'], cb)

    # Partial sums
    print("[Alice] Combine partial sum delta1 for kgamma")
    delta1 = mpc.mpc_sum_mta(k1, gamma1, alpha1, beta1)

    print("[Bob] Combine partial sum delta2 for kgamma")
    delta2 = mpc.mpc_sum_mta(k2, gamma2, alpha2, beta2)

    ## Engage in MTA with k_i, sk_j

    # k1, sk2
    print("[Alice] Engage in MTA with k1, s2")
    ca = mpc.mpc_mta_client1(rng, key_material1['paillier_pk'], k1)
    cb, beta2 = mpc.mpc_mta_server(rng, c_key_material2['paillier_pk'], key_material2['ecdsa_sk'], ca)
    alpha1 = mpc.mpc_mta_client2(key_material1['paillier_sk'], cb)

    # k2, sk1
    print("[Bob] Engage in MTA with k2, s1")
    ca = mpc.mpc_mta_client1(rng, key_material2['paillier_pk'], k2)
    cb, beta1 = mpc.mpc_mta_server(rng, c_key_material1['paillier_pk'], key_material1['ecdsa_sk'], ca)
    alpha2 = mpc.mpc_mta_client2(key_material2['paillier_sk'], cb)

    # Partial sums
    print("[Alice] Combine partial sum sigma1 for kw")
    sigma1 = mpc.mpc_sum_mta(k1, key_material1['ecdsa_sk'], alpha1, beta1)

    print("[Bob] Combine partial sum sigma2 for kw")
    sigma2 = mpc.mpc_sum_mta(k2, key_material2['ecdsa_sk'], alpha2, beta2)

    ## Decommitment and Proofs for R component

    # Generate Schnorr's Proofs
    print("[Alice] Generate Schnorr's Proof")
    GAMMA_schnorr_r1, GAMMA_schnorr_c1 = schnorr.commit(rng)
    GAMMA_schnorr_e1 = schnorr.challenge(GAMMA1, GAMMA_schnorr_c1)
    GAMMA_schnorr_p1 = schnorr.prove(GAMMA_schnorr_r1, GAMMA_schnorr_e1, gamma1)

    print("[Bob] Generate Schnorr's Proof")
    GAMMA_schnorr_r2, GAMMA_schnorr_c2 = schnorr.commit(rng)
    GAMMA_schnorr_e2 = schnorr.challenge(GAMMA2, GAMMA_schnorr_c2)
    GAMMA_schnorr_p2 = schnorr.prove(GAMMA_schnorr_r2, GAMMA_schnorr_e2, gamma2)

    print("[Alice] Transmit decommitment and Schnorr Proof for GAMMA1")
    print("[Bob] Transmit decommitment and Schnorr Proof for GAMMA2")

    # Decommit GAMMAi and verify Schnorr Proof
    rc = commitments.nm_decommit(GAMMA2, GAMMAR2, GAMMAC2)
    assert rc == commitments.OK, f'[Alice] Error decommitting GAMMA2. rc {rc}'

    GAMMA_schnorr_e2 = schnorr.challenge(GAMMA2, GAMMA_schnorr_c2)
    rc = schnorr.verify(GAMMA2, GAMMA_schnorr_c2, GAMMA_schnorr_e2, GAMMA_schnorr_p2)
    assert rc == schnorr.OK, f'[Alice] Error verifying Schnorr proof for GAMMA2'

    rc = commitments.nm_decommit(GAMMA1, GAMMAR1, GAMMAC1)
    assert rc == commitments.OK, f'[Bob] Error decommitting GAMMA1. rc {rc}'

    GAMMA_schnorr_e1 = schnorr.challenge(GAMMA1, GAMMA_schnorr_c1)
    rc = schnorr.verify(GAMMA1, GAMMA_schnorr_c1, GAMMA_schnorr_e1, GAMMA_schnorr_p1)
    assert rc == schnorr.OK, f'[Bob] Error verifying Schnorr proof for GAMMA1'

    ## Reconcile R component
    print("[Alice] Recombine kgamma^(-1)")
    ikgamma1 = mpc.mpc_invkgamma(delta1, delta2)
    rc, R1, _ = mpc.mpc_r(ikgamma1, GAMMA1, GAMMA2)
    assert rc == 0, f'[Alice] Error reconciling R. rc {rc}'

    print("[Bob] Recombine kgamma^(-1)")
    ikgamma2 = mpc.mpc_invkgamma(delta1, delta2)
    rc, R2, _ = mpc.mpc_r(ikgamma2, GAMMA1, GAMMA2)
    assert rc == 0, f'[Bob] Error reconciling R. rc {rc}'

    ## Compute signature shares
    hm = mpc.mpc_hash(M)

    rc, s1 = mpc.mpc_s(hm, R1, k1, sigma1)
    assert rc == 0, f'[Alice] Error computing signature share s1'

    rc, s2 = mpc.mpc_s(hm, R2, k2, sigma2)
    assert rc == 0, f'[Bob] Error computing signature share s1'

    ## Reconcile S component

    # Commit to signature shares
    print("[Alice] Transmit commitment signature share s1")
    SR1, SC1 = commitments.nm_commit(rng, s1)

    print("[Bob] Transmit commitment signature share s2")
    SR2, SC2 = commitments.nm_commit(rng, s2)

    # Decommit signature shares and combine
    print("[Alice] Decommit s2")
    rc = commitments.nm_decommit(s2, SR2, SC2)
    assert rc == 0, f'[Alice] Error decommitting s2. rc {rc}'

    print("[Bob] Decommit s1")
    rc = commitments.nm_decommit(s1, SR1, SC1)
    assert rc == 0, f'[Bob] Error decommitting s1. rc {rc}'

    print("[Alice] Recombine S component")
    S1 = mpc.mpc_sum_s(s1, s2)

    print("[Bob] Recombine S component")
    S2 = mpc.mpc_sum_s(s1, s2)

    rc = mpc.mpc_ecdsa_verify(hm, ecdsa_full_pk1, R1, S1)
    assert rc == 0, f'[Alice] Invalid reconstructed signature'

    rc = mpc.mpc_ecdsa_verify(hm, ecdsa_full_pk2, R2, S2)
    assert rc == 0, f'[Bob] Invalid reconstructed signature'

    assert R1 == R2, f'R component is different:\n{R1}\n{R2}'
    assert S1 == S2, f'S component is different:\n{S1}\n{S2}'

    print('\nReconstructed signature')
    print(f'\tR = {R1.hex()}')
    print(f'\tS = {S1.hex()}')
