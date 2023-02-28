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

/* GMR ZKP for a Square Free RSA Modulus */

#include "amcl/hash_utils.h"
#include "amcl/gmr.h"

// Prime buckets necessary for the 10 iterations protocol.
#define GMR_PRIMES_LENGTH 417

const sign32 GMR_primes[GMR_PRIMES_LENGTH] =
{
    111546435,   58642669,  600662303,   33984931,   89809099,  167375713,
    371700317,  645328247, 1070560157, 1596463769,   11592209,   13420567,
    16965341,   20193023,   23300239,   29884301,   35360399,   42749359,
    49143869,   56466073,   65111573,   76027969,   84208541,   94593973,
    103569859,  119319383,  133390067,  154769821,  178433279,  193397129,
    213479407,  229580147,  250367549,  271661713,  293158127,  319512181,
    357349471,  393806449,  422400701,  452366557,  507436351,  547978913,
    575204137,  627947039,  666785731,  710381447,  777767161,  834985999,
    894826021,  951747481, 1019050649, 1072651369, 1125878063, 1185362993,
    1267745273, 1322520163, 1391119619, 1498299287, 1608372013, 1700725291,
    1805418283, 1871456063, 2008071007, 2115193573,    1674427,    1695203,
    1723933,    1752967,    1860487,    1896113,    1971191,    2030621,
    2047757,    2082233,    2108303,    2146189,    2196323,    2214143,
    2238007,    2301253,    2362333,    2405597,    2442953,    2480609,
    2528051,    2572807,    2595317,    2624399,    2663399,    2755591,
    2782223,    2873021,    2903591,    2965283,    3017153,    3062491,
    3125743,    3186221,    3221989,    3301453,    3381857,    3474487,
    3504383,    3526883,    3590989,    3648091,    3732623,    3802499,
    3904567,    3960091,    3992003,    4028033,    4088459,    4137131,
    4235339,    4305589,    4347221,    4384811,    4460543,    4536899,
    4575317,    4613879,    4708819,    4862021,    4915073,    5008643,
    5048993,    5143823,    5184713,    5244091,    5303773,    5391563,
    5475599,    5517797,    5588447,    5659637,    5692987,    5740807,
    5827387,    5904851,    5973127,    6066353,    6125621,    6310063,
    6426209,    6482107,    6522907,    6682189,    6765137,    6859157,
    6969551,    7064963,    7112873,    7182391,    7225343,    7268407,
    7338677,    7376647,    7452899,    7535009,    7617551,    7745053,
    7806427,    7851203,    7986227,    8065591,    8145307,    8236819,
    8363639,    8444827,    8538059,    8678867,    8761591,    8820899,
    8999999,    9090209,    9180851,    9272009,    9388087,    9492557,
    9603701,    9734399,    9922331,   10036223,   10137847,   10220773,
    10323353,   10400609,   10575503,   10614563,   10791029,   10916407,
    10995847,   11062267,   11135533,   11242573,   11329931,   11431097,
    11553137,   11716829,   11923193,   11985443,   12027023,   12215009,
    12348187,   12446783,   12503287,   12559927,   12659363,   12787751,
    12873719,   13032091,   13104391,   13205947,   13329737,   13483583,
    13571807,   13682597,   13793771,   13912891,   14062379,   14197823,
    14333747,   14439991,   14607683,   14745551,   14837903,   14976851,
    15093209,   15280277,   15350723,   15413467,   15499933,   15657749,
    15959989,   16040021,   16128247,   16192567,   16402499,   16524161,
    16687189,   16777207,   16966097,   17065157,   17189267,   17288963,
    17547577,   17757787,   17842151,   17943671,   18045479,   18147599,
    18249983,   18369787,   18593119,   18818243,   18948593,   19079399,
    19307227,   19492189,   19642543,   19793597,   19891591,   20088323,
    20249951,   20385221,   20439437,   20684303,   20830087,   21040553,
    21159991,   21427577,   21538877,   21622499,   21715591,   21864967,
    22061773,   22297283,   22382357,   22610009,   22896221,   22953677,
    23039999,   23184221,   23483491,   23755867,   23970767,   24147371,
    24324623,   24403591,   24542107,   24681023,   24800351,   24960007,
    25060027,   25160231,   25310897,   25553009,   25796237,   25938613,
    26050807,   26173447,   26522491,   26718557,   26873831,   27071173,
    27342437,   27405221,   27741253,   27878399,   28089991,   28259807,
    28515551,   28793731,   29052091,   29192393,   29322221,   29430589,
    29582717,   29658907,   29964667,   30041357,   30272003,   30393133,
    30514567,   30735767,   30980347,   31102913,   31438193,   31809599,
    31911197,   31979021,   32080871,   32330587,   32455793,   32649787,
    32936117,   33016507,   33419957,   33593591,   33756091,   33918967,
    34117277,   34222499,   34327877,   34433423,   34574399,   34809991,
    35105621,   35354867,   35808247,   36108077,   36397073,   36542021,
    36723551,   36917767,   37088099,   37295413,   37527851,   37675019,
    37908613,   38254081,   38452397,   38613787,   38750609,   39087479,
    39262747,   39363067,   39601813,   39765611,   39942391,   40106873,
    40297079,   40449599,   40576891,   40755431,   41075137,   41447723,
    41731519,   41951513,   42327811,   42745363,   42928703,   43112347,
    43217467,   43428019,   43731733,   44155961,   44355599,   44568967,
    44756099,   44916803,   45077771,   45360221,   45724643,   45968399,
    46131263,   46416869,   46621583,   46744553,   47059591,   47196899,
    47485817,   47734277,   48052399,   48358091,   48497287,   48636667,
    48818153,   48985997,   49224247,   49463053,   49702451,   50041451,
    50495227,   50751367,   50979479
};

/*
 * Encode N, ID and AD and fill sha for the challenges generation
 * i.e. N || len(ID) || ID || len(AD) || AD
 * with ID and AD optional
 */
void GMR_prepare_hash(hash256 *sha, BIG_1024_58 *N, const octet *ID, const octet*AD)
{
    char o[FS_2048];
    octet O = {0, sizeof(o), o};

    FF_2048_toOctet(&O, N, FFLEN_2048);

    HASH_UTILS_hash_oct(sha, &O);

    HASH_UTILS_hash_i2osp4(sha, ID->len);
    HASH_UTILS_hash_oct(sha, ID);

    if (AD != NULL)
    {
        HASH_UTILS_hash_i2osp4(sha, AD->len);
        HASH_UTILS_hash_oct(sha, AD);
    }
}

// Copy and complete sha with I2OSP(k) and sample a challenge
void GMR_challenge(hash256 *sha, int k, BIG_1024_58 *N, BIG_1024_58 *X)
{
    hash256 sha_k;

    HASH_UTILS_hash_copy(&sha_k, sha);
    HASH_UTILS_hash_i2osp4(&sha_k, k);

    HASH_UTILS_sample_mod_FF(&sha_k, N, X);
}

void GMR_prove(MODULUS_priv *m, const octet *ID, const octet *AD, GMR_proof Y)
{
    int i;

    hash256 sha;

    BIG_1024_58 Mp[HFLEN_2048], Mq[HFLEN_2048];
    BIG_1024_58 Xp[HFLEN_2048], Xq[HFLEN_2048];
    BIG_1024_58 ws[FFLEN_2048];

    /* Compute Mp, Mq s.t.
     *   M = CRT(Mp, Mq, P-1, Q-1) and
     *   M = N^(-1) mod (P-1)(Q-1)
     *
     * i.e.
     *   Mp = Q^(-1) mod P-1
     *   Mq = P^(-1) mod Q-1
     */

    // Compute Mp

    // Since P is odd P>>1 = (P-1)/2
    FF_2048_copy(ws, m->p, HFLEN_2048);
    FF_2048_shr(ws, HFLEN_2048);

    // Compute inverse mod (P-1)/2
    FF_2048_invmodp(Mp, m->q, ws, HFLEN_2048);

    // Apply correction to obtain inverse mod P-1
    if (!FF_2048_parity(Mp))
    {
        FF_2048_add(Mp, ws, Mp, HFLEN_2048);
        FF_2048_norm(Mp, HFLEN_2048);
    }

    // Compute Mq

    // Since Q is odd Q>>1 = (Q-1)/2
    FF_2048_copy(ws, m->q, HFLEN_2048);
    FF_2048_shr(ws, HFLEN_2048);

    // Compute inverse mod (Q-1)/2
    FF_2048_invmodp(Mq, m->p, ws, HFLEN_2048);

    // Apply correction to obtain inverse mod Q-1
    if (!FF_2048_parity(Mq))
    {
        FF_2048_add(Mq, ws, Mq, HFLEN_2048);
        FF_2048_norm(Mq, HFLEN_2048);
    }

    // Prepare hash for Xs generation
    HASH256_init(&sha);
    GMR_prepare_hash(&sha, m->n, ID, AD);

    for(i = 0; i < GMR_PROOF_ITERS; i++)
    {
        // Generate Xk and prepare reduced terms for CRT
        GMR_challenge(&sha, i, m->n, ws);

        FF_2048_dmod(Xp, ws, m->p, HFLEN_2048);
        FF_2048_dmod(Xq, ws, m->q, HFLEN_2048);

        // Compute Xk^M using Mp, Mq and CRT
        FF_2048_ct_pow(Xp, Xp, Mp, m->p, HFLEN_2048, HFLEN_2048);
        FF_2048_ct_pow(Xq, Xq, Mq, m->q, HFLEN_2048, HFLEN_2048);

        FF_2048_crt(Y[i], Xp, Xq, m->p, m->invpq, m->n, HFLEN_2048);
    }
}

int GMR_verify(octet *N, GMR_proof Y, const octet *ID, const octet *AD)
{
    int i, k;

    hash256 sha;

    BIG_1024_58 n[FFLEN_2048];
    BIG_1024_58 x[FFLEN_2048];
    BIG_1024_58 ws[FFLEN_2048];

    FF_2048_fromOctet(n, N, FFLEN_2048);

    // Check N parity since the buckets must be odd
    // for cfactor to work
    if (FF_2048_parity(n) == 0)
    {
        return GMR_FAIL;
    }

    // Common factor check with prime buckets
    for (k = 0; k < GMR_PRIMES_LENGTH; k++)
    {
        // These values are all public so it is ok to
        // terminate early
        if (FF_2048_cfactor(n, GMR_primes[k], FFLEN_2048))
        {
            return GMR_FAIL;
        }
    }

    // Prepare hash for Xs generation
    HASH256_init(&sha);
    GMR_prepare_hash(&sha, n, ID, AD);

    // Generate each Xk and compute Yk^N
    for(i = 0; i < GMR_PROOF_ITERS; i++)
    {
        GMR_challenge(&sha, i, n, x);

        FF_2048_nt_pow(ws, Y[i], n, n, FFLEN_2048, FFLEN_2048);

        // These values are all public so it is ok to
        // terminate early
        if (FF_2048_comp(ws, x, FFLEN_2048) != 0)
        {
            return GMR_FAIL;
        }
    }

    return GMR_OK;
}

void GMR_proof_toOctet(octet *O, GMR_proof p)
{
    int i;

    char w[FS_2048];
    octet W = {0, sizeof(w), w};

    OCT_clear(O);

    for (i = 0; i < GMR_PROOF_ITERS; i++)
    {
        FF_2048_toOctet(&W, p[i], FFLEN_2048);
        OCT_joctet(O, &W);
    }
}

int GMR_proof_fromOctet(GMR_proof p, octet *O)
{
    int i;

    char w[FS_2048];
    octet W = {0, sizeof(w), w};

    if (O->len != GMR_PROOF_SIZE)
    {
        return GMR_INVALID_PROOF;
    }

    for (i = GMR_PROOF_ITERS - 1; i >= 0; i--)
    {
        OCT_chop(O, &W, O->len - FS_2048);
        FF_2048_fromOctet(p[i], &W, FFLEN_2048);
    }

    // Restore length of O
    O->len = GMR_PROOF_SIZE;

    return GMR_OK;
}
