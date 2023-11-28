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
#include "amcl/cg21/cg21_utilities.h"

int teq_(sign32 b,sign32 c)
{
    sign32 x=b^c;
    x-=1;  // if x=0, x now -1
    return (x>>31)&1;
}

void ECP_cmove_local(ECP_SECP256K1 *P, const ECP_SECP256K1 *Q,int d)
{
    FP_SECP256K1_cmove(&(P->x),&(Q->x),d);
#if CURVETYPE_SECP256K1!=MONTGOMERY
    FP_SECP256K1_cmove(&(P->y),&(Q->y),d);
#endif
    FP_SECP256K1_cmove(&(P->z),&(Q->z),d);
}

void ECP_select(ECP_SECP256K1 *P, const ECP_SECP256K1 W[],sign32 b)
{
    ECP_SECP256K1 MP;
    sign32 m=b>>31;
    sign32 babs=(b^m)-m;

    babs=(babs-1)/2;

    ECP_cmove_local(P,&W[0],teq_(babs,0));  // conditional move
    ECP_cmove_local(P,&W[1],teq_(babs,1));
    ECP_cmove_local(P,&W[2],teq_(babs,2));
    ECP_cmove_local(P,&W[3],teq_(babs,3));
    ECP_cmove_local(P,&W[4],teq_(babs,4));
    ECP_cmove_local(P,&W[5],teq_(babs,5));
    ECP_cmove_local(P,&W[6],teq_(babs,6));
    ECP_cmove_local(P,&W[7],teq_(babs,7));

    ECP_SECP256K1_copy(&MP,P);
    ECP_SECP256K1_neg(&MP);  // minus P
    ECP_cmove_local(P,&MP,m&1);
}

void ECP_mul_1024(ECP_SECP256K1 *P,BIG_1024_58 e[HFLEN_2048])
{
    /* fixed size windows */
    int nb;
    int s;
    int ns;
    BIG_1024_58 mt[HFLEN_2048];
    BIG_1024_58 t[HFLEN_2048];
    ECP_SECP256K1 Q;
    ECP_SECP256K1 W[8];
    ECP_SECP256K1 C;

    int w[1+(4*NLEN_256_56*BASEBITS_256_56+3)/4];

    if (ECP_SECP256K1_isinf(P)) {
        return;
    }

    if (BIG_1024_58_iszilch(*e))
    {
        ECP_SECP256K1_inf(P);
        return;
    }

    ECP_SECP256K1_affine(P);

    /* precompute table */

    ECP_SECP256K1_copy(&Q,P);
    ECP_SECP256K1_dbl(&Q);

    ECP_SECP256K1_copy(&W[0],P);

    for (int i=1; i<8; i++)
    {
        ECP_SECP256K1_copy(&W[i],&W[i-1]);
        ECP_SECP256K1_add(&W[i],&Q);
    }

    /* make exponent odd - add 2P if even, P if odd */
    BIG_1024_58_copy(*t,*e);
    s=BIG_1024_58_parity(*t);
    BIG_1024_58_inc(*t,1);
    BIG_1024_58_norm(*t);
    ns=BIG_1024_58_parity(*t);
    BIG_1024_58_copy(*mt,*t);
    BIG_1024_58_inc(*mt,1);
    BIG_1024_58_norm(*mt);
    BIG_1024_58_cmove(*t,*mt,s);
    ECP_cmove_local(&Q,P,ns);

    ECP_SECP256K1_copy(&C,&Q);

    nb = 1+ (BIGBITS_1024_58+3)/4;

    /* convert exponent to signed 4-bit window */
    for (int i=0; i<nb; i++)
    {
        w[i]=BIG_1024_58_lastbits(*t,5)-16;
        BIG_1024_58_dec(*t,w[i]);
        BIG_1024_58_norm(*t);
        BIG_1024_58_fshr(*t,4);
    }

    w[nb]=BIG_1024_58_lastbits(*t,5);
    ECP_SECP256K1_copy(P,&W[(w[nb]-1)/2]);

    for (int i=nb-1; i>=0; i--)
    {
        ECP_select(&Q,W,w[i]);
        ECP_SECP256K1_dbl(P);
        ECP_SECP256K1_dbl(P);
        ECP_SECP256K1_dbl(P);
        ECP_SECP256K1_dbl(P);
        ECP_SECP256K1_add(P,&Q);
    }
    ECP_SECP256K1_sub(P,&C); /* apply correction */
    ECP_SECP256K1_affine(P);
}

void CG21_hash_pubKey_pubCom(hash256 *sha, PAILLIER_public_key *pub_key, PEDERSEN_PUB *pub_com)
{
    char oct[FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    // Process Paillier Public pub_key
    FF_4096_toOctet(&OCT, pub_key->n, HFLEN_4096);
    HASH_UTILS_hash_oct(sha, &OCT);

    // Process Bit Commitment modulus
    FF_2048_toOctet(&OCT, pub_com->N, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_2048_toOctet(&OCT, pub_com->b0, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_2048_toOctet(&OCT, pub_com->b1, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);
}

void CG21_hash_pubKey2x_pubCom(hash256 *sha, PAILLIER_public_key *pub_keya, PAILLIER_public_key *pub_keyb, PEDERSEN_PUB *pub_com){
    char oct[FS_2048];
    octet OCT = {0, sizeof(oct), oct};

    // Process Paillier Public pub_key
    FF_4096_toOctet(&OCT, pub_keya->n, HFLEN_4096);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_4096_toOctet(&OCT, pub_keyb->n, HFLEN_4096);
    HASH_UTILS_hash_oct(sha, &OCT);

    // Process Bit Commitment modulus
    FF_2048_toOctet(&OCT, pub_com->N, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_2048_toOctet(&OCT, pub_com->b0, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);

    FF_2048_toOctet(&OCT, pub_com->b1, FFLEN_2048);
    HASH_UTILS_hash_oct(sha, &OCT);
}

void CG21_FF_2048_amul(BIG_1024_58 *r, BIG_1024_58 *x, int xlen, BIG_1024_58 *y, int ylen)
{
    int rlen = xlen+ylen;

#ifndef C99
    BIG_1024_58 t[2*FFLEN_2048];
#else
    BIG_1024_58 t[rlen];
#endif

    FF_2048_zero(r, rlen);

    for (int i = 0; i < ylen; i+=xlen)
    {
        FF_2048_zero(t, rlen);
        FF_2048_mul(t+i, x, y+i, xlen);
        FF_2048_add(r, r, t, rlen);
    }
}

/*
 * Check if a number is a safe prime
 */
static bool safe_prime_check(BIG_1024_58 *p, BIG_1024_58 *P, csprng *RNG, int n)
{
#ifndef C99
    BIG_1024_58 Pm1[FFLEN_2048];
    BIG_1024_58 f[FFLEN_2048];
#else
    BIG_1024_58 Pm1[n];
    BIG_1024_58 f[n];
#endif

    // Sieve small primes from P, p is already checked in Miller-Rabin
    sign32 sf=4849845;/* 3*5*.. *19 */

    if(FF_2048_cfactor(P, sf, n))
    {
        return false;
    }

    // Check primality of p
    if (FF_2048_prime(p, RNG, n) == 0)
    {
        return false;
    }

    // Simplified primality check for safe primes using
    // Pocklington's criterion
    //
    // If p is prime, P = 2p+1, 2^(P-1) = 1 mod P, then P is prime
    FF_2048_init(f, 2, n);
    FF_2048_copy(Pm1, P, n);
    FF_2048_dec(Pm1, 1, n);

    FF_2048_nt_pow(f, f, Pm1, P, n, n);
    FF_2048_dec(f, 1, n);
    if (FF_2048_iszilch(f, n))
    {
        return true;
    }

    return false;
}

void safe_prime_gen(csprng *RNG, BIG_1024_58 *p, BIG_1024_58 *P, int n)
{
#ifndef C99
    BIG_1024_58 r[HFLEN_2048];
    BIG_1024_58 twelve[HFLEN_2048];
#else
    BIG_1024_58 r[n];
    BIG_1024_58 twelve[n];
#endif
    FF_2048_init(twelve, 12, n);

    FF_2048_random(p, RNG, n);
    FF_2048_shr(p, n);

    // Make sure p = 11 mod 12
    //
    // p == 3 mod 4 for library
    // p == 2 mod 3 otherwise 3 | P
    //
    // Naive check for now. We can probably benefit from a custom mod3
    // sum((-1)^i * xi mod 3) that spits an integer
    // so we can do the lastbits check + mod3 check but this is negligible
    // compared to the search time
    FF_2048_copy(r, p, n);
    FF_2048_mod(r, twelve, n);
    FF_2048_inc(p, 11, n);
    FF_2048_sub(p, p, r, n);

    // P = 2p + 1
    FF_2048_copy(P, p, n);
    FF_2048_shl(P, n);
    FF_2048_inc(P, 1, n);

    while (!safe_prime_check(p, P, RNG, n))
    {
        // Increase p by 12 to keep it = 11 mod 12, P grows as 2*p
        FF_2048_inc(p, 12, n);
        FF_2048_inc(P, 24, n);
    }
}

void BC_find_generator(csprng *RNG, BIG_1024_58* x, BIG_1024_58 *P, int n)
{
#ifndef C99
    BIG_1024_58 r[FFLEN_2048];
#else
    BIG_1024_58 r[n];
#endif

    FF_2048_randomnum(r, P, RNG, n);

    do
    {
        FF_2048_nt_pow_int(x, r, 2, P, n);
        FF_2048_inc(r, 1, n);
    }
    while (FF_2048_isunity(x, n));
}

void ring_Pedersen_setup(csprng *RNG, PEDERSEN_PRIV *m, octet *P, octet *Q)
{
    BIG_1024_58 p[HFLEN_2048];
    BIG_1024_58 q[HFLEN_2048];
    BIG_1024_58 gp[HFLEN_2048];
    BIG_1024_58 gq[HFLEN_2048];
    BIG_1024_58 ap[HFLEN_2048];
    BIG_1024_58 aq[HFLEN_2048];

    /* Load or generate safe primes P, Q */
    if (P == NULL)
    {
        safe_prime_gen(RNG, p, m->mod.p, HFLEN_2048);
    }
    else
    {
        OCT_pad(P, HFS_2048);
        FF_2048_fromOctet(m->mod.p, P, HFLEN_2048);
        FF_2048_copy(p, m->mod.p, HFLEN_2048);

        // Since P is odd, P>>1 == (P-1) / 2
        FF_2048_shr(p, HFLEN_2048);
    }

    if (Q == NULL)
    {
        safe_prime_gen(RNG, q, m->mod.q, HFLEN_2048);
    }
    else
    {
        OCT_pad(Q, HFS_2048);
        FF_2048_fromOctet(m->mod.q, Q, HFLEN_2048);
        FF_2048_copy(q, m->mod.q, HFLEN_2048);

        // Since Q is odd, Q>>1 == (Q-1) / 2
        FF_2048_shr(q, HFLEN_2048);
    }

    FF_2048_mul(m->mod.n, m->mod.p, m->mod.q, HFLEN_2048);
    FF_2048_mul(m->pq, p, q, HFLEN_2048);
    FF_2048_invmodp(m->mod.invpq, m->mod.p, m->mod.q, HFLEN_2048);

    // Find a generator of G_pq in Z/NZ using the crt to
    // combine generators of G_p in Z/PZ and G_q in Z/QZ
    BC_find_generator(RNG, gp, m->mod.p, HFLEN_2048);
    BC_find_generator(RNG, gq, m->mod.q, HFLEN_2048);
    FF_2048_crt(m->b0, gp, gq, m->mod.p, m->mod.invpq, m->mod.n, HFLEN_2048);

    FF_2048_randomnum(m->alpha, m->pq, RNG, FFLEN_2048);

    // Look for invertible alpha and precompute inverse
    FF_2048_invmodp(m->ialpha, m->alpha, m->pq, FFLEN_2048);
    while (FF_2048_iszilch(m->ialpha, FFLEN_2048))
    {
        FF_2048_inc(m->alpha, 1, FFLEN_2048);
        FF_2048_invmodp(m->ialpha, m->alpha, m->pq, FFLEN_2048);
    }

    /* Compute b1=b0^alpha using CRT */
    FF_2048_dmod(ap, m->alpha, p, HFLEN_2048);
    FF_2048_dmod(aq, m->alpha, q, HFLEN_2048);

    FF_2048_ct_pow(gp, gp, ap, m->mod.p, HFLEN_2048, HFLEN_2048);
    FF_2048_ct_pow(gq, gq, aq, m->mod.q, HFLEN_2048, HFLEN_2048);

    FF_2048_crt(m->b1, gp, gq, m->mod.p, m->mod.invpq, m->mod.n, HFLEN_2048);

    // Clean memory
    FF_2048_zero(p,  HFLEN_2048);
    FF_2048_zero(q,  HFLEN_2048);
    FF_2048_zero(gp, HFLEN_2048);
    FF_2048_zero(gq, HFLEN_2048);
    FF_2048_zero(ap, HFLEN_2048);
    FF_2048_zero(aq, HFLEN_2048);
}

void Pedersen_get_public_param(PEDERSEN_PUB *pub, PEDERSEN_PRIV *priv)
{
    FF_2048_copy(pub->b0, priv->b0, FFLEN_2048);
    FF_2048_copy(pub->b1, priv->b1, FFLEN_2048);
    FF_2048_copy(pub->N, priv->mod.n, FFLEN_2048);
}

void CG21_Pedersen_Private_Kill( PEDERSEN_PRIV *priv){

    FF_2048_zero(priv->pq,  FFLEN_2048);
    FF_2048_zero(priv->alpha,  FFLEN_2048);
    FF_2048_zero(priv->ialpha,  FFLEN_2048);
    FF_2048_zero(priv->b0,  FFLEN_2048);
    FF_2048_zero(priv->b1,  FFLEN_2048);
    FF_2048_zero(priv->mod.n,  FFLEN_2048);
    FF_2048_zero(priv->mod.p,  HFLEN_2048);
    FF_2048_zero(priv->mod.q,  HFLEN_2048);
    FF_2048_zero(priv->mod.invpq,  HFLEN_2048);

}

void CG21_FF_2048_amod(BIG_1024_58 *r, BIG_1024_58 *x, int xlen, BIG_1024_58 *p, int plen)
{

#ifndef C99
    BIG_1024_58 t[2*FFLEN_2048];
#else
    BIG_1024_58 t[xlen];
#endif

    FF_2048_copy(t, x, xlen);

    for (int i = xlen - 2*plen; i >= 0; i--)
    {
        FF_2048_dmod(t+i, t+i, p, plen);
    }

    FF_2048_copy(r, t, plen);
}

void CG21_Pedersen_verify(BIG_1024_58 *proof, PEDERSEN_PRIV *st, BIG_1024_58 *z1,
                          BIG_1024_58 *z3, BIG_1024_58 *S, BIG_1024_58 *e, BIG_1024_58 *p, bool reduce_s1)
{
    // ------------ VARIABLE DEFINITION ----------
    BIG_1024_58 hws1[HFLEN_2048];
    BIG_1024_58 hws2[HFLEN_2048];
    BIG_1024_58 hws3[HFLEN_2048];
    BIG_1024_58 hws4[HFLEN_2048];
    BIG_1024_58 eneg[HFLEN_2048];

    // ------------ PEDERSEN COMMITMENT VERIFICATION ----------
    FF_2048_copy(hws1, p, HFLEN_2048);
    FF_2048_dec(hws1, 1, HFLEN_2048);
    CG21_FF_2048_amod(hws4, z3, FFLEN_2048 + HFLEN_2048, hws1, HFLEN_2048);
    FF_2048_sub(eneg, hws1, e, HFLEN_2048);
    FF_2048_norm(eneg, HFLEN_2048);

    if (reduce_s1)
    {
        FF_2048_dmod(hws3, z1, hws1, HFLEN_2048);
    }
    else
    {
        FF_2048_copy(hws3, z1, HFLEN_2048);
    }

    FF_2048_dmod(hws1, st->b0, p, HFLEN_2048);
    FF_2048_dmod(hws2, st->b1, p, HFLEN_2048);

    FF_2048_dmod(proof, S, p, HFLEN_2048);
    FF_2048_ct_pow_3(proof, hws1, hws3, hws2, hws4, proof, eneg, p, HFLEN_2048, HFLEN_2048);

    // ------------ CLEAN MEMORY ----------
    FF_2048_zero(hws1, HFLEN_2048);
    FF_2048_zero(hws2, HFLEN_2048);
    FF_2048_zero(hws3, HFLEN_2048);
    FF_2048_zero(hws4, HFLEN_2048);
}

void CG21_GET_CURVE_ORDER(BIG_1024_58 *q){
    BIG_256_56 q_;
    BIG_256_56_rcopy(q_, CURVE_Order_SECP256K1);

    char q_c[MODBYTES_256_56];
    octet q_oct = {0, sizeof(q_c), q_c};

    BIG_256_56_toBytes(q_oct.val, q_);
    q_oct.len = EGS_SECP256K1;

    char q_hex[2*MODBYTES_256_56+1];
    OCT_toHex(&q_oct, q_hex);

    char oct2[2 * FS_2048];
    octet OCT2 = {0, sizeof(oct2), oct2};
    OCT_fromHex(&OCT2, q_hex);

    OCT_pad(&OCT2, HFS_2048);
    FF_2048_fromOctet(q, &OCT2, HFLEN_2048);
}

void hex_to_array(const char *temp, int *arr, int n){
    for (int i = 0; i < n; i++) {
        arr[i] = (temp[4*i+0] - '0') << 12 |
                 (temp[4*i+1] - '0') << 8 |
                 (temp[4*i+2] - '0') << 4 |
                 (temp[4*i+3] - '0');
    }
}

void sort_indices(const char *temp, int *indices, int n)
{
    int arr[n];

    hex_to_array(temp, arr, n);

    // Initialize the indices array
    for (int i = 0; i < n; i++) {
        indices[i] = i;
    }

    // Sort the indices array based on the values in the input array
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            if (arr[indices[i]] > arr[indices[j]]) {
                int temp2 = indices[i];
                indices[i] = indices[j];
                indices[j] = temp2;
            }
        }
    }
}

void init_octets(char* mem, octet *OCTETS, int max, int n)
{
    for (int i = 0; i < n; i++)
    {
        OCTETS[i].val = mem + (i*max);
        OCTETS[i].len = 0;
        OCTETS[i].max = max;
    }
}

extern int CG21_unpack_and_sort(octet *set, octet *set_packed, const octet *j_packed, int n, int size, int *indices){

    // checked the length of X_packed
    if (set_packed->len != n*size)
    {
        return CG21_UTILITIES_WRONG_PACKED_SIZE;
    }

    for (int i = n - 1; i >= 0; i--)
    {
        OCT_clear(&set[i]);
        OCT_chop(set_packed, &set[i], set_packed->len - size);
    }

    // restore length of the packed X
    set_packed->len = n * size;

    // unpack j_packed and get sorted indices
    char temp[n * 4 + 1];

    // convert oct to hex
    OCT_toHex(j_packed, temp);

    // convert each j to int, then get sorted indices
    sort_indices(temp,indices,n);

    return CG21_OK;
}

extern int CG21_hash_set_X(hash256 *sha, octet *X_packed, octet *j_packed, int n, int m){

    int indices[n];

    char x_[n][m];
    octet X[n];
    init_octets((char *)x_,  X,  m, n);

    // unpack X_packed into X and return sorted indices based on j_packed
    int rc = CG21_unpack_and_sort(X, X_packed,j_packed,n,m,indices);
    if (rc != CG21_OK){
        return rc;
    }

    // process X[i] into sha based on the indices
    for (int i=0;i<n;i++){
        HASH_UTILS_hash_oct(sha, &X[indices[i]]);
    }

    for (int i=0;i<n;i++) {
        OCT_clear(&X[i]);
    }

    return CG21_OK;
}

int CG21_set_comp(octet *set_packed1, octet *j_packed1, octet *set_packed2, octet *j_packed2, int n, int size){

    int indices1[n];
    int indices2[n];
    int arr1[n];
    int arr2[n];
    int ret;

    char x1_[n][size];
    char x2_[n][size];
    char temp1[n * 4 + 1];
    char temp2[n * 4 + 1];

    octet X1[n];
    octet X2[n];

    init_octets((char *)x1_,  X1,  size, n);
    init_octets((char *)x2_,  X2,  size, n);

    // convert oct to hex
    OCT_toHex(j_packed1, temp1);
    OCT_toHex(j_packed2, temp2);

    // convert hex to array of int
    hex_to_array(temp1, arr1, n);
    hex_to_array(temp2, arr2, n);

    ret = CG21_unpack_and_sort(X1, set_packed1,j_packed1,n,size,indices1);
    if (ret != CG21_OK){
        return ret;
    }
    ret = CG21_unpack_and_sort(X2, set_packed2,j_packed2,n,size,indices2);
    if (ret != CG21_OK){
        return ret;
    }

    for (int i=0;i<n;i++){
        if (arr1[indices1[i]] != arr2[indices2[i]]){
            return 0;
        }
    }

    for (int i=0;i<n;i++){
        ret = OCT_comp(&X1[indices1[i]],&X2[indices2[i]]);
        if (ret != 1){
            return 0;
        }
    }

    return 1;
}

void CG21_get_G(octet *g_oct){
    ECP_SECP256K1 G;

    ECP_SECP256K1_generator(&G);

    // convert the generator to octet
    ECP_SECP256K1_toOctet(g_oct, &G, true);

}

void CG21_get_q(octet *q_oct){
    BIG_256_56 q;
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    // convert the curve order to octet
    q_oct->len=EGS_SECP256K1;
    BIG_256_56_toBytes(q_oct->val,q);
}

int CG21_ADD_TWO_PK(octet *O, const octet *P){

    ECP_SECP256K1 tt;
    ECP_SECP256K1 accum;

    // convert Xi from octet to point
    if (!ECP_SECP256K1_fromOctet(&accum, O) || (!ECP_SECP256K1_fromOctet(&tt, P)) ){
        return CG21_INVALID_ECP;
    }

    ECP_SECP256K1_add(&accum, &tt);

    // convert X from point to octet
    ECP_SECP256K1_toOctet(O, &accum, true);

    // clean up variables
    ECP_SECP256K1_inf(&tt);
    ECP_SECP256K1_inf(&accum);

    return CG21_OK;
}

void CG21_pack_vss_checks(const octet *checks, int t, octet *out){
    for (int i = 0; i < t; i++){
        OCT_joctet(out, checks+i);
    }
}

int CG21_unpack(octet *checks, int t, octet *out, int size){

    // checked the length of X_packed
    if (checks->len != t*size)
    {
        return CG21_UTILITIES_WRONG_PACKED_SIZE;
    }

    char c[size];
    octet C = {0, size, c};

    for (int i = t-1; i >=0 ; i--){
        OCT_chop(checks, &C, checks->len - size);
        OCT_copy(out+i, &C);
    }
    checks->len = t*size;

    return CG21_OK;
}

int CG21_double_unpack(octet *checks, int t1, int t2, octet *out){

    // checked the length of X_packed
    if (checks->len != t1*t2*(EFS_SECP256K1 + 1))
    {
        return CG21_UTILITIES_WRONG_PACKED_SIZE;
    }

    char c1[t2*(EFS_SECP256K1 + 1)];
    octet C1 = {0, t2*(EFS_SECP256K1 + 1), c1};

    char c2[EFS_SECP256K1 + 1];
    octet C2 = {0, sizeof(c2), c2};

    int c = t1*t2-1;
    for (int i = t1-1; i >=0 ; i--){
        OCT_chop(checks, &C1, checks->len - t2*(EFS_SECP256K1 + 1));

        for (int j = t2-1; j >=0 ; j--){
            OCT_chop(&C1, &C2, C1.len - (EFS_SECP256K1 + 1));
            OCT_copy(out+c , &C2);
            c=c-1;
        }
    }
    checks->len = t1*t2*(EFS_SECP256K1 + 1);

    return CG21_OK;
}

void CG21_PedersenPriv_to_octet(PEDERSEN_PRIV *priv, octet *oct){
    char t[6][FS_2048];
    octet T1[6];
    init_octets((char *)t,  T1,  FS_2048, 6);

    char tt[3][HFS_2048];
    octet T2[3];
    init_octets((char *)tt,  T2,  HFS_2048, 3);

    FF_2048_toOctet(&T1[0], priv->b0, FFLEN_2048);
    FF_2048_toOctet(&T1[1], priv->b1, FFLEN_2048);
    FF_2048_toOctet(&T1[2], priv->alpha, FFLEN_2048);
    FF_2048_toOctet(&T1[3], priv->ialpha, FFLEN_2048);
    FF_2048_toOctet(&T1[4], priv->pq, FFLEN_2048);
    FF_2048_toOctet(&T1[5], priv->mod.n, FFLEN_2048);
    FF_2048_toOctet(&T2[0], priv->mod.p, HFLEN_2048);
    FF_2048_toOctet(&T2[1], priv->mod.q, HFLEN_2048);
    FF_2048_toOctet(&T2[2], priv->mod.invpq, HFLEN_2048);

    for (int i=0; i<6; i++) {
        OCT_joctet(oct, &T1[i]);
        OCT_clear(&T1[i]);
    }

    for (int i=0; i<3; i++) {
        OCT_joctet(oct, &T2[i]);
        OCT_clear(&T2[i]);
    }

}

int CG21_PedersenPriv_from_octet(PEDERSEN_PRIV *priv, octet *oct){

    // check whether the length of the octet is correct
    if (oct->len != 6*FS_2048+3*HFS_2048)
    {
        return CG21_UTILITIES_WRONG_PACKED_SIZE;
    }

    char t[6][FS_2048];
    octet T1[6];
    init_octets((char *)t,  T1,  FS_2048, 6);

    char tt[3][HFS_2048];
    octet T2[3];
    init_octets((char *)tt,  T2,  HFS_2048, 3);

    //  split packed octet into several small octets in different for loops based on their sizes
    for (int i=0; i<3; i++) {
        OCT_chop(oct, &T2[i], oct->len - (HFS_2048));
    }

    for (int i=0; i<6; i++) {
        OCT_chop(oct, &T1[i], oct->len - (FS_2048));
    }

    FF_2048_fromOctet(priv->mod.invpq, &T2[0],HFLEN_2048 );
    FF_2048_fromOctet(priv->mod.q, &T2[1],HFLEN_2048 );
    FF_2048_fromOctet(priv->mod.p, &T2[2],HFLEN_2048 );
    FF_2048_fromOctet(priv->mod.n, &T1[0],FFLEN_2048 );
    FF_2048_fromOctet(priv->pq, &T1[1],FFLEN_2048 );
    FF_2048_fromOctet(priv->ialpha, &T1[2],FFLEN_2048 );
    FF_2048_fromOctet(priv->alpha, &T1[3],FFLEN_2048 );
    FF_2048_fromOctet(priv->b1, &T1[4],FFLEN_2048 );
    FF_2048_fromOctet(priv->b0, &T1[5],FFLEN_2048 );

    // recover the length of the packed octet
    oct->len = 6*FS_2048+3*HFS_2048;

    // clean up
    for (int i=0; i<6; i++) {
        OCT_clear(&T1[i]);
    }

    for (int i=0; i<3; i++) {
        OCT_clear(&T2[i]);
    }

    return CG21_OK;
}

void CG21_PedersenPub_to_octet(PEDERSEN_PUB *priv, octet *oct){
    char t[3][FS_2048];
    octet T1[3];
    init_octets((char *)t,  T1,  FS_2048, 3);

    FF_2048_toOctet(&T1[0], priv->b0, FFLEN_2048);
    FF_2048_toOctet(&T1[1], priv->b1, FFLEN_2048);
    FF_2048_toOctet(&T1[2], priv->N, FFLEN_2048);

    for (int i=0; i<3; i++) {
        OCT_joctet(oct, &T1[i]);
    }

}

int CG21_PedersenPub_from_octet(PEDERSEN_PUB *priv, octet *oct){

    // check whether the length of the octet is correct
    if (oct->len != 3*FS_2048)
    {
        return CG21_UTILITIES_WRONG_PACKED_SIZE;
    }

    char t[3][FS_2048];
    octet T1[3];
    init_octets((char *)t,  T1,  FS_2048, 3);

    //  split packed octet into several small octets
    for (int i=0; i<3; i++) {
        OCT_chop(oct, &T1[i], oct->len - (FS_2048));
    }

    FF_2048_fromOctet(priv->N, &T1[0],FFLEN_2048 );
    FF_2048_fromOctet(priv->b1, &T1[1],FFLEN_2048 );
    FF_2048_fromOctet(priv->b0, &T1[2],FFLEN_2048 );

    // recover the length of the packed octet
    oct->len = 3*FS_2048;

    return CG21_OK;
}

void CG21_PaillierPriv_to_octet(PAILLIER_private_key *priv, octet *oct){

    char tt[2][HFS_2048];
    octet T2[2];
    init_octets((char *)tt,  T2,  HFS_2048, 2);

    FF_2048_toOctet(&T2[0], priv->p, HFLEN_2048);
    FF_2048_toOctet(&T2[1], priv->q, HFLEN_2048);

    for (int i=0; i<2; i++) {
        OCT_joctet(oct, &T2[i]);
        OCT_clear(&T2[i]);
    }
}

int CG21_PaillierKeys_from_octet(CG21_PAILLIER_KEYS *key, octet *oct){

    // check whether the length of the octet is correct
    if (oct->len != 2*HFS_2048)
    {
        return CG21_UTILITIES_WRONG_PACKED_SIZE;
    }

    char tt[2][HFS_2048];
    octet T2[2];
    init_octets((char *)tt,  T2,  HFS_2048, 2);

    // split packed octet into different small octets
    for (int i=0; i<2; i++) {
        OCT_chop(oct, &T2[i], oct->len - (HFS_2048));
    }

    // recover Paillier private params from primes
    PAILLIER_KEY_PAIR(NULL, &T2[1],&T2[0], &key->paillier_pk, &key->paillier_sk);

    // recover the length of the packed octet
    oct->len = 2*HFS_2048;

    // clean up
    for (int i=0; i<2; i++) {
        OCT_clear(&T2[1]);
    }

    return CG21_OK;
}

void CG21_PaillierPub_to_octet(PAILLIER_public_key *pub, octet *oct){

    // to hold N
    char t1[HFS_4096];
    octet T1 = {0, sizeof(t1), t1};
    FF_4096_toOctet(&T1, pub->n, HFLEN_4096);


    // to hold N^2
    char t2[FS_4096];
    octet T2 = {0, sizeof(t2), t2};
    FF_4096_toOctet(&T2, pub->n2, FFLEN_4096);


    OCT_joctet(oct, &T1);
    OCT_joctet(oct, &T2);
}

int CG21_PaillierPub_from_octet(PAILLIER_public_key *pub, octet *oct){

    // check whether the length of the octet is correct
    if (oct->len != FS_4096+HFS_4096)
    {
        return CG21_UTILITIES_WRONG_PACKED_SIZE;
    }

    // to hold N
    char t1[HFS_4096];
    octet T1 = {0, sizeof(t1), t1};

    // to hold N^2
    char t2[FS_4096];
    octet T2 = {0, sizeof(t2), t2};

    // split packed octet into different small octets
    OCT_chop(oct, &T2, oct->len - (FS_4096));
    FF_4096_fromOctet(pub->n2, &T2, FFLEN_4096);

    OCT_chop(oct, &T1, oct->len - (HFS_4096));
    FF_4096_fromOctet(pub->n, &T1, HFLEN_4096);

    // recover the length of the packed octet
    oct->len = FS_4096+HFS_4096;

    return CG21_OK;
}

void CG21_lagrange_index_to_octet(int t, const int *T, int myID, octet *out){

    BIG_256_56 x[t-1];
    int c = 0;

    // we need t number of X component of the private share points to calculate the Lagrange coefficient
    for (int i = 0; i < t; i++) {
        if (T[i] == myID){
            continue;
        }

        // convert int number T[i] to octet
        BIG_256_56_zero(x[c]);
        BIG_256_56_inc(x[c], T[i]);
        BIG_256_56_toBytes((out+c)->val, x[c]);
        (out+c)->len = SGS_SECP256K1;

        c++;
    }
}

void CG21_lagrange_calc_coeff(int k, const octet *X_j, const octet *X, BIG_256_56 *out){

    BIG_256_56 x_j;
    BIG_256_56 q;
    DBIG_256_56 dw;
    BIG_256_56 n;
    BIG_256_56 d;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);

    BIG_256_56_fromBytesLen(x_j, X_j->val, X_j->len);

    // Initialize accumulators for numerator and denominator
    BIG_256_56_one(n);
    BIG_256_56_one(d);

    // x_j = -x_j mod q
    BIG_256_56_sub(x_j, q, x_j);

    for (int i = 0; i < k-1; i++)
    {
        // n = prod(x_i)
        BIG_256_56_fromBytesLen(*out, X[i].val, X[i].len);
        BIG_256_56_mul(dw, n, *out);
        BIG_256_56_dmod(n, dw, q);

        // d = prod(x_i - x_j)
        BIG_256_56_add(*out, *out, x_j);
        BIG_256_56_norm(*out);
        BIG_256_56_mul(dw, d, *out);
        BIG_256_56_dmod(d, dw, q);
    }

    // s = n/d
    BIG_256_56_invmodp(d, d, q);
    BIG_256_56_mul(dw, n, d);
    BIG_256_56_dmod(*out, dw, q);

}

int CG21_CALC_XI(int t, const octet *i, const octet *checks, ECP_SECP256K1 *V)
{
    int rc;
    ECP_SECP256K1 G;
    BIG_256_56  x;
    BIG_256_56 xn;
    BIG_256_56 q;
    DBIG_256_56 w;

    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    BIG_256_56_fromBytesLen(x, i->val, i->len);

    // Initialize accumulator and exponent
    rc = ECP_SECP256K1_fromOctet(V, checks);
    if (rc != 1)
    {
        return VSS_INVALID_CHECKS;
    }
    BIG_256_56_one(xn);

    for (int j = 1; j < t; j++)
    {
        rc = ECP_SECP256K1_fromOctet(&G, checks+j);
        if (rc != 1)
        {
            return VSS_INVALID_CHECKS;
        }

        BIG_256_56_mul(w, xn, x);
        BIG_256_56_dmod(xn, w, q);

        ECP_SECP256K1_mul(&G, xn);
        ECP_SECP256K1_add(V, &G);
    }



    return VSS_OK;
}

int FF_4096_jacobi(BIG_512_60 a[HFLEN_4096], BIG_512_60 p[HFLEN_4096])
{
    int size = HFLEN_4096;
    int n8;
    int k;
    int m=0;
    BIG_512_60 t[size];
    BIG_512_60 x[size];
    BIG_512_60 n[size];
    BIG_512_60 zilch[size];
    BIG_512_60 one[size];
    FF_4096_init(one,1,size);
    FF_4096_zero(zilch,size);
    if (FF_4096_parity(p)==0 || FF_4096_comp(a,zilch,size)==0 || FF_4096_comp(p,one,size)<=0) return 0;
    FF_4096_norm(a,size);
    FF_4096_copy(x,a,size);
    FF_4096_copy(n,p,size);
    FF_4096_mod(x, p,size);

    while (FF_4096_comp(n,one,size)>0)
    {
        if (FF_4096_comp(x,zilch,size)==0) return 0;
        n8=FF_4096_lastbits(n,3);
        k=0;
        while (FF_4096_parity(x)==0)
        {
            k++;
            FF_4096_shr(x,size);
        }
        if (k%2==1) m+=(n8*n8-1)/8;
        m+=(n8-1)*(FF_4096_lastbits(x,2)-1)/4;
        FF_4096_copy(t,n,size);

        FF_4096_mod(t,x,size);
        FF_4096_copy(n,x, size);
        FF_4096_copy(x,t,size);
        m%=2;

    }
    if (m==0) return 1;
    else return -1;
}

bool CG21_check_sqrt_exist(BIG_1024_58 a[FFLEN_2048], BIG_1024_58 p[HFLEN_2048]){
    BIG_1024_58 t[HFLEN_2048];
    BIG_1024_58 t2[HFLEN_2048];
    BIG_1024_58 t3[HFLEN_2048];
    BIG_1024_58 t4[FFLEN_2048];
    BIG_1024_58 t5[FFLEN_2048];
    BIG_1024_58 p_[FFLEN_2048];

    // Check p = 3 mod 4
    FF_2048_init(t3,4,FFLEN_2048);
    FF_2048_zero(t,FFLEN_2048);
    FF_2048_copy(t,p,FFLEN_2048);
    FF_2048_mod(t, t3,FFLEN_2048);

    BIG_1024_58_dec(*t,3);
    BIG_1024_58_norm(*t);

    int rc = BIG_1024_58_iszilch(*t);
    if (rc==0) {
        return false;
    }

    FF_2048_zero(p_,FFLEN_2048);
    FF_2048_copy(p_,p,HFLEN_2048);


    /* ---------STEP 1: compute t ----------
     * t = (p-1)/2 mod p
    */

    FF_2048_zero(t,HFLEN_2048);
    FF_2048_copy(t,p,HFLEN_2048); // t <- p
    BIG_1024_58_dec(*t,1); // t = p - 1
    BIG_1024_58_norm(*t);

    FF_2048_init(t3,2,HFLEN_2048);
    FF_2048_invmodp(t3,t3,p,HFLEN_2048); // inverse of 2 mod p
    FF_2048_mul(t4,t3,t,HFLEN_2048); // (p-1)/2
    FF_2048_mod(t4,p_,FFLEN_2048); // (p-1)/2 mod p
    FF_2048_copy(t, t4, HFLEN_2048); // t <- (p-1)/2 mod p


    /* ---------STEP 2: compute t2 ----------
     * t5 = a mod p
     * t2 = a^{(p-1)/2} mod p
    */

    FF_2048_copy(t5, a, FFLEN_2048);
    FF_2048_mod(t5,p_,FFLEN_2048); // t5 <- a mod p
    FF_2048_copy(t3, t5, HFLEN_2048); // t5 <- t3

    FF_2048_ct_pow(t2,t3,t,p,HFLEN_2048,HFLEN_2048); // a^{(p-1)/2} mod p

    // n^{(p-1)/2} mod p = 1 then a has a square root
    BIG_1024_58_dec(*t2,1);     // t2 <- n^{(p-1)/2} - 1
    rc = BIG_1024_58_iszilch(*t2);  // rc=(t2==0)

    // clean up
    FF_2048_zero(t,HFLEN_2048);
    FF_2048_zero(t2,HFLEN_2048);
    FF_2048_zero(t3,HFLEN_2048);
    FF_2048_zero(t4,FFLEN_2048);
    FF_2048_zero(t5,FFLEN_2048);
    FF_2048_zero(p_,FFLEN_2048);


    if (rc==1)
        return true;
    else
        return false;
}

void CG21_sqrt(BIG_1024_58 r[FFLEN_2048], BIG_1024_58 a[FFLEN_2048], BIG_1024_58 p[HFLEN_2048]){
    BIG_1024_58 t[HFLEN_2048];
    BIG_1024_58 t3[HFLEN_2048];
    BIG_1024_58 t4[FFLEN_2048];
    BIG_1024_58 t5[FFLEN_2048];
    BIG_1024_58 p_[FFLEN_2048];

    // Calculate square root
    FF_2048_zero(p_,FFLEN_2048);
    FF_2048_copy(p_,p,HFLEN_2048);

    FF_2048_zero(t,HFLEN_2048);
    FF_2048_copy(t,p,HFLEN_2048); // t <- p
    BIG_1024_58_inc(*t,1); // t = p + 1
    BIG_1024_58_norm(*t);

    FF_2048_init(t3,4,HFLEN_2048);
    FF_2048_invmodp(t3,t3,p,HFLEN_2048); // inverse of 2 mod p
    FF_2048_mul(t4,t3,t,HFLEN_2048); // (p+1)/4
    FF_2048_mod(t4,p_,FFLEN_2048); // (p+1)/4 mod p
    FF_2048_copy(t, t4, HFLEN_2048);

    FF_2048_copy(t5, a, FFLEN_2048);
    FF_2048_mod(t5,p_,FFLEN_2048); // yi mod p
    FF_2048_copy(t3, t5, HFLEN_2048);

    FF_2048_zero(r,FFLEN_2048);
    FF_2048_ct_pow(r,t3,t,p,HFLEN_2048,HFLEN_2048); // t2 = a^t3 mod p


    FF_2048_zero(t,HFLEN_2048);
    FF_2048_zero(t3,HFLEN_2048);
    FF_2048_zero(t4,HFLEN_2048);
    FF_2048_zero(t5,FFLEN_2048);
    FF_2048_zero(p_,FFLEN_2048);

}

int CG21_hash_SSID(CG21_SSID *ssid, hash256 *sha){

    HASH_UTILS_hash_oct(sha, ssid->rho);
    HASH_UTILS_hash_oct(sha, ssid->rid);
    HASH_UTILS_hash_oct(sha, ssid->uid);
    HASH_UTILS_hash_oct(sha, ssid->q);
    HASH_UTILS_hash_oct(sha, ssid->g);

    int rc = CG21_hash_set_X(sha, ssid->X_set_packed, ssid->j_set_packed, *ssid->n1, EFS_SECP256K1 + 1);
    if (rc!=CG21_OK){
        return rc;
    }

    rc = CG21_hash_set_X(sha, ssid->N_set_packed, ssid->j_set_packed2, *ssid->n2, FS_2048);
    if (rc!=CG21_OK){
        return rc;
    }

    rc = CG21_hash_set_X(sha, ssid->s_set_packed, ssid->j_set_packed2, *ssid->n2, FS_2048);
    if (rc!=CG21_OK){
        return rc;
    }

    rc = CG21_hash_set_X(sha, ssid->t_set_packed, ssid->j_set_packed2, *ssid->n2, FS_2048);

    if (rc!=CG21_OK){
        return rc;
    }

    return CG21_OK;
}

int CG21_calculateBitLength(int number) {
    int count = 0;

    // Count the number of shifts required to reach zero
    while (number != 0) {
        number >>= 1;  // Right shift by 1 bit
        count++;
    }

    return count;
}