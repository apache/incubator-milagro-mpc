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

/* Modulus declarations */

#include "amcl/modulus.h"

void MODULUS_kill(MODULUS_priv *m)
{
    FF_2048_zero(m->p,     HFLEN_2048);
    FF_2048_zero(m->q,     HFLEN_2048);
    FF_2048_zero(m->invpq, HFLEN_2048);
}

void MODULUS_fromOctets(MODULUS_priv *m, octet *P, octet *Q)
{
    FF_2048_fromOctet(m->p, P, HFLEN_2048);
    FF_2048_fromOctet(m->q, Q, HFLEN_2048);

    FF_2048_mul(m->n, m->p, m->q, HFLEN_2048);
    FF_2048_invmodp(m->invpq, m->p, m->q, HFLEN_2048);
}

void MODULUS_toOctets(octet *P, octet *Q, MODULUS_priv *m)
{
    FF_2048_toOctet(P, m->p, HFLEN_2048);
    FF_2048_toOctet(Q, m->q, HFLEN_2048);
}
