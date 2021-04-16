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


"""
bls

This module use cffi to access the c functions in the BLS library.

There is also an example usage program in this file.

"""

import platform
from . import core_utils

_ffi = core_utils._ffi
_ffi.cdef("""
typedef struct {
    octet *X;
    octet *Y;
} SSS_shares;

void SSS_make_shares(int k, int n, csprng *RNG, SSS_shares *shares, octet* S);
void SSS_recover_secret(int k, SSS_shares *shares, octet* SK);

void SSS_shamir_to_additive(int k, octet *X_j, octet *Y_j, octet *X, octet *S);

void VSS_make_shares(int k, int n, csprng *RNG, SSS_shares *shares, octet *C, octet *S);
int VSS_verify_shares(int k, octet *X_j, octet * Y_j, octet *C);
""")

if (platform.system() == 'Windows'):
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.dll")
elif (platform.system() == 'Darwin'):
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.dylib")
else:
    _libamcl_mpc = _ffi.dlopen("libamcl_mpc.so")


# Constants
EGS = 32      # Size of a Z/qZ element in bytes
EFS = 1 + EGS # SIze of an ECP in bytes

OK = 0              # Success
INVALID_SHARE = 161 # Share inconsistency
INVALID_CHECK = 162 # A check is not a valid ECP


def make_shares(k, n, rng, S=None):
    """ Make shares for a (k, n) SSS of S

    Args::
        k   : Threshold of the scheme
        n   : Number of participants in the scheme
        rng : Pointer to csprng
        S   : octet containing the secret. If None the secret is generated using rng

    Returns::
        shares : List of n pairs containing the shares
        S      : Secret shared
    """

    if S is None:
        s_oct, s_val = core_utils.make_octet(EGS)
        _ = s_val # Suppress warning
    else:
        s_oct, s_val = core_utils.make_octet(None, S)
        _ = s_val # Suppress warning

    x_octs, x_val = core_utils.make_empty_octets(n, EGS)
    y_octs, y_val = core_utils.make_empty_octets(n, EGS)
    _ = x_val, y_val # Suppress warning

    shares = _ffi.new("SSS_shares*")
    shares.X = x_octs
    shares.Y = y_octs

    _libamcl_mpc.SSS_make_shares(k, n, rng, shares, s_oct)

    # Output strings
    shares_str = []
    for i in range(n):
        x_str = core_utils.to_str(x_octs[i])
        y_str = core_utils.to_str(y_octs[i])

        shares_str.append((x_str, y_str))

    S = core_utils.to_str(s_oct)

    # Clear memory
    core_utils.clear_octet(s_oct)
    core_utils.clear_octets(x_octs, n)
    core_utils.clear_octets(y_octs, n)

    return shares_str, S


def recover_secret(shares):
    """ Recover secret from shares. Assuming k = #shares

    Args::
        shares : list of shares (x, y) to recover the secret
    """
    k = len(shares)

    (x, y) = zip(*shares)

    s_oct,  s_val = core_utils.make_octet(EGS)
    x_octs, x_val = core_utils.make_octets(x)
    y_octs, y_val = core_utils.make_octets(y)
    _ = s_val, x_val, y_val # Suppress warning

    shares = _ffi.new("SSS_shares*")
    shares.X = x_octs
    shares.Y = y_octs

    _libamcl_mpc.SSS_recover_secret(k, shares, s_oct)

    S = core_utils.to_str(s_oct)

    # Clear memory
    core_utils.clear_octet(s_oct)
    core_utils.clear_octets(x_octs, k)
    core_utils.clear_octets(y_octs, k)

    return S


def to_additive(s_share, x):
    """ Convert a shamir share to an additive share

    Args::
        s_share : (x, y) share to convert
        x       : x portion of the shares of the other participants

    Returns::
        a_share : converted additive share
    """
    k = len(x) + 1

    (xj, yj) = s_share

    x_octs, x_val  = core_utils.make_octets(x)
    xj_oct, xj_val = core_utils.make_octet(None, xj)
    yj_oct, yj_val = core_utils.make_octet(None, yj)
    s_oct,  s_val  = core_utils.make_octet(EGS)
    _ = x_val, xj_val, yj_val, s_val

    _libamcl_mpc.SSS_shamir_to_additive(k, xj_oct, yj_oct, x_octs, s_oct)

    a_share = core_utils.to_str(s_oct)

    # Clean memory
    core_utils.clear_octet(yj_oct)
    core_utils.clear_octet(s_oct)

    return a_share


def vss_make_shares(k, n, rng, S=None):
    """ Make shares for a (k, n) SSS of S and checks for shares verification

    Args::
        k   : Threshold of the scheme
        n   : Number of participants in the scheme
        rng : Pointer to csprng
        S   : octet containing the secret. If None the secret is generated using rng

    Returns::
        shares : List of n pairs containing the shares
        checks : List of k checks for the shares
        S      : Secret shared
    """

    if S is None:
        s_oct, s_val = core_utils.make_octet(EGS)
        _ = s_val # Suppress warning
    else:
        s_oct, s_val = core_utils.make_octet(None, S)
        _ = s_val # Suppress warning

    x_octs, x_val = core_utils.make_empty_octets(n, EGS)
    y_octs, y_val = core_utils.make_empty_octets(n, EGS)
    c_octs, c_val = core_utils.make_empty_octets(k, EFS)
    _ = x_val, y_val, c_val # Suppress warning

    shares = _ffi.new("SSS_shares*")
    shares.X = x_octs
    shares.Y = y_octs

    _libamcl_mpc.VSS_make_shares(k, n, rng, shares, c_octs, s_oct)

    # Output strings
    shares_str = []
    for i in range(n):
        x_str = core_utils.to_str(x_octs[i])
        y_str = core_utils.to_str(y_octs[i])

        shares_str.append((x_str, y_str))

    checks_str = []
    for i in range(k):
        c_str = core_utils.to_str(c_octs[i])

        checks_str.append(c_str)

    S = core_utils.to_str(s_oct)

    # Clear memory
    core_utils.clear_octet(s_oct)
    core_utils.clear_octets(x_octs, n)
    core_utils.clear_octets(y_octs, n)

    return shares_str, checks_str, S


def vss_verify_shares(share, checks):
    """ Verify a share against the corresponding checks

    Args::
        share  : (x, y) share to verify
        checks : List of k checks for verification

    Returns::
        ok     : OK or an error code
    """
    k = len(checks)

    (xj, yj) = share

    c_octs, c_val = core_utils.make_octets(checks)
    xj_oct, xj_val = core_utils.make_octet(None, xj)
    yj_oct, yj_val = core_utils.make_octet(None, yj)
    _ = c_val, xj_val, yj_val

    rc = _libamcl_mpc.VSS_verify_shares(k, xj_oct, yj_oct, c_octs)

    # Clear memory
    core_utils.clear_octet(yj_oct)

    return rc
