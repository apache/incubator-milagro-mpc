#! /usr/bin/env python3

import sys
sys.path.append("../")

import sec256k1.shamir as shamir


def genVector(test_no, t, n, secret=None, check=True):
    """Generate a single test vector

        Use parameters to generate a single test vector

        Args::

            test_no: Test vector identifier
            t: t value for the (t,n) SSS/VSS
            n: n value for the (t,n) SSS/VSS
            secret: predefined secret value
            check: generate shares checks for VSS

        Returns::

            vector: A test vector

        Raises::

            Exception
    """

    secret1, shares, checks = shamir.make_shares(t, n, check=check)

    # Check shares consistency
    if check:
        for share in shares:
            (x, y) = share

            assert shamir.verify_share(
                checks, share), "inconsistent share ({}, {})".format(x, hex(y)[2:].zfill(64))

    x_s, y_s = zip(*shares)
    coef = shamir.lagrange_interpolate1(x_s[:t])
    secret2, m = shamir.lagrange_interpolate2(coef, y_s[:t])

    # Check secret consistency
    assert secret1 == secret2, "secret1 != secret2"

    vector = {
        "TEST"     : test_no,
        "T"        : t,
        "N"        : n,
        "SECRET"   : hex(secret1)[2:].zfill(64),
        "X"        : [hex(x)[2:].zfill(64) for x in x_s],
        "Y"        : [hex(y)[2:].zfill(64) for y in y_s],
        "CHECKS"   : ["{}".format(c) for c in checks],
        "I_COEFFS" : [hex(c)[2:].zfill(64) for c in coef],
        "P_COEFFS" : [hex(a)[2:].zfill(64) for a in m],
    }

    return vector
