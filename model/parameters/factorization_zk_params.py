#! /usr/bin/env python3

import math
from scipy.special import zeta

# --- Integer Factorization ZK proof parameter generation ---
#
#   Poupard, Stern
#
#   Short Proofs of Knowledge for Factoring
#
#   https://link.springer.com/content/pdf/10.1007%2F978-3-540-46588-1_11.pdf
#

## User configurable part ##

# Length of the number for factoring proof n = p * q
nlen = 4096

# Security parameter
k = 128

# Max number of generators. Must be more than 2
maxK = 4

# Number of rounds
l = 1

## End of user configurable part ##

# Range for the challenge
B = 2**k

# The bound for A is (N-phiN)lB, estimating the size.
# We estimate |N-phiN| ~ 1/2 * |N|, since N is biprimal in our setting
# Then we can estimate the size of (N-phiN)B as (1/2|N|+k)
#
# The actual value for A must be orders of magnitude bigger than the bound.
# A good rule of thumb is to pick the next power of two, provided it's not
# too close

A_bound = nlen/2 + k + math.log(l,2)

# Tabulate C values for different choices of K
# assuming the number is biprimal (n = p * q).
#
# This computes C such that the probability of
# generating subgroups of order |p|/C is at least (1/2)^k
#
# The lower C, the higher the subgroup order we are likely to obtain
# with a given probability.

KC = [(K, (k + 1 - math.log((K-1)*zeta(K), 2)) / (K-1)) for K in range(2,maxK+1)]

print("Computing parameters for input:")
print("|N|  = {}".format(nlen))
print("k    = {}".format(k))
print("l    = {}".format(l))
print("\nParameters:")
print("A_lb = {}".format(A_bound))
for (K,C) in KC:
    print("C({}) = {} - subgroup order {}".format(K,C,nlen-C))
