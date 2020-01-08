#! /usr/bin/env python3

import math

# --- Integer Factorization ZK proof parameter generation ---
#
#   Poupard, Stern
#
#   Short Proofs of Knowledge for Factoring
#
#   https://link.springer.com/content/pdf/10.1007%2F978-3-540-46588-1_11.pdf
#

## User configurable part ##

# Length of the number for factoring proof
nlen = 4096

# Security parameter
k = 128

# Number of rounds
l = 1

## End of user configurable part ##

B = 2**k

# The bound for A is (N-phiN)lB, estimating the size.
# We estimate |N-phiN| ~ 1/2 * |N|, since N is biprimal in our setting
# Then we can estimate the size of (N-phiN)B as (1/2|N|+k)
A_bound = nlen/2 + k + math.log(l,2)

# Tabulate C values for different choices of K
# assuming the number is biprimal.
# Target probability 1/2^k

# K = 2
# |zeta(2)| ~ 1
C2size = k - 1

# k = 3
# |zeta(3)| ~ 0
C3size = (k-1)/2

# k = 4
# |zeta(4)| ~ 0
C4size = (k-2)/3

print("Computing parameters for input:")
print("|N|  = {}".format(nlen))
print("k    = {}".format(k))
print("l    = {}".format(l))
print("\nParameters:")
print("A_lb = {}".format(A_bound))
print("C2   = {}".format(C2size))
print("C3   = {}".format(C3size))
print("C4   = {}".format(C4size))
