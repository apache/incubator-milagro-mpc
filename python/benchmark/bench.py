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

import time

multipliers = {
    "ms": 1000,
    "us": 1000000
}

def time_func(stmt, fncall, minIter=10, minTime=1, unit="ms"):
    """Benchmark a function

    Benchmark fncall(). It iterates until minIter or minTime is reached.
    The results are printed using the specified time unit

    Args::

        stmt    : name of the benchmarked function
        fncall  : function call initialized with the functools partial
        minIter : minimum number of iterations to run, regardless of time spent
        minTime : minimum number of time to spend, regardless of iterations
        unit    : "ms" or "us", the time unit for the benchmark

    Returns::

    Raises::
        KeyError
    """

    unit_multiplier = multipliers[unit]

    total_time = 0
    nIter = 0

    while nIter < minIter or total_time < minTime:
        t = time.time()

        fncall()

        elapsed_time = time.time() - t
        total_time = total_time + elapsed_time
        nIter+=1

    iter_time = (total_time * unit_multiplier) / nIter
    print("func: {} \tnIter: {} \ttotal_time: {:.2f}s \titer_time: {:.2f}{}".format(stmt, nIter, total_time, iter_time, unit))
