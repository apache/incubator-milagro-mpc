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

This module use cffi to access the c functions for the amcl AES-GCM.

"""

from . import core_utils
import platform

_ffi = core_utils._ffi
_ffi.cdef("""
extern void AES_GCM_ENCRYPT(octet *K,octet *IV,octet *H,octet *P,octet *C,octet *T);
extern void AES_GCM_DECRYPT(octet *K,octet *IV,octet *H,octet *C,octet *P,octet *T);
""")

if (platform.system() == 'Windows'):
    _libamcl_core = _ffi.dlopen("libamcl_core.dll")
elif (platform.system() == 'Darwin'):
    _libamcl_core = _ffi.dlopen("libamcl_core.dylib")
else:
    _libamcl_core = _ffi.dlopen("libamcl_core.so")


# Constants
AES_KEY = 32 # Length in bytes of an AES key


def gcm_encrypt(aes_key, iv, header, plaintext):
    """AES-GCM Encryption

    AES-GCM Encryption

    Args::

        aes_key: AES Key
        iv: Initialization vector
        header: header
        plaintext: Plaintext to be encrypted

    Returns::

        ciphertext: resultant ciphertext
        tag: MAC


    Raises:

    """
    aes_key1, aes_key1_val = core_utils.make_octet(None, aes_key)
    iv1, iv1_val = core_utils.make_octet(None, iv)
    header1, header1_val = core_utils.make_octet(None, header)
    plaintext1, plaintext1_val = core_utils.make_octet(None, plaintext)
    tag1, tag1_val = core_utils.make_octet(AES_KEY)
    ciphertext1, ciphertext1_val = core_utils.make_octet(len(plaintext))
    _ = aes_key1_val, iv1_val, header1_val, plaintext1_val, tag1_val, ciphertext1_val # Suppress warnings

    _libamcl_core.AES_GCM_ENCRYPT(
        aes_key1,
        iv1,
        header1,
        plaintext1,
        ciphertext1,
        tag1)
    tag = core_utils.to_str(tag1)
    ciphertext = core_utils.to_str(ciphertext1)

    # clear memory
    core_utils.clear_octet(aes_key1)
    core_utils.clear_octet(iv1)
    core_utils.clear_octet(header1)
    core_utils.clear_octet(plaintext1)
    core_utils.clear_octet(tag1)
    core_utils.clear_octet(ciphertext1)

    return ciphertext, tag


def gcm_decrypt(aes_key, iv, header, ciphertext):
    """AES-GCM Decryption

    AES-GCM Deryption

    Args::

        aes_key: AES Key
        iv: Initialization vector
        header: header
        ciphertext: ciphertext

    Returns::

        plaintext: resultant plaintext
        tag: MAC

    Raises:

    """
    aes_key1, aes_key1_val = core_utils.make_octet(None, aes_key)
    iv1, iv1_val = core_utils.make_octet(None, iv)
    header1, header1_val = core_utils.make_octet(None, header)
    ciphertext1, ciphertext1_val = core_utils.make_octet(None, ciphertext)
    tag1, tag1_val = core_utils.make_octet(AES_KEY)
    plaintext1, plaintext1_val = core_utils.make_octet(len(ciphertext))
    _ = aes_key1_val, iv1_val, header1_val, plaintext1_val, tag1_val, ciphertext1_val # Suppress warnings

    _libamcl_core.AES_GCM_DECRYPT(
        aes_key1,
        iv1,
        header1,
        ciphertext1,
        plaintext1,
        tag1)

    tag = core_utils.to_str(tag1)
    plaintext = core_utils.to_str(plaintext1)

    # clear memory
    core_utils.clear_octet(aes_key1)
    core_utils.clear_octet(iv1)
    core_utils.clear_octet(header1)
    core_utils.clear_octet(plaintext1)
    core_utils.clear_octet(tag1)
    core_utils.clear_octet(ciphertext1)

    return plaintext, tag
