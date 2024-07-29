/usr/bin/env python

# hey, it pushed!
# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
import os
import pathlib
import subprocess
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import cryptography
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")
ROOT_KEY = b"hi"


def key_derivation(root_key):
    salt = os.urandom(16)
    info1 = b"AES key"
    info2 = b"HMAC key"
    backend = default_backend()

    ikm = root_key

    hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=len(ROOT_KEY),  # Length of the keying material in bytes
    salt=salt,
    info=info1,
    backend=backend)
    aes_key = hkdf.derive(ikm)

    hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=len(ROOT_KEY),  # Length of the keying material in bytes
    salt=salt,
    info=info2,
    backend=backend)
    

    hmac_key = hkdf.derive(ikm)
    with open('../Team-8/tools/secret_build_output.txt', 'wb') as file:
        print(aes_key.hex())
        print(hmac_key.hex())
        file.write(aes_key)
        file.write(b"\n")
        file.write(hmac_key)
    # with open('../Team-8/tools/secret_build_output.txt', 'rb') as file:
    #     print(file.read().hex())


    return aes_key, hmac_key






def make_bootloader() -> bool:
    # Build the bootloader from source.

    os.chdir(BOOTLOADER_DIR)

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0

# input: unencrypted AES key
# output: RSA key pair and encrypted AES key
# output format: [[public key, private key], encrypted AES key]
def generate_and_encrypt(unenc_key):
    rsa_private = RSA.generate(2048)
    rsa_public = rsa_private.public_key()
    enc_aes = rsa_public.encrypt(unenc_key)
    return [[rsa_public, rsa_private], enc_aes]

if __name__ == "__main__":
    make_bootloader()

    key_derivation(ROOT_KEY)
    #make_bootloader()
