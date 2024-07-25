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

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")


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
