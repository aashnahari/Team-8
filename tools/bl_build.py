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

def create_header_file(aes, hmac, rsaPriv):
    with open('../Team-8/tools/header.h', 'w') as header_file:
        header_file.write("#ifndef HEADER_H\n")
        header_file.write("#define HEADER_H\n\n")
        header_file.write(f"#define ENC_AES_KEY \"{aes}\"\n")
        header_file.write(f"#define HMAC_KEY \"{hmac}\"\n\n")
        header_file.write(f"#define RSA_PRIVATE_KEY \"{rsaPriv}\"\n\n\n")
        header_file.write("#endif // HEADER_H\n")


def delete_header_file(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)

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
        key_arr = generate_and_encrypt(aes_key) # encrypts AES key with generated RSA key
        rsa_private = key_arr[0][1]
        rsa_public = key_arr[0][0]
        aes_key_enc = key_arr[1]
        file.write(aes_key)
        file.write(b"\n")
        file.write(hmac_key)
        file.write(b"\n")
        file.write(rsa_private)
        file.write(b"\n")
        file.write(rsa_public)
        file.write(b"\n")
    # with open('../Team-8/tools/secret_build_output.txt', 'rb') as file:
    #     print(file.read().hex())
       


    return aes_key_enc, hmac_key, rsa_private






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

    aes_enc, hmac, rsaPriv = key_derivation(ROOT_KEY)
    create_header_file(aes_enc, hmac, rsaPriv)
    delete_header_file("../Team-8/tools/header.h")
    #make_bootloader()
