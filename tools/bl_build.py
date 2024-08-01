#!/usr/bin/env python
#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
from util import *
from util import *
import os
import pathlib
import subprocess
from Crypto.Cipher import PKCS1_OAEP

import cryptography
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")
ROOT_KEY = b"hi"



def create_header_file(aes, hmac):
    with open('./header.h', 'w') as header_file:
        header_file.write("#ifndef HEADER_H\n")
        header_file.write("#define HEADER_H\n\n")

        # Convert the keys to be written in the header for C coding
        aes_hex = bytes_to_hex_string(aes)
        hmac_hex = bytes_to_hex_string(hmac)

        header_file.write("static const unsigned char AES_KEY[] = { ")
        header_file.write(', '.join(f'0x{aes_hex[i:i+2]}' for i in range(0, len(aes_hex)-1, 2)))
        header_file.write(" };\n")

        header_file.write("static const unsigned char HMAC_KEY[] = { ")
        header_file.write(', '.join(f'0x{hmac_hex[i:i+2]}' for i in range(0, len(hmac_hex), 2)))
        header_file.write(" };\n")


        header_file.write("#endif // HEADER_H\n")



#function to delete the header after building bootloader.bin
#prevents unauthorized access to the header file
def delete_header_file(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)

#getting rid of the KDF for simplicity sake
def key_derivation(root_key):
    '''salt = os.urandom(16)
    info1 = b"AES key"
    info2 = b"HMAC key"
    backend = default_backend()

    ikm = root_key

    hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=31,  # Length of the keying material in bytes
    salt=salt,
    info=info1,
    backend=backend)
    aes_key = hkdf.derive(ikm)

    hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=31,  # Length of the keying material in bytes
    salt=salt,
    info=info2,
    backend=backend)
    
    
    hmac_key = hkdf.derive(ikm)'''
    # randomly generating 32-byte keys to use
    aes_key = os.urandom(32)
    hmac_key = os.urandom(32)
    with open('./secret_build_output.txt', 'wb') as file:
        file.write(aes_key)
        file.write(hmac_key)

    return aes_key, hmac_key
    






def make_bootloader() -> bool:
    # Build the bootloader from source.

    os.chdir(BOOTLOADER_DIR)

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0



if __name__ == "__main__":
    aes_k, hmac = key_derivation(ROOT_KEY)
    create_header_file(aes_k, hmac)
    make_bootloader()
    delete_header_file("../Team-8/tools/header.h")