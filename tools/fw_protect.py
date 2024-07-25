#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from pwn import *


def protect_firmware(infile, outfile, version, message):
# FRAME 0: METADATA
    # packing metadata
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little')  
    
    # put metadata into a frame with 'METADATA'
    version_frame = metadata + message.encode()
    
    # hash it (place holder for now )
    version_hash = b'\x00\x00'
    
    # append hash to frame
    version_frame = version_frame + version_hash

    # write version frame to outfile (writing this first)
    with open(outfile, "wb+") as outfile:
        outfile.write(version_frame)

# FRAME 1: FIRMWARE DATA
    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        raw_firmware = fp.read()

    # pad the firmware here
    while len(raw_firmware) % 512 != 0:
        raw_firmware += b'0x00'

    # read key from secrets file here, decrypt, save to variable
    with open("./secret_build_output.txt", "rb") as secret:
        secret_raw = secret.read()
        enc_aes_key = secret_raw[PLACEHOLDERVAL:PLACEHOLDERVAL + 32] # replace with location of enc. AES key relative to start
        rsa_private = secret_raw[PLACEHOLDERVAL2:PLACEHOLDERVAL2 + 256] # replace with location of RSA priv. key rel. to start
        rsa_dec_object = PKCS1_OAEP.new(rsa_private)
        usable_aes_key = rsa_dec_object.decrypt(enc_aes_key)

    # encryption of the firmware here
    iv = get_random_bytes(AES.block_size) # generates random iv
    aes_crypt = AES.new(usable_aes_key, AES.MODE_CBC, iv)
    raw_firmware = AES.encrypt(raw_firmware)

    # split the now encrypted firmware into frames
    for i in range(0,len(firmware)-1, 20):
        # split the firmware into chunks of (20 bytes?)
        chunk = firmware[i:i+20] 

        #^^^^this definitely isnt how this should be done, need to double check
        frame_size = p16(len(chunk), endian='little')
        # hash it
        data_hash = b'\x01\x01'

        # add message & hash to firmware frame
        data_frame = frame_size + chunk + data_hash

        #write frames into outfile
        with open(outfile, "wb+") as outfile:
            outfile.write(data_frame)
    
#FRAME 2: END
    end_message = b'END'
    end_hash = b'\x02\x02'
    end_size = p16(len(end_hash), endian = 'little')
    end_frame = end_message + end_size+ end_hash
    
    with open(outfile, "wb+") as outfile:
        outfile.write(end_frame)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)

    # need to add an argument of the key for encryption --> idk how to do this without exposing 
    # the key but whatever
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
