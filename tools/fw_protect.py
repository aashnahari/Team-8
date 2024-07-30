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
def sign(ky, frame_data):  #call 'sign' whenever need to sign
    #-----------------------------------------------------------------------
    signature = (HMAC.new(ky, frame_data, digestmod=SHA256)).digest()
    return signature
    #-----------------------------------------------------------------------



def protect_firmware(infile, outfile, version, message):
# FRAME 0: METADATA
    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        raw_firmware = fp.read()
    firmware = raw_firmware

    # Packing metadata
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little')

    # padding message to be 1024 bytes (biggest size possible)
    message_length = len(message.encode())
    if message_length < 1024:
        # Pad message with zero bytes if it's shorter than 1024 bytes
        padded_message = message.encode() + b'\x00' * (1024 - message_length)
    elif message_length == 1024:
        padded_message = message.encode()
    else:
        # If the message is longer than 1024 bytes, truncate it (but this shouldn't happen since the 
        # parameters for the challenge said that the largest message to handle would be 1 kB)
        padded_message = message.encode()[:1024]

    # Create version frame
    version_frame = metadata + padded_message

# sign it (placeholder for now)
    version_sig = b'\x00' * 32

    # Append signature to frame
    version_frame = version_frame + version_sig

    # Write version frame to outfile (writing frame 0 first specifically)
    with open(outfile, "wb+") as out_fp:
        out_fp.write(version_frame)


# FRAME 1: FIRMWARE DATA
    
      # pad the firmware here
    while len(raw_firmware) % 512 != 0:
        raw_firmware += b'0x00'

    # read key from secrets file here, decrypt, save to variable
    with open("./secret_build_output.txt", "rb") as secret:
        secret_arr = secret.readlines()
        enc_aes_key = secret_arr[0]
        rsa_private = secret_arr[2] # replace with location of RSA priv. key rel. to start
        rsa_dec_object = PKCS1_OAEP.new(rsa_private)
        usable_aes_key = rsa_dec_object.decrypt(enc_aes_key)

        secret_hmac_key = secret_arr[1]

    # encryption of the firmware here
    iv = get_random_bytes(AES.block_size) # generates random iv
    aes_crypt = AES.new(usable_aes_key, AES.MODE_CBC, iv)
    firmware = aes_crypt.encrypt(raw_firmware)

    # Split the now encrypted firmware into frames
    for i in range(0, len(firmware), 512):
        # Split the firmware into chunks of 512 bytes
        chunk = firmware[i:i + 512]
        
        #pack the chunk size appropriately for writing to serial
        chunk_size = p16(len(chunk), endian='little')

# SIGNATURE
        data_sig = b'\x00' * 32 #placeholder

        # assemble the frame
        data_frame = iv + chunk_size + chunk + data_sig 

        # Write frame into outfile
        with open(outfile, "ab+") as out_fp:
            out_fp.write(data_frame)

# FRAME 2: END
    end_message = b'\x00\x00'
    
    end_sig= sign(secret_hmac_key, end_message)
    
    end_frame = end_message + end_sig

    # Append end frame to outfile
    with open(outfile, "ab+") as out_fp:
        out_fp.write(end_frame)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)

    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)