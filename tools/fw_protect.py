#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
from Crypto.Cipher import AES
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

    # encryption of the firmware here
    firmware = raw_firmware #for now just keeping this as the "encryption step"
    
    # split the now encrypted firmware into frames
    for i in range(0,len(firmware)-1, 256):
        # split the firmware into chunks of 256
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
    #the key but whatever
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
