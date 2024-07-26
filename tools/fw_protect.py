#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool
"""
import argparse
from pwn import *
from util import *

def protect_firmware(infile, outfile, version, message):
# FRAME 0: METADATA
    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        raw_firmware = fp.read()
    firmware = raw_firmware

    # Packing metadata
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little')
    version_frame = metadata + message.encode()
    #PAD MESSAGE TO BE 1024 BYTES

    # Hash it (placeholder for now)
    version_hash = b'\x00\x00'
    print(len(version_frame))

    # Append hash to frame
    version_frame = version_frame + version_hash

    # Write version frame to outfile (writing this first)
    with open(outfile, "wb+") as out_fp:
        out_fp.write(version_frame)


# FRAME 1: FIRMWARE DATA
    
    # encryption (including iv generation) placeholder
    iv = b'6576' # delete when encryption is incorportated

    # Split the now encrypted firmware into frames
    for i in range(0, len(firmware), 20):
        # Split the firmware into chunks of 20 bytes
        chunk = firmware[i:i + 20]
        
        frame_size = p16(len(chunk), endian='little')

        # Hash it
        data_hash = b'\x01\x01' #placeholder

        # Add message & hash to firmware frame
        data_frame = iv + frame_size + chunk + data_hash
        

        # Write frames into outfile
        with open(outfile, "ab+") as out_fp:
            out_fp.write(data_frame)

# FRAME 2: END
    end_message = b'\x00\x00'
    end_hash = b'\x02\x02' #placeholder
    end_size = p16(len(end_hash), endian='little')
    end_frame = end_message + end_size + end_hash

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
