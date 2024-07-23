#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
from pwn import *


def protect_firmware(infile, outfile, version, message):
# FRAME 0: METADATA
    # packing metadata
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little')  
    

#-----------------------------------------------------------------------

    # put metadata into a frame with 'METADATA'
    
    message = ""

    version_frame = metadata + message.encode()
    
    #hash it (place holder for now )

    version_signature = (HMAC.new(key, metadata, digestmod=SHA256)).digest()

    
    #append hash to frame
    version_frame = version_frame + signature

#-----------------------------------------------------------------------


    # write version frame to outfile (writing this first)
    with open(outfile, "wb+") as outfile:
        outfile.write(version_frame)

# FRAME 1: FIRMWARE DATA
    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        raw_firmware = fp.read()

    # encryption of the firmware here
    firmware = raw_firmware #for now just keeping this as the "encryption step"

    
    #split the now encrypted firmware into frames
    for i in range(0,len(firmware), 512):
        # split the firmware into chunks of (512 bytes)
        chunk = firmware[i:i+512] 
        #^^^^this definitely isnt how this should be done, need to double check
        
        frame_size = p16(len(chunk), endian='little')
        # hash it

    """
        size = u16(ser.read(2), endian = "little")            #get the size of the data --> len(chunk)                                                                                        
        data = ser.read(size)                                 # the data --> chunk
        with open("hmackeyfile.bin", "rb") as f:              # get the key  --> should be from secret_output
            key = f.read()
            print(key)
        hashed = HMAC.new(key, data, digestmod=SHA256)        #hashing/signature --> signature
        ser.write(hashed.digest())
    """
        


        #-----------------------------------------------------------------------
        signature = (HMAC.new(key, chunk, digestmod=SHA256)).digest()
        #-----------------------------------------------------------------------
        


    


        

        # add message & hash to firmware frame
        data_frame = frame_size + chunk + signature

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