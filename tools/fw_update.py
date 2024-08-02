#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Updater Tool

A frame consists of two sections:
1. Two bytes for the length of the data section
2. A data section of length defined in the length section

[ 0x02 ]  [ variable ]
--------------------
| Length | Data... |
--------------------

In our case, the data is from one line of the Intel Hex formated .hex file

We write a frame to the bootloader, then wait for it to respond with an
OK message so we can write the next frame. The OK message in this case is
just a zero
"""

import argparse
from pwn import *
import time
import serial

from util import *

ser = serial.Serial("/dev/ttyACM0", 115200)

RESP_OK = b"\x04"
FRAME_SIZE = 546 #we took away the IV

def read_byte():
    byte = ser.read(1)
    if byte.decode == b'W':
        return RuntimeError("ERROR: Bootloader freaking reset!??!")
    while byte != b'\x04':
        byte = ser.read(1)
        print(byte)
    return byte

def send_frame_zero(ser, frame_zero, debug=False):
    #assert(len(frame_zero) == 1060)
    iv = frame_zero[:16]
    print(f'iv is')
    print_hex(iv)
    

    # Handshake for update 
    ser.write(b"U")

    print("Waiting for bootloader to enter update mode...")
    if ser.read(1).decode() == "U":
        print("starting load_firmware()")

    #Send size and version to bootloader
    print_hex(frame_zero)
    print(f'length of frame 0: {len(frame_zero)}')
    ser.write(frame_zero)


    if debug:
        print(frame_zero)

        
    # Wait for an OK from the bootloader.
    resp = read_byte()
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))
    print('moving past frame_zero')

def send_frame(ser, frame, debug=False):
    print('sending frame next')
    ser.write(frame)  # Write the frame...
    print_hex(frame)
    print(f'length of frame {len(frame)}')

    if debug:
        print_hex(frame)

    resp = ser.read(1)  # Wait for an OK from the bootloader
    print_hex(resp)
    print(f'bootloader okayed  a firmware frame,')

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))


def update(ser, infile, debug):
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, "rb") as fp:
        firmware_blob = fp.read()

    frame_zero = firmware_blob[:1088]
    firmware = firmware_blob[1088:-2]
    end = firmware_blob[-2:]
    '''print_hex(frame_zero)
    print('\n')
    print_hex(firmware)
    print('\n')
    print_hex(end)'''

    #sending frame_zero (version_frame) first to bootloader to verify the versioning
    send_frame_zero(ser, frame_zero, debug=debug)
    
    ##EACH FRAME IS 546
    for idx, frame_start in enumerate(range(0, len(firmware), FRAME_SIZE)):
        # getting each (already divided) frame from firmware_protected.bin
        frame = firmware[frame_start : frame_start+FRAME_SIZE]
        if idx == 5:
            print(f'frame start: {frame_start}')
            print_hex(frame)
        send_frame(ser, frame, debug=debug)
        print(f"\nWrote frame {idx} ({len(frame)} bytes)")

    print("\nDone writing firmware.")

    # Send a zero length payload to tell the bootlader to finish writing it's page.
    print_hex(end)
    ser.write(end)
    resp = ser.read(1)  # Wait for an OK from the bootloader
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded to zero length frame with {}".format(repr(resp)))
    print(f"Wrote end frame (2 bytes)")

    return ser


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")

    parser.add_argument("--port", help="Does nothing, included to adhere to command examples in rule doc", required=False)
    parser.add_argument("--firmware", help="Path to firmware image to load.", required=False)
    parser.add_argument("--debug", help="Enable debugging messages.", action="store_true")
    args = parser.parse_args()

    update(ser=ser, infile=args.firmware, debug=args.debug)
    ser.close()