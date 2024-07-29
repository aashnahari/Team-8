#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

def print_hex(data):
    hex_string = " ".join(format(byte, "02x") for byte in data)
    print(hex_string)

#function to convert from bytes into a hex string (used in bl_build.py's create_header_file() function)
def bytes_to_hex_string(data):
    """Convert bytes to a hexadecimal string with each byte represented as two hex digits."""
    return ''.join(f'{byte:02X}' for byte in data)