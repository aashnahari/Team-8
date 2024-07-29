# Cryptographic Automotive Software Handler and Bootloader (CrASHBoot)
This is the documentation for Team 8's (name in progress) secure data transmission system for our "autonomous car" (tiva board). Enjoy!

# Project Structure
```
├── bootloader *
│   ├── bin
│   │   ├── bootloader.bin
│   ├── src
│   │   ├── bootloader.c
│   │   ├── startup_gcc.c
│   ├── bootloader.ld
│   ├── Makefile
├── firmware
│   ├── bin
│   │   ├── firmware.bin
│   ├── lib
│   ├── src
├── lib
│   ├── driverlib
│   ├── inc
│   ├── uart
├── tools *
│   ├── bl_build.py
│   ├── fw_protect.py
│   ├── fw_update.py
│   ├── util.py
├── README.md

Directories marked with * are part of the CrASHBoot system
```

## Bootloader

The `bootloader` directory contains source code that is compiled and loaded onto the TM4C microcontroller. The bootloader manages which firmware can be updated to the TM4C. When connected to the fw_update tool, the bootloader will first check the version of the new firmware, which will be sent in the version frame–FRAME 0– against the stored firmware version. If the firmware version is valid, the bootloader will then decrypt the frames of firmware data using the stored AES key (from header.h) and verify the signature of each frame using the HMAC-SHA256 key (again, from header.h). If no errors arise, the firmware (and its version number) will be stored in memory. 

The bootloader will also start the execution of the loaded vehicle firmware.

## Tools

There are three python scripts in the `tools` directory which are used to:

1. Provision the bootloader (`bl_build.py`)
2. Encrypt the firmware and package the data into frames (`fw_protect.py`)
3. Update the firmware to a TM4C with a provisioned bootloader (`fw_update.py`)

### bl_build.py

This script calls `make` in the `bootloader` directory.

### fw_protect.py

This script encrypts the firmware data, breaks the data into frames, and then adds a signature to each frame. The frames are then written to the outfile `protected_firmware.bin`. There are 3 types of frames that this script creates.
 #### FRAME 0 (version_frame)
 This frame type contains all of the metadata–the version of the firmware and the total size of the firmware– along with the firmware's release message and an HMAC-SHA256 signature.

 #### FRAME 1 (firmware_frame)
 This frame type contains the AES encryption IV, the size of the firmware data in the frame, a chunk of AES-encrypted firmware, and then an HMAC-SHA256 signature.

 #### FRAME 2 (end_frame)
 This frame type contains a 'frame size' of 0 bytes and an HMAC-SHA256 signature. This frame indicates to the bootloader that all of the firmware data has been sent through serial.

### fw_update.py

This script opens a serial channel with the bootloader, then writes the firmware metadata and binary broken into data frames to the bootloader.

# Building and Flashing the Bootloader

1. Enter the `tools` directory and run `bl_build.py`

```
cd ./tools
python bl_build.py
```

2. Flash the bootloader using `lm4flash` tool
   
```
sudo lm4flash ../bootloader/bin/bootloader.bin
```

# Bundling and Updating Firmware

1. Enter the firmware directory and `make` the example firmware.

```
cd ./firmware
make
```

2. Enter the tools directory and run `fw_protect.py`

```
cd ../tools
python fw_protect.py --infile ../firmware/bin/firmware.bin --outfile firmware_protected.bin --version 2 --message "Firmware V2"
```

This creates a firmware bundle called `firmware_protected.bin` in the tools directory.

3. Reset the TM4C by pressig the RESET button

4. Run `fw_update.py`

```
python fw_update.py --firmware ./firmware_protected.bin
```

If the firmware bundle is accepted by the bootloader, the `fw_update.py` tool will report it wrote all frames successfully.

Additional firmwares can be updated by repeating steps 3 and 4, but only firmware versions higher than the one flashed to the board (or version 0) will be accepted.

# Interacting with the Bootloader

Using the custom `car-serial` script:
```
car-serial
```

Using `pyserial` module:

```
python -m serial.tools.miniterm /dev/ttyACM0 115200
```

You can now interact with the bootloader and firmware! Type 'B' to boot.

Exit miniterm: `Ctrl-]`
Exit picocom: `Ctrl-A X`

# Launching the Debugger
Use OpenOCD with the configuration files for the board to get it into debug mode and open GDB server ports:
```bash
openocd -f /usr/share/openocd/scripts/interface/ti-icdi.cfg -f /usr/share/openocd/scripts/board/ti_ek-tm4c123gxl.cfg
```

Start GDB and connect to the main OpenOCD debug port:
```bash
gdb-multiarch -ex "target extended-remote localhost:3333" bootloader/bin/bootloader.axf
```

Go to `main` function and set a breakpoint
```
layout src
list main
break bootloader.c:50
```

Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED <br>
Approved for public release. Distribution unlimited 23-02181-25.
