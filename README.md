# Foreword

This code has been developped while searching for portable and reliable solutions to flash ST10 and PIC18F chips.

While I found a few utilities to do so, most of them were closed source, and/or compiled binaries for Windows only, and I needed a portable (interpreted) version that I could modify.

ST10 is a quite old chip, that is well spread in automotive ECUs. Unfortunately its associated programming software may soon become unsupported, because they rely on old versions of Windows, and I could find almost no documentation about the flashing communication protocol going on between the flasher and the MCU.

However, it became to me obvious that, because this chip has been heavily used, it is a good and cheap option for DIY projects.
I thus publish this source code in the hope that other people will find it useful to repair and reprogram these existing chips, instead of just throwing them away because one can't find the utilities to reprogram them anymore.
This can give these chips a new life, and it is also positive for the planet.

# Disclaimer

This software is provided "AS IS", without warranty of any kind, express of implied.

It is published in the hope that it can help others to program compatible microcontrollers that they own, but you do so at your own risk.
Also, I can only highly recommend that you first attempt to perform a `dump` of you chip's flash as a first step before any other (and more dangerous...) operation (like `program`).

More details about the license can be found [here](./LICENSE).

# Generic flasher tools

This directory contains script-only (python3), portable flasher utilities.

The aim of these scripts is to be able to program ST10 chips used as embedded MCUs, and to do this without relying on any third-party and/or OS-dependent binary/library (DLL).

These scripts can also verify (compare with a provided hex file) or dump the data stored in the MCU program memory.

## Setting up the environment for the python scripts

This setup is required before flashing MCU chips.

Prepare a python virtual environment to run multiflasher scripts:
```
cd /path/to/topdir/multiflasher-python/
export FLASHER_TOPDIR="$(pwd)"
python3 -m venv venv
source "$FLASHER_TOPDIR/venv/bin/activate"
"$FLASHER_TOPDIR"/venv/bin/pip3 install -r "$FLASHER_TOPDIR"/requirements.txt
```

> **Note**  
> The before last line (`source ...`) (but not the previous ones) will need to be run again each time a new shell is opened.

## ST10 flasher tool

Instructions are available in [the dedicated readme](./README_st10.md).

## PIC18F flasher tool

Instructions are available in [the dedicated readme](./README_pic18f.md).

## Debugging scripts

In order to debug the multiflasher scripts, update the logger line in the corresponding python script.

Configuration *without* debug:
```
logger = create_main_logger(name="flasher", log_level=INFO, also_log_libs=False)
```

Configuration *with* debug:
```
logger = create_main_logger(name="flasher", log_level=DEBUG, also_log_libs=True)
```
