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

This setup is required before flashing an ST10 chip.

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

The ST10 flasher tool is [`st10_flasher.py`](./st10_flasher.py)

Please note that the code may also work for C166 chips as both ST10/C166 are very similar in microcontroller architecture and share the same bootstrapping process.

The original "ST10FLASHER tool" was provided by ST Microelectronics many years ago and can be still found for download, as the time of writing these lines, one can download it at: https://www.st.com/en/embedded-software/stsw-st10004.html

Download for this tool will be needed, at least to get hold of 2 binaries compiled for the ST10, and provided in the original ST10FLASHER tool's package (see above to get them) as Intel HEX files, namely:
* `startchipid.hex` (a short executable code that extracts the CHIP ID value from the ST10 and dumps it on the serial port)
* `Monitor004b.hex` (an embedded executable for ST10F276 that is able to write/read/erase flash, or dump registers based on a master/slave serial protocol)

> **Warning**  
> I only tested my script against ST10F276 because I had no other variant at hand, but the script probably works with most of the ST10 family, except that you might have to properly adjust the version of the Monitor software used to something else than version 4b (`Monitor004b.hex`).

A path to both these hex files should be provided to the script using environment variables (see the st10 flasher's help for more information)

This python code represent the master-end of the protocol to communicate with the embedded Monitor executable, as well as the bootstrap process to inject that Monitor executable to the ST10 in bootstrap mode.

Before being able to run the Monitor code in the ST10, you will need to enter bootstrap mode on the ST10. This is hardware-dependant, may or not be feasible on your board, and may require hard-wiring pins on the ST10 (see ST Microelectronics' datasheet for the specifics on how to do this).

Once the ST10 is switched to bootstrap mode, this python script will verify that it is correctly waiting in BSL-mode (Bootstrap Loader) by sending a probe usind a dedicated method `probe_check_st10()`, then will verify that the remote MCU is the expected one (using the ST10's burried CHIP ID value).

> **Warning**  
> Please note that the whole python code is customized for the specific ST10F276 chip (especially CHIP ID detection and flash partitionning definition), but adapting it to other variants should be quite easy.
> In order to accepts non-ST10F276 variants, you should changed the content of the function provided as `MonitorRemoteLauncher`'s `validate_chip_id` argument.

The rest of the code is targetted to flash manipulation (reading/erasing/writing).

To run the ST10 flashing script, execute the python script `st10_flasher.py`, providing the serial port and the firmware to program on the command line (and pointing it to utility hex filenames via the relevant environment variables).

### Sample invokation of the script

* First, make sure you have [setup the environment](#setting-up-the-environment-for-the-python-scripts) to execute the programming python scripts.

* Switch the ST10 MCU to boostrap mode

* Point the script to the required STARTCHIPID and ST10_MONITOR hex files via environment variables and start (for example), a dump of the firmware:
```
ST10_STARTCHIPID="/path/to/startchipid.hex \
ST10_MONITOR="/path/to/Monitor004b.hex \
python3 "$FLASHER_TOPDIR"/st10_flasher.py dump /dev/ttyUSB1 /path/to/output/file.hex
```

In order to program a firmware image, use `program` instead of `dump` in the command above.

## PIC18F flasher tool

The PIC18F flasher tool is [`pic18f_flasher.py`](./pic18f_flasher.py)

The original "PIC18F tool" was provided by Microchip as both binary libraries driver (DLL) and source code (together with documentation in the form of the Application Note 851) many years ago and can be still found for download.
At the time these lines are written (2022), one can download it at: http://ww1.microchip.com/downloads/en/DeviceDoc/00851.zip

This python code represent the master part of the protocol to communicate with the embedded picboot executable, as well as the bootstrap process to force the PIC to run in bootstrap mode.

Before being able to switch the PIC MCU to picboot mode, you will need to perform a reset on it. This is hardware-dependant, may or not be feasible on your board, and may require hard-wiring pins on the PIC. You will also need to wire the UART pins of the PIC to your master so that it can communicate with the PIC.

Switching the PIC MCU to picboot mode also implies that the PIC should already be programmed (config zone + bootloader EEPROM) prior to running this script. This can be done using a PIC18F-compatible on-board probe. This flasher will only accept programming the programmable memory of the PIC (not the bootloader in EEPROM, nor the config)

Once the PIC is switched to picboot mode, this python script will verify that it is correctly in picboot mode by retrieving the PIC device ID.

The rest of the code is targetted to flash manipulation (reading/erasing/writing).

> **Warning**  
> Please note that the whole python code is customized for the specific PIC18F6622 chip (especially CHIP ID detection and flash partitionning definition), but adapting it to other variants should be quite easy.

To run the PIC18F flashing script, execute the python script `pic18_flasher.py`, providing the serial port and the firmware to program on the command line.

### Sample invokation of the script

* First, make sure you have [setup the environment](#setting-up-the-environment-for-the-python-scripts) to execute the programming python scripts.

* Switch the PIC MCU to picboot mode

* Start (for example), a dump of the firmware:
```
python3 "$FLASHER_TOPDIR"/pic18f_flasher.py dump /dev/ttyUSB0 /path/to/output/file.hex
```

In order to program a firmware image, use `program` instead of `dump` in the command above.

## Debugging scripts

In order to debug the multiflasher scripts, update the logger line in the corresponding python script.

Configuration *without* debug:
```
logger = create_main_logger(name="st10_flasher", log_level=INFO, also_log_libs=False)
```

Configuration *with* debug:
```
logger = create_main_logger(name="st10_flasher", log_level=DEBUG, also_log_libs=True)
```
