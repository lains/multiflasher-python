# PIC18F flasher tool

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

## Sample invokation of the script

* First, make sure you have [setup the environment](#setting-up-the-environment-for-the-python-scripts) to execute the programming python scripts.

* Switch the PIC MCU to picboot mode

* Start (for example), a dump of the firmware:
```
python3 "$FLASHER_TOPDIR"/pic18f_flasher.py dump /dev/ttyUSB0 /path/to/output/file.hex
```

In order to program a firmware image, use `program` instead of `dump` in the command above.

## Debugging the script

In order to debug the multiflasher scripts, update the logger line in the corresponding python script.

Configuration *without* debug:
```
logger = create_main_logger(name="flasher", log_level=INFO, also_log_libs=False)
```

Configuration *with* debug:
```
logger = create_main_logger(name="flasher", log_level=DEBUG, also_log_libs=True)
```
