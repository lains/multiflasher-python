# ST10 flasher tool

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

## Sample invokation of the script

* First, make sure you have [setup the environment](#setting-up-the-environment-for-the-python-scripts) to execute the programming python scripts.

* Switch the ST10 MCU to boostrap mode

* Point the script to the required STARTCHIPID and ST10_MONITOR hex files via environment variables and start (for example), a dump of the firmware:
```
ST10_STARTCHIPID="/path/to/startchipid.hex \
ST10_MONITOR="/path/to/Monitor004b.hex \
python3 "$FLASHER_TOPDIR"/st10_flasher.py dump /dev/ttyUSB1 /path/to/output/file.hex
```

In order to program a firmware image, use `program` instead of `dump` in the command above.
