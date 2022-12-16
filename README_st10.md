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

## Using the library in interactive mode

Because the execution of individual commands to the MCU is also available as Python methods, the ST10 Monitor can be manipulated via a Python interpreter.

In this example, I use IPython.

First, we will need to import external libraries:
```
from serial import Serial
import struct
import domain.st10.monitor_comm as comm
from domain.mcu_addressing import MCULogicalAddressRange
from domain.st10.st10f276 import ST10F276FlashBlocksCatalog
from intelhex import IntelHex
```

> **Note**  
> Importing from IntelHex is only useful if you are going to read of write hex files.


Now, put your ST10 in boostrap mode and make it upload and execute the Monitor embedded software in RAM:
```
p = Serial('/dev/ttyUSB1', 115200)
def accept_chip_id(chip_id):
     print("CHIP ID: " + str(chip_id))
     return True

startchipid_hex_filename='/path/to/startchipid.hex'
monitor_hex_filename='/path/to/Monitor004b.hex'
comm.MonitorRemoteLauncher(device=p, startchipid_hex_filename=startchipid_hex_filename, monitor_hex_filename=monitor_hex_filename, validate_chip_id=accept_chip_id).start()
```

The above command should succeed, and output the value of the ST10 chip ID (in its decimal format)
If you get a BSLProbError `Could not probe ST10 to check it is in BSL mode`, the ST10 is probably not in BSL (bootstrap) mode or it is not properly connected to the serial link.

We should now get a handle on the monitor protocol session before we can run Monitor commands:

```
m=comm.MonitorProtocolSession(device=p).get_handler()
```

Here are a few sample commands we can use (please make sure you know what you are doing when executing these commands):

## Reading the EMUCON register content

```
emucon_reg = struct.unpack('<H', m.execute(comm.CommandDataReceive16BitWords(MCULogicalAddressRange(0x00fe0a, 0x00fe0c)))[0:2])[0]
```

## Erasing the whole flash
```
m.execute(comm.CommandFlashErase(flash_mask=0xffff))
```

> **Note**  
> The flash is now fully erases, it only contains 0xff bytes

## Reading the first 512 bytes of the flash

```
from domain.command_preprocessor import CommandPreprocessor
m.execute(comm.CommandDataReceiveBytes(MCULogicalAddressRange(0, 16)))
```

## Reading B0F0

```
# Create an object of type ST10F276FlashBlocksCatalog, this allows us to have access to the ST10F276 flash organization.
fb = ST10F276FlashBlocksCatalog(ROMS1_set=False, cmd_preprocessor=CommandPreprocessor())
# Get the details of the flash block that contains address 0
r = fb.get_flash_block_at_index(fb.get_block_index_for_address(0))
m.execute(comm.CommandDataReceiveBytes(r))
```

## Writing 512 bytes at the 0x018000 (block B0F4 on ST10F276)

```
from domain.mcu_addressing import MCULocatedLogicalDataChunk
r = fb.get_flash_block_at_index(4)
s = r.start_address # s=0x018000 here
# Write 512 time the byte 0x00
m.execute(comm.CommandDataSend(chunk_to_send=MCULocatedLogicalDataChunk(r.start_address, b'\x00'*512)))
# Read the flash again
m.execute(comm.CommandDataReceiveBytes(MCULogicalAddressRange(r.start_address, r.start_address+512)))
```
