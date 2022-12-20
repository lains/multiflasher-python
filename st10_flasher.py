#!/usr/bin/env python3
# coding: utf-8
"""BSL-based flasher for ST10

Usage:
  st10_flasher.py <command> <serial_port> <hex_filename>

Where <command> is one of the following:
- program
- verify
- dump

Note:
ST10_STARTCHIPID environment variable should point to the filename containing the startchipid hex-formatted file
ST10_MONITOR environment variable should point to the filename containing the relevant monitor hex-formatted file
"""

from logging import DEBUG, INFO
from serial import Serial
import struct
import sys
import os
from domain.mcu_addressing import MCULogicalAddressRange

import domain.st10.monitor_comm as comm
import domain.st10.flashing_tools as ftools
from domain.st10.st10f276 import ST10F276FlashBlocksCatalog
from domain.common import create_main_logger
from domain.flasher_context import FlasherContext
from adapters.hex_file_parser_python_intelhex import PythonIntelHexFileParser
from adapters.progressbar_progressbar2 import ProgressBar2Factory
from adapters.progressbar_silent import SilentProgressBarFactory

logger = None

def get_args(command, serial_port, firmware_image_filename):
    """@brief Extract command-line arguments
    @note Simplistic built-in version without external dependencies
    """
    return (command, serial_port, firmware_image_filename)

if __name__ == "__main__":
    minimal_flash_erase = False
    debug = False
    debug_libs = False
    argv=sys.argv
    if len(argv) < 4:  # arg count + 1 for programe
        print("Not enough arguments", file=sys.stderr)
        print(__doc__, file=sys.stderr) # Output usage
        exit(1)
    progname = argv.pop(0)
    while len(argv) > 3:
        option = argv.pop(0)
        if option == '-f':
            minimal_flash_erase = True
        elif option == '-d':
            if not debug:
                debug = True
            else:
                debug_libs = True
        else:
            print(f"Unknown leading option: '{option}'", file=sys.stderr)
            exit(1)
    try:
        (command, st10_comm_device, st10_firmware_filename) = get_args(*argv)
        try:
            startchipid_hex_filename = os.environ['ST10_STARTCHIPID']
        except KeyError:
            print("Missing ST10_STARTCHIPID environment variable, please check help for more details", file=sys.stderr)
            exit(1)
        assert startchipid_hex_filename
        try:
            monitor_hex_filename = os.environ['ST10_MONITOR']
        except KeyError:
            print("Missing ST10_MONITOR environment variable, please check help for more details", file=sys.stderr)
            print(__doc__, file=sys.stderr) # Output usage
            exit(1)
        assert monitor_hex_filename
    except TypeError:
        print(__doc__, file=sys.stderr) # Output usage
        exit(1)
    logger = create_main_logger(name="st10_flasher", log_level=(DEBUG if debug else INFO), also_log_libs=debug_libs)
    if command != "program" and command != "verify" and command != "dump":
        logger.error("Unsupported command '" + command + "'")
        raise NotImplementedError
    st10_firmware = PythonIntelHexFileParser()
    if command != "dump":
        try:
            st10_firmware.read_hex_from(st10_firmware_filename)
        except Exception as e:
            logger.error("Error while reading input firmware file '" + st10_firmware_filename + "': " + str(e))
            exit(1)
    with Serial(st10_comm_device, baudrate=115200) as p:
        accept_chip_id = lambda chip_id: ((chip_id & 0xfff0) == 0x1140) # We are expecting a ST10F276E (identifier is thus 0x114? with ? being a single hex digit revision)
        monitor_info_addr = comm.MonitorRemoteLauncher(device=p,
                                                       startchipid_hex_filename=startchipid_hex_filename,
                                                       monitor_hex_filename=monitor_hex_filename,
                                                       validate_chip_id=accept_chip_id,
                                                      ).start()
        logger.info("Target is ready to process commands")
        # Currently monitor_info_addr is always 0x00e3d0 and is thus located inside the XRAM1
        with comm.MonitorProtocolSession(device=p) as target:
            if not logger.isEnabledFor(DEBUG):
                progressbar_factory=ProgressBar2Factory
            else:
                progressbar_factory=SilentProgressBarFactory

            def monitor_command_executor(command: comm.MonitorCommand):
                """@brief Closure allowing execution of commands on the target

                @param command A MonitorCommand to run

                @return An optional result from the command
                """
                return target.execute(command)

            flasher_ctx = FlasherContext(name='cli',
                                         progressbar_factory=progressbar_factory,
                                         logger=logger,
                                         firmware_file_parser=st10_firmware,
                                         target_command_executor=monitor_command_executor,
                                         retries=5)
            result = target.execute(comm.CommandDataReceiveBytes(MCULogicalAddressRange(monitor_info_addr, monitor_info_addr+42)))
            result = target.execute(comm.CommandDataReceive16BitWords(MCULogicalAddressRange(0x00fe0a, 0x00fe0c))) # Ask for EMUCON register in SFR zone (bit 5 is ABM flag)
            emucon_reg = struct.unpack('<H', result[0:2])[0]
            alternate_boot_mode = (emucon_reg & (1 << 5)) != 0
            logger.debug("Alternate boot mode" + (" enabled" if alternate_boot_mode else " disabled"))

            # ROMS1 register is expected to be cleared in the linker script that generated the st10_firmware to program (that we are going to parse now)
            # Also, Monitor comm requires some preprocessing on ranges provided as input. This preprocessing is made available via get_command_preprocessor()
            st10f276_flash_blocks = ST10F276FlashBlocksCatalog(ROMS1_set=False, cmd_preprocessor=comm.get_command_preprocessor())
            if command == "program":
                ftools.st10_program_cmd(context=flasher_ctx, target_flash_blocks=st10f276_flash_blocks, full_erase=(not minimal_flash_erase))
            elif command == "verify":
                if not ftools.st10_verify_cmd(context=flasher_ctx, target_flash_blocks=st10f276_flash_blocks):
                    logger.error("Firmware mismatch")
                    exit(2)
            elif command == "dump":
                ftools.st10_dump_cmd(context=flasher_ctx, target_flash_blocks=st10f276_flash_blocks)
                st10_firmware.write_hex_to(st10_firmware_filename)
            else:
                raise NotImplementedError

    logger.info('Done')
