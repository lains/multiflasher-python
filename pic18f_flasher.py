#!/usr/bin/env python3
# coding: utf-8
"""PICBOOT-based flasher for PIC18F

Usage:
  pic18f_flasher.py <command> <serial_port> <hex_filename>

Where <command> is one of the following:
- program
- verify
- dump
"""

from logging import DEBUG, INFO
import serial
from serial import Serial
import sys

import domain.pic18f.picboot_comm as comm
import domain.pic18f.flashing_tools as ftools
from domain.pic18f.pic18f6622 import PIC18F6622ConfigCatalog
from domain.common import create_main_logger
from domain.flasher_context import FlasherContext
from adapters.hex_file_parser_python_intelhex import PythonIntelHexFileParser
from adapters.progressbar_progressbar2 import ProgressBar2Factory
from adapters.progressbar_silent import SilentProgressBarFactory

logger = None

def get_args(_, command, serial_port, firmware_image_filename):
    """@brief Extract command-line arguments
    @note Simplistic built-in version without external dependencies
    """
    return (command, serial_port, firmware_image_filename)

if __name__ == "__main__":
    try:
        (command, pic_comm_device, pic_firmware_filename) = get_args(*sys.argv)
    except TypeError:
        print(__doc__, file=sys.stderr) # Output usage
        exit(1)
    logger = create_main_logger(name="pic_flasher", log_level=INFO, also_log_libs=False)
    if command != "program" and command != "verify" and command != "dump":
        logger.error("Unsupported command '" + command + "'")
        raise NotImplementedError
    pic_firmware = PythonIntelHexFileParser()
    if command != "dump":
        try:
            pic_firmware.read_hex_from(pic_firmware_filename)
        except Exception as e:
            logger.error("Error while reading input firmware file '" + pic_firmware_filename + "': " + str(e))
            exit(1)
    with Serial(pic_comm_device, baudrate=115200, parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, xonxoff=False) as p:
        '''Note: from PICFlasher.INI's DEVICELIST section:
        0="PICUNKNOWN"
        32="PIC18F252"
        33="PIC18F452"
        36="PIC18F242"
        37="PIC18F442"
        48="PIC18F8720"
        49="PIC18F6720"
        52="PIC18F8620"
        53="PIC18F6620"
        156="PIC18F6622"
        2048="PIC16F877"
        2049="PIC16F877A"
        2050="PIC16F876"
        2051="PIC16F876A"
        '''
        accept_device_id = lambda device_id: (device_id == 156) # We are expecting a PIC18F6622 (identifier is thus 156)
        comm.BootloaderRemoteLauncher(device=p,
                                      validate_device_id=accept_device_id,
                                     ).start()
        logger.info("Target is ready to process commands")
    with Serial(pic_comm_device, baudrate=115200, parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, xonxoff=False) as p:
        with comm.PicbootProtocolSession(device=p) as target:
            if not logger.isEnabledFor(DEBUG):
                progressbar_factory=ProgressBar2Factory
            else:
                progressbar_factory=SilentProgressBarFactory
            
            def picboot_command_executor(command: comm.PicbootCommand):
                """@brief Closure allowing execution of commands on the target

                @param command A PicbootCommand to run

                @return An optional result from the command
                """
                return target.execute(command)

            flasher_ctx = FlasherContext(name='cli',
                                         progressbar_factory=progressbar_factory,
                                         logger=logger,
                                         firmware_file_parser=pic_firmware,
                                         target_command_executor=picboot_command_executor)
            pic18f6622_config = PIC18F6622ConfigCatalog()
            if command == "program":
                ftools.pic_program_cmd(context=flasher_ctx, target_config=pic18f6622_config)
            elif command == "verify":
                if not ftools.pic_verify_cmd(context=flasher_ctx, target_config=pic18f6622_config):
                    logger.error("Firmware mismatch")
                    exit(2)
            elif command == "dump":
                ftools.pic_dump_cmd(context=flasher_ctx, target_config=pic18f6622_config)
                pic_firmware.write_hex_to(pic_firmware_filename)
            else:
                raise NotImplementedError
            target.execute(comm.CommandExitBootloader())
            p.timeout = 5   # Wait for a reboot signal for 5s
            assert p.read(1) == b'\x00'

    logger.info('Done')
