# coding: utf-8
import pytest
import random
from typing import List

from adapters.mock_logger import MockLogger, ERROR, WARNING, INFO, DEBUG
from adapters.hex_file_parser_python_intelhex import PythonIntelHexFileParser
from adapters.mock_progressbar import ProgressBarFactoryInterface, MockProgressBar
from adapters.progressbar_silent import SilentProgressBarFactory
from domain.mcu_addressing import MCULocatedLogicalDataChunk, MCULogicalAddressRange
import domain.st10.flashing_tools as flashing_tools
import domain.st10.monitor_comm as monitor_comm
from domain.st10.st10f276 import ST10F276FlashBlocksCatalog
from domain.flasher_context import FlasherContext

test_flashblockscatalog = ST10F276FlashBlocksCatalog(ROMS1_set=False, cmd_preprocessor=monitor_comm.get_command_preprocessor())

class UncaughtException(Exception):
    """@brief Void but unknown exception used to be propagated to caller
    """
    pass

class EmulatedFlash:
    """@brief Emulation of flash storage, in memory
    """
    def __init__(self, flash_size: int, ignore_out_of_bounds_on_erase: bool=True, ignore_all_out_of_bounds_accesses: bool=False):
        self.flash_size = flash_size
        self.ignore_all_out_of_bounds_accesses = ignore_all_out_of_bounds_accesses
        self.ignore_out_of_bounds_on_erase = ignore_out_of_bounds_on_erase
        if self.ignore_all_out_of_bounds_accesses:
            self.ignore_out_of_bounds_on_erase
        self.flash = bytearray([0x00] * flash_size)
    
    def write_data_at(self, chunk: MCULocatedLogicalDataChunk):
        write_addr = chunk.start_address
        for b in chunk.get_content():
            if write_addr < self.flash_size:
                self.flash[write_addr] = b
                write_addr += 1
            else:
                if self.ignore_all_out_of_bounds_accesses:
                    break
                else:
                    raise IndexError(f'Outside of flash space: {write_addr:06x}/{self.flash_size:06x}')

    def read_data_at(self, address: MCULogicalAddressRange) -> bytes:
        if address.start_address <= self.flash_size and address.end_address <= self.flash_size:
            return self.flash[address.start_address:address.end_address]
        else:
            if self.ignore_all_out_of_bounds_accesses:
                return b''
            else:
                raise IndexError(f'Outside of flash space: {address}/{self.flash_size:06x}')

    def erase_at(self, addr_range: MCULogicalAddressRange):
        for write_addr in range(addr_range.start_address, addr_range.end_address):
            if write_addr < self.flash_size:
                self.flash[write_addr] = 0xff
            else:
                if self.ignore_out_of_bounds_on_erase:
                    break
                else:
                    raise IndexError(f'Outside of flash space: {write_addr:06x}/{self.flash_size:06x}')

def test_flash_writer_with_0_retries():
    sample_address = 0x2000
    sample_content = b'0123456789abcdef'
    def fake_write_handler(command: monitor_comm.MonitorCommand):
        assert command.COMMAND_ID == monitor_comm.CommandDataSend.COMMAND_ID
        assert command.get_content_payload() == sample_content
    
    test_firmware = PythonIntelHexFileParser()
    test_firmware.put_data_chunk(MCULocatedLogicalDataChunk(sample_address, sample_content))
    test_context = FlasherContext('',
                                  progressbar_factory=SilentProgressBarFactory,
                                  logger=MockLogger(DEBUG),
                                  firmware_file_parser=test_firmware,
                                  target_command_executor=fake_write_handler)
    
    # When a flash write operation is invoked
    flash_writer = flashing_tools.create_flash_writer(context=test_context,
                                                     target_flash_blocks=test_flashblockscatalog,
                                                     progress_updater=None)
    flash_writer(MCULogicalAddressRange(start_address=sample_address, end_address=sample_address+len(sample_content)))

    # Then no exception should be raised

def test_flash_writer_no_retry_on_unknown_exception():
    class TestContext:
        def __init__(self):
            self.total_tries_number = 0

    sample_address = 0x2000
    sample_content = b'0123456789abcdef'
    retry_test_context = TestContext()

    def fake_write_handler(command: monitor_comm.MonitorCommand):
        retry_test_context.total_tries_number += 1
        raise UncaughtException("Unexpected exception")
    
    test_firmware = PythonIntelHexFileParser()
    test_firmware.put_data_chunk(MCULocatedLogicalDataChunk(sample_address, sample_content))
    test_context = FlasherContext('',
                                  progressbar_factory=SilentProgressBarFactory,
                                  logger=MockLogger(DEBUG),
                                  firmware_file_parser=test_firmware,
                                  target_command_executor=fake_write_handler,
                                  retries=3)
    
    # When a flash write operation is invoked
    with pytest.raises(UncaughtException):
        flash_writer = flashing_tools.create_flash_writer(context=test_context,
                                                          target_flash_blocks=test_flashblockscatalog,
                                                          progress_updater=None)
        flash_writer(MCULogicalAddressRange(start_address=sample_address, end_address=sample_address+len(sample_content)))

    # Then, the UncaughtException should have been raised and no retry should be performed
    assert retry_test_context.total_tries_number == 1

def test_flash_writer_with_2_retries():
    class TestContext:
        def __init__(self):
            self.total_tries_number = 0
            self.expected_erase = False

    sample_address = 0x2000
    sample_content = b'0123456789abcdef'
    retry_test_context = TestContext()

    def fake_write_handler(command: monitor_comm.MonitorCommand):
        if retry_test_context.expected_erase:
            assert command.COMMAND_ID == monitor_comm.CommandFlashErase.COMMAND_ID
            retry_test_context.expected_erase = False  # Once erase has been done, we should write again
        else:
            assert command.COMMAND_ID == monitor_comm.CommandDataSend.COMMAND_ID
            assert command.get_content_payload() == sample_content
            if retry_test_context.total_tries_number < 3:
                retry_test_context.total_tries_number += 1
                retry_test_context.expected_erase = True    # Next call should be an erase
                raise monitor_comm.ChecksumError("Should retry")
            else:
                return  # At the 3rd retry, succeed!
    
    test_firmware = PythonIntelHexFileParser()
    test_firmware.put_data_chunk(MCULocatedLogicalDataChunk(sample_address, sample_content))

    test_context = FlasherContext('',
                                  progressbar_factory=SilentProgressBarFactory,
                                  logger=MockLogger(DEBUG),
                                  firmware_file_parser=test_firmware,
                                  target_command_executor=fake_write_handler,
                                  retries=3)
    
    # When a flash write operation is invoked
    flash_writer = flashing_tools.create_flash_writer(context=test_context,
                                                      target_flash_blocks=test_flashblockscatalog,
                                                      progress_updater=None)
    flash_writer(MCULogicalAddressRange(start_address=sample_address, end_address=sample_address+len(sample_content)))

    # Then we should have tried 3 times in total (1 initial attempt + 2 retries) times without exception
    assert retry_test_context.total_tries_number == 3

def test_flash_verifier_with_0_retries():
    sample_address = 0x2000
    sample_content = b'0123456789abcdef'
    def fake_verify_handler(command: monitor_comm.MonitorCommand):
        assert command.COMMAND_ID == monitor_comm.CommandDataVerify.COMMAND_ID
        assert command.get_content_payload() == sample_content
    
    test_firmware = PythonIntelHexFileParser()
    test_firmware.put_data_chunk(MCULocatedLogicalDataChunk(sample_address, sample_content))
    test_context = FlasherContext('',
                                  progressbar_factory=SilentProgressBarFactory,
                                  logger=MockLogger(DEBUG),
                                  firmware_file_parser=test_firmware,
                                  target_command_executor=fake_verify_handler)
    
    # When a flash verify operation is invoked
    flash_verifier = flashing_tools.create_flash_verifier(context=test_context,
                                                          target_flash_blocks=test_flashblockscatalog,
                                                          progress_updater=None)
    flash_verifier(requested_range=MCULogicalAddressRange(start_address=sample_address, end_address=sample_address+len(sample_content)))

    # Then no exception should be raised

def test_flash_verifier_no_retry_on_unknown_exception():
    class TestContext:
        def __init__(self):
            self.total_tries_number = 0

    sample_address = 0x2000
    sample_content = b'0123456789abcdef'
    retry_test_context = TestContext()

    def fake_verify_handler(command: monitor_comm.MonitorCommand):
        retry_test_context.total_tries_number += 1
        raise UncaughtException("Unexpected exception")
    
    test_firmware = PythonIntelHexFileParser()
    test_firmware.put_data_chunk(MCULocatedLogicalDataChunk(sample_address, sample_content))
    test_context = FlasherContext('',
                                  progressbar_factory=SilentProgressBarFactory,
                                  logger=MockLogger(DEBUG),
                                  firmware_file_parser=test_firmware,
                                  target_command_executor=fake_verify_handler,
                                  retries=3)
    
    # When a flash verify operation is invoked
    with pytest.raises(UncaughtException):
        flash_verifier = flashing_tools.create_flash_verifier(context=test_context,
                                                              target_flash_blocks=test_flashblockscatalog,
                                                              progress_updater=None)
        flash_verifier(requested_range=MCULogicalAddressRange(start_address=sample_address, end_address=sample_address+len(sample_content)))

    # Then, the UncaughtException should have been raised and no retry should be performed
    assert retry_test_context.total_tries_number == 1

def test_flash_verifier_with_2_retries():
    class TestContext:
        def __init__(self):
            self.total_tries_number = 0

    sample_address = 0x2000
    sample_content = b'0123456789abcdef'
    retry_test_context = TestContext()

    def fake_write_handler(command: monitor_comm.MonitorCommand):
        assert command.COMMAND_ID == monitor_comm.CommandDataVerify.COMMAND_ID
        if retry_test_context.total_tries_number < 3:
            retry_test_context.total_tries_number += 1
            raise monitor_comm.ChecksumError("Should retry")
        else:
            return  # At the 3rd retry, succeed!
    
    test_firmware = PythonIntelHexFileParser()
    test_firmware.put_data_chunk(MCULocatedLogicalDataChunk(sample_address, sample_content))

    test_context = FlasherContext('',
                                  progressbar_factory=SilentProgressBarFactory,
                                  logger=MockLogger(DEBUG),
                                  firmware_file_parser=test_firmware,
                                  target_command_executor=fake_write_handler,
                                  retries=3)
    
    # When a flash verify operation is invoked
    flash_verifier = flashing_tools.create_flash_verifier(context=test_context,
                                                          target_flash_blocks=test_flashblockscatalog,
                                                          progress_updater=None)
    flash_verifier(requested_range=MCULogicalAddressRange(start_address=sample_address, end_address=sample_address+len(sample_content)))

    # Then we should have tried 3 times in total (1 initial attempt + 2 retries) times without exception
    assert retry_test_context.total_tries_number == 3

def test_read_firmware_range_with_0_retries():
    sample_address = 0x020000
    sample_len = 0x10
    sample_content = b'0123456789abcdef' * (sample_len // 0x10 + 1)
    def fake_read_handler(command: monitor_comm.MonitorCommand):
        assert command.COMMAND_ID == monitor_comm.CommandDataReceive.COMMAND_ID
        assert command.chunk.start_address == sample_address
        assert command.chunk.get_size() == 0x10
        return sample_content[0:command.chunk.get_size()]
    
    test_firmware = PythonIntelHexFileParser()
    test_context = FlasherContext('',
                                  progressbar_factory=SilentProgressBarFactory,
                                  logger=MockLogger(DEBUG),
                                  firmware_file_parser=test_firmware,
                                  target_command_executor=fake_read_handler)
    
    # When a flash read operation is invoked
    flash_reader = flashing_tools.create_flash_reader(context=test_context,
                                                      target_flash_blocks=test_flashblockscatalog,
                                                      progress_updater=None)
    flash_reader(MCULogicalAddressRange(start_address=sample_address, end_address=sample_address+sample_len))
    
    assert test_firmware.get_data_chunk_for_range(MCULogicalAddressRange(start_address=sample_address, end_address=sample_address+sample_len)).get_content() == sample_content[0:sample_len]

def test_flash_reader_no_retry_on_unknown_exception():
    class TestContext:
        def __init__(self):
            self.total_tries_number = 0

    sample_address = 0x2000
    sample_len = 0x10
    retry_test_context = TestContext()

    def fake_read_handler(command: monitor_comm.MonitorCommand):
        retry_test_context.total_tries_number += 1
        raise UncaughtException("Unexpected exception")
    
    test_firmware = PythonIntelHexFileParser()
    test_context = FlasherContext('',
                                  progressbar_factory=SilentProgressBarFactory,
                                  logger=MockLogger(DEBUG),
                                  firmware_file_parser=test_firmware,
                                  target_command_executor=fake_read_handler,
                                  retries=3)
    
    # When a flash read operation is invoked
    with pytest.raises(UncaughtException):
        flash_reader = flashing_tools.create_flash_reader(context=test_context,
                                                          target_flash_blocks=test_flashblockscatalog,
                                                          progress_updater=None)
        flash_reader(MCULogicalAddressRange(start_address=sample_address, end_address=sample_address+sample_len))

    # Then, the UncaughtException should have been raised and no retry should be performed
    assert retry_test_context.total_tries_number == 1

def test_flash_reader_with_2_retries():
    class TestContext:
        def __init__(self):
            self.total_tries_number = 0

    sample_address = 0x020000
    sample_len = 0x10
    sample_content = b'0123456789abcdef' * (sample_len // 0x10 + 1)
    retry_test_context = TestContext()

    def fake_read_handler(command: monitor_comm.MonitorCommand):
        assert command.COMMAND_ID == monitor_comm.CommandDataReceive.COMMAND_ID
        assert command.chunk.start_address == sample_address
        assert command.chunk.get_size() == 0x10
        if retry_test_context.total_tries_number < 3:
            retry_test_context.total_tries_number += 1
            raise monitor_comm.ChecksumError("Should retry")
        else:
            return sample_content[0:command.chunk.get_size()]  # At the 3rd retry, succeed!

    test_firmware = PythonIntelHexFileParser()

    test_context = FlasherContext('',
                                  progressbar_factory=SilentProgressBarFactory,
                                  logger=MockLogger(DEBUG),
                                  firmware_file_parser=test_firmware,
                                  target_command_executor=fake_read_handler,
                                  retries=3)
    
    # When a flash read operation is invoked
    flash_reader = flashing_tools.create_flash_reader(context=test_context,
                                                      target_flash_blocks=test_flashblockscatalog,
                                                      progress_updater=None)
    flash_reader(MCULogicalAddressRange(start_address=sample_address, end_address=sample_address+sample_len))

    # Then we should have tried 3 times in total (1 initial attempt + 2 retries) times without exception
    assert retry_test_context.total_tries_number == 3
    assert test_firmware.get_data_chunk_for_range(MCULogicalAddressRange(start_address=sample_address, end_address=sample_address+sample_len)).get_content() == sample_content[0:sample_len]

def test_st10_program_cmd_happy_pass():
    class TestContext:
        def __init__(self):
            self.step = 0

    test_flash = EmulatedFlash(flash_size=0x060000)
    test_step = TestContext()

    def fake_command_handler(command: monitor_comm.MonitorCommand):
        if test_step.step == 0:  # First step is flash erase
            assert command.COMMAND_ID == monitor_comm.CommandFlashErase.COMMAND_ID
            for bit in range(0, 16):
                if command.flash_mask & (1<<bit):
                    flash_block_index = bit
                    flash_block_range: MCULogicalAddressRange = test_flashblockscatalog.get_flash_block_at_index(flash_block_index)
                    test_flash.erase_at(flash_block_range)
        else:
            assert command.COMMAND_ID == monitor_comm.CommandDataSend.COMMAND_ID
            test_flash.write_data_at(command.chunk_to_send)
        test_step.step += 1

    test_firmware = PythonIntelHexFileParser()

    content = bytes(range(0,256))
    test_firmware.put_data_chunk(MCULocatedLogicalDataChunk(start_address=0x030000, content=content*16))
    test_firmware.put_data_chunk(MCULocatedLogicalDataChunk(start_address=0x040000, content=content))
    test_firmware.put_data_chunk(MCULocatedLogicalDataChunk(start_address=0x050000, content=content*32))

    test_context = FlasherContext('',
                                  progressbar_factory=SilentProgressBarFactory,
                                  logger=MockLogger(DEBUG),
                                  firmware_file_parser=test_firmware,
                                  target_command_executor=fake_command_handler)
    
    # When a program operation is invoked
    flashing_tools.st10_program_cmd(context=test_context, target_flash_blocks=test_flashblockscatalog)

    # Then, the flash should match what we have prepared in the firmware file image
    empty_bytes_in_segments = test_flash.read_data_at(MCULogicalAddressRange(start_address=0x020000, end_address=0x030000))
    assert empty_bytes_in_segments == b'\xff' * 0x10000
    assert test_flash.read_data_at(MCULogicalAddressRange(start_address=0x030000, end_address=0x030000+len(content)*16)) == content*16
    trailing_empty_bytes_in_segments = test_flash.read_data_at(MCULogicalAddressRange(start_address=0x030000+len(content)*16, end_address=0x040000))
    assert trailing_empty_bytes_in_segments == b'\xff' * len(trailing_empty_bytes_in_segments)
    assert test_flash.read_data_at(MCULogicalAddressRange(start_address=0x040000, end_address=0x040000+len(content))) == content
    trailing_empty_bytes_in_segments = test_flash.read_data_at(MCULogicalAddressRange(start_address=0x040000+len(content), end_address=0x050000))
    assert trailing_empty_bytes_in_segments == b'\xff' * len(trailing_empty_bytes_in_segments)
    assert test_flash.read_data_at(MCULogicalAddressRange(start_address=0x050000, end_address=0x050000+len(content)*32)) == content*32
    trailing_empty_bytes_in_segments = test_flash.read_data_at(MCULogicalAddressRange(start_address=0x050000+len(content*32), end_address=0x060000))
    assert trailing_empty_bytes_in_segments == b'\xff' * len(trailing_empty_bytes_in_segments)

def test_st10_verify_cmd_happy_pass():
    test_flash = EmulatedFlash(flash_size=0x060000)

    def fake_command_handler(command: monitor_comm.MonitorCommand):
        assert command.COMMAND_ID == monitor_comm.CommandDataReceive.COMMAND_ID
        # FIXME we should only raise on error for verify commands, no return value
        return test_flash.read_data_at(command.chunk)

    test_firmware = PythonIntelHexFileParser()

    content = bytes(range(0,256))
    test_flash.write_data_at(MCULocatedLogicalDataChunk(start_address=0x030000, content=content*16))
    test_flash.write_data_at(MCULocatedLogicalDataChunk(start_address=0x040000, content=content))
    test_flash.write_data_at(MCULocatedLogicalDataChunk(start_address=0x050000, content=content*32))
    test_firmware.put_data_chunk(MCULocatedLogicalDataChunk(start_address=0x030000, content=content*16))
    test_firmware.put_data_chunk(MCULocatedLogicalDataChunk(start_address=0x040000, content=content))
    test_firmware.put_data_chunk(MCULocatedLogicalDataChunk(start_address=0x050000, content=content*32))

    test_context = FlasherContext('',
                                  progressbar_factory=SilentProgressBarFactory,
                                  logger=MockLogger(DEBUG),
                                  firmware_file_parser=test_firmware,
                                  target_command_executor=fake_command_handler)
    
    # When a verify write operation is invoked
    result = flashing_tools.st10_verify_cmd(context=test_context, target_flash_blocks=test_flashblockscatalog)

    # Then, the flash should match what we have prepared in the firmware file image
    assert result == True

def test_st10_verify_cmd_fail():
    test_flash = EmulatedFlash(flash_size=0x040000)

    def fake_command_handler(command: monitor_comm.MonitorCommand):
        assert command.COMMAND_ID == monitor_comm.CommandDataVerify.COMMAND_ID
        if command.chunk.start_address <= 0x030000 + len(content) and command.chunk.end_address >= 0x030000 + len(content):
            # We are at the emulated failed byte, just fail to simulate an erroneous byte
            raise monitor_comm.LocatedChecksumError('Unit Tests', address=0x030000 + len(content))

    test_firmware = PythonIntelHexFileParser()

    content = bytes(range(0,256))
    test_flash.write_data_at(MCULocatedLogicalDataChunk(start_address=0x030000, content=content*2))
    test_firmware.put_data_chunk(MCULocatedLogicalDataChunk(start_address=0x030000, content=content*2))
    test_flash.write_data_at(MCULocatedLogicalDataChunk(start_address=0x030000 + len(content), content=b'\x47'))   # Insert an error here

    test_context = FlasherContext('',
                                  progressbar_factory=SilentProgressBarFactory,
                                  logger=MockLogger(DEBUG),
                                  firmware_file_parser=test_firmware,
                                  target_command_executor=fake_command_handler)
    
    # When a verify operation is invoked
    with pytest.raises(RuntimeError):
        result = flashing_tools.st10_verify_cmd(context=test_context, target_flash_blocks=test_flashblockscatalog)

    # Then, the verification should have raised an exception above

def test_st10_dump_cmd_happy_pass():
    test_flash = EmulatedFlash(flash_size=test_flashblockscatalog.get_flash_addr_ranges()[-1].end_address)

    def fake_command_handler(command: monitor_comm.MonitorCommand):
        assert command.COMMAND_ID == monitor_comm.CommandDataReceive.COMMAND_ID
        return bytes(test_flash.read_data_at(command.chunk))

    test_firmware = PythonIntelHexFileParser()

    content = bytes(range(0,256))
    for addr_range in test_flashblockscatalog.get_flash_addr_ranges():
        # Simulate empty flash, erase it all
        test_flash.erase_at(addr_range)
    test_flash.write_data_at(MCULocatedLogicalDataChunk(start_address=0x030000, content=content*16))
    test_flash.write_data_at(MCULocatedLogicalDataChunk(start_address=0x040000, content=content))
    test_flash.write_data_at(MCULocatedLogicalDataChunk(start_address=0x050000, content=content*32))
    test_flash.write_data_at(MCULocatedLogicalDataChunk(start_address=test_flash.flash_size-1, content=b'\xa1'))    # Set the last byte as well...

    test_context = FlasherContext('',
                                  progressbar_factory=SilentProgressBarFactory,
                                  logger=MockLogger(DEBUG),
                                  firmware_file_parser=test_firmware,
                                  target_command_executor=fake_command_handler)
    
    # When a dump operation is invoked
    result = flashing_tools.st10_dump_cmd(context=test_context, target_flash_blocks=test_flashblockscatalog)

    # Then, the firmware image should match what we have prepared in the emulated flash
    assert test_firmware.get_data_chunk_for_range(MCULogicalAddressRange(start_address=0x030000, end_address=0x030000+len(content)*16)).get_content() == content*16
    trailing_empty_bytes_in_segments = test_firmware.get_data_chunk_for_range(MCULogicalAddressRange(start_address=0x030000+len(content)*16, end_address=0x040000)).get_content()
    assert trailing_empty_bytes_in_segments == b'\xff' * len(trailing_empty_bytes_in_segments)
    assert test_firmware.get_data_chunk_for_range(MCULogicalAddressRange(start_address=0x040000, end_address=0x040000+len(content))).get_content() == content
    trailing_empty_bytes_in_segments = test_firmware.get_data_chunk_for_range(MCULogicalAddressRange(start_address=0x040000+len(content), end_address=0x050000)).get_content()
    assert trailing_empty_bytes_in_segments == b'\xff' * len(trailing_empty_bytes_in_segments)
    assert test_firmware.get_data_chunk_for_range(MCULogicalAddressRange(start_address=0x050000, end_address=0x050000+len(content)*32)).get_content() == content*32
    trailing_empty_bytes_in_segments = test_firmware.get_data_chunk_for_range(MCULogicalAddressRange(start_address=0x050000+len(content*32), end_address=0x060000)).get_content()
    assert trailing_empty_bytes_in_segments == b'\xff' * len(trailing_empty_bytes_in_segments)
    assert test_firmware.get_data_chunk_for_range(MCULogicalAddressRange(start_address=test_flash.flash_size-1, end_address=test_flash.flash_size)).get_content() == b'\xa1'    # Check the last byte as well...

def test_st10_chained_program_dump_cmd():
    flash_size = test_flashblockscatalog.get_flash_addr_ranges()[-1].end_address
    test_flash = EmulatedFlash(flash_size=flash_size)

    def fake_command_handler(command: monitor_comm.MonitorCommand):
        if command.COMMAND_ID == monitor_comm.CommandFlashErase.COMMAND_ID:
            for bit in range(0, 16):
                if command.flash_mask & (1<<bit):
                    flash_block_index = bit
                    flash_block_range: MCULogicalAddressRange = test_flashblockscatalog.get_flash_block_at_index(flash_block_index)
                    test_flash.erase_at(flash_block_range)
        elif command.COMMAND_ID == monitor_comm.CommandDataSend.COMMAND_ID:
            test_flash.write_data_at(command.chunk_to_send)
        elif command.COMMAND_ID == monitor_comm.CommandDataReceive.COMMAND_ID:
            return bytes(test_flash.read_data_at(command.chunk))
        else:
            raise UncaughtException('Unexpected dommand')

    input_firmware = PythonIntelHexFileParser()

    content = bytes(range(0,256))
    random.seed()
    # Insert 1000 blocks of content into the firmware file
    for bloc in range(0,1000):
        address = random.randrange(0x30000, flash_size-len(content))
        input_firmware.put_data_chunk(MCULocatedLogicalDataChunk(start_address=address, content=content))

    for addr_range in test_flashblockscatalog.get_flash_addr_ranges():
        # Simulate empty flash, erase it all
        test_flash.erase_at(addr_range)
    
    program_context = FlasherContext('',
                                     progressbar_factory=SilentProgressBarFactory,
                                     logger=MockLogger(DEBUG),
                                     firmware_file_parser=input_firmware,
                                     target_command_executor=fake_command_handler)
    
    # When a program operation is invoked
    flashing_tools.st10_program_cmd(context=program_context, target_flash_blocks=test_flashblockscatalog)

    # ... followed by a dump operation
    output_firmware = PythonIntelHexFileParser()
    dump_context = FlasherContext('',
                                  progressbar_factory=SilentProgressBarFactory,
                                  logger=MockLogger(DEBUG),
                                  firmware_file_parser=output_firmware,
                                  target_command_executor=fake_command_handler)
    flashing_tools.st10_dump_cmd(context=dump_context, target_flash_blocks=test_flashblockscatalog)

    # Then, the resulting firmware image should match the input firmware image
    assert input_firmware.get_data_chunk_for_range(MCULogicalAddressRange(0x30000, flash_size)).get_content() == \
           output_firmware.get_data_chunk_for_range(MCULogicalAddressRange(0x30000, flash_size)).get_content()

'''
################# Not yet implemented ###############
def test_st10_program_cmd_progress_bar():
    progressbars_generated = []
    class GenerationRecordingMockProgressBarFactory(ProgressBarFactoryInterface):
        @staticmethod
        def create(*args, **kwargs):
            new_progress_bar = MockProgressBar(*args, **kwargs)
            progressbars_generated.append(new_progress_bar)
            return new_progress_bar

    sample_address = 0x2000
    sample_content = b'0123456789abcdef'

    def test_response_handler(command: monitor_comm.MonitorCommand):
        return
    
    test_firmware = PythonIntelHexFileParser()
    test_firmware.put_data_chunk(MCULocatedLogicalDataChunk(sample_address, sample_content))
    test_context = FlasherContext('',
                                  progressbar_factory=GenerationRecordingMockProgressBarFactory,
                                  logger=MockLogger(DEBUG),
                                  firmware_file_parser=test_firmware,
                                  target_command_executor=test_response_handler)
    
    flashing_tools.write_firmware_range_in_flash_block_with_retries(context=test_context,
                                                                    requested_range=MCULogicalAddressRange(start_address=sample_address, end_address=sample_address+len(sample_content)),
                                                                    target_flash_blocks=test_flashblockscatalog,
                                                                    allowed_retries=0,
                                                                    progress_updater=None)

'''