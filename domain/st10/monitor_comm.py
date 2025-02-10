#!/usr/bin/env python3
# coding: utf-8

import abc
from intelhex import IntelHex
import struct
import time
from typing import Callable, List

from logging import getLogger

from domain.common import align_on_8_bytes, split_address_range_to_max_size
from domain.mcu_addressing import MCULogicalAddress, MCULogicalAddressRange, MCUPhysicalAddress, MCULocatedLogicalDataChunk
from domain.command_preprocessor import CommandPreprocessor

logger = getLogger(__name__)

ACK=b'\x5a'
NACK=b'\xa5'

class NACKReceivedError(Exception):
    pass

class ChecksumError(Exception):
    pass

class LocatedChecksumError(ChecksumError):
    def __init__(self, generic_message: str, address = None):
        message = generic_message
        if address is not None:
            message = f'At address 0x{address:06x}: ' + message
        self.address = address
        super().__init__(message)

class CommandFailedError(Exception):
    pass

class BSLProbeError(Exception):
    pass

class CommandArgumentError(Exception):
    pass

def get_16bit_arithmetic_checksum(buffer) -> int:
    """@brief Computes a basic checksum (arithmetic byte sum limited to 16-bit results without carry) on a buffer
    @param buffer The byte buffer to process
    @return The resulting unsigned 16-bit checksum
    """
    checksum_result: int = 0
    for byte in buffer:
        checksum_result = (checksum_result + byte) & 0xffff
    return checksum_result

def write_expect_echo(input_device, buffer) -> None:
    """@brief Write a buffer to a serial device and expect each byte to be echoed back
    @param input_device The device we write and read serial data from
    @param buffer The bytes or bytearray buffer to write
    @warning We will raise an exception if no byte is received or if the sent and received bytes mismatch

    @note We allow the remote to be late at most one byte (to reduce round-trip time)
    """
    def chunker(seq, size):
        return (seq[pos:pos + size] for pos in range(0, len(seq), size))

    for byte_seq in chunker(buffer, 32):    # We send bursts of 32 bytes each time (the ST10 has large enough incoming and outgoing serial buffers to handle this)
        input_device.write(byte_seq)
        feedback_byte_seq = input_device.read(len(byte_seq))
        if feedback_byte_seq != byte_seq:
            raise RuntimeError(f'Unexpected feedback byte {feedback_byte_seq}, expected {byte_seq}')

def expect_ack(input_device, timeout=None) -> None:
    """@brief Expect a serial ack on the input device
    @param input_device The device we read serial data from
    @param timeout An optional timeout after which we will raise an exception if no byte is received

    @warning We are expecting the serial ack as the very first byte on the serial link, if we receive no byte and there
             is a timeout or if the byte is not an ACK, we will raise an exception
    """
    if timeout is not None:
        input_device.timeout = timeout
    state_byte = input_device.read(1)
    if len(state_byte) < 1:
        raise RuntimeError('Timeout while waiting for ACK')
    if state_byte != ACK:
        if state_byte == NACK:
            raise NACKReceivedError(f'Got a NACK while expecting a NACK')
        else:
            raise RuntimeError(f'Expected an ACK ({ord(ACK):02x} byte, got {ord(state_byte):02x} instead)')

def get_command_preprocessor() -> CommandPreprocessor:
    """@brief Get a command preprocessor adapter to Monitor commands
    """
    def align_memory_address_range(range: MCULogicalAddressRange) -> MCULogicalAddressRange:
        start_address = align_on_8_bytes(range.start_address, excess=False)
        end_address = align_on_8_bytes(range.end_address, excess=True)
        return MCULogicalAddressRange(start_address=start_address,
                                        end_address=end_address)

    def split_to_max_range(range: MCULogicalAddressRange) -> List[MCULogicalAddressRange]:
        return list(split_address_range_to_max_size(address_range=range, max_size=0x8000))

    return CommandPreprocessor(aligner=align_memory_address_range, range_splitter=split_to_max_range)

class MonitorCommand(metaclass=abc.ABCMeta):
    """@brief Interface to which must comply all concrete implementations of monitor command encoders/decoders
    A ST10 Monitor command contains
    * a 16-bit command ID (and its human-readable transcription)
    * arguments to this command
    * optional binary content to upload to the target
    get_arguments_payload() allows to retrieve the arguments only
    get_as_buffer() will return a concatenated version of the command and the arguments
    get_content_payload() will return the buffer that will be sent to the target. Not all commands come with a buffer (only write and verify do)
    """
    COMMAND_ID = None
    COMMAND_NAME = '(unknown)'

    def __init__(self, command_id: int):
        self.command_id = command_id

    @staticmethod
    def to_physical_address(input) -> MCUPhysicalAddress:
        """@brief Try to convert an input value into a MCUPhysicalAddress
        @return The resulting MCUPhysicalAddress instance
        @warning If conversion is not possible, an TypeError exception will be raised
        """
        if isinstance(input, MCUPhysicalAddress):
            return input
        elif isinstance(input, MCULogicalAddress):
            return MCUPhysicalAddress.create_from_logical_address(input)
        elif isinstance(input, int):
            return MCUPhysicalAddress.create_from_logical_address(MCULogicalAddress(input))
        else:
            raise TypeError('Unsupported argument type ' + str(type(input)))

    @staticmethod
    def is_aligned_on_8_bytes(input) -> bool:
        """@brief Check if an input value is aligned on 8-bytes boundaries
        @return True if the input is aligned
        @warning If conversion is not possible, an TypeError exception will be raised
                 If a range is provided, we will check both boundaries
        """
        def _is_address_aligned(input) -> bool:
            if isinstance(input, MCUPhysicalAddress):
                input = input.to_logical_address()
            elif isinstance(input, int):
                input = MCULogicalAddress(input)
            else:
                raise TypeError('Unsupported argument type ' + str(type(input)))
            return input.is_aligned_on_bytes_multiple(8)

        if isinstance(input, MCULocatedLogicalDataChunk):
            input = input.to_address_range()
        if isinstance(input, MCULogicalAddressRange):
            return _is_address_aligned(input.start_address) and _is_address_aligned(input.end_address)
        else:
            return _is_address_aligned(input)

    @abc.abstractmethod
    def get_arguments_payload(self) -> bytearray:
        """@brief Get the arguments for this command
        @return The arguments formatted as a byte buffer
        """
        raise NotImplementedError

    def get_content_payload(self) -> bytearray:
        """@brief Get the content (body) of data following this command
        @return The content formatted as a byte buffer
        """
        return b''

    @abc.abstractmethod
    def get_reply_timeout(self) -> int:
        """@brief Get the amount of time we should wait for a reply to this command
        @return The amount of time (timeout) in ms
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_expected_reply_sz(self) -> int:
        """@brief Get the expected reply size returned to us when issueing this command
        @return The number of bytes we are expecting as a reply
        """
        raise NotImplementedError

    @abc.abstractmethod
    def parse_reply(self, reply_payload: bytearray):
        """@brief Parse the reply from embedded monitor software
        @param reply_payload The data returned by the embedded monitor software
        @return An object containing our interpretation of the reply_payload
        """
        raise NotImplementedError

    def get_as_buffer(self) -> bytearray:
        """@brief Represent this command as a binary buffer
        @return The byte buffer to send to the remote target (includes command+arguments)
        """
        arguments_payload = self.get_arguments_payload()
        full_command_length = 2 + len(arguments_payload)
        full_command_length_le = struct.pack('<H', full_command_length)
        command_id_le = struct.pack('<H', self.command_id)
        return full_command_length_le + command_id_le + arguments_payload

    def __str__(self) -> str:
        """@brief Generic formatter of a command as a string"""
        return self.COMMAND_NAME

class CommandDataReceive(MonitorCommand):
    """@brief Class for encoding/decoding a data receive command targetted to the embedded monitor software"""
    COMMAND_ID = 0x0001
    COMMAND_NAME = 'DATA_RECEIVE'

    def __init__(self, range_to_read: MCULogicalAddressRange, flags: int = 0x0000, **kwargs):
        """@brief Constructor
        @param range_to_read The address range of the binary data to receive from the embedded monitor software
        @param flags Internal command flags (undocumented!)
        """
        if range_to_read.get_size() < 0x0000 or range_to_read.get_size() > 0x8000:
            raise CommandArgumentError("Invalid range_to_read with size " + str(range_to_read.get_size()))
        if flags < 0x0000 or flags > 0xffff:
            raise CommandArgumentError("Invalid flags")
        self.chunk = range_to_read
        if flags & 0x0010 and flags & 0x0008:   # Invalid combination? should be mutually exclusive...
            raise CommandArgumentError('Unsupported flags')
        if flags & 0x0008:
            self.expected_result_size = self.chunk.get_size()  # In 0x0008 mode (byte read), we'll get as many bytes as requested (chunk_size)
        elif flags & 0x0010:
            assert self.chunk.get_size() % 2 == 0   # The address range should contain an even number of bytes
            assert self.chunk.start_address % 2 == 0    # The starting addess of the chunk should be alligned on 16-bit words
            self.expected_result_size = self.chunk.get_size()   # In 0x0010 mode (16-bit word read), we get as many 16-bit words as requested (chunk_size)
        else:
            self.expected_result_size = 0

        self.flags = flags
        super().__init__(command_id = self.COMMAND_ID, **kwargs)

    def get_arguments_payload(self) -> bytearray:
        chunk_start_offset_le = struct.pack('<H', super().to_physical_address(self.chunk.start_address).offset)
        chunk_start_segment_le = struct.pack('<H', super().to_physical_address(self.chunk.start_address).segment)
        if self.flags & 0x0010:
            data_reg_size = self.chunk.get_size() // 2  # If 16-bit word read, registers are half the size in bytes
        else:
            data_reg_size = self.chunk.get_size()
        chunk_size_le = struct.pack('<H', data_reg_size)
        null_16bit_le = struct.pack('<H', 0)
        flags_le = struct.pack('<H', self.flags)
        return chunk_start_offset_le + chunk_start_segment_le + chunk_size_le + null_16bit_le + flags_le + null_16bit_le + null_16bit_le

    def get_reply_timeout(self) -> int:
        return self.chunk.get_size() * 0.005 + 0.3   # 5ms/byte returned

    def get_expected_reply_sz(self) -> int:
        expected_reply_sz = self.expected_result_size
        expected_reply_sz += 2  # An 16-bit checksum
        expected_reply_sz += 4  # In all modes, we get a 16-bit (status?) register in the reply payload
        return expected_reply_sz

    def parse_reply(self, reply_payload):
        if len(reply_payload) != self.get_expected_reply_sz():
            raise RuntimeError('Short read while receiving reply for ' + str(self) + ' expected a ' + str(self.get_expected_reply_sz()) + ' bytes reply')
        assert reply_payload[-4:] == b'\x00\x00\x00\x00' # Last 4 bytes of the... status register? always seem to be 0x00000000
        if self.flags & 0x0018:
            enclosed_checksum = struct.unpack('<H', reply_payload[self.expected_result_size:self.expected_result_size+2])[0]
            computed_checksum = get_16bit_arithmetic_checksum(buffer=reply_payload[:self.expected_result_size])
            if computed_checksum != enclosed_checksum:
                msg = f'Wrong enclosed checksum received from remote: 0x{enclosed_checksum:04x} (computed 0x{computed_checksum:04x})'
                logger.error(msg)
                raise ChecksumError(msg)
            reply_payload = reply_payload[0:self.expected_result_size]
        return reply_payload

    def __str__(self) -> str:
        if self.flags & 0x0010:
            word_type = '16-bit words'
        else:
            word_type = 'bytes'
        return super().__str__() + f'({self.chunk.get_size()} {word_type} at 0x{str(self.chunk.start_address)})'


class CommandDataReceiveBytes(CommandDataReceive):
    """@brief Wrapper class for handling 8-bit data receive commands
    """

    def __init__(self, range_to_read: MCULogicalAddressRange, **kwargs):
        """@brief Constructor
        @param range_to_read The address range of the binary data to receive from the embedded monitor software
        """
        super().__init__(range_to_read=range_to_read, flags=0x0008)


class CommandDataReceive16BitWords(CommandDataReceive):
    """@brief Wrapper class for handling 16-bit data receive commands
    """

    def __init__(self, range_to_read: MCULogicalAddressRange, **kwargs):
        """@brief Constructor
        @param range_to_read The address range of the binary data to receive from the embedded monitor software

        @note The address range represented by @p range_to_read should be even, to allow for 16-bit word dumps
        """
        super().__init__(range_to_read=range_to_read, flags=0x0010)


class CommandFlashErase(MonitorCommand):
    """@brief Class for encoding/decoding a flash erase command targetted to the embedded monitor software"""
    COMMAND_ID = 0x0102
    COMMAND_NAME = 'FLASH_ERASE'

    def __init__(self, flash_mask: int=0xffff, **kwargs):
        """@brief Constructor
        @param flash_mask The flashing mask (each bit corresponds maps to a flash block)
        """
        if flash_mask < 0x0000 or flash_mask > 0xffff:
            raise CommandArgumentError(f"Invalid flash_mask: 0x{flash_mask:x}")
        self.flash_mask = flash_mask
        super().__init__(command_id = self.COMMAND_ID, **kwargs)

    def get_arguments_payload(self) -> bytearray:
        flash_mask_le = struct.pack('<H', self.flash_mask)
        return flash_mask_le

    def get_reply_timeout(self) -> int:
        return 20   # allow 20s for full flash erase

    def get_expected_reply_sz(self) -> int:
        return 1

    def parse_reply(self, reply_payload):
        if len(reply_payload) != self.get_expected_reply_sz():
            raise RuntimeError('Short read while receiving reply for ' + str(self))
        if reply_payload[0] != 0x00:
            raise CommandFailedError(f'Unexpected reply payload: ' + str(reply_payload))


class CommandDataSend(MonitorCommand):
    """@brief Class for encoding/decoding a data send command targetted to the embedded monitor software"""
    COMMAND_ID = 0x0106
    COMMAND_NAME = 'DATA_SEND'

    def __init__(self, chunk_to_send: MCULocatedLogicalDataChunk, **kwargs):
        """@brief Constructor
        @param chunk_to_send The chunk of binary data to send to the embedded monitor software
        """
        if chunk_to_send.size < 0x0000 or chunk_to_send.size > 0x8000:
            raise CommandArgumentError("Invalid size in chunk_to_send: " + str(chunk_to_send.size))
        if not MonitorCommand.is_aligned_on_8_bytes(chunk_to_send):
            raise CommandArgumentError("chunk_to_send not aligned to 8 bytes boundary")

        logger.debug(f'Will send data buffer of {chunk_to_send.size} bytes')
        self.chunk_to_send = chunk_to_send
        self.buffer_checksum = get_16bit_arithmetic_checksum(self.chunk_to_send.get_content())
        super().__init__(command_id = self.COMMAND_ID, **kwargs)

    def get_arguments_payload(self) -> bytearray:
        physical_start_address = MCUPhysicalAddress.create_from_logical_address(self.chunk_to_send.start_address)
        chunk_start_offset_le = struct.pack('<H', physical_start_address.offset)
        chunk_start_segment_le = struct.pack('<H', physical_start_address.segment)
        chunk_size_le = struct.pack('<H', self.chunk_to_send.size)
        null_16bit_le = struct.pack('<H', 0)
        return chunk_start_offset_le + chunk_start_segment_le + chunk_size_le + null_16bit_le

    def get_content_payload(self) -> bytearray:
        return self.chunk_to_send.get_content()

    def get_reply_timeout(self) -> int:
        return self.chunk_to_send.size * 0.001 + 0.3   # 10ms/byte sent

    def get_expected_reply_sz(self) -> int:
        return 2

    def parse_reply(self, reply_payload):
        if len(reply_payload) != 2:
            raise RuntimeError('Short read while receiving reply for ' + str(self))
        remote_computed_checksum = struct.unpack('<H', reply_payload[0:2])[0]
        if self.buffer_checksum != remote_computed_checksum:
            msg = f'Wrong data chunk checksum received from remote: 0x{remote_computed_checksum:04x} (expected 0x{self.buffer_checksum:04x})'
            logger.error(msg)
            raise ChecksumError(msg)

    def __str__(self) -> str:
        return super().__str__() + f'({self.chunk_to_send.size} bytes at address 0x{self.chunk_to_send.start_address:06x})'


class CommandDataVerify(CommandDataReceive):
    COMMAND_NAME = 'DATA_VERIFY'

    def __init__(self, chunk_to_check: MCULocatedLogicalDataChunk, **kwargs):
        """@brief Constructor
        @param chunk_to_send The chunk of binary data to be compared to the embedded monitor software's memory
        """
        if chunk_to_check.size < 0x0000 or chunk_to_check.size > 0x8000:
            raise CommandArgumentError("Invalid size in chunk_to_check")
        if not MonitorCommand.is_aligned_on_8_bytes(chunk_to_check):
            raise CommandArgumentError("chunk_to_check not aligned to 8 bytes boundary")

        logger.debug(f'Will check data buffer of {chunk_to_check.size} bytes')
        self.chunk_data = chunk_to_check.get_content()
        self.buffer_checksum = get_16bit_arithmetic_checksum(self.chunk_data)
        super().__init__(range_to_read=chunk_to_check.to_address_range(), flags=0x0200, **kwargs)

    def get_content_payload(self) -> bytearray:
        return self.chunk_data

    def parse_reply(self, reply_payload):
        if len(reply_payload) != self.get_expected_reply_sz():
            raise RuntimeError('Short read while receiving reply for ' + str(self))
        remote_computed_checksum = struct.unpack('<H', reply_payload[0:2])[0]
        if self.buffer_checksum != remote_computed_checksum:
            if self.get_expected_reply_sz() >= 6:
                remote_failed_address = struct.unpack('<I', reply_payload[2:6])[0] & 0xffffff   # Mask high bits as they are not part of the addressing space
            msg = f'Wrong data chunk checksum received from remote: 0x{remote_computed_checksum:04x} (expected 0x{self.buffer_checksum:04x})'
            if remote_failed_address != 0:
                msg += f'. First offending byte at address 0x{remote_failed_address:06x}'
            logger.error(msg)
            raise LocatedChecksumError(msg, address=remote_failed_address)


class MonitorProtocol:
    """@brief Class representing the communication protocol with the remote embedded monitor software
    """
    PING = b"\xb7"
    PONG = b"\x7b"
    COMMIT = 0xcafe

    def __init__(self, device):
        """@brief Constructor
        @param device The device we read/write serial data from/to
        """
        self.device = device

    def __enter__(self):
        pass

    def __exit__(self, type, value, traceback):
        pass

    def _ping_sync(self):
        """@brief Go through a monitor sync sequence (if we are not already in sync)
        """
        self.device.timeout = 0.5
        nack_count = 0
        while self.device.in_waiting:
            flushed_incoming_byte = self.device.read(1)
            if flushed_incoming_byte == NACK:
                nack_count += 1
            else:
                raise RuntimeError(f'Got an unexpected byte 0x{flushed_incoming_byte[0]:02x} while flushing trailing NACKs')
        if nack_count > 0:
            logger.warning(f'Flushed {nack_count} unexpected trailing NACKs, is your serial port generating errors?')
        self.device.write(self.PING)
        pong = self.device.read(1)
        if len(pong) != 1:
            raise RuntimeError('Timeout while waiting for pong byte')
        if pong != self.PONG:
            raise RuntimeError(f'Expected a pong byte, got 0x{pong[0]:02x} instead')

    @staticmethod
    def get_checksum(buffer: bytes) -> int:
        """@brief Computes a basic checksum (arithmetic byte sum limited to 16-bit results without carry) on a buffer
        @param buffer The byte buffer to process (should contain an even number of bytes)
        @return The resulting unsigned 16-bit checksum
        """
        return get_16bit_arithmetic_checksum(buffer)

    def _get_remote_checksum(self, timeout=None) -> int:
        """@brief Get a checksum from the remote device
        @param timeout An optional timeout that we accept to wait for the reception of the 16-bit checksum value
        @return The checksum value (16-bit integer)
        """
        if timeout is not None:
            self.device.timeout = timeout
        remote_checksum_le = self.device.read(2)
        if len(remote_checksum_le) != 2:
            raise RuntimeError('Timeout while waiting for a remote checksum feedback')
        return struct.unpack('<H', remote_checksum_le)[0]

    def _commit_last_command(self) -> None:
        """@brief Send a commit order to remote target (effectively confirming that the last command should be executed)
        """
        commit_buffer = struct.pack('<H', self.COMMIT)
        self.device.write(commit_buffer)

    def _recover_from_remote_nack(self) -> None:
        """@brief Restore the communication when the remote target issued a NACK to us
        """
        self.device.write(b'\x00')
        self.device.timeout = 1 # Give some time to the remote to sort itself out!
        remote_resurrect_le = self.device.read(2)
        if len(remote_resurrect_le) != 2:
            logger.error('Short read while performing recovery handshake: ' + str(remote_resurrect_le))
            raise NACKReceivedError
        remote_resurrect = struct.unpack('<H', remote_resurrect_le)[0]
        if remote_resurrect < 0x0309 or remote_resurrect > 0x030b:
            raise RuntimeError(f'Wrong remote resurect code: 0x{remote_resurrect:04x}')
        self.device.write(b'\x19\x00')
        if self.device.read(1) != ACK:
            raise RuntimeError('No ACK after end of remote resurect procedure')

    def execute(self, command: MonitorCommand):
        """@brief Request execution of a specific command on the remote embedded monitor software
        @param command The command to execute
        @return The outcome of the command (can be None, a boolean or the instance of an object encapsulating data)
        """
        assert isinstance(command, MonitorCommand)  # command provided as argument should implement the MonitorCommand interface
        command_buffer = command.get_as_buffer()
        expected_checksum = self.get_checksum(command_buffer)
        self._ping_sync()
        logger.info('Sending command: ' + str(command))
        self.device.write(command_buffer)   # Send command detail to remote
        self.device.timeout = 1
        remote_checksum = self._get_remote_checksum(timeout=1)
        if remote_checksum != expected_checksum:
            raise CommandFailedError(f'Got a wrong remote checksum: 0x{remote_checksum:04x} (expected 0x{expected_checksum:04x})')
        self._commit_last_command()
        content_buffer = command.get_content_payload()
        if len(content_buffer) > 0:
            time.sleep(0.001)
            self.device.write(content_buffer)
        self.device.timeout = command.get_reply_timeout() # Reply timeout depends on the command type
        expected_reply_sz = command.get_expected_reply_sz()
        reply_bytes = self.device.read(expected_reply_sz)
        logger.debug(f'Got {len(reply_bytes)}/{expected_reply_sz} bytes reply')
        if len(reply_bytes) == 1 and expected_reply_sz != 1:    # A single byte reply is probably just the ack
            if reply_bytes[0:1] == NACK:
                logger.error('Got a NACK')
                self._recover_from_remote_nack()
                raise NACKReceivedError('While executing command ' + str(command))
        logger.debug('Response buffer: ' + ' '.join('{:02x}'.format(b) for b in reply_bytes))
        response_parsing_exception = None
        outcome = None
        try:
            outcome = command.parse_reply(reply_bytes)
        except Exception as e:
            logger.error('An error occured while parsing the command reply')
            response_parsing_exception = e
        try:
            expect_ack(self.device, timeout=0.5)
        except NACKReceivedError as e:   # We were expecting an ACK state byte, we got a NACK instead
            raise NACKReceivedError('While executing command ' + str(command)) from e
        if response_parsing_exception is not None:
            raise response_parsing_exception
        else:
            if outcome is not None:
                logger.debug('parse_reply outcome: ' + str(outcome))
            return outcome


class MonitorProtocolSession:
    """@brief Class allowing RAII for communication sessions with the embedded monitor software
    """
    def __init__(self, device):
        """@brief Constructor
        @param device The device we read/write serial data from/to
        """
        self.device = device
        self.handler = None

    def get_handler(self) -> MonitorProtocol:
        """@Get a monitor protocol handler to run commands on the target
        @return A MonitorProtocol instance (we'll create it at the first invokation, then keep it in cache)
        """
        if self.handler is None:
            self.handler = MonitorProtocol(device=self.device)
        return self.handler

    def __enter__(self):
        return self.get_handler()

    def __exit__(self, type, value, traceback):
        pass

class MonitorRemoteLauncher:
    """@brief Class allowing to launch the monitor embedded software on a remote target (via the serial communication)
    """
    def __init__(self, device, startchipid_hex_filename: str, monitor_hex_filename: str, validate_chip_id: Callable[[int], bool]):
        """@brief Constructor
        @param device The device we read/write serial data from/to in order to communicate with the embedded target
        @param startchipid_hex_filename The filename containing Intel Hex-formatted data for the startchipid embedded software to run on the target
        @param monitor_hex_filename The filename containing Intel Hex-formatted data for the monitor embedded software to run on the target
        @param validate_chipid A lamba function taking the remote target's CHIP ID as argument and returning True if this value is accepted
        """
        self.device = device
        self.startchipid_hex_filename = startchipid_hex_filename
        self.monitor_hex_filename = monitor_hex_filename
        self.validate_chip_id = validate_chip_id
        self.chip_id = None

    def start(self) -> int:
        """@brief Make a target device run the monitor protocol handler
        @return The monitor information structure's address in the target's RAM

        @note In order for this method to work, the remote device should initially be (idle) in bootstrap mode, we will then
              take all the necessary steps to make it run the embedded monitor
        """
        self._probe_check_st10(timeout=2)
        chip_id = self._get_chipid()
        if not self.validate_chip_id(chip_id):
            raise RuntimeError("CHIP ID 0x{chip_id:x}} is invalid")
        self.chip_id = chip_id
        monitor_info_addr = self._execute_monitor()
        return monitor_info_addr

    def _probe_check_st10(self, timeout=None) -> None:
        """@brief Send an initial probe to the ST10 chip and check is it bootstrapped in BSL mode
        @param timeout The duration (in s) during which we are ready to wait for a response from the remote target
        @note If no exception is raised, then the S10 is in bootstrap mode and provided the expected ST10 echo type
        """
        logger.info('Probing remote for bootstrap mode')
        self.device.write(b'\x00')     # Probe the target, allowing it to guess the baudrate
        if timeout is not None:
            self.device.timeout = timeout
        ackByte = self.device.read(1)
        if ackByte != b'\xd5':
            logger.error("Did not get BSL feedback byte D5")
            raise BSLProbeError("Could not probe ST10 to check it is in BSL mode")

    def _get_chipid(self) -> int:
        """@brief Retrieve the chip ID from the target board
        @return The chip ID value as an integer
        """
        def _recv_id_chip(timeout=None) -> int:
            """@brief Read a 16-bit ID CHIP data from a stream
            @param timeout An optional timeout that we accept to wait for the reception of the 2 bytes CHIP ID value
            @return The ID CHIP value as an integer
            """
            if timeout is not None:
                self.device.timeout = timeout
            idchip_buf = self.device.read(2)
            if len(idchip_buf) != 2:
                raise RuntimeError('Failed receiving ID CHIP data')
            return struct.unpack('<H', idchip_buf)[0]

        startchipid = IntelHex()
        startchipid.loadhex(self.startchipid_hex_filename)
        startchipid_asm = bytearray(startchipid.tobinarray())
        if len(startchipid_asm) != 154:
            raise RuntimeError('Unexpected startchipid assembly size: ' + str(len(startchipid_asm)))
        self._send_preloader(first_byte_addr=startchipid.minaddr(), length=len(startchipid_asm))
        logger.debug(f'Sending startchipid assembly code')
        write_expect_echo(self.device, startchipid_asm)
        expect_ack(self.device, timeout=0.5)
        return _recv_id_chip(timeout=0.1)

    def _execute_monitor(self) -> int:
        """@brief Send and execute the monitor utility on the target board
        @return The memory address to read for (some info?) about the monitor
        """
        def _recv_monitor_feedback(expected_id_chip, timeout=None) -> int:
            """@brief Read monitor feedback data
            @param expected_id_chip The expected value for the CHIP ID
            @param timeout An optional timeout that we accept to wait for the reception of the monitor feedback data
            @return The ID CHIP value as an integer
            """
            if timeout is not None:
                self.device.timeout = timeout
            monitor_feedback_buf = self.device.read(8)
            (id_chip, reg, null, unknown) = struct.unpack('<HHHH', monitor_feedback_buf)
            if id_chip != expected_id_chip:
                raise RuntimeError('Unexpected ID CHIP value')
            if null != 0:
                raise RuntimeError('Unexpected non 0 payload')
            return reg

        if self.chip_id is None:
            raise RuntimeError('Unknown CHIP ID, cannot run Monitor... invoke get_chipid() first')
        monitor = IntelHex()
        monitor.loadhex(self.monitor_hex_filename)
        monitor_asm = bytearray(monitor.tobinarray())
        if len(monitor_asm) != 1960:
            raise RuntimeError('Unexpected monitor assembly size: ' + str(len(monitor_asm)))
        self._send_preloader(first_byte_addr=monitor.minaddr(), length=len(monitor_asm))
        logger.debug(f'Sending monitor assembly code')
        write_expect_echo(self.device, monitor_asm)
        expect_ack(self.device, timeout=2)
        reg = _recv_monitor_feedback(expected_id_chip=self.chip_id)
        if reg != 0xe3d0:
            raise RuntimeError(f'Unexpected reg feedback from monitor {reg:04x}')
        return reg

    def _send_preloader(self, first_byte_addr: MCULogicalAddress, length: int) -> None:
        """@brief Send a primary preloader assembly code to the target via the serial link

        @note We expect the MCU to be in BSL mode (bootstrap). In that mode, it is waiting for 32-bytes to be sent via the serial link.
            We will forge these 32 bytes in this function, they will effectively act as a assembly code that will then fetch (also via the serial link) a subsequent secondary program to run

        @param first_byte_addr The location (in the MCU address space) where the subsequent embedded code will be written
        @param length The size (in bytes) of the embedded code
        """
        preloader_code = bytearray(  b'\xE6\xF0\x60\xFA' #    mov   r0, #0FA60h            ; Set r0 to point to the destination memory start address
                                   + b'\xEC\xF0'         #    push  r0
                                                         #LOOP:
                                   + b'\x9A\xB7\xFE\x70' #    jnb   S0RIR, $               ; loop until a byte comes in
                                   + b'\xA4\x00\xB2\xFE' #    movb  [r0], S0RBUF           ; write the byte in memory
                                   + b'\x7E\xB7'         #    bclr  S0RIR                  ; clear the receive flag to get the next incoming byte
                                   + b'\xB4\x00\xB0\xFE' #    movb  S0TBUF, [r0]           ; echo back the received byte to the serial port
                                   + b'\xCC\x00'         #    nop                          ; give time for the previous byte to be sent out (we should use "jnb S0TIR, $" here but we have no room for 2 more bytes)
                                   + b'\x7E\xB6'         #    bclr  S0TIR                  ; clear the transmit flag
                                   + b'\x86\xF0\xFF\xFD' #    cmpi1 R0, #0FDFFh            ; check if we're done (value here should be the expected following binary size+0xFA60h-1). We used 0xFDFF in this example as a maximum value, because the code to be downloaded should not overwrite the Special Function Registers (SFR) area immediately following the internal RAM. The C166 SFRs start at FE00h.
                                   + b'\x3D\xF4'         #    jmpr  cc_NE, LOOP            ; if not done, continue receiving the next byte
                                   + b'\xCB\x00'         #    ret                          ; jump to 0xFA60 (see push above)
                                  )
        length_le = struct.pack('<H', length)
        first_byte_addr_le = struct.pack('<H', first_byte_addr)
        last_byte_addr_le = struct.pack('<H', first_byte_addr + length - 1)
        preloader_code[2:4] = first_byte_addr_le # Replace bytes at offset 2 and 3
        preloader_code[26:28] = last_byte_addr_le # Replace bytes at offset 26 and 27
        assert len(preloader_code) == 32    # ST10/C166 bootrom expects exactly 32 bytes
        logger.debug('Writing ' + str(len(preloader_code)) + f' bytes of assembly preloader code to receive and execute {length:d} bytes at address 0x{first_byte_addr:06x}')
        self.device.write(preloader_code)
