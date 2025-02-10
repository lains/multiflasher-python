#!/usr/bin/env python3
# coding: utf-8

import abc
import struct
from typing import Callable
import itertools
from logging import getLogger
import time

from domain.mcu_addressing import MCULogicalAddress, MCULocatedLogicalDataChunk

logger = getLogger(__name__)

class MaxRetriesReachedError(Exception):
    pass

class ChecksumError(Exception):
    pass

class ReadTimeoutError(Exception):
    pass

class CommandFailedError(Exception):
    pass

class BootloaderProbeError(Exception):
    pass

class ProtocolError(Exception):
    pass

def get_8bit_arithmetic_checksum(buffer) -> int:
    """@brief Computes a basic checksum (arithmetic byte sum limited to 8-bit results without carry) on a buffer
    @param buffer The byte buffer to process
    @return The resulting unsigned 8-bit checksum
    """
    checksum_result: int = 0
    for byte in buffer:
        checksum_result = (checksum_result + byte) & 0xff
    return checksum_result

class PicbootCommand(metaclass=abc.ABCMeta):
    """@brief Interface to which must comply all concrete implementations of picboot command encoders/decoders"""
    COMMAND_ID = None
    COMMAND_NAME = '(unknown)'
    MAX_PACKET_SIZE = 256

    def __init__(self, command_id: int, max_retries: int=1):
        self.command_id = command_id
        self.max_retries = max_retries

    @staticmethod
    def to_logical_address(input) -> MCULogicalAddress:
        """@brief Try to convert an input value into a MCULogicalAddress
        @return The resulting MCULogicalAddress instance
        @warning If conversion is not possible, an TypeError exception will be raised
        """
        if isinstance(input, MCULogicalAddress):
            return input
        elif isinstance(input, int):
            return MCULogicalAddress(input)
        else:
            raise TypeError('Unsupported argument type ' + str(type(input)))

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

    def get_max_retries(self) -> int:
        """@brief Get the number of retries allowed
        @return The number of retries (0 means we will only try the first time, 1 means 2 attempts will be done in total)
        """
        return self.max_retries

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
        """@brief Parse the reply from embedded picboot software
        @param reply_payload The data returned by the embedded picboot software
        @return An object containing our interpretation of the reply_payload
        """
        raise NotImplementedError

    def get_as_buffer(self) -> bytearray:
        """@brief Represent this command as a binary buffer
        @return The byte buffer to send to the remote target (includes command+arguments)
        """
        arguments_payload = self.get_arguments_payload()
        command_id = struct.pack('B', self.command_id)
        return command_id + arguments_payload

    def __str__(self) -> str:
        """@brief Generic formatter of a command as a string"""
        return self.COMMAND_NAME

class CommandReadProgramMemory(PicbootCommand):
    """@brief Class for encoding/decoding a command to read program memory from the target"""
    COMMAND_ID = 0x01
    COMMAND_NAME = 'RD_FLASH'

    def __init__(self, chunk_start_address, chunk_size: int, **kwargs):
        """@brief Constructor
        @param chunk_start_address The location of the binary data to receive from the target
        @param chunk_size The size of the binary data to receive (in bytes)
        """
        assert chunk_size > 0x0000 and chunk_size <= PicbootCommand.MAX_PACKET_SIZE - 6  # 5 bytes are used as an echo to this command's representation, 1 more byte is needed for checksum
        #chunk_start_address = super().to_physical_address(chunk_start_address)
        self.chunk_start_address = chunk_start_address
        self.chunk_size = chunk_size
        super().__init__(command_id = self.COMMAND_ID, **kwargs)

    def get_arguments_payload(self) -> bytearray:
        chunk_size_byte = struct.pack('B', self.chunk_size)
        chunk_start_addr24 = struct.pack('<I', self.chunk_start_address)[0:3]   # We only grab the 3 first bytes (discarding the most significant byte)
        return chunk_size_byte + chunk_start_addr24

    def get_reply_timeout(self) -> int:
        return self.chunk_size * 0.005 + 0.3   # 5ms/byte returned

    def get_expected_reply_sz(self) -> int:
        return len(self.get_as_buffer()) + self.chunk_size  # We're expecting the full command to be echoed back to us, plus the result

    def parse_reply(self, reply_payload):
        if len(reply_payload) != self.get_expected_reply_sz():
            raise RuntimeError('Short read while receiving reply for ' + str(self) + ' expected a ' + str(self.get_expected_reply_sz()) + ' bytes reply')
        expected_echoed_arguments = self.get_as_buffer()
        # Make sure the first bytes match the command echoed back
        if reply_payload[0:len(expected_echoed_arguments)] != expected_echoed_arguments:
            raise RuntimeError('Wrong echoed arguments. Expected ' + ' '.join('{:02x}'.format(b) for b in expected_echoed_arguments + ', got ' + ' '.join('{:02x}'.format(b) for b in reply_payload)))
        
        return reply_payload[len(expected_echoed_arguments):]  # Only keep response part (discard echoed command)

    def __str__(self) -> str:
        return super().__str__() + f'({self.chunk_size} bytes at 0x{self.chunk_start_address:06x})'


class CommandWriteProgramMemory(PicbootCommand):
    """@brief Class for encoding/decoding a command to write program memory to the target"""
    COMMAND_ID = 0x02
    COMMAND_NAME = 'WT_FLASH'

    def __init__(self, chunk_to_send: MCULocatedLogicalDataChunk, **kwargs):
        """@brief Constructor
        @param chunk_to_send The chunk of binary data to send to the target, its length must be a multiple of 8 bytes (= size of a flash block) and at most 128 flash blocks
        """
        assert chunk_to_send.size >= 0x00 and chunk_to_send.size <= 128 * 8
        assert chunk_to_send.size % 8 == 0  # We only take multiples of the write block size as chunks
        logger.debug(f'Will send data buffer of {chunk_to_send.size} bytes')
        self.chunk_to_send = chunk_to_send
        super().__init__(command_id = self.COMMAND_ID, max_retries=3, **kwargs)

    def get_arguments_payload(self) -> bytearray:
        chunk_size_byte = struct.pack('B', self.chunk_to_send.size // 8)
        chunk_start_addr24 = struct.pack('<I', self.chunk_to_send.start_address)[0:3]   # We only grab the 3 first bytes (discarding the most significant byte)
        return chunk_size_byte + chunk_start_addr24 + self.chunk_to_send.get_content()

    def get_reply_timeout(self) -> int:
        return self.chunk_size * 0.020 + 0.1   # 20ms/byte written

    def get_expected_reply_sz(self) -> int:
        return 1

    def parse_reply(self, reply_payload):
        if len(reply_payload) != self.get_expected_reply_sz():
            raise RuntimeError('Short read while receiving reply for ' + str(self) + ' expected a ' + str(self.get_expected_reply_sz()) + ' bytes reply')
        if reply_payload[0] != self.COMMAND_ID:
            raise RuntimeError(f'Wrong reply. Expected {self.COMMAND_ID:02x}, got ' + ' '.join('{:02x}'.format(b) for b in reply_payload))        

    def __str__(self) -> str:
        return super().__str__() + f'({self.chunk_to_send.size} bytes at 0x{self.chunk_to_send.start_address:06x})'


class CommandEraseProgramMemoryRange(PicbootCommand):
    """@brief Class for encoding/decoding a command to erase program memory on the target"""
    COMMAND_ID = 0x03
    COMMAND_NAME = 'ER_FLASH'

    def __init__(self, start_address: MCULogicalAddress, nb_rows: int, **kwargs):
        """@brief Constructor
        @param start_address The starting address to erase on the target
        @param nb_rows The number of rows to erase
        """
        assert nb_rows > 0 and nb_rows <= 0xff
        self.start_address = self.to_logical_address(start_address)
        assert self.start_address >= 0x000000 and self.start_address <= 0xffffff+1
        self.nb_rows = nb_rows
        super().__init__(command_id = self.COMMAND_ID, max_retries=5, **kwargs)

    def get_arguments_payload(self) -> bytearray:
        nb_rows_byte = struct.pack('B', self.nb_rows)
        start_addr24 = struct.pack('<I', self.start_address)[0:3]   # We only grab the 3 first bytes (discarding the most significant byte)
        return nb_rows_byte + start_addr24

    def get_reply_timeout(self) -> int:
        return 20   # Allow 20s for a full flash erase

    def get_expected_reply_sz(self) -> int:
        return 1

    def parse_reply(self, reply_payload):
        if len(reply_payload) != self.get_expected_reply_sz():
            raise RuntimeError('Short read while receiving reply for ' + str(self) + ' expected a ' + str(self.get_expected_reply_sz()) + ' bytes reply')
        if reply_payload[0] != self.COMMAND_ID:
            raise RuntimeError(f'Wrong reply. Expected {self.COMMAND_ID:02x}, got ' + ' '.join('{:02x}'.format(b) for b in reply_payload))

    def __str__(self) -> str:
        return super().__str__() + f'({self.nb_rows} rows at 0x{self.start_address:06x})'


class CommandReadDeviceID(CommandReadProgramMemory):
    """@brief Class for reading the PIC device ID of the target"""
    COMMAND_NAME = 'READ_PIC'

    def __init__(self):
        super().__init__(chunk_start_address=0x3ffffe, chunk_size=2, max_retries=10)

    def parse_reply(self, reply_payload):
        """@brief Parse the reply string and extract the PIC device ID
        @param reply_payload The data returned by the embedded picboot software
        @return A tuple containing device ID, followed by the device revision
        """
        command_response = super().parse_reply(reply_payload)
        reg_device_id = struct.unpack('<H', command_response[0:2])[0]
        rev = reg_device_id & 0x01f
        devid = reg_device_id >> 5
        return (devid, rev)


class CommandEnterBootloader(PicbootCommand):
    """@brief Class for encoding/decoding a command to make the target enter the bootloader"""
    COMMAND_ID = 0x55
    COMMAND_NAME = 'ENTER_BOOTLOADER'

    def __init__(self, **kwargs):
        """@brief Constructor
        """
        super().__init__(command_id = self.COMMAND_ID, **kwargs)

    def get_arguments_payload(self) -> bytearray:
            return b'\x02'

    def get_reply_timeout(self) -> int:
        return 0.001   # allow 1ms for command to proceed

    def get_expected_reply_sz(self) -> int:
        return 0

    def parse_reply(self, reply_payload):
        return


class CommandExitBootloader(PicbootCommand):
    """@brief Class for encoding/decoding a command to make the target exit the bootloader"""
    COMMAND_ID = 0x08
    COMMAND_NAME = 'RESET'
    
    def __init__(self, **kwargs):
        """@brief Constructor
        """
        super().__init__(command_id = self.COMMAND_ID, **kwargs)

    def get_arguments_payload(self) -> bytearray:
            return b''

    def get_reply_timeout(self) -> int:
        return 0.100   # Allow 100ms for the reboot to complete

    def get_expected_reply_sz(self) -> int:
        return 0

    def parse_reply(self, reply_payload):
        return

class CommandReadBootloaderVersion(PicbootCommand):
    """@brief Class for encoding/decoding a command to get the bootloader firmware version"""
    COMMAND_ID = 0x00
    COMMAND_NAME = 'RD_VER'

    def __init__(self, **kwargs):
        """@brief Constructor
        """
        super().__init__(command_id = self.COMMAND_ID, **kwargs)

    def get_arguments_payload(self) -> bytearray:
            return b'\x02'

    def get_reply_timeout(self) -> int:
        return 0.001   # allow 1ms for command to proceed

    def get_expected_reply_sz(self) -> int:
        return 4

    def parse_reply(self, reply_payload):
        if reply_payload[0] != self.COMMAND_ID:
            raise RuntimeError(f'Wrong reply. Expected first byte equal to command ID {self.COMMAND_ID:02x}, got frame ' + ' '.join('{:02x}'.format(b) for b in reply_payload))
        if reply_payload[1] != 0x02:
            raise RuntimeError(f'Wrong reply. Expected second byte equal 0x02, got frame ' + ' '.join('{:02x}'.format(b) for b in reply_payload))
        (minor_version, major_version) = struct.unpack('BB', reply_payload[2:4])
        return (major_version, minor_version)

class PicbootProtocol:
    """@brief Class representing the communication protocol with the remote embedded monitor software
    """
    STX = 0x0f
    ETX = 0x04
    DLE = 0x05
    READ_TIMEOUT = 0.4  # Timeout for each single byte read operation (replies), in ms

    def __init__(self, device):
        """@brief Constructor
        @param device The device we read/write serial data from/to
        """
        self.device = device

    def __enter__(self):
        pass

    def __exit__(self, type, value, traceback):
        pass

    @staticmethod
    def unescape(buffer: bytes) -> bytearray:
        """@brief Unescape a byte stream according to the bootloader escape scheme
        @param buffer The input buffer potentially including escape sequences
        @return An equivalent buffer, raw (without escape sequences)
        """
        result: bytearray = b''
        inEscape: bool = False
        for b in buffer:
            if b == PicbootProtocol.DLE and not inEscape:  # This is the start of an escape sequence
                inEscape = True
            else:
                inEscape = False
                result.append(b)
        if inEscape:    # Last byte was an escape character but not followed by anything
            raise RuntimeError('Trailing escape character')
        return result

    @staticmethod
    def escape(buffer: bytes) -> bytearray:
        """@brief Escape a byte stream according to the bootloader escape scheme
        @param buffer The input buffer
        @return An equivalent buffer, with escape sequences added whenever needed
        """
        result: bytearray = b''
        for b in buffer:
            if b in [PicbootProtocol.DLE, PicbootProtocol.STX, PicbootProtocol.ETX]:  # This character should be escaped
                result += bytes([PicbootProtocol.DLE])   # Append a DLE byte
            result += bytes([b])    # Copy byte as is
        return result

    @staticmethod
    def get_checksum(buffer) -> int:
        """@brief Computes a standard bootloader-type checksum
        @note The checksum used by bootloader is an arithmetic byte sum limited to 8-bit results without carry, negated and incremented
              Example: get_checksum(b'\x55\x02') -> 0xa9
        @param buffer The byte buffer to process (should already be unescaped)
        @return The resulting unsigned 8-bit checksum
        """
        sum = get_8bit_arithmetic_checksum(buffer)
        return (~sum + 1) & 0xff

    def _get_reply_packet(self) -> bytearray:
        """@brief Wait for an incoming reply packet from the target
        @return The returned packet, unescaped, without the protocol header and footer, and with the checksum validated
        """
        allowed_leading_garbage_sz = 10 # Max 10 bytes of garbage before an actual response
        sync_with_single_STX = False
        sync_with_double_STX = False
        end_of_packet = False
        in_escape = False
        payload: bytearray = b''
        while not end_of_packet:
            self.device.timeout = PicbootProtocol.READ_TIMEOUT
            input = self.device.read(1)
            #logger.warning('Incoming: ' + str(input))
            if len(input) < 1:
                current_state = []
                if in_escape:
                    current_state += ['in_escape']
                if sync_with_double_STX:
                    current_state += ['double_ETX', 'in_payload']
                elif sync_with_single_STX:
                    current_state += ['single_ETX']
                current_state_str = ""
                if len(current_state) > 0:
                    current_state_str = ". state=[" + ','.join(current_state) + "]"
                raise ReadTimeoutError("Timeout waiting for a reply from target" + current_state_str)
            if in_escape:    # The current byte is escaped, add it to the payload as is
                payload += input
                in_escape = False
                continue
            if sync_with_double_STX:
                # Note: we know that inEscape is False because of the inEscape condition above
                if input[0] == PicbootProtocol.ETX:
                    remote_checksum = payload[-1]
                    expected_checksum = self.get_checksum(payload[:-1])
                    if remote_checksum != expected_checksum:
                        raise ChecksumError(f'Got a wrong remote checksum: 0x{remote_checksum:02x} (expected 0x{expected_checksum:02x})')
                    else:
                        payload = payload[:-1]  # Wipe the checksum, the payload is ready
                        end_of_packet = True
                        break
                elif input[0] == PicbootProtocol.STX:  # We are receiving an unescaped STX, this should not occur, we are probably de-synchronized
                    logger.error('Wrong packet synchronization, restarting STX*2 lookup')
                    sync_with_double_STX = False
                    sync_with_single_STX = True
                    continue
                elif input[0] == PicbootProtocol.DLE:  # This is the beginning of an escape sequence
                    in_escape = True
                    continue
                else:
                    payload += input
                    continue
            else:
                # We are not in sync yet (not parsing the payload)
                if input[0] != PicbootProtocol.STX:
                    logger.warning(f'Got a leading garbage byte 0x{input[0]:02x}')
                    if allowed_leading_garbage_sz <= 0:
                        raise ProtocolError(f'Too many leading garbage bytes received')
                    else:
                        allowed_leading_garbage_sz -= 1
                        continue
                else:   # Incoming byte is an STX
                    if sync_with_single_STX:
                        sync_with_double_STX = True
                    else:
                        sync_with_single_STX = True
        if end_of_packet:
            return payload

    def _send_get_with_retries(self, command: PicbootCommand, expected_reply: bool, allowed_retries: int=0) -> bytearray:
        """@brief Send a command (optionally retrying on failures)
        @param command The command to send
        @param expected_reply Do we expect any reply to that command?
        @param allowed_retries The maximum number of retries (in case of failure, if 0 we will try only once)
        @return The reply bytes (or None if no reply was expected)
        """
        command_buffer = command.get_as_buffer()
        expected_checksum = self.get_checksum(command_buffer)
        encapsulated_command_buffer = bytes([PicbootProtocol.STX, PicbootProtocol.STX])
        encapsulated_command_buffer += self.escape(command_buffer + struct.pack('B', expected_checksum))
        encapsulated_command_buffer += bytes([PicbootProtocol.ETX])
        attempt_number = 0
        while attempt_number <= allowed_retries:
            logger.info(('Sending' if attempt_number == 0 else 'Re-sending') + ' command: ' + str(command))
            #logger.warning('Bytes sent to serial port: ' + str(encapsulated_command_buffer))
            reply_bytes: bytearray = b''
            try:
                self.device.write(encapsulated_command_buffer)   # Send command detail to remote
                if not expected_reply:
                    return
                reply_bytes = self._get_reply_packet()
                return reply_bytes
            except Exception as e:
                logger.error('Caught the following exception: ' + str(e))
                attempt_number += 1
        raise MaxRetriesReachedError('Aborting transmission of command ' + str(command) + ' after ' + str(allowed_retries) + ' retrie(s)')

    def execute(self, command: PicbootCommand):
        """@brief Request execution of a specific command on the remote embedded monitor software
        @param command The command to execute
        @return The outcome of the command (can be None, a boolean or the instance of an object encapsulating data)
        """
        assert isinstance(command, PicbootCommand)  # command provided as argument should implement the PicbootCommand interface
        expected_reply_sz = command.get_expected_reply_sz()
        reply_bytes = self._send_get_with_retries(command=command, expected_reply=(expected_reply_sz > 0), allowed_retries=command.get_max_retries())
        if not expected_reply_sz > 0:
            return
        assert reply_bytes is not None
        logger.debug(f'Got {len(reply_bytes)}/{expected_reply_sz} bytes reply')
        logger.debug('Response buffer: ' + ' '.join('{:02x}'.format(b) for b in reply_bytes))
        
        outcome = None
        try:
            outcome = command.parse_reply(reply_bytes)
        except Exception as e:
            logger.error('An error occured while parsing the command reply')
            raise e
        if outcome is not None:
            logger.debug('parse_reply outcome: ' + str(outcome))
        return outcome


class PicbootProtocolSession:
    """@brief Class allowing RAII for communication sessions with the embedded bootloader software
    """
    def __init__(self, device):
        """@brief Constructor
        @param device The device we read/write serial data from/to
        """
        self.device = device
        self.handler = None

    def get_handler(self) -> PicbootProtocol:
        """@Get a picboot protocol handler to run commands on the target
        @return A PicbootProtocol instance (we'll create it at the first invokation, then keep it in cache)
        """
        if self.handler is None:
            self.handler = PicbootProtocol(device=self.device)
        return self.handler

    def __enter__(self):
        return self.get_handler()

    def __exit__(self, type, value, traceback):
        pass


class BootloaderRemoteLauncher:
    """@brief Class allowing to launch the embedded bootloader software on a remote target (via the serial communication)
    """
    def __init__(self, device, validate_device_id: Callable[[int], bool]):
        """@brief Constructor
        @param device The device we read/write serial data from/to in order to communicate with the embedded target
        @param validate_device_id A lamba function taking the remote target's device ID as argument and returning True if this value is accepted
        """
        self.device = device
        self.validate_device_id = validate_device_id
        self.device_id = None
        self.device_rev = None

    def start(self) -> None:
        """@brief Make a target device run the bootloader protocol handler

        @note In order for this method to work, the remote device should initially be (idle) and turned off, we will then
              take all the necessary steps to make it start the embedded bootloader
        """
        with PicbootProtocolSession(device=self.device) as target:
            for _ in itertools.repeat(None, 10):
                target.execute(CommandEnterBootloader())
            (version_major, version_minor) = target.execute(CommandReadBootloaderVersion())
            logger.info('Communicating with PICBOOT v' + str(version_major) + '.' + str(version_minor))
            (device_id, device_rev) = target.execute(CommandReadDeviceID())
            if not self.validate_device_id(device_id):
                raise RuntimeError("CHIP ID 0x{device_id:x}} is invalid")
        self.device_id = device_id
        self.device_rev = device_rev
