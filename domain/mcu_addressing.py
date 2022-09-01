#!/usr/bin/env python3
# coding: utf-8
from typing import Tuple

"""@file MCU addressing-related representation
"""

class MCULogicalAddress(int):
    """@brief Class representing a logical address in the MCU linera address space (24-bit value for ST10 family)
    """

    def is_aligned_on_bytes_multiple(self, multiple: int) -> bool:
        """@brief Check if the specified address range is a multiple of the provided argument
        @param mulitple The multiple to check (eg: 2 means address is even)
        @return True if the provided address range is aligned
        """
        return int(self) % multiple == 0


class MCULogicalAddressRange:
    """@brief Class representing an address range in the MCU adress space
    """
    def __init__(self, start_address: MCULogicalAddress, end_address: MCULogicalAddress):
        """@brief Constructor
        @param start_address The address of the first byte in the range
        @param end_address The address of the byte after the last byte included in the range (thus end_address is excluded)
        """
        assert(start_address < end_address)
        self.start_address = start_address
        self.end_address = end_address

    def __str__(self):
        return f'MCULogicalAddressRange[0x{self.start_address:06x},0x{self.end_address:06x}['
    
    def __repr__(self):
        return str(self)

    def get_size(self) -> int:
        """@brief Get the size in bytes of this range
        @return The number of bytes included in this range
        """
        return self.end_address - self.start_address

    def contains(self, address: MCULogicalAddress) -> bool:
        """@brief Check if the specified address is within this address range
        @param address The logical address to check
        @return True if the provided address is inside the range represented by this instance
        """
        return (address >= self.start_address and address < self.end_address)

    def includes(self, address_range) -> bool:
        """@brief Check if the specified address range is fully included within this address range
        @param address_range The address range to check
        @return True if the provided address range is inside the range represented by this instance
        """
        assert address_range.end_address > 0
        return self.contains(address_range.start_address) and self.contains(address_range.end_address-1)

    @staticmethod
    def create_from_hex_segment(segment: Tuple[int, int]):
        """@brief Create a MCUAddressRange instance from a tuple
        @param segment A tuple of (start_address, end_address) like what is returned by IntelHex.segments()
        @return The newly constructed MCUAddressRange instance
        """
        (segment_start_addr, segment_end_addr) = segment
        return MCULogicalAddressRange(start_address=segment_start_addr, end_address=segment_end_addr)


class MCUPhysicalAddress:
    """@brief Class representing a physical address location in the MCU addressing space
    """
    def __init__(self, offset: int, segment: int):
        """@brief Constructor
        @param offset An offset (address relative of the beginning of the segment), between 0x0000 and 0xffff inclusive
        @param segment A address segment, between 0x00 and 0xff inclusive
        """
        assert offset >= 0x0000 and offset<=0xffff
        assert segment >= 0x00 and segment<=0xff
        self.offset = offset
        self.segment = segment

    def get_data_page(self):
        """@brief Get the datapage this address belongs to
        """
        return self.segment * 4 + (self.offset & 0xC000) >> 14

    @staticmethod
    def create_from_logical_address(address: MCULogicalAddress):
        """@brief Create an MCUPhysicalAddress from a logical address value
        """
        assert address >= 0x000000 and address <= 0xffffff
        return MCUPhysicalAddress(offset=address & 0xffff, segment=address >> 16)

    def to_logical_address(self) -> MCULogicalAddress:
        """@brief Represent this physical address as a logical address
        """
        return MCULogicalAddress(self.segment << 16 | self.offset)

    def __str__(self) -> str:
        return f'{self.segment:02x}{self.offset:04x}'


class MCULocatedLogicalDataChunk:
    """@brief Class representing one MCU chunk of data located at a specific logical location in the MCU address space
    """
    def __init__(self, start_address, content: bytearray):
        """@brief Constructor
        @param start_address The starting address for this chunk
        @param content A byte buffer containing the content of this chunk
        """
        if isinstance(start_address, MCULogicalAddress):
            start_address = start_address
        elif isinstance(start_address, int):
            start_address = MCULogicalAddress(start_address)
        else:
            raise TypeError('Unsupported argument type ' + str(type(start_address)))
        self.start_address: MCULogicalAddress = start_address
        self.size = len(content)
        self.content = content

    def get_content(self) -> bytearray:
        """@brief Get the data chunk's raw bytes
        @return The data chunk bytes as a bytearray buffer
        """
        return self.content
    
    def to_address_range(self) -> MCULogicalAddressRange:
        return MCULogicalAddressRange(start_address=self.start_address, end_address=self.start_address + self.size)

    def __str__(self):
        return f'MCULocatedLogicalDataChunk({self.size} bytes @ 0x{self.start_address:06x},0x{self.end_address:06x})=' + self.content.__repr__
    
    def __repr__(self):
        return str(self)
