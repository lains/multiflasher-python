# coding: utf-8
"""@brief Module declaring the interface to which must comply all concrete implementations of hex-formatted file parsers
"""
import abc
from typing import List

from domain.mcu_addressing import MCULocatedLogicalDataChunk, MCULogicalAddress, MCULogicalAddressRange

class HexFileParser(metaclass=abc.ABCMeta):
    """@brief Interface to which must comply all concrete implementations of hex-formatted file parsers"""

    @abc.abstractmethod
    def __init__(self):
        """@brief Construct a hex file parser object
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_segments(self) -> List[MCULogicalAddressRange]:
        """@brief Get a list of distinct segments contained in the hex file"""
        raise NotImplementedError
    
    @abc.abstractmethod
    def get_lowest_addr(self) -> MCULogicalAddress:
        """@brief Get the lowest address contained in the hex file"""
        raise NotImplementedError

    @abc.abstractmethod
    def get_highest_addr(self) -> MCULogicalAddress:
        """@brief Get the highest address contained in the hex file"""
        raise NotImplementedError

    @abc.abstractmethod
    def get_data_chunk_for_range(self, address_range: MCULogicalAddressRange) -> MCULocatedLogicalDataChunk:
        """@brief Get data contained in the hex file representation, for a given address range
        
        @return The data read from the hex file"""
        raise NotImplementedError

    @abc.abstractmethod
    def put_data_chunk(self, content: MCULocatedLogicalDataChunk):
        """@brief Insert the provided content into the hex file representation

        @param content A data chunk with its logical location in flash

        @note This changes the file representation, but in order to be saved on disk, you should then invoke write_as_hex_file()
        """
        raise NotImplementedError
    
    @abc.abstractmethod
    def write_hex_to(self, file):
        """@brief Save the content of the current firmware representation to a file
        
        @param file A file-like object or a filename
        """
        raise NotImplementedError

    @abc.abstractmethod
    def read_hex_from(self, file):
        """@brief Read the current firmware representation from a file
        
        @param file A file-like object or a filename
        """
        raise NotImplementedError

    @classmethod
    def __subclasshook__(cls, subclass):
        if cls is not HexFileParser:
            return NotImplemented
        return (
            hasattr(subclass, "get_segments")
            and callable(  # pylint: disable=consider-using-ternary
                subclass.get_segments
            )
            and hasattr(subclass, "get_lowest_addr")
            and callable(  # pylint: disable=consider-using-ternary
                subclass.get_lowest_addr
            )
            and hasattr(subclass, "get_highest_addr")
            and callable(  # pylint: disable=consider-using-ternary
                subclass.get_highest_addr
            )
            and hasattr(subclass, "get_data_chunk_for_range")
            and callable(  # pylint: disable=consider-using-ternary
                subclass.get_data_chunk_for_range
            )
            and hasattr(subclass, "put")
            and callable(  # pylint: disable=consider-using-ternary
                subclass.put
            )
            and hasattr(subclass, "write_hex_to")
            and callable(  # pylint: disable=consider-using-ternary
                subclass.write_hex_to
            )
            and hasattr(subclass, "read_hex_from")
            and callable(  # pylint: disable=consider-using-ternary
                subclass.read_hex_from
            )
            or NotImplemented
        )
