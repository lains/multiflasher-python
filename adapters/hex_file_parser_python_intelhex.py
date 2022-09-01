# coding: utf-8
"""@brief Module declaring the interface to which must comply all concrete implementations of hex-formatted file parsers
"""
from intelhex import IntelHex

from domain.ext_adapters_interface.hex_file_parser_interface import HexFileParser
from domain.ext_adapters_interface.hex_file_parser_interface import MCULocatedLogicalDataChunk, MCULogicalAddress, MCULogicalAddressRange
from domain.ext_adapters_interface.hex_file_parser_interface import List
from io import IOBase

class PythonIntelHexFileParser(HexFileParser):
    """@brief Interface to which must comply all concrete implementations of hex-formatted file parsers"""

    def __init__(self):
        """@brief Construct a hex file parser object
        """
        self.intel_hex = IntelHex()

    def get_segments(self) -> List[MCULogicalAddressRange]:
        return [MCULogicalAddressRange.create_from_hex_segment(s) for s in self.intel_hex.segments()]
    
    def get_lowest_addr(self) -> MCULogicalAddress:
        return MCULogicalAddress(self.intel_hex.minaddr())

    def get_highest_addr(self) -> MCULogicalAddress:
        return MCULogicalAddress(self.intel_hex.maxaddr())

    def get_data_chunk_for_range(self, address_range: MCULogicalAddressRange) -> MCULocatedLogicalDataChunk:
        data_chunk = self.intel_hex.tobinstr(start=address_range.start_address, end=address_range.end_address-1) # IntelHex.tobinstr()'s end address is included, while MCUAddressRange.end_address is excluded, this is why we rewind 1 byte for the end address
        return MCULocatedLogicalDataChunk(start_address=address_range.start_address, content=data_chunk)

    def put_data_chunk(self, content: MCULocatedLogicalDataChunk):
        self.intel_hex.puts(content.start_address, content.get_content())

    def write_hex_to(self, file):
        if not isinstance(file, IOBase):
            with open(file=file, mode="wt") as f:
                self.write_hex_to(f)
        else:
            self.intel_hex.write_hex_file(file)

    def read_hex_from(self, file):
        if not isinstance(file, str):
            raise NotImplementedError    # Reading from file-like object is not implemented yet
        self.intel_hex.loadhex(file)
