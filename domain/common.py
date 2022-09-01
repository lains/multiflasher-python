#!/usr/bin/env python3
# coding: utf-8

from typing import List, Iterator, Generator
from logging import getLogger, StreamHandler, Formatter
from logging import DEBUG, INFO, WARNING
from collections.abc import Iterable

from domain.ext_adapters_interface.hex_file_parser_interface import HexFileParser
from domain.mcu_addressing import MCULogicalAddressRange, MCULogicalAddress, MCULocatedLogicalDataChunk

def create_main_logger(name: str, log_level=WARNING, also_log_libs: bool = False):
    """@brief Create the main applicative logger and return it
    @param name The name of the logger
    @param log_level The log level over which logs are output
    @param also_log_libs Also configure all python loggers similarly to the main applicative logger
    """
    LOG_FORMAT = "%(asctime)s :: %(levelname)s :: %(name)s: %(message)s"
    main_logger = getLogger(name=name)
    main_logger.handlers = []
    main_logger.setLevel(log_level)
    stream_handler = StreamHandler()
    stream_handler.setLevel(log_level)
    stream_handler.setFormatter(Formatter(LOG_FORMAT))
    if also_log_libs:
        root_logger = getLogger()
        root_logger.setLevel(log_level)
        root_logger.addHandler(stream_handler)
    else:  # We do not enable a handler on the main_logger if the root logger is already generating messages to avoid duplicates
        main_logger.addHandler(stream_handler)
    return main_logger

def aggregate_close_data_segments(address_segments: List[MCULogicalAddressRange], min_gap: int = 16) -> Iterator[MCULogicalAddressRange]:
    """@brief Aggregate a list of segments into possibly larger segments when consecutive segments sufficiently close to one another
    @param address_segments A list of MCUAddressRange for each consecutive segment to try to aggregate
    @param min_gap The minimum gap between two consecutive data segments, if a smaller gap exists, segments will be aggregated
    @return Sequence of MCUAddressRange objects for each consecutive (possibly aggregated) segment

    @note This allows us to avoid flashing ridiculously small blocks, but we will only aggregate successive entries (ie, not if they are not in order)
    @warning the generated segments may return excessively large blocks also!
    """
    start_addr = None
    end_addr = None
    for segment in address_segments: # Parse all file segments
        if end_addr is None:  # First segment, use as is
            start_addr = segment.start_address
            end_addr = segment.end_address
        else:
            if end_addr <= segment.start_address and (segment.start_address - end_addr) < min_gap: # Less than min_gap bytes of padding between two segments, aggregate both
                end_addr = segment.end_address
            else:   # Too much gap with previous segment, let's handle them separately
                yield MCULogicalAddressRange(start_address=start_addr, end_address=end_addr)
                start_addr = segment.start_address
                end_addr = segment.end_address
    if end_addr is not None and start_addr is not None:
        yield MCULogicalAddressRange(start_address=start_addr, end_address=end_addr)
    return

def align_on_8_bytes(address: MCULogicalAddress, excess: bool = True) -> MCULogicalAddress:
    """@brief Make sure address is aligned on 8-bytes boundary
    @param Address the address to align
    @param excess If set to True, and input address is not aligned, we will align to the next boundary. If set to False, we will align to the previous boundary
    @return The closest 8-byte aligned address after (if excess==True) or before (if excess=False) the provided address
    """
    if excess:
        address += 7
    return MCULogicalAddress((address // 8) * 8)

def get_hex_chunk_from_address_range(firmware_data: HexFileParser, address_range: MCULogicalAddressRange) -> MCULocatedLogicalDataChunk:
    """@brief Extract binary data for a specific adress range out of an Intel Hex file
    @param firmware_data The IntelHex instance containing the data to use for extraction
    @param address_range The address range for the data to extract
    @return The extracted binary data
    """
    return firmware_data.get_data_chunk_for_range(address_range)

def split_address_range_to_max_size(address_range: MCULogicalAddressRange, max_size: int) -> Iterator[MCULogicalAddressRange]:
    """@brief Split a range of logical addresses into possibly smaller ranges given a max permitted range size
    @param raaddress_rangenge A MCULogicalAddressRange to split if too large
    @return Sequence of MCULogicalAddressRange objects for each consecutive (possibly split) range
    """
    while address_range.get_size() > max_size:
        pending_range_start_address = address_range.start_address
        pending_range_end_address = address_range.start_address + max_size
        address_range = MCULogicalAddressRange(start_address = pending_range_end_address, end_address=address_range.end_address)
        yield MCULogicalAddressRange(start_address=pending_range_start_address, end_address=pending_range_end_address)
    if address_range.get_size() > 0:  # There is a remaining range that fits into the max_size
        yield address_range
    return

def flatten(nl) -> Generator:
    """@brief Flatten nested lists to one single sequence of payload elements

    @param nl Potentially nested list

    @return An iterator over the flattened element list
    
    @note str will not be split into their constituent characters
    """
    for e in nl:
        if isinstance(e, Iterable) and not isinstance(e, (str, bytes)):
            yield from flatten(e)
        else:
            yield e

def run_on_each(fn, items):
    """@brief A version of map that discards results from fn
    """
    for item in items:
        fn(item)
