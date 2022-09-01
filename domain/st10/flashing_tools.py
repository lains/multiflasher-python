#!/usr/bin/env python3
# coding: utf-8
import abc
from typing import List, Iterator, Callable

from domain.flasher_context import FlasherContext
import domain.st10.monitor_comm as comm
from domain.mcu_addressing import MCULogicalAddress, MCULocatedLogicalDataChunk, MCULogicalAddressRange, MCUPhysicalAddress
from domain.common import aggregate_close_data_segments, get_hex_chunk_from_address_range, flatten, run_on_each
from domain.command_preprocessor import CommandPreprocessor

def relocate_logical_address(source_ROMS1_set: bool, result_ROMS1_set: bool, source_address: MCULogicalAddress) -> MCULogicalAddress:
    """"@brief Relocate an input data address for two different ROMS1 register configurations
    @param source_ROMS1_set Is the ROMS1 register set when describing the source_address
    @param result_ROMS1_set Is the ROMS1 register set when describing the resulting (returned) address
    @param source_address The logical address to relocate (convert)
    @return The logical address once converted
    """
    assert(source_address >= 0)
    assert(source_address <= 0xffffff)

    if source_ROMS1_set == result_ROMS1_set:
        return source_address
    if not source_ROMS1_set and result_ROMS1_set:
        if source_address >= 0x000000 and source_address <= 0x007fff:   # In ROMS1 set configuration, this range will differ from a ROMS1 clear configuration
            return MCULogicalAddress(source_address | 0x010000)    # Shift addresses in the higher segment
        else:
            return MCULogicalAddress(source_address)
    if source_ROMS1_set and not result_ROMS1_set:
        if source_address >= 0x010000 and source_address <= 0x017fff:   # In ROMS1 clear configuration, this range will differ from a ROMS1 set configuration
            return MCULogicalAddress(source_address & (0xffffff ^ 0x010000))    # Shift addresses in the lower segment
        else:
            return MCULogicalAddress(source_address)
    raise RuntimeError('Code should not reach here')

class FlashBlocksCatalog(metaclass=abc.ABCMeta):
    def __init__(self,
                 cmd_preprocessor: CommandPreprocessor):
        """@brief Construct a flash catalog
        @param aligner A function to align addresses
        @param range_splitter A function to split address ranges to a dimension that is acceptable by underlying commands to the target
        """
        self.flash_blocks: list = []
        self.cmd_preprocessor = cmd_preprocessor

    def get_flash_blocks_list(self) -> List[MCULogicalAddressRange]:
        """@brief Get a list of flash blocks for the target MCU
        @return A list of address ranges for each flash block
        """
        return self.flash_blocks

    def get_flash_block_at_index(self, index) -> MCULogicalAddressRange:
        """@brief Get the range represented by the flash block # index
        """
        return self.flash_blocks[index]

    def get_bloc_index_for_address(self, address: MCULogicalAddress) -> int:
        """@brief Map a given address into one of the MCU's flash memory blocks
        @param address The flash address to search
        @return The flash block index or None if this address could not be found
        """
        #logger.debug(f'Searching for address {address:06x}')
        for index in range(0, len(self.flash_blocks)):
            flash_block: MCULogicalAddressRange = self.flash_blocks[index]
            #logger.debug(f'Checking block at index {index}: [{flash_block.start_address:06x}:{flash_block.end_address:06x}[')
            if flash_block is not None:
                if address >= flash_block.start_address and address < flash_block.end_address:
                    return index
        raise IndexError(f'Could not find bloc for address 0x{address:06x}')

    @abc.abstractmethod
    def get_flash_addr_ranges(self) -> List[MCULogicalAddressRange]:
        """@brief Get a list of valid flash ranges for the target MCU
        @return A minimalist list of address ranges that are available on the MCU (all contiguous addresses in these ranges are valid)
        """
        raise NotImplementedError

    def map_data_segment(self, address_segment: MCULogicalAddressRange) -> Iterator[MCULogicalAddressRange]:
        """@brief Map a segment into flash blocks, splitting them if needed
        @param address_segments A MCUAddressRange segment to map to flash
        @return A sequence of MCUAddressRange that will all fit in one flash block
        """
        if address_segment.start_address < address_segment.end_address and address_segment.end_address > 0: # Only work on segments with at least one byte included, and refuse 0x0 as end_address
            current_start_addr = MCULogicalAddress(address_segment.start_address)
            segment_fully_split = False
            while not segment_fully_split:
                start_block_index = self.get_bloc_index_for_address(current_start_addr)
                end_block_index = self.get_bloc_index_for_address(address_segment.end_address - 1)   # Only care about the included data bytes (thus -1)
                #logger.debug(f'(0x{current_start_addr:06x}, 0x{segment.end_address:06x}) spans blocs {start_block_index}-{end_block_index}')
                if start_block_index != end_block_index: # The whole range of addresses for pending data does not fit in the same block, we have to yield an intermediate block that does not cover the whole segment end range yet
                    current_block_end_addr = self.flash_blocks[start_block_index].end_address   # Note that this address is excluded (it is after the last byte of the block)
                    yield MCULogicalAddressRange(start_address=current_start_addr, end_address=current_block_end_addr)
                    current_start_addr = MCULogicalAddress(current_block_end_addr) # Start over from the next byte not yet written
                else: # start_block_index == end_block_index, use the exact segment addresses, and terminate
                    yield MCULogicalAddressRange(start_address=current_start_addr, end_address=address_segment.end_address)
                    segment_fully_split = True

def create_flash_writer(context: FlasherContext,
                        target_flash_blocks: FlashBlocksCatalog,
                        progress_updater = None) -> Callable[[MCULogicalAddressRange], None]:
    """@brief Higher order function returning a flash writer closure
    @param context The context container to burry inside the returned closure
    @param target_flash_blocks A MCU-specific flash block catalog to burry inside the returned closure
    @param progress_updater A handler used to display progress, to burry inside the returned closure

    @return A dedicated flash writer function, taking a MCULogicalAddressRange as argument (see write_flash_range below)
    """

    def write_chunk(address_range: MCULogicalAddressRange):
        """@brief Write one chunk of addresses
        @param address_range An address range to write (should not span multiple physical segments)
        
        @warning Raises an exception on write errors
        """
        chunk: MCULocatedLogicalDataChunk = get_hex_chunk_from_address_range(firmware_data=context.firmware_file_parser, address_range=address_range)
        assert chunk.size == address_range.get_size()
        # Input firmware file addresses are computed as if ROMS1 is not set
        # However in Boostrap mode, writes should always be done as if ROMS1 was set, so we need to translate addresses (while not touching the payload itself of course)
        chunk.start_address = relocate_logical_address(source_ROMS1_set=False, result_ROMS1_set=True, source_address=chunk.start_address)
        context.logger.debug(f'Writing {chunk.size} bytes (0x{chunk.size:04x}) at relocated target address 0x{chunk.start_address:06x}')
        context.execute_on_target(comm.CommandDataSend(chunk_to_send=chunk))
        try:
            progress_updater.update(chunk.start_address + chunk.size)
        except:
            pass

    def write_flash_block_collocated_chunk_with_retries(address_range: MCULogicalAddressRange, allowed_retries=0) -> None:
        """@brief Write one chunk of addresses with optional multiple retries
        @param address_range An address range to read (should not span multiple flash blocks)
        
        @param allowed_retries The maximum number of retries (in case of failure, if 0 we will try only once)
        """
        context.logger.debug(f'Extracting data from input file at address 0x{address_range.start_address:06x} for {address_range.get_size()} (0x{address_range.get_size():04x}) bytes')
        flash_block_index = target_flash_blocks.get_bloc_index_for_address(address=address_range.start_address)
        flash_block_range: MCULogicalAddressRange = target_flash_blocks.get_flash_block_at_index(flash_block_index)
        if address_range.end_address > flash_block_range.end_address: # The requested range should not span more than one flash block
            raise NotImplementedError
        ranges_to_write = target_flash_blocks.cmd_preprocessor.flash_addr_align_and_split(address_range)
        allowed_retries = allowed_retries * len(ranges_to_write)   # If we split the range to be written into 2, we double the number of allowed retries
        rewrite_all_chunks_needed = True
        while rewrite_all_chunks_needed:
            rewrite_all_chunks_needed = False
            for address_range_for_chunk in ranges_to_write:
                try:
                    write_chunk(address_range=address_range_for_chunk)
                except comm.ChecksumError as e:   # On checksum errors, try on new attempts
                    context.logger.warning(f'Caught a checksum error (see above)')
                    if allowed_retries <= 0:
                        context.logger.error(f'This was the last retry, aborting')
                        raise RuntimeError(f'Failed writing chunk for address {str(address_range_for_chunk)}') from e
                    else:
                        context.logger.warning(f'Will still retry writing {allowed_retries} time(s))')
                        allowed_retries -= 1
                        context.logger.warning(f'Re-erasing the flash block containing the failed write (block at index {flash_block_index}, actually erasing range {str(flash_block_range)})')
                        flash_erase_mask = 1 << flash_block_index
                        context.execute_on_target(comm.CommandFlashErase(flash_mask=flash_erase_mask))
                        rewrite_all_chunks_needed = True
                        break   # Exit for loop, will rewrite all chunks again

    def write_flash_range(requested_range: MCULogicalAddressRange) -> None:
        """@brief Write the provided data to the target, within the specified address range
        @param requested_range An address range to write (may be spread over multiple flash blocks)

        @note If the range is spread over multiple flash blocks, we will perform multiple split writes in each individual flash block
        @note We may split the provided chunk is smaller parts if it is too large to process in one single write command
        """
        if requested_range.get_size() == 0:
            return

        mapped_flash_ranges: List[MCULogicalAddressRange] = list(target_flash_blocks.map_data_segment(requested_range))
        # Note: we only align here, but we don't split because we want to fetch full flash blocks to write_flash_block_collocated_chunk_with_retries() in case flash erase and rewrite is needed
        aligned_flash_ranges: List[MCULogicalAddressRange] = list(map(target_flash_blocks.cmd_preprocessor.apply_flash_alignment_to, mapped_flash_ranges))
        run_on_each(lambda x: write_flash_block_collocated_chunk_with_retries(address_range=x, allowed_retries=context.retries),
                    aligned_flash_ranges)

        context.logger.debug(f"Succesfully wrote in {len(aligned_flash_ranges)} flash blocks writes to cover addresses {str(requested_range)}")
    
    return write_flash_range

def create_flash_verifier(context: FlasherContext,
                          target_flash_blocks: FlashBlocksCatalog,
                          progress_updater = None) -> None:
    """@brief Higher order function returning a flash verifier closure
    @param context The context container to burry inside the returned closure
    @param target_flash_blocks A MCU-specific flash block catalog to burry inside the returned closure
    @param progress_updater A handler used to display progress, to burry inside the returned closure

    @return A dedicated flash verifier function, taking a MCULogicalAddressRange as argument (see verify_flash_range below)
    """
    def verify_chunk_with_retries(address_range: MCULogicalAddressRange, allowed_retries=0) -> None:
        """@brief Verify one chunk of addresses with optional multiple retries
        @param address_range An address range to read (should not span multiple physical segments)
        @param allowed_retries The maximum number of retries (in case of failure, if 0 we will try only once)
        """
        if MCUPhysicalAddress.create_from_logical_address(address_range.start_address).segment != MCUPhysicalAddress.create_from_logical_address(address_range.end_address - 1).segment:  # The requested address range should not span more than one physical segment
            raise NotImplementedError

        context.logger.debug(f'Extracting data from input file at address 0x{address_range.start_address:06x} for {address_range.get_size()} (0x{address_range.get_size():04x}) bytes')
        chunk = get_hex_chunk_from_address_range(firmware_data=context.firmware_file_parser, address_range=address_range)
        assert chunk.size == address_range.get_size()
        # Input firmware file addresses are computed as if ROMS1 is not set
        # However, during Monitor, ROMS1 seems to be set, so we need to translate addresses (while not touching the payload itself of course)
        chunk.start_address = relocate_logical_address(source_ROMS1_set=False, result_ROMS1_set=True, source_address=chunk.start_address)
        context.logger.debug(f'Verifying {chunk.size} bytes (0x{chunk.size:04x}) at relocated target address 0x{chunk.start_address:06x}')
        current_chunk_verified = False
        while not current_chunk_verified:
            try:
                context.execute_on_target(comm.CommandDataVerify(chunk_to_check=chunk))
                current_chunk_verified = True
                try:
                    progress_updater.update(chunk.start_address + chunk.size)
                except:
                    pass
            except comm.ChecksumError as e:   # On checksum errors, try on new attempts
                offending_byte_address = None
                if isinstance(e, comm.LocatedChecksumError):
                    offending_byte_address = e.address
                error_location = ''
                if offending_byte_address is not None:
                    error_location = f' for a byte at address 0x{offending_byte_address:06x}'
                context.logger.warning(f'Caught a checksum error{error_location} (see above)')
                if allowed_retries <= 0:
                    context.logger.error(f'This was the last retry, aborting')
                    raise RuntimeError(f'Failed verifying chunk starting at relocated target address 0x{chunk.start_address:06x}') from e
                else:
                    context.logger.warning(f'Will still retry verifying {allowed_retries} time(s))')
                    allowed_retries -= 1

    def verify_flash_range(requested_range: MCULogicalAddressRange) -> None:
        """@brief Verify that the data stored within an address range on the target, matches the firmware data
        @param requested_range An address range to verify (may be spread over multiple flash blocks)
        """
        if requested_range.get_size() == 0:
            return
        
        mapped_flash_ranges: List[MCULogicalAddressRange] = target_flash_blocks.map_data_segment(requested_range)
        verify_chunks: List[MCULogicalAddressRange] = target_flash_blocks.cmd_preprocessor.flash_addr_align_and_split(mapped_flash_ranges)

        run_on_each(lambda x: verify_chunk_with_retries(address_range=x, allowed_retries=context.retries),
                    verify_chunks)

        context.logger.debug(f"Succesfully verified firmware {str(requested_range)}")

    return verify_flash_range

def create_flash_reader(context: FlasherContext,
                        target_flash_blocks: FlashBlocksCatalog,
                        progress_updater = None) -> Callable[[MCULogicalAddressRange], None]:
    """@brief Higher order function returning a flash reader closure
    @param context The context container to burry inside the returned closure
    @param target_flash_blocks A MCU-specific flash block catalog to burry inside the returned closure
    @param progress_updater A handler used to display progress, to burry inside the returned closure

    @return A dedicated flash reader function, taking a MCULogicalAddressRange as argument (see read_flash_range below)
    """
    def read_chunk_with_retries(address_range: MCULogicalAddressRange, allowed_retries=0) -> None:
        """@brief Read one chunk of addresses with optional multiple retries
        @param address_range An address range to read (should not span multiple physical segments)
        
        @param allowed_retries The maximum number of retries (in case of failure, if 0 we will try only once)
        """
        if MCUPhysicalAddress.create_from_logical_address(address_range.start_address).segment != MCUPhysicalAddress.create_from_logical_address(address_range.end_address - 1).segment:  # The requested address range should not span more than one physical segment
            raise NotImplementedError

        def read_one_chunk(address_range: MCULogicalAddressRange) -> bytes:
            """@brief Read one chunk of address range and return it as bytes
            @param address_range An address range to read (should not span multiple physical segments)

            @warning May raise exceptions, in particular comm.LocatedChecksumError or comm.ChecksumError on chunk read failures
            """
            # Flash partitionning addresses are computed as if ROMS1 is not set
            # However, during Monitor, ROMS1 seems to be set, so we need to translate addresses (while not touching the payload itself of course)
            monitor_dump_start_address = relocate_logical_address(source_ROMS1_set=False, result_ROMS1_set=True, source_address=address_range.start_address)
            data = context.execute_on_target(comm.CommandDataReceiveBytes(range_to_read=MCULogicalAddressRange(monitor_dump_start_address, monitor_dump_start_address+address_range.get_size())))
            assert len(data) == address_range.get_size()
            if data == b'\xff' * address_range.get_size():    # Block contains only erased flash content
                return b''    # Only empty flash, nothing to dump
            else:
                while len(data)>16:
                    if data[-16:] == b'\xff' * 16:    # Block ends with 16 bytes of erased flash content
                        data = data[:-16]   # Remove all empty flash content suffix
                    else:
                        break
            return data

        context.logger.debug(f'Reading data from input file at relocated target address 0x{address_range.start_address:06x} for {address_range.get_size()} (0x{address_range.get_size():04x}) bytes')
        current_chunk_read = False
        while not current_chunk_read:
            try:
                data = read_one_chunk(address_range)
                current_chunk_read = True
                context.firmware_file_parser.put_data_chunk(MCULocatedLogicalDataChunk(start_address=address_range.start_address, content=data))
                try:
                    progress_updater.update(address_range.end_address)
                except:
                    pass

            except comm.ChecksumError as e:   # On checksum errors, try on new attempts
                offending_byte_address = None
                if isinstance(e, comm.LocatedChecksumError):
                    offending_byte_address = e.address
                error_location = ''
                if offending_byte_address is not None:
                    error_location = f' for a byte at address 0x{offending_byte_address:06x}'
                context.logger.warning(f'Caught a checksum error{error_location} (see above)')
                if allowed_retries <= 0:
                    context.logger.error(f'This was the last retry, aborting')
                    raise RuntimeError(f'Failed reading chunk starting at relocated target address 0x{address_range.start_address:06x}') from e
                else:
                    context.logger.warning(f'Will still retry writing {allowed_retries} time(s))')
                    allowed_retries -= 1
    
    def read_flash_range(requested_range: MCULogicalAddressRange) -> None:
        """@brief Read the data stored within an address range on the target and store it into the firmware data
        @param requested_range An address range to read

        @note We support optional multiple read retries if needed to counter possible transmission errors (see FlasherContext)
        """
        if requested_range.get_size() == 0:
            return
        
        mapped_flash_ranges: List[MCULogicalAddressRange] = target_flash_blocks.map_data_segment(requested_range)
        read_chunks: List[MCULogicalAddressRange] = target_flash_blocks.cmd_preprocessor.flash_addr_align_and_split(mapped_flash_ranges)

        run_on_each(lambda x: read_chunk_with_retries(address_range=x, allowed_retries=context.retries),
                    read_chunks)

        context.logger.debug(f"Succesfully read addresses {str(requested_range)}")

    return read_flash_range

def st10_program_cmd(context: FlasherContext, target_flash_blocks: FlashBlocksCatalog) -> None:
    """@brief Program a firmware in a ST10 MCU
    @param context The context container for flashing operations
    @param target_flash_blocks A MCU-specific flash block catalog allowing to guess which flash sector to erase on write error
    """
    firmware_segments_from_hex_file: List[MCULogicalAddressRange] = context.firmware_file_parser.get_segments()

    with context.create_progress_bar(name="Erasing flash ", min_value=context.firmware_file_parser.get_lowest_addr(), max_value=context.firmware_file_parser.get_highest_addr(), show_eta=False) as bar:
        bar.start() # We want to display an empty progress bar initially, as the flash erase is atomic and will reach 100% in one step
        context.execute_on_target(comm.CommandFlashErase())
        bar.finish()

    with context.create_progress_bar(name="Writing flash ", min_value=context.firmware_file_parser.get_lowest_addr(), max_value=context.firmware_file_parser.get_highest_addr(), show_eta=False) as bar:
        write_flash = create_flash_writer(context=context, target_flash_blocks=target_flash_blocks, progress_updater=bar)
        run_on_each(lambda x: write_flash(x),
                    aggregate_close_data_segments(firmware_segments_from_hex_file))
        bar.finish()

    context.logger.info('Flashing succeeded!')


def st10_verify_cmd(context: FlasherContext, target_flash_blocks: FlashBlocksCatalog) -> bool:
    """@brief Check that the expected firmware in properly stored in a PIC MCU
    @param context The context container for flashing operations
    @param target_flash_blocks A MCU-specific flash block catalog allowing to guess which flash sector to erase on write error
    @return True if the firmware matches
    """
    firmware_segments_from_hex_file: List[MCULogicalAddressRange] = context.firmware_file_parser.get_segments()

    with context.create_progress_bar(name="Checking flash ", min_value=context.firmware_file_parser.get_lowest_addr(), max_value=context.firmware_file_parser.get_highest_addr(), show_eta=False) as bar:
        verify_flash = create_flash_verifier(context=context, target_flash_blocks=target_flash_blocks, progress_updater=bar)
        run_on_each(lambda x: verify_flash(x),
                    aggregate_close_data_segments(firmware_segments_from_hex_file))
        bar.finish()
    
    return True

def st10_dump_cmd(context: FlasherContext, target_flash_blocks: FlashBlocksCatalog) -> None:
    """@brief Read a firmware from a ST10 MCU
    @param context The context container for flashing operations
    @param target_flash_blocks A MCU-specific flash block catalog allowing to understand where to read data in the addressing space
    """
    flash_addr_ranges: List[MCULogicalAddressRange] = target_flash_blocks.get_flash_addr_ranges()

    with context.create_progress_bar(name="Reading flash ", min_value=flash_addr_ranges[0].start_address, max_value=flash_addr_ranges[-1].end_address, show_eta=True) as bar:
        read_flash = create_flash_reader(context=context, target_flash_blocks=target_flash_blocks, progress_updater=bar)
        run_on_each(lambda x: read_flash(x),
                    flash_addr_ranges)
        bar.finish()
