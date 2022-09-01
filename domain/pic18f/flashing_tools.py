#!/usr/bin/env python3
# coding: utf-8

from typing import List, Iterator

from domain.flasher_context import FlasherContext
import domain.pic18f.picboot_comm as comm
from domain.mcu_addressing import MCULocatedLogicalDataChunk, MCULogicalAddress, MCULogicalAddressRange
from domain.common import aggregate_close_data_segments, align_on_8_bytes, get_hex_chunk_from_address_range, split_address_range_to_max_size

class PicBootConfigCatalog:
    def __init__(self, pmrange: MCULogicalAddressRange, # Range represented by PICFlasher.INI's config values pmrangelow+pmrangehigh
                       eerange: MCULogicalAddressRange, # Range represented by PICFlasher.INI's config values eerangelow+eerangehigh
                       cfgrange: MCULogicalAddressRange,# Range represented by PICFlasher.INI's config values cfgrangelow+cfgrangehigh
                       usrrange: MCULogicalAddressRange,# Range represented by PICFlasher.INI's config values usrrangelow+usrrangehigh
                       bytesperaddr: int, maxpacketsize: int, eraseblock: int, readblock: int, writeblock:int, devicetype: int):
        self.ProgMemAddrRange = pmrange
        self.EEDataAddrRange = eerange
        self.ConfigAddrRange = cfgrange
        self.UserIDAddrRange = usrrange
        self.DevBytesPerAddr = bytesperaddr
        self.MaxPacketSize = maxpacketsize
        self.DeviceErsBlock = eraseblock
        self.DeviceRdBlock = readblock
        self.DeviceWrtBlock = writeblock
        self.DeviceType = devicetype

    def filter_progmem_segments(self, address_segments: List[MCULogicalAddressRange]) -> Iterator[MCULogicalAddressRange]:
        """@brief Filter-out all segments that are not part of the PIC progmem address space
        @param address_segments A list of MCUAddressRange for each segment to filter
        @return A sequence of MCUAddressRange that are located within the progmem address space
        """
        for segment in address_segments:
            if segment.start_address < segment.end_address and segment.end_address > 0: # Only work on segments with at least one byte included, and refuse 0x0 as end_address
                start_addr = segment.start_address
                end_addr = segment.end_address
                if start_addr > self.ProgMemAddrRange.end_address or end_addr < self.ProgMemAddrRange.start_address:
                    continue    # Segment is outside the progmem range
                if start_addr < self.ProgMemAddrRange.start_address:
                    start_addr = self.ProgMemAddrRange.start_address    # Keep only the part within the progmem range
                if end_addr > self.ProgMemAddrRange.end_address:
                    end_addr = self.ProgMemAddrRange.end_address    # Keep only the part within the progmem range
                if start_addr < end_addr:   # There is at least one byte in the range, deliver it
                    yield MCULogicalAddressRange(start_address=start_addr, end_address=end_addr)

    def map_data_segment(self, address_segments: List[MCULogicalAddressRange]) -> Iterator[MCULogicalAddressRange]:
        """@brief Map a list of segments into flash blocks, splitting them if needed
        @param address_segments A list of MCUAddressRange for each segment to map to flash
        @return A sequence of MCUAddressRange that will all fit in one flash block
        """
        for segment in address_segments:
            if segment.start_address < segment.end_address and segment.end_address > 0: # Only work on segments with at least one byte included, and refuse 0x0 as end_address
                current_start_addr = MCULogicalAddress(segment.start_address)
                segment_fully_split = False
                while not segment_fully_split:
                    start_block_index = current_start_addr // self.DeviceWrtBlock
                    end_block_index = (segment.end_address - 1) // self.DeviceWrtBlock   # Only care about the included data bytes (thus -1)
                    #logger.debug(f'(0x{current_start_addr:06x}, 0x{segment.end_address:06x}) spans blocs {start_block_index}-{end_block_index}')
                    if start_block_index != end_block_index: # The whole range of addresses for pending data does not fit in the same block, we have to yield an intermediate block that does not cover the whole segment end range yet
                        current_block_end_addr = current_start_addr + self.DeviceWrtBlock  # Note that this address is excluded (it is after the last byte of the block)
                        if current_start_addr != current_block_end_addr:
                            yield MCULogicalAddressRange(start_address=current_start_addr, end_address=current_block_end_addr)
                        current_start_addr = current_block_end_addr # Start over from the next byte not yet written
                    else: # start_block_index == end_block_index, use the exact segment addresses, and terminate
                        if current_start_addr != segment.end_address:
                            yield MCULogicalAddressRange(start_address=current_start_addr, end_address=segment.end_address)
                        segment_fully_split = True

def pic_erase_progmem_flash_range(context: FlasherContext, address_range: MCULogicalAddressRange, target_config: PicBootConfigCatalog):
    """@brief Erase a range of addresses in the PIC progmem flash
    @param context The context container for flashing operations
    @param address_range The address range to erase
    @param target_config A MCU-specific memory mapping catalog
    """
    device_erase_block_sz = target_config.DeviceErsBlock
    assert address_range.start_address % device_erase_block_sz == 0 # Make sure the starting address is at the beginning of an erase block
    assert address_range.end_address % device_erase_block_sz == 0 # Make sure the last erased address is at the end of an erase block
    current_block_start_address = address_range.start_address
    with context.create_progress_bar_from_range(name="Erasing flash ",
                                                range=address_range,
                                                show_eta=True) as bar:
        bar.start()
        while current_block_start_address < address_range.end_address:
            context.execute_on_target(comm.CommandEraseProgramMemoryRange(start_address=current_block_start_address, nb_rows=1))   # Erase one row at each pass
            current_block_start_address += device_erase_block_sz
            bar.update(current_block_start_address)
        bar.finish()

def write_firmware_range_in_flash_block(context: FlasherContext, requested_range: MCULogicalAddressRange, target_config: PicBootConfigCatalog):
    """@brief Write the provided data to the target, within the specified address range (flash block)
    @param context The context container for flashing operations
    @param requested_range The range to write (should not span multiple flash blocks)
    @param target_config A MCU-specific memory mapping catalog
    @param allowed_retries The maximum number of retries (in case of failure, if 0 we will try only once)

    @note We may split the provided chunk is smaller parts to match flash blocks
    """
    with context.create_progress_bar_from_range(name="Writing flash ",
                                                range=requested_range,
                                                show_eta=True) as bar:
        bar.start()
        for flash_block_range in target_config.map_data_segment([requested_range]):
            aligned_flash_block_range: MCULogicalAddressRange = MCULogicalAddressRange(start_address=align_on_8_bytes(flash_block_range.start_address, excess=False),
                                                                                       end_address=align_on_8_bytes(flash_block_range.end_address, excess=True))
            chunk_to_write = get_hex_chunk_from_address_range(firmware_data=context.firmware_file_parser, address_range=aligned_flash_block_range)
            context.execute_on_target(comm.CommandWriteProgramMemory(chunk_to_send=chunk_to_write))
            # PIC requires to re-read the flash after each write
            re_read_chunk = context.execute_on_target(comm.CommandReadProgramMemory(chunk_start_address=chunk_to_write.start_address, chunk_size=chunk_to_write.size))
            # FIXME: If content does not match a first time, allow a second retry (like in the DLL)
            assert re_read_chunk == chunk_to_write.get_content()
            new_pos = chunk_to_write.start_address + chunk_to_write.size
            bar.update(new_pos)
        bar.finish()


def pic_program_cmd(context: FlasherContext, target_config: PicBootConfigCatalog) -> None:
    """@brief Program a firmware in a PIC MCU
    @param context The context container for flashing operations
    @param target_config A MCU-specific memory mapping catalog
    """
    firmware_segments_from_hex_file: List[MCULogicalAddressRange] = context.firmware_file_parser.get_segments()
    # The data in range 000000 to 000200 contains (the bootloader?), it is not sent to the PIC (it should be programmed using a PIC chip programming probe)
    # Also data in range 300000 to 30000d (included) contains the PIC config area, it is not sent to the PIC during firmware programmation (it should be programmed using a PIC chip programming probe)
    # We thus limit ourselves to the programmable memory (for erasing and writing):
    pic_erase_progmem_flash_range(context=context, address_range=target_config.ProgMemAddrRange, target_config=target_config)
    for address_range in aggregate_close_data_segments(target_config.filter_progmem_segments(firmware_segments_from_hex_file), min_gap=target_config.DeviceErsBlock):
        context.logger.debug('Writing firmware data at address range ' + str(address_range))
        write_firmware_range_in_flash_block(context=context, requested_range=address_range, target_config=target_config)

    context.logger.info('Flashing succeeded!')


def pic_verify_cmd(context: FlasherContext, target_config: PicBootConfigCatalog) -> bool:
    """@brief Check that the expected firmware in properly stored in a PIC MCU
    @param context The context container for flashing operations
    @param target_config A MCU-specific memory mapping catalog
    @return True if the firmware matches
    """
    firmware_segments_from_hex_file: List[MCULogicalAddressRange] = list(aggregate_close_data_segments(context.firmware_file_parser.get_segments(), min_gap=8))
    # gen_title allows us to quickly generate the progressbar title/name
    gen_title = lambda area_name, address : f"Checking {area_name} at 0x{address:06x}"
    for segment in firmware_segments_from_hex_file:
        if target_config.EEDataAddrRange.includes(segment):
            area_name = "EEPROM "
        elif target_config.ProgMemAddrRange.includes(segment):
            area_name = "program"
        elif target_config.ConfigAddrRange.includes(segment):
            area_name = "config "
        else:
            area_name = "flash  "

        with context.create_progress_bar_from_range(name=gen_title(area_name=area_name, address=segment.start_address),
                                                    range=segment,
                                                    show_eta=True) as bar:
            bar.start()
            for address_range in split_address_range_to_max_size(address_range=segment, max_size=16):
                block_read = context.execute_on_target(comm.CommandReadProgramMemory(address_range.start_address, chunk_size=address_range.get_size()))
                block_expected = get_hex_chunk_from_address_range(firmware_data=context.firmware_file_parser, address_range=address_range).get_content()
                if block_read != block_expected:
                    context.logger.error(f"Flash differs from expected content in block starting at address 0x{address_range.start_address:06x}:")
                    context.logger.error("Read:     " + ' '.join('{:02x}'.format(b) for b in block_read))
                    context.logger.error("Expected: " + ' '.join('{:02x}'.format(b) for b in block_expected))
                    return False
                else:
                    bar.update(address_range.end_address)
            bar.finish()
    return True

def read_firmware_range(context: FlasherContext, requested_range: MCULogicalAddressRange, progress_updater = None) -> None:
    """@brief Read the data stored within an address range on the target and store it into the firmware data (handling multiple retries on errors)
    @param context The context container for flashing operations
    @param requested_range An address range to read
    @param progress_updater A handler used to display progress, we will invoke bar.update() on the last address of each block read
    """
    if requested_range.get_size() == 0:
        return

    for address_range in split_address_range_to_max_size(address_range=requested_range, max_size=16):
        dumped_start_address = address_range.start_address
        data = context.execute_on_target(comm.CommandReadProgramMemory(chunk_start_address=dumped_start_address, chunk_size=address_range.get_size()))
        assert len(data) == address_range.get_size()
        if data == b'\xff' * address_range.get_size():    # Block contains only erased flash content
            pass    # Only empty flash, nothing to dump
        else:
            context.firmware_file_parser.put_data_chunk(MCULocatedLogicalDataChunk(start_address=address_range.start_address, content=data))
        try:
            progress_updater.update(address_range.end_address)
        except:
            pass
    context.logger.debug(f"Succesfully read addresses {str(requested_range)}")

def pic_dump_cmd(context: FlasherContext, target_config: PicBootConfigCatalog) -> None:
    """@brief Read a firmware from a PIC MCU
    @param context The context container for flashing operations
    @param target_config A MCU-specific memory mapping catalog
    """
    # gen_title allows us to quickly generate the progressbar title/name
    gen_title = lambda area_name, address : f"Reading {area_name} at 0x{address:06x}"
    with context.create_progress_bar_from_range(name=gen_title(area_name="EEPROM ", address=target_config.EEDataAddrRange.start_address),
                                                range=target_config.EEDataAddrRange,
                                                show_eta=True) as bar:
        bar.start()
        read_firmware_range(context=context, requested_range=target_config.EEDataAddrRange, progress_updater=bar)
        bar.finish()
    
    with context.create_progress_bar_from_range(name=gen_title(area_name="program", address=target_config.ProgMemAddrRange.start_address),
                                                range=target_config.ProgMemAddrRange,
                                                show_eta=True) as bar:
        bar.start()
        read_firmware_range(context=context, requested_range=target_config.ProgMemAddrRange, progress_updater=bar)
        bar.finish()

    with context.create_progress_bar_from_range(name=gen_title(area_name="config ", address=target_config.ConfigAddrRange.start_address),
                                                range=target_config.ConfigAddrRange,
                                                show_eta=True) as bar:
        bar.start()
        read_firmware_range(context=context, requested_range=target_config.ConfigAddrRange, progress_updater=bar)
        bar.finish()
