#!/usr/bin/env python3
# coding: utf-8

from typing import List
from domain.st10.flashing_tools import MCULogicalAddressRange, FlashBlocksCatalog

class ST10F276FlashBlocksCatalog(FlashBlocksCatalog):
    """@brief Class representing available flash blocks on the target and related utility methods
    """
    def __init__(self, ROMS1_set: bool, **kwargs):
        """@brief Constructor
        @param ROMS1_set Adapt addresses to the ROMS1 register config (the flash is mapped to different addresses depending on the ROMS1 register)
        """
    
        super().__init__(**kwargs)

        # Source for the flash blocks layout can be found in the ST10F276 datasheet (UM0404) in Table 3. 512 Kbyte IFlash memory block organization
        # Warning: defined blocks below should NOT overlap or unexpected behaviour will occur
        # Also, the index (order) or flash blocks is important as they should match with the bit number in the bitmap used for the flash erase command's argument
        # For example, a flash erase using a mask 0x0010 has bit 5 set, it is thus expected that it will erase block at index 5 in the list below
        # Note: in address ranges below, the first address is the first byte of the flash block, and is included
        #       The second address is the byte AFTER the last byte of the flash block (it is thus excluded)
        if ROMS1_set:
            self.flash_blocks.append(MCULogicalAddressRange(0x010000, 0x012000)) # B0F0
            self.flash_blocks.append(MCULogicalAddressRange(0x012000, 0x014000)) # B0F1
            self.flash_blocks.append(MCULogicalAddressRange(0x014000, 0x016000)) # B0F2
            self.flash_blocks.append(MCULogicalAddressRange(0x016000, 0x018000)) # B0F3
            self.B0F0toB0F3_flash_range = MCULogicalAddressRange(0x010000, 0x018000)
        else:
            self.flash_blocks.append(MCULogicalAddressRange(0x000000, 0x002000)) # B0F0
            self.flash_blocks.append(MCULogicalAddressRange(0x002000, 0x004000)) # B0F1
            self.flash_blocks.append(MCULogicalAddressRange(0x004000, 0x006000)) # B0F2
            self.flash_blocks.append(MCULogicalAddressRange(0x006000, 0x008000)) # B0F3
            self.B0F0toB0F3_flash_range = MCULogicalAddressRange(0x000000, 0x008000)

        self.flash_blocks.append(MCULogicalAddressRange(0x018000, 0x020000))  # B0F4
        self.flash_blocks.append(MCULogicalAddressRange(0x020000, 0x030000))  # B0F5
        self.flash_blocks.append(MCULogicalAddressRange(0x030000, 0x040000))  # B0F6
        self.flash_blocks.append(MCULogicalAddressRange(0x040000, 0x050000))  # B0F7
        self.flash_blocks.append(MCULogicalAddressRange(0x050000, 0x060000))  # B0F8
        self.flash_blocks.append(MCULogicalAddressRange(0x060000, 0x070000))  # B0F9
        self.flash_blocks.append(MCULogicalAddressRange(0x070000, 0x080000))  # B1F0
        self.flash_blocks.append(MCULogicalAddressRange(0x080000, 0x090000))  # B1F1

        self.flash_blocks.append(MCULogicalAddressRange(0x090000, 0x0a0000))  # B2F0
        self.flash_blocks.append(MCULogicalAddressRange(0x0a0000, 0x0b0000))  # B2F1
        self.flash_blocks.append(MCULogicalAddressRange(0x0b0000, 0x0c0000))  # B2F2
        self.flash_blocks.append(MCULogicalAddressRange(0x0c0000, 0x0d0000))  # B3F0
        self.flash_blocks.append(MCULogicalAddressRange(0x0d0000, 0x0e0000))  # B3F1
        self.B0F4toB3F1_flash_range = MCULogicalAddressRange(0x018000, 0x0e0000)

    def get_flash_addr_ranges(self) -> List[MCULogicalAddressRange]:
        if self.B0F0toB0F3_flash_range.end_address >= self.B0F4toB3F1_flash_range.start_address:    # Both ranges can be merged
            return [MCULogicalAddressRange(start_address=self.B0F0toB0F3_flash_range.start_address, end_address=self.B0F4toB3F1_flash_range.end_address)]
        else:
            return [self.B0F0toB0F3_flash_range, self.B0F4toB3F1_flash_range]
        