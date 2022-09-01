#!/usr/bin/env python3
# coding: utf-8
from typing import List, Callable
from domain.mcu_addressing import MCULogicalAddressRange
from domain.common import flatten

class CommandPreprocessor:
    def __init__(self,
                 aligner: Callable[[MCULogicalAddressRange], MCULogicalAddressRange]=lambda x:x,
                 range_splitter: Callable[[MCULogicalAddressRange], List[MCULogicalAddressRange]]=lambda x:[x]):
        """@brief Construct a command preprocessor environment
        @param aligner A function to align addresses
        @param range_splitter A function to split address ranges to a dimension that is acceptable by underlying commands to the target
        """
        if not callable(aligner):
            raise TypeError("aligner argument is not callable")
        self.aligner = aligner
        if not callable(range_splitter):
            raise TypeError("range_splitter argument is not callable")
        self.range_splitter = range_splitter

    def flash_addr_align_and_split(self, flash_range) -> List[MCULogicalAddressRange]:
        """@brief Perform both flash address aligment and split to maximum admissible range
        @param flash_range Either one flash range (MCULogicalAddressRange instance) or a list of flash ranges to process
        @return A list of aligned and split flash ranges
        """
        if isinstance(flash_range, MCULogicalAddressRange):
            flash_range = [flash_range]

        def _flash_addr_align_and_split_one_range(flash_range: MCULogicalAddressRange) -> List[MCULogicalAddressRange]:
            assert isinstance(flash_range, MCULogicalAddressRange)
            return list(flatten(self.range_splitter(self.aligner(flash_range))))

        return list(flatten(list(map(_flash_addr_align_and_split_one_range, flash_range))))

    def apply_flash_alignment_to(self, range: MCULogicalAddressRange) -> MCULogicalAddressRange:
        return self.aligner(range)

    def apply_range_split_to(self, range: MCULogicalAddressRange) -> List[MCULogicalAddressRange]:
        return self.range_splitter(range)