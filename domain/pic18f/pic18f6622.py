#!/usr/bin/env python3
# coding: utf-8

from domain.pic18f.flashing_tools import MCULogicalAddressRange, PicBootConfigCatalog

class PIC18F6622ConfigCatalog(PicBootConfigCatalog):
    """@brief Flash layout for PIC18F6622"""
    def __init__(self):
        pmrangelow = 0x000800
        pmrangehigh = 0x00FFFF
        pmrange = MCULogicalAddressRange(start_address=pmrangelow, end_address=pmrangehigh+1)
        eerangelow=0x000000
        eerangehigh=0x0003FF
        eerange = MCULogicalAddressRange(start_address=eerangelow, end_address=eerangehigh+1)
        usrrangelow=0x200000
        usrrangehigh=0x20000F
        usrrange = MCULogicalAddressRange(start_address=usrrangelow, end_address=usrrangehigh+1)
        cfgrangelow=0x300000
        cfgrangehigh=0x30000D
        ''' Config registers seem to be mapped as follows (they are part of the input HEX image but won't be written):
        CONFIG1L 300000h
        CONFIG1H 300001h
        CONFIG2L 300002h
        CONFIG2H 300003h
        CONFIG3L 300004h
        CONFIG3H 300005h
        CONFIG4L 300006h
        CONFIG4H 300007h
        CONFIG5L 300008h
        CONFIG5H 300009h
        CONFIG6L 30000Ah
        CONFIG6H 30000Bh
        CONFIG7L 30000Ch
        CONFIG7H 30000Dh
        '''
        cfgrange = MCULogicalAddressRange(start_address=cfgrangelow, end_address=cfgrangehigh+1)
        super().__init__(pmrange=pmrange, eerange=eerange, usrrange=usrrange, cfgrange=cfgrange, bytesperaddr=1, maxpacketsize=128, eraseblock=64, readblock=1, writeblock=8, devicetype=1)
