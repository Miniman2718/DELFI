#!/usr/bin/env python

from capstone import *
from elftools.elf.elffile import ELFFile

import os
import sys
import logging

def get_offset(elf, text):
    for s in elf.iter_segments():
        if s.section_in_segment(text):
            return s['p_offset'], s['p_vaddr']

def findBL(text, offset):
    bl_instructions = []
    code = text.data()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB+CS_MODE_MCLASS)
    logging.debug(f"Offset: {hex(text.header['sh_offset'] - offset)}")
    logging.debug(f"BL detected:")
    for i in md.disasm(code, text.header['sh_offset'] - offset):
        # Uncomment to dump the disassembled file
        # print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        if(i.mnemonic == 'bl'):
            bl_instructions.append((i.address, i.mnemonic, i.op_str))
            logging.debug(f"{hex(i.address)}, {i.mnemonic}, {i.op_str}")
    return bl_instructions

def read_elf(file_name):
    # Open the elf to be analyzed
    raw = open(file_name, 'rb')
    elf = ELFFile(raw)
    text = elf.get_section_by_name(".text")

    offset, vaddr = get_offset(elf, text)
    bls = findBL(text, offset)
    output = []
    
    # Formatting the output list
    for bl in bls:
        output.append((bl[0]+vaddr, bl[1], int(bl[2][3:], 16) + vaddr))

    return output, vaddr, offset

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Insufficient arguments. Please provide a binary file path.")

    file = sys.argv[1]
    if not os.path.isfile(file):
        sys.exit(f"File not found: {file}")

    (output, vaddr, offset) = read_elf(sys.argv[1])
    for instruction in output:
        print(f'{instruction[1]}, address: {hex(instruction[0])}, target: {hex(instruction[2])}')
