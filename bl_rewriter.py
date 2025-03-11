#!/usr/bin/env python

from capstone import *
from io import BytesIO

import logging
import sys

def rewrite_bl(bl_addr, target, file_name, vaddr, offset):
    try:
        bl_offset = target - (bl_addr+4)
        encoded_instruction = encode_bl(bl_offset)
    except ValueError as e:
        print(f"Error: {e}")

    w = open(file_name, 'r+b')
    w.seek(bl_addr - vaddr + offset)
    w.write(encoded_instruction)
    w.close()
    logging.debug(f"Rewritten bl at {hex(bl_addr)}, now pointing to {hex(target)}, bytes = 0x{encoded_instruction.hex()}")

def encode_bl(offset):
    '''
    0-4: opcode (0xf:0)
    5: S
    6-15: imm10
    16-17: op-code (0b11)
    18: J1
    19: op-code (1)
    20: J2
    21-31: imm11
    offset = SignExtend(S:I1:I2:imm10:imm11:0, 32)
    '''
    # Ensure the offset is within the valid range (-16777216 to 16777214) and even
    if offset < -16777216 or offset > 16777214: # or offset % 2 != 0:
        raise ValueError("Offset is not valid!")

    # Extract the sign bit (S)
    S = 1 if offset < 0 else 0

    # Convert offset to unsigned and remove the least significant bit
    offset = (offset & 0x01FFFFFE) >> 1

    # Extract imm11 and imm10
    imm11 = offset & 0x7FF
    imm10 = (offset >> 11) & 0x3FF

    # Calculate J1 and J2
    I1 = (offset >> 22) & 1
    I2 = (offset >> 21) & 1
    J1 = (~I1 ^ S) & 1
    J2 = (~I2 ^ S) & 1

    # Construct the instruction
    instruction = (0b11110 << 27) | (S << 26) | (imm10 << 16) | (0b11 << 14) | \
                  (J1 << 13) | (1 << 12) | (J2 << 11) | imm11

    # Convert to bytes in the required format (BBAADDCC)
    instruction = instruction.to_bytes(4, byteorder='big')
    
    # Swap bytes within each halfword to get AABBCCDD
    instruction = bytes([
        instruction[1], instruction[0],
        instruction[3], instruction[2]
    ])

    return instruction

