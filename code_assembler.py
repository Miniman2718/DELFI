#!/usr/bin/env python
from keystone import *

import pprint
import logging

dyn_module = '''
func{}:
    movs r0, #{}
    movs r1, #{}
    movs r2, #{}       
    lsls r2, r2, #8      
    adds r1, r1, r2      
    movs r2, #{}       
    lsls r2, r2, #8      
    adds r2, #{}       
    lsls r2, r2, #16     
    adds r1, r1, r2  
    b main
'''

static_module = '''
main:
    bx r1
'''

def create_code(bls):
    code_string = ""
    for i, bl in enumerate(bls):
        a = bl[2]
        code_string += dyn_module.format(i, i, hex((a & 0xff)+1), hex((a>>8) & 0xff), hex((a>>24)&0xff), hex((a>>16)&0xff))
    code_string += static_module

    with open('code.asm', 'w') as f:
        f.write(code_string)
    logging.info("Gadget code has been written to code.asm")
    return code_string

def assemble(code):
    try:
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        encoding, count = ks.asm(code)
        logging.debug(f"Assembled code = [{', '.join(hex(num) for num in encoding)}]")
    except KsError as e:
        print("ERROR: %s" %e)

    with open('code.obj', 'wb') as f:
        for b in encoding:
            f.write(b.to_bytes(1, 'little'))
    logging.info("Assembled gadget code has been written to code.obj")
    return encoding
