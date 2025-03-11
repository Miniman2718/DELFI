#!/usr/bin/env python
# from arm_anal import main

from add_section import add_section, compute_vaddr
from elf_reader import read_elf
from bl_rewriter import rewrite_bl
from code_assembler import create_code, assemble

import logging
import sys
import os

def initialize_logging():
    logger = logging.getLogger("")
    logger.setLevel(logging.DEBUG)

    debug_handler = logging.StreamHandler()
    info_handler = logging.StreamHandler()

    debug_handler.setLevel(logging.DEBUG)
    debug_handler.addFilter(lambda record: record.levelno == logging.DEBUG)
    info_handler.setLevel(logging.INFO)
    info_handler.addFilter(lambda record: record.levelno >= logging.DEBUG)

    debug_formatter = logging.Formatter("DEBUG: %(message)s")
    info_formatter = logging.Formatter("%(message)s")
    
    debug_handler.setFormatter(debug_formatter)
    info_handler.setFormatter(info_formatter)

    logger.addHandler(debug_handler)
    logger.addHandler(info_handler)

def check_arguments():
    if len(sys.argv) < 3:
        sys.exit("Insufficient arguments. Please provide two file paths.")

    src = sys.argv[1]
    if not os.path.isfile(src):
        sys.exit(f"Source file not found: {src}")

    dest = sys.argv[2]
    if os.path.isfile(dest):
        print(f"Destination file already existing. Overwriting {dest}...")

    return src, dest

def instrumentator(file_src, file_dest):
    initialize_logging()

    logging.info("Extracting bls...")
    bls, baseaddr, offset = read_elf(file_src)

    # Implement a BL selection filter
    # Example: filtering out third `bl` as it is not part of the code to be instrumented
    del bls[2]


    logging.debug("Filtered BLS list")
    for i, bl in enumerate(bls):
        logging.debug (f'address: {hex(bl[0])}, target: {hex(bl[2])}')

    logging.info("Generating and adding new section...")
    sizeofcode = 22
    newsec_vaddr = compute_vaddr(file_src)
    code_string = create_code(bls)
    code_bytes = assemble(code_string)

    add_section(file_src, file_dest, code_bytes, newsec_vaddr)

    logging.info("Rewriting the bls...")
    for i, bl in enumerate(bls):
        rewrite_bl(bl[0], newsec_vaddr+i*sizeofcode, file_dest, baseaddr, offset)

if __name__ == "__main__":
    file_src, file_dest = check_arguments()
    instrumentator(file_src, file_dest)
