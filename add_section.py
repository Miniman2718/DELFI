#!/usr/bin/env python

import sys
sys.path.append("./LIEF/api/python/lief")

import os
import _lief as lief

from pprint import pprint
import logging

def log_settings():
    lief.logging.enable()

# Create a new logical construct to hold new information
def create_section(code, vaddr):
    new_s = lief.ELF.Section()
    new_s.name = ".ADDED"
    new_s.type =  lief.ELF.Section.TYPE.PROGBITS

    new_s.content = list(code)

    new_s.size = len(new_s.content)
    new_s.flags = lief.ELF.Section.FLAGS.ALLOC | lief.ELF.Section.FLAGS.EXECINSTR

    new_s.virtual_address = vaddr
    new_s.alignment = 0x1000
    return new_s

### Create a segment to fisically hold the new section data
def create_segment(section):
    s = lief.ELF.Segment()
    s.add(lief.ELF.Segment.FLAGS.X)
    s.add(lief.ELF.Segment.FLAGS.R)
    s.add(lief.ELF.Segment.FLAGS.W)
    s.type = lief.ELF.Segment.TYPE.LOAD
    s.content = section.content
    s.alignment = 0x1000
    s.virtual_address = section.virtual_address
    return s

def add_section(src, dest, code, vaddr):
    log_settings()
    binary = lief.ELF.parse(src)
    new_section = create_section(code, vaddr)
    binary.add(new_section)
    new_segment = create_segment(new_section)
    binary.add(new_segment)
    binary.write(dest)
    return new_section.virtual_address

def compute_vaddr(src):
    new_vaddr = 0

    binary = lief.ELF.parse(src)
    for s in binary.segments:
        if s.virtual_address & ~0xfffffff == 0 :
            tmp = s.virtual_address + s.virtual_size
            if tmp > new_vaddr:
                new_vaddr = tmp
    # Align new_vaddr to 0x1000
    if new_vaddr & 0xfff != 0:
        new_vaddr = (new_vaddr+0x1000)& ~0xfff
    new_vaddr += 0x1000 #Leave space for PHDR relocation
    return new_vaddr
