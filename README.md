# DELFI
## Dark-grey box Embedded Lighweight Firmware Instrumentation
DELFI is a higlhy customizable Python framework to instrument ARM embedded firmware.

## Files structure
- `instrumentator.py`: the main file of the tool, responsible for orchestrating calls to all other modules and
functions.
- `add_section.py`: adds the new code to the binary at the right location, adding the necessary structures to hold the code and make it executable.
- `bl_rewrite.py`: hooks the gadget into the execution flow, by patching the branch instruction in the binary with new offset.
- `code_assembler.py`: creates the gadget to be added. It assemble custom user code in such a way to ensure the normal execution flow is restored.
- `elf_reader.py`:  parses the existing firmware, creating a list of instrumentation target where the tool will hook the user's gadget.
- `LIEF`: git submodule for my fork of LIEF library
