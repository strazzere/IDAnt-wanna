#!/usr/bin/env python3
#
# IDAnt-wanna.py
#
# Mangle an ELF file, thus making some (AV) static analysis engines
# and disassemblers barf on the binary.
#
#
# Copyright (C) 2015 Tim 'diff' Strazzere
#                    <diff@sentinelone.com>
#                    <strazz@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import sys
import os
import struct

class Elf:
    def init(self, data):
        self._data = data
        return self.parse(data)

    def parse(self, data):
        # Parse identity
        (self.magic, self.ei_class_2, self.ei_data, self.ei_version, self.ei_osabi,
         self.ei_abiversion, self.ei_pad, self.ei_nident) = struct.unpack_from('4sbbbbb6sb', data, 0)
        if self.magic != b'\x7FELF':
            return False

        # Parse rest of header
        unpacker = 'HHIIIIIHHHHHH' if self.ei_class_2 == 0x1 else 'HHIQQQIHHHHHH'
        (self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff, self.e_shoff,
         self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum,
         self.e_shtrndx) = struct.unpack_from(unpacker, data, 0x10)

        # Parse program header segments
        self.program_header = []
        offset = self.e_phoff

        for x in range(0, self.e_phnum):
            header = ProgramHeader()
            header.parse(self.ei_class_2, data, offset)
            self.program_header.append(header)
            offset += self.e_phentsize

        return True

    def pack(self):
        # Pack identity
        ident = struct.pack('4sbbbbb6sb', self.magic, self.ei_class_2, self.ei_data,
                            self.ei_version, self.ei_osabi, self.ei_abiversion,
                            self.ei_pad, self.ei_nident)
        # Pack rest of header
        packer = 'HHIIIIIHHHHHH' if self.ei_class_2 == 0x1 else 'HHIQQQIHHHHHH'
        elf_head = struct.pack(packer, self.e_type, self.e_machine, self.e_version, self.e_entry,
                               self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize,
                               self.e_phnum, self.e_shentsize, self.e_shnum, self.e_shtrndx)

        # Unsure if it is allowable to have a binary misaligned... shouldn't ever happen?
        if len(ident) + len(elf_head) < self.e_phoff:
            print(' [!] Protentially need buffer? Continuing anyway...')

        # Pack program header segments
        program_headers = b''
        for header in self.program_header:
            program_headers += header.pack(self.ei_class_2)

        # Return the slightly modified bits plus the rest of the original binary
        return ident + elf_head + program_headers + data[len(ident + elf_head + program_headers):]

class ProgramHeader():
    def parse(self, bit, data, offset):
        # Unpack program header segment
        if bit == 0x1:
            (self.p_type, self.p_offset, self.p_vaddr, self.p_paddr, self.p_filesz,
             self.p_memsz, self.p_flags, self.p_align) = struct.unpack_from('IIIIIIII', data, offset)
        else:
            (self.p_type, self.p_flags, self.p_offset, self.p_vaddr, self.p_paddr, self.p_filesz,
             self.p_memsz, self.p_align) = struct.unpack_from('IIQQQQQQ', data, offset)

    def pack(self, bit):
        # Pack program header segment
        if bit == 0x1:
            return struct.pack('IIIIIIII', self.p_type, self.p_offset, self.p_vaddr, self.p_paddr,
                               self.p_filesz, self.p_memsz, self.p_flags, self.p_align)
        else:
            return struct.pack('IIQQQQQQ', self.p_type, self.p_flags, self.p_offset, self.p_vaddr, self.p_paddr,
                           self.p_filesz, self.p_memsz, self.p_align)

def check(file, og_size):
    for segment in file.program_header:
        if segment.p_offset >= og_size:
            return True
    return False

def change(file, to):
    # Find a segment we don't actually need, but IDA/GDB require, then mess it up
    # This is actually the lazy way to do it, we could parse the binary and inject
    # a new, unneeded header to cause issues, however that exercise is (currently)
    # left up to the reader :D
    for segment in file.program_header:
        # Look for PT_SHT_ARM_EXIDX
        if segment.p_type == 0x70000001:
            segment.p_offset = to
            return True
        # Look for PT_GNU_STACK or PT_NOTE
        elif segment.p_type == 0x6474e550 or segment.p_type == 0x4:
            # Nerd the section type and the offset for 64bit
            segment.p_type = 0x70000001
            segment.p_offset = to
            return True
    return False

if __name__ == '__main__':
    print('[*] IDAnt-wanna; Breaking ELF loading on:')
    print('     <= IDA 6.8.150428 / GNU gdb (Ubuntu 7.10-1ubuntu2) 7.10')
    print(' [*] Tim (diff) Strazzere - diff@sentinel.com - strazz@gmail.com')
    print
    
    file = Elf()
    if len(sys.argv) < 3:
        print(' [!] Please enter an option --t(est) --f(ix) --n(erf) [filename]+')
        raise SystemExit

    for filename in sys.argv[2:]:
        print(' [+] Processing %s...' % filename)
        with open(filename, 'rb') as f:
            og_size = os.fstat(f.fileno()).st_size
            data = f.read()
        
        if(file.init(data)):
            if sys.argv[1].startswith('--t'):
                if check(file, og_size):
                    print(' [+] Detected weirdness in a program header...')
                else:
                    print(' [-] Nothing weird found...')
            elif sys.argv[1].startswith('--f'):
                if check(file, og_size):
                    print(' [+] Found a weird program header, attempting to null out...')
                    change(file, 0)
                    with open(('%s.fixed' % filename), 'wb') as f: f.write(file.pack()) 
                    print(' [+] Fixed file saved to %s' % ('%s.fixed' % filename))
                else:
                    print(' [-] Nothing weird found to fix, exiting...')
            elif sys.argv[1].startswith('--n'):
                if not check(file, og_size):
                    if change(file, og_size + 10):
                        # By nulling out these sections, IDA can't recover from the bad program header offset
                        file.e_shentsize = 0
                        file.e_shnum = 0
                        file.e_shtrndx = 0
                        print(' [+] Found section to nerf, saving to %s' % ('%s.nerfed' % filename))
                        with open(('%s.nerfed' % filename), 'wb') as f: f.write(file.pack())
                    else:
                        print(' [!] Unable to find a proper section to kill...')
                else:
                    print(' [!] Binary already appears mangled...')
        else:
            print(' [!] Either the file in not an ELF or something bad happened...')
