#!/usr/bin/env python2.7

import sys

from idc import *
from idaapi import *
from idautils import *

from struct import pack
from ctypes import c_uint32, c_uint64
import subprocess
from collections import defaultdict

class IDA_XrefTypes:
    Data_Unknown = 0
    Data_Offset = 1
    Data_Write = 2
    Data_Read = 3
    Data_Text = 4
    Data_Informational = 5
    Code_Far_Call = 16
    Code_Near_Call = 17
    Code_Far_Jump = 18
    Code_Near_Jump = 19
    Code_User = 20
    Ordinary_Flo = 21

base = get_imagebase()
plt_start, plt_end = 0, 0
segments = list(Segments())

# C++ configuration
dump_vtables = True
vtable_section_names = [".rodata",
    ".data.rel.ro",
    ".data.rel.ro.local",
    ".rdata"]

# pure_virtual resides in plt, therefore we can ignore it
pure_virtual_addr = None 

# Gives the number of allowed zero entries in the beginning of
# a vtable candidate.
vtbl_number_allowed_zero_entries = 0

is_linux = None
is_windows = None

cmd_readelf = "/usr/bin/readelf"

# Class that represents an elf symbol read by readelf.
class Elf_Symbol:
    def __init__(self):
        self.num = None
        self.buc = None
        self.value = None
        self.size = None
        self.type = None
        self.bind = None
        self.vis = None
        self.ndx = None
        self.name = None

class Elf_Reloc:
    def __init__(self):
        self.relocation = None
        self.offset = None
        self.info = None
        self.type = None
        self.value = None
        self.name = None

# Parse symbols with readelf.
def readelf_parse_symbols(elf_file):

    symbols = list()
    try:
        result = subprocess.check_output(
            [cmd_readelf, '--use-dynamic', '--symbols', '--wide', elf_file])
    except:
        raise Exception("Not able to extract symbols from binary.")

    # Symbol table for image:
    #   Num Buc:    Value          Size   Type   Bind Vis      Ndx Name
    #    83   0: 00000000009cee90    20 FUNC    GLOBAL DEFAULT  12 i2s_ASN1_OCTET_STRING
    header = False
    for line in result.split('\n'):

        # Parse until we found the .dynsym section.
        if line == "":
            continue
        elif line.startswith("Symbol table for image:"):
            header = True
            continue
        elif line.startswith("Symbol table of `.gnu.hash' for image:"):
            header = True
            continue
        if header:
            header = False
            continue

        # Split line and check if we have a conforming length.
        line = line.split()
        if len(line) == 0:
            break
        elif len(line) < 8:
            continue

        # Prase symbol.
        symbol = Elf_Symbol()
        symbol.num = int(line[0], 10)
        symbol.buc = int(line[1].replace(":", ""), 10)
        symbol.value = int(line[2], 16)
        if(line[3].startswith("0x")):
            symbol.size = int(line[3], 16)
        else:
            symbol.size = int(line[3], 10)
        symbol.type = line[4]
        symbol.bind = line[5]
        symbol.vis = line[6]
        symbol.ndx = line[7]
        symbol.name = line[8]
        symbols.append(symbol)
    return symbols


# Prase relocation entries.
def readelf_parse_relocs(elf_file):

    relocs = dict()
    relocs["RELA"] = list()
    relocs["PLT"] = list()
    try:
        result = subprocess.check_output(
            [cmd_readelf, '--use-dynamic', '--relocs', '--wide', elf_file])
    except:
        raise Exception("Not able to extract symbols from binary.")

    # 'RELA' relocation section at offset 0x8fa7a8 contains 83496 bytes:
    #     Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
    # 000000000204eda0  0000000200000006 R_X86_64_GLOB_DAT      0000000000000000 __gmon_start__ + 0
    header = False
    current = None
    for line in result.split('\n'):

        # Parse until we found the RELA or PLT section.
        if line == "":
            continue
        elif line.startswith("'RELA' relocation section at offset"):
            header = True
            current = "RELA"
            continue
        elif line.startswith("'PLT' relocation section at offset"):
            header = True
            current = "PLT"
            continue
        if header:
            header = False
            continue

        # Split line and check if we have a conforming length.
        line = line.split()
        if len(line) < 7:
            continue

        # Prase relocation.
        reloc = Elf_Reloc()
        reloc.relocation = current
        reloc.offset = int(line[0], 16)
        reloc.info = int(line[1], 16)
        reloc.type = line[2]
        reloc.symbol = int(line[3], 16)
        reloc.name = line[4]
        relocs[current].append(reloc)
    
    return relocs


# extracts all relocation entries from the ELF file
# (needed for vtable location heuristics)
def get_relocation_entries_gcc64(elf_file):

    relocs = readelf_parse_relocs(elf_file)
    relocation_entries = set()

    for reloc in relocs["RELA"]:
        relocation_entries.add(reloc.offset)

    for reloc in relocs["PLT"]:
        relocation_entries.add(reloc.offset)

    return relocation_entries


def memory_accessible(addr):
    for segment in segments:
        if SegStart(segment) <= addr < SegEnd(segment):
            return True
    return False


# check the given vtable entry is valid
def check_entry_valid_gcc64(addr, qword):

    # is qword a pointer into the text section?
    ptr_to_text = (text_start <= qword < text_end)

    # is qword a pointer to the extern section?
    ptr_to_extern = (extern_start <= qword < extern_end)

    # is qword a pointer to the plt section?
    ptr_to_plt = (plt_start <= qword < plt_end)

    # is the current entry a relocation entry
    # (means the value is updated during startup)
    # But ignore relocation entries that point to a vtable section
    # (relocated RTTI entries do that).
    is_relocation_entry = ((addr in relocation_entries)
        and not any(map(
        lambda x: SegStart(x) <= qword <= SegEnd(x), vtable_sections)))

    if (ptr_to_text
        or ptr_to_extern
        or ptr_to_plt
        or qword == pure_virtual_addr
        or is_relocation_entry):
        return True
    return False


# returns a dict with key = vtable address and value = set of vtable entries
def get_vtable_entries_gcc64(vtables_offset_to_top):

    vtable_entries = dict()

    # get all vtable entries for each identified vtable
    for vtable_addr in vtables_offset_to_top.keys():

        curr_addr = vtable_addr
        curr_qword = Qword(curr_addr)
        entry_ctr = 0
        vtable_entries[vtable_addr] = list()

        # get all valid entries and add them as vtable entry
        # (ignore the first x zero entries)
        while (check_entry_valid_gcc64(curr_addr, curr_qword)
            or (entry_ctr < vtbl_number_allowed_zero_entries and curr_qword == 0)):

            vtable_entries[vtable_addr].append(curr_qword)

            curr_addr += 8
            entry_ctr += 1
            curr_qword = Qword(curr_addr)

    return vtable_entries


# returns a dict with key = vtable address and value = offset to top
def get_vtables_gcc64():

    vtables_offset_to_top = dict()

    # is it preceded by a valid offset to top and rtti entry?
    # heuristic value for offset to top taken from vfguard paper
    def check_rtti_and_offset_to_top(rtti_candidate, ott_candidate, addr):
        ott_addr = addr - 16
        offset_to_top = ctypes.c_longlong(ott_candidate).value
        ott_valid = (-0xFFFFFF <= offset_to_top and offset_to_top <= 0xffffff)
        rtti_valid = (rtti_candidate == 0
            or (not text_start <= rtti_candidate < text_end
            and memory_accessible(rtti_candidate)))

        # offset to top can not be a relocation entry
        # (RTTI on the other hand can be a relocation entry)
        # => probably a vtable beginning
        ott_no_rel = (not ott_addr in relocation_entries)

        if ott_valid and rtti_valid and ott_no_rel:
            return True
        return False


    for vtable_section in vtable_sections:
        i = SegStart(vtable_section)
        qword = 0
        prevqword = 0

        while i <= SegEnd(vtable_section) - 8:

            pprevqword = prevqword
            prevqword = qword
            qword = Qword(i)

            # heuristic that we also find vtables that have a zero
            # entry as first entry (libxul.so has some of them which
            # are not abstract classes, so we have to find them)
            is_zero_entry = (qword == 0)

            # Could entry be a valid vtable entry?
            if check_entry_valid_gcc64(i, qword):

                # is it preceded by a valid offset to top and rtti entry?
                if check_rtti_and_offset_to_top(prevqword, pprevqword, i):

                    # extract offset to top value for this vtable
                    offset_to_top = ctypes.c_longlong(pprevqword).value
                    vtables_offset_to_top[i] = offset_to_top

                # skip succeeding function pointers of the vtable
                while (check_entry_valid_gcc64(i, qword)
                    and i < (SegEnd(vtable_section) - 8)):

                    i += 8
                    prevqword = qword
                    qword = Qword(i)

            # Allow the first x vtable entries to be a zero entry
            # and check if it is preceded by a valid
            # offset to top and RTTI entry
            elif (is_zero_entry
                and (i-16) >= SegStart(vtable_section)
                and check_rtti_and_offset_to_top(prevqword, pprevqword, i)):

                for j in range(1, vtbl_number_allowed_zero_entries+1):

                    if (i+(j*8)) <= (SegEnd(vtable_section)-8):

                        nextqword = Qword(i+(j*8))

                        # skip if next entry is a zero entry
                        if nextqword == 0:
                            continue

                        # if entry is a valid vtable entry add it
                        if check_entry_valid_gcc64(i+(j*8), nextqword):

                            # extract offset to top value for this vtable
                            offset_to_top = ctypes.c_longlong(pprevqword).value
                            vtables_offset_to_top[i] = offset_to_top
                            break

                        # do not check further if it is an invalid vtable entry
                        else:
                            break

                    # break if we would check outside of the section
                    else:
                        break

            i += 8

    # Heuristic to filter out vtable candidates (like wrong candidates
    # because of the allowed 0 entries in the beginning):
    # If vtable + 8 or vtable + 16 is also considered a vtable,
    # check if they have Xrefs => remove candidates if they do not have Xrefs.
    # Same goes for wrongly detected vtables that reside before the actual
    # vtable.
    for vtable in list(vtables_offset_to_top.keys()):
        for i in range(1, vtbl_number_allowed_zero_entries+1):
            if (vtable + i*8) in vtables_offset_to_top.keys():

                if not list(XrefsTo(vtable + i*8)):
                    if (vtable + i*8) in vtables_offset_to_top.keys():
                        del vtables_offset_to_top[(vtable + i*8)]
                    continue

                if not list(XrefsTo(vtable)):
                    if vtable in vtables_offset_to_top.keys():
                        del vtables_offset_to_top[vtable]
                    continue

    return vtables_offset_to_top


# Searches all vtables that reside as a copy relocation in the .bss section.
# Returns a dict with key = vtable address and value = symbol dict.
def get_bss_vtables_gcc64(elf_file):

    vtables_bss = dict()

    symbols = readelf_parse_symbols(elf_file)

    # Create dicts using name and value as key.
    symbols_value_dict = defaultdict(list)
    symbols_name_dict = defaultdict(list)
    for symbol in symbols:
        symbols_value_dict[symbol.value].append(symbol)
        symbols_name_dict[symbol.name].append(symbol)

    # Tuple looks like this: (6894776L, '.init_proc')
    for name_tuple in Names():
        addr = name_tuple[0]
        name = name_tuple[1]

        # Check if the address resides in the .bss section.
        if bss_start <= addr <= bss_end:

            # Vtable symbol starts with "_ZTV"
            if "_ZTV" in name:

                found = False
                # IDA symbol contains double "@@" instead of "@", i.e.,
                # _ZTVSt9basic_iosIcSt11char_traitsIcEE@@GLIBCXX_3.4
                # instead of
                # _ZTVSt9basic_iosIcSt11char_traitsIcEE@GLIBCXX_3.4
                modified_name = name.replace("@@", "@")
                if modified_name in symbols_name_dict.keys():
                    found = True
                    sym_list = symbols_name_dict[modified_name]
                    if len(sym_list) == 1:
                        symbol = sym_list[0]

                        # Since a copy relocation just copies the plain
                        # data from the shared object to the .bss section,
                        # it does not contain any information about
                        # sub-vtables. Therefore, we have to assume that
                        # at each entry a new sub-vtable begins.
                        for i in range(16, symbol.size, 8):
                            vtables_bss[addr + i] = {"name": symbol.name,
                                                     "size": symbol.size - i,
                                                     "offset": i - 16}

                    # We have no unique result for the name, try searching
                    # by value.
                    else:
                        found = False

                # Search symbol by value if we have not found it by name.
                if not found and addr in symbols_value_dict.keys():
                    found = True
                    sym_list = symbols_value_dict[addr]
                    if len(sym_list) == 1:
                        symbol = sym_list[0]

                        # Since a copy relocation just copies the plain
                        # data from the shared object to the .bss section,
                        # it does not contain any information about
                        # sub-vtables. Therefore, we have to assume that
                        # at each entry a new sub-vtable begins.
                        for i in range(16, symbol.size, 8):
                            vtables_bss[addr + i] = {"name": symbol.name,
                                                     "size": symbol.size - i,
                                                     "offset": i - 16}

                    # We have no unique result for the value, skip searching.
                    else:
                        found = False

                if not found:
                    print("Not able to find symbol with name '%s' "
                          % name
                          + "and address '0x%x"
                          % addr)

    return vtables_bss


# Searches all vtables that reside as a relocation in the .got section.
# Returns a dict with key = vtable address and value = symbol name.
def get_got_relocs_vtables_gcc64(elf_file):

    vtables_got_relocs = dict()

    relocs = readelf_parse_relocs(elf_file)

    for reloc in relocs["RELA"]:
        if reloc.name.startswith("_ZTV"):
            addr = reloc.offset

            if got_start <= addr <= got_end:
                vtables_got_relocs[addr] = reloc.name

    return vtables_got_relocs


# Search every instance of the internally found vtables that reside in the GOT.
def get_got_vtables_gcc64(vtables_offset_to_top):
    vtables_got = dict()

    for vtable_addr in vtables_offset_to_top.keys():
        vtable_meta_addr = vtable_addr - 16

        # Get xref from the metadata begin of the vtable, check if
        # xref resides in GOT => we found an internal vtable in the GOT.
        for xref_obj in XrefsTo(vtable_meta_addr, 0):
            if xref_obj.type == IDA_XrefTypes.Data_Offset:
                if got_start <= xref_obj.frm <= got_end:
                    vtables_got[xref_obj.frm] = vtable_addr

    return vtables_got
        

# check the given vtable entry is valid
def check_entry_valid_msvc64(addr, qword):

    # is qword a pointer into the text section?
    ptr_to_text = (text_start <= qword < text_end)

    if (ptr_to_text
        or qword == pure_virtual_addr):
        return True
    return False


# TODO: function only works if RTTI is enabled in windows binary.
def get_vtables_msvc64():

    vtables_offset_to_top = dict()

    # is it preceded by a valid rtti entry?
    def check_rtti_and_offset_to_top(rtti_candidate, addr):

        # rtti pointer points to this structure
        #
        # http://blog.quarkslab.com/visual-c-rtti-inspection.html
        #typedef const struct _s__RTTICompleteObjectLocator {
        #  unsigned long signature;
        #  unsigned long offset;
        #  unsigned long cdOffset;
        #  _TypeDescriptor *pTypeDescriptor;
        #  __RTTIClassHierarchyDescriptor *pClassDescriptor;
        #} __RTTICompleteObjectLocator;

        rtti_pointer_valid = False
        for vtable_section in vtable_sections:
            if (SegStart(vtable_section)
                <= rtti_candidate
                < SegEnd(vtable_section)):

                rtti_pointer_valid = True
                break

        ott_valid = False
        try:
            ott_candidate = Dword(rtti_candidate + 4)
            offset_to_top = ctypes.c_ulong(ott_candidate).value
            ott_valid = offset_to_top <= 0xffffff
        except:
            pass

        rtti_valid = (not text_start <= rtti_candidate < text_end
            and rtti_pointer_valid)

        if rtti_valid and ott_valid:
            return True
        return False


    for vtable_section in vtable_sections:
        i = SegStart(vtable_section)
        qword = 0
        prevqword = 0

        while i <= SegEnd(vtable_section) - 8:

            pprevqword = prevqword
            prevqword = qword
            qword = Qword(i)

            # Could entry be a valid vtable entry?
            if check_entry_valid_msvc64(i, qword):

                # is it preceded by a valid offset to top and rtti entry?
                if check_rtti_and_offset_to_top(prevqword, i):

                    ott_candidate = Dword(prevqword + 4)
                    # Offset To Top is stored as a positive value and not
                    # as negative one like gcc does
                    # => we assume negative values.
                    vtables_offset_to_top[i] = \
                        ctypes.c_ulong(ott_candidate).value * (-1)

                # skip succeeding function pointers of the vtable
                while (check_entry_valid_msvc64(i, qword)
                    and i < (SegEnd(vtable_section) - 8)):

                    i += 8
                    prevqword = qword
                    qword = Qword(i)

            i += 8

    return vtables_offset_to_top


# returns a dict with key = vtable address and value = set of vtable entries
def get_vtable_entries_msvc64(vtables_offset_to_top):

    vtable_entries = dict()

    # get all vtable entries for each identified vtable
    for vtable_addr in vtables_offset_to_top.keys():

        curr_addr = vtable_addr
        curr_qword = Qword(curr_addr)
        entry_ctr = 0
        vtable_entries[vtable_addr] = list()

        # get all valid entries and add them as vtable entry
        while check_entry_valid_msvc64(curr_addr, curr_qword):

            vtable_entries[vtable_addr].append(curr_qword)

            curr_addr += 8
            entry_ctr += 1
            curr_qword = Qword(curr_addr)

    return vtable_entries


def process_function(function):
    dump = pack('<I', function - base)
    flow = FlowChart(get_func(function))
    assert len(dump) == 4

    block_dump, block_count = '', 0
    for block in flow:
        block_start = block.startEA
        block_end = block.endEA

        if plt_start <= block_start < plt_end:
            continue

        address, instruction_count = block_start, 0
        while address != BADADDR and address < block_end:
            instruction_count += 1
            address = NextHead(address)

        block_dump += pack('<I', block_start - base)
        block_dump += pack('<I', block_end - block_start)
        block_dump += pack('<H', instruction_count)

        block_count += 1

    dump += pack('<H', block_count)
    dump += block_dump
    return dump


def main():

    # Windows does only work if the image base is set to 0x0.
    if is_windows and get_imagebase() != 0x0:
        print "Image base has to be 0x0."
        return

    global plt_start, plt_end, segments
    dump = pack('<Q', base)
    assert len(dump) == 8

    for segment in segments:
        if SegName(segment) == '.plt':
            plt_start = SegStart(segment)
            plt_end = SegEnd(segment)
            break

    functions_dump = ''
    function_count = 0

    funcs = set()
    for segment in segments:
        permissions = getseg(segment).perm
        if not permissions & SEGPERM_EXEC:
            continue

        if SegStart(segment) == plt_start:
            continue

        print('\nProcessing segment %s.' % SegName(segment))
        for i, function in enumerate(Functions(SegStart(segment),
            SegEnd(segment))):

            funcs.add(function)
            functions_dump += process_function(function)
            function_count += 1

            if i & (0x100 - 1) == 0 and i > 0:
                print('Function %d.' % i)

    packed_function_count = pack('<I', function_count)
    assert len(packed_function_count) == 4

    dump += packed_function_count
    dump += functions_dump

    with open(GetInputFile() + '.dmp', 'w') as f:
        f.write(dump)

    print('\nExported %d functions.' % function_count)

    # Export function names.
    counter = 0
    with open(GetInputFile() + '_funcs.txt', 'w') as f:

        # Write Module name to file.
        # NOTE: We consider the file name == module name.
        f.write("%s\n" % GetInputFile())

        for func in funcs:
            # Ignore functions that do not have a name.
            func_name = GetFunctionName(func)
            if not func_name:
                continue

            f.write("%x %s\n" % (func, func_name))
            counter += 1

    print('\nExported %d function names.' % counter)

    # Export function blacklist.
    counter = 0
    with open(GetInputFile() + '_funcs_blacklist.txt', 'w') as f:

        # Write Module name to file.
        # NOTE: We consider the file name == module name.
        f.write("%s\n" % GetInputFile())

        # Blacklist pure virtual function.
        if pure_virtual_addr:
            f.write("%x\n" % pure_virtual_addr)

        # TODO
        # Write logic that creates addresses of blacklisted functions.
        # (needed for Windows binaries)

    print('\nExported %d function blacklist.' % counter)

    # Export vtables.
    if dump_vtables:

        vtables_bss = dict()
        vtables_got_relocs = dict()
        if is_linux:
            vtables_offset_to_top = get_vtables_gcc64()
            vtable_entries = get_vtable_entries_gcc64(vtables_offset_to_top)
            vtables_bss = get_bss_vtables_gcc64(GetInputFilePath())
            vtables_got_relocs = get_got_relocs_vtables_gcc64(
                                                            GetInputFilePath())
            vtables_got = get_got_vtables_gcc64(vtables_offset_to_top)

        elif is_windows:
            vtables_offset_to_top = get_vtables_msvc64()
            vtable_entries = get_vtable_entries_msvc64(vtables_offset_to_top)

        else:
            raise Exception("Do not know underlying architecture.")

        with open(GetInputFile() + '_vtables.txt', 'w') as f:

            # Write Module name to file.
            # NOTE: We consider the file name == module name.
            f.write("%s\n" % GetInputFile())

            vtable_ctr = 0

            for k in vtables_offset_to_top:
                f.write("%x %d" % (k, vtables_offset_to_top[k]))

                # write vtable entries in the correct order
                for vtbl_entry in vtable_entries[k]:
                    f.write(" %x" % vtbl_entry)

                f.write("\n")
                vtable_ctr += 1

            # Export also vtables residing in the .bss section.
            for vtable_addr, symbol_dict in vtables_bss.iteritems():
                f.write("%x bss %d %d %s\n" % (vtable_addr,
                                               symbol_dict["offset"],
                                               symbol_dict["size"],
                                               symbol_dict["name"]))
                vtable_ctr += 1

            for vtable_addr, symbol_name in vtables_got_relocs.iteritems():
                f.write("%x got_reloc %s\n" % (vtable_addr, symbol_name))
                vtable_ctr += 1

            for vtable_got_addr, vtable_addr in vtables_got.iteritems():
                f.write("%x got %x\n" % (vtable_got_addr, vtable_addr))
                vtable_ctr += 1

        print('\nExported %d vtables.' % vtable_ctr)

    # Export .plt entries.
    if dump_vtables and is_linux:
        counter = 0
        with open(GetInputFile() + '_plt.txt', 'w') as f:

            # Write Module name to file.
            # NOTE: We consider the file name == module name.
            f.write("%s\n" % GetInputFile())

            for i, function in enumerate(Functions(plt_start, plt_end)):

                # Ignore functions that do not have a name.
                func_name = GetFunctionName(function)
                if not func_name:
                    continue

                # Names of .plt function start with an ".". Remove it.
                f.write("%x %s\n" % (function, func_name[1:]))
                counter += 1
        print('\nExported %d .plt entries.' % counter)

    # Export .got entries.
    if dump_vtables and is_linux:
        counter = 0
        with open(GetInputFile() + '_got.txt', 'w') as f:

            # Write Module name to file.
            # NOTE: We consider the file name == module name.
            f.write("%s\n" % GetInputFile())

            curr_addr = got_start
            while curr_addr <= got_end:
                f.write("%x %x\n" % (curr_addr, Qword(curr_addr)))
                curr_addr += 8
                counter += 1
        print('\nExported %d .got entries.' % counter)

    # Export .idata entries.
    if dump_vtables and is_windows:
        counter = 0
        with open(GetInputFile() + '_idata.txt', 'w') as f:

            # Write Module name to file.
            # NOTE: We consider the file name == module name.
            f.write("%s\n" % GetInputFile())

            addr = idata_start
            while addr <= idata_end:

                # Ignore imports that do not have a name.
                import_name = Name(addr)
                if not import_name:
                    addr += 8
                    continue

                f.write("%x %s\n" % (addr, import_name))
                counter += 1
                addr += 8

        print('\nExported %d .idata entries.' % counter)


info = get_inf_structure()
if not info.is_64bit():
    raise Exception("Only 64 bit architecture is supported.")

if info.ostype == idc.OSTYPE_WIN and info.filetype == 11:
    is_windows = True
    is_linux = False
elif info.ostype == 0 and info.filetype == 18:
    is_windows = False
    is_linux = True
else:
    raise Exception("OS type not supported.")

# global variables that are needed for multiple C++ algorithms
if dump_vtables:
    extern_seg = None
    extern_start = 0
    extern_end = 0
    text_seg = None
    text_start = 0
    text_end = 0
    plt_seg = None
    plt_start = 0
    plt_end = 0
    got_seg = None
    got_start = 0
    got_end = 0
    idata_seg = None
    idata_start = 0
    idata_end = 0
    bss_seg = None
    bss_start = 0
    bss_end = 0
    vtable_sections = list()
    for segment in segments:
        if SegName(segment) == "extern":
            extern_seg = segment
            extern_start = SegStart(extern_seg)
            extern_end = SegEnd(extern_seg)
        elif SegName(segment) == ".text":
            text_seg = segment
            text_start = SegStart(text_seg)
            text_end = SegEnd(text_seg)
        elif SegName(segment) == ".plt":
            plt_seg = segment
            plt_start = SegStart(plt_seg)
            plt_end = SegEnd(plt_seg)
        elif SegName(segment) == ".got":
            got_seg = segment
            got_start = SegStart(got_seg)
            got_end = SegEnd(got_seg)
        elif SegName(segment) == ".idata":
            idata_seg = segment
            idata_start = SegStart(idata_seg)
            idata_end = SegEnd(idata_seg)
        elif SegName(segment) == ".bss":
            bss_seg = segment
            bss_start = SegStart(bss_seg)
            bss_end = SegEnd(bss_seg)
        elif SegName(segment) in vtable_section_names:
            vtable_sections.append(segment)

    if is_linux:
        relocation_entries = get_relocation_entries_gcc64(GetInputFilePath())
    else:
        relocation_entries = set()

if __name__ == '__main__':
    if pure_virtual_addr:
        print("pure_virtual function at 0x%x" % pure_virtual_addr)
    main()