import idc
import idautils
import idaapi

import __builtin__
import time
import pickle
import os

from lib.shovel.cfg import Function
import lib.shovel.arch.meta
from lib.shovel.arch import RegistersTricore, RegistersX64
from export.ssa_export import export_ssa_functions

from marx.export import main as marx_export


# Set used architecture.
#__builtin__.REGISTERS = RegistersTricore()
__builtin__.REGISTERS = RegistersX64()

# Remove vtables that do not have xrefs.
vtbl_remove_without_xrefs = False

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


# Checks if a vtable has a xref to the got.
def has_got_xref(vtables_got, vtable_addr):
    return any(vtables_got[k] == vtable_addr for k in vtables_got.keys())

# Removes the renaming of all registers.
def remove_regvars(func_addr):
    func = idaapi.get_func(func_addr)

    # Store register renaming.
    addr = func.startEA
    regvars = set()
    while addr <= func.endEA:
        for reg_str in __builtin__.REGISTERS._to_idx.keys():
            regvar = idaapi.find_regvar(func, addr, reg_str)
            if regvar is not None:

                regvars.add((reg_str,
                             regvar.user,
                             regvar.cmt,
                             regvar.startEA,
                             regvar.endEA))
        addr += 1

    # Since IDA places two not connected CFGs sometimes in the same
    # functions (multiple entry basic blocks), we have to go
    # through all basic blocks also.
    ida_blocks = list(idaapi.FlowChart(func))
    for b in ida_blocks:

        addr = b.startEA
        block_end = b.endEA
        while addr != BADADDR and addr < block_end:

            for reg_str in __builtin__.REGISTERS._to_idx.keys():

                regvar = idaapi.find_regvar(func, addr, reg_str)

                if regvar is not None:

                    regvars.add((reg_str,
                                 regvar.user,
                                 regvar.cmt,
                                 regvar.startEA,
                                 regvar.endEA))
            addr = NextHead(addr)


    # Remove register renaming.
    for regvar in regvars:
        idaapi.del_regvar(func,
                          regvar[3], # startEA
                          regvar[4], # endEA
                          regvar[0]) # register string

    return regvars


# Restores all removed register renamings.
def restore_regvars(func_addr, regvars):
    func = idaapi.get_func(func_addr)
    for regvar in regvars:
        idaapi.add_regvar(func,
                          regvar[3], # startEA
                          regvar[4], # endEA
                          regvar[0], # register string
                          regvar[1], # user register string
                          regvar[2]) # comment


# Creates a preliminary configuration file.
def create_config():

    # Searches all new operators that are imported via the plt.
    def get_new_operators():
        newoperators = set()
        for i, func_addr in enumerate(idautils.Functions(plt_start, plt_end)):
            demangled_name = idc.Demangle(idc.Name(func_addr), 0)
            if demangled_name is not None and "operator new" in demangled_name:
                newoperators.add(func_addr)
        return newoperators

    cfg_module_name = idc.GetInputFile()
    cfg_target_dir = os.path.dirname(GetInputFilePath()) + "/"
    cfg_format = "ELF64"
    cfg_newoperators = get_new_operators()
    cfg_externalmodules = set()
    cfg_numthreads = 8
    cfg_vtvverify = set()

    print("Writing config.cfg file.")
    with open(cfg_target_dir + "/config.cfg", 'w') as fp:
        fp.write("MODULENAME " + cfg_module_name + "\n")
        fp.write("TARGETDIR " + cfg_target_dir + "\n")
        fp.write("FORMAT " + cfg_format + "\n")

        fp.write("NEWOPERATORS %d" % len(cfg_newoperators))
        for temp in cfg_newoperators:
            fp.write(" %x" % temp)
        fp.write("\n")

        fp.write("EXTERNALMODULES %d" % len(cfg_externalmodules))
        for temp in cfg_externalmodules:
            fp.write(" %x" % temp)
        fp.write("\n")

        fp.write("NUMTHREADS %d\n" % cfg_numthreads)

        fp.write("VTVVERIFY %d" % len(cfg_vtvverify))
        for temp in cfg_vtvverify:
            fp.write(" %x" % temp)
        fp.write("\n")


# Triple recursion limit.
sys.setrecursionlimit(3*sys.getrecursionlimit())

plt_seg = None
plt_start = 0
plt_end = 0
segments = list(idautils.Segments())
exec_segments = list()
for segment in segments:
    if idc.SegName(segment) == ".plt":
        plt_seg = segment
        plt_start = idc.SegStart(plt_seg)
        plt_end = idc.SegEnd(plt_seg)

    permissions = idaapi.getseg(segment).perm
    if permissions & idaapi.SEGPERM_EXEC:
        exec_segments.append(segment)

allowed_xref_types = [IDA_XrefTypes.Code_Far_Call,
                      IDA_XrefTypes.Code_Near_Call,
                      IDA_XrefTypes.Code_Far_Jump,
                      IDA_XrefTypes.Code_Near_Jump,
                      IDA_XrefTypes.Data_Offset]

start_time = time.time()

# Import existing ssa file if exists in order to be able to process idb
# in multiple steps.
export_ssa_file = idc.GetInputFile() + "_ssa.pb2"
export_ssa_dict = dict()

export_xref_dict = dict()

export_icalls_set = set()

file_counter = 0

# Starting exporting script of Marx
print("Starting Marx export.")
marx_export()
create_config()

# Load vtables.
input_vtables = idc.GetInputFile() + "_vtables.txt"
vtables_xrefs = dict()
vtables_set = set()
vtables_0x10_set = set()
vtables_0x18_set = set()
vtables_0x20_set = set()
vtables_got = dict()
vtables_file_entry = dict()
with open(input_vtables, 'r') as f:
    first = True
    for line in f:
        # Skip first line.
        if first:
            first = False
            continue

        temp = line.split()
        vtable_addr = int(temp[0], 16)
        vtables_xrefs[vtable_addr] = {0: set(),
                                      -0x10: set(),
                                      -0x18: set(),
                                      -0x20: set()}
        vtables_set.add(vtable_addr)

        # Vtables from the .got can only have direct xrefs.
        if temp[1] != "got" and temp[1] != "got_reloc":
            vtables_0x10_set.add(vtable_addr - 0x10)
            vtables_0x18_set.add(vtable_addr - 0x18)
            vtables_0x20_set.add(vtable_addr - 0x20)

        # Load also the whole file entry in order to remove it
        # if activated.
        vtables_file_entry[vtable_addr] = list()
        for element in temp:
            vtables_file_entry[vtable_addr].append(element)

        # Load vtables from the got since they have a xref to
        # existing vtables (so we do not remove the vtables
        # that are referenced via the got).
        if temp[1] == "got":
            vtables_got[vtable_addr] = int(temp[2], 16)

# Remove all regvars before starting the analysis.
for i, func_addr in enumerate(idautils.Functions()):
    print("Removing regvars for 0x%x" % func_addr)
    regvars = remove_regvars(func_addr)
    #print("Restoring regvars for 0x%x" % func_addr)
    #restore_regvars(func_addr, regvars)

for segment in exec_segments:

    if idc.SegStart(segment) == plt_start:
        continue

    start_ea = idc.SegStart(segment)
    end_ea = idc.SegEnd(segment)

    print('\nProcessing segment %s.' % idc.SegName(segment))

    for i, func_addr in enumerate(idautils.Functions(start_ea, end_ea)):

        print("Building CFG for 0x%x" % func_addr)
        func = Function(func_addr)

        print("Building SSA for 0x%x" % func_addr)
        func.transform()

        # DEBUG
        func.comment()
        print("")

        temp = list()
        for xref_obj in idautils.XrefsTo(func_addr, 0):
            if xref_obj.type not in allowed_xref_types:
                continue
            temp.append(xref_obj.frm)

        export_xref_dict[func_addr] = temp
        export_ssa_dict[func_addr] = func

        # Export every 150 functions in order to compensate memory problems.
        if len(export_ssa_dict) % 150 == 0:
            current_file = export_ssa_file + "_part%d" % file_counter
            print("Exporting to %s" % current_file)
            export_ssa_functions(__builtin__.REGISTERS,
                                 export_ssa_dict,
                                 current_file)
            file_counter += 1

            # Empty dictionary because of memory problems in IDA 32 bit python.
            export_ssa_dict = dict()

    # Manually search through the executable segment.
    for ea in idautils.Heads(start_ea, end_ea):

        if not idc.isCode(idc.GetFlags(ea)):
            continue

        # Get icall addrs.
        # Return values of GetOpType
        # https://www.hex-rays.com/products/ida/support/idadoc/276.shtml
        if (GetMnem(ea).startswith("call")
            and GetOpType(ea, 0) >= 1
            and GetOpType(ea, 0) <= 4):
            export_icalls_set.add(ea)

        # Search for vtable assignments.
        for o in range(1, 6):
            op_value = idc.GetOperandValue(ea, o)
            if op_value == 0:
                continue
            elif op_value == -1:
                break
            elif op_value in vtables_set:
                vtables_xrefs[op_value][0].add(ea)

            # For example, Mongodb on Linux (g++ and clang++)
            # does not write the vtable ptr directly but 
            # moves the address to the vtable metadata
            # (vtable ptr - 0x10) into a register and adds 0x10
            # before writing it into the object.
            elif op_value in vtables_0x10_set:
                vtables_xrefs[op_value + 0x10][-0x10].add(ea)

            # For example, Mysqld on Linux uses virtual
            # inheritance which adds a so called vbase offset
            # to the metadata field. Hence, if the vtable is not
            # referenced directly, we have to check also for this case.
            elif op_value in vtables_0x18_set:
                vtables_xrefs[op_value + 0x18][-0x18].add(ea)

            # For example, Mysqld on Linux uses virtual
            # inheritance which adds a so called vbase offset
            # to the metadata field. However, some vtables are
            # also referenced by assuming an additional field.
            # I do not know why.
            elif op_value in vtables_0x20_set:
                vtables_xrefs[op_value + 0x20][-0x20].add(ea)

# Final export of ssa.
if export_ssa_dict:
    current_file = export_ssa_file + "_part%d" % file_counter
    print("Exporting to %s" % current_file)
    export_ssa_functions(__builtin__.REGISTERS,
                         export_ssa_dict,
                         current_file)

# Final export function xref.
if export_xref_dict:
    current_file = idc.GetInputFile() + '_funcs_xrefs.txt'
    print("Exporting function xrefs to %s" % current_file)
    with open(current_file, 'w') as f:
        # Write Module name to file.
        # NOTE: We consider the file name == module name.
        f.write("%s\n" % idc.GetInputFile())
        for k, v in export_xref_dict.iteritems():
            f.write("%x" % k)
            for xref_addr in v:
                f.write(" %x" % xref_addr)
            f.write("\n")

# Get all xrefs of vtables.
current_file = idc.GetInputFile() + '_vtables_xrefs.txt'
print("Exporting vtable xrefs to %s" % current_file)
for vtable_addr in vtables_set:
    for xref_obj in idautils.XrefsTo(vtable_addr, 0):
        if (xref_obj.type == IDA_XrefTypes.Data_Offset
            or xref_obj.type == IDA_XrefTypes.Data_Read):

            # We are only interested in xrefs that reside in the
            # executable segments.
            for segment in exec_segments:
                if (idc.SegStart(segment)
                    <= xref_obj.frm
                    <= idc.SegEnd(segment)):

                    vtables_xrefs[vtable_addr][0].add(xref_obj.frm)

for vtable_addr in vtables_0x10_set:
    # For example, Mongodb on Linux (g++ and clang++)
    # does not write the vtable ptr directly but 
    # moves the address to the vtable metadata
    # (vtable ptr - 0x10) into a register and adds 0x10
    # before writing it into the object.
    for xref_obj in idautils.XrefsTo(vtable_addr, 0):
        if (xref_obj.type == IDA_XrefTypes.Data_Offset
            or xref_obj.type == IDA_XrefTypes.Data_Read):

            # We are only interested in xrefs that reside in the
            # executable segments.
            for segment in exec_segments:
                if (idc.SegStart(segment)
                    <= xref_obj.frm
                    <= idc.SegEnd(segment)):

                    vtables_xrefs[vtable_addr + 0x10][-0x10].add(xref_obj.frm)

for vtable_addr in vtables_0x18_set:
    # For example, Mysqld on Linux uses virtual
    # inheritance which adds a so called vbase offset
    # to the metadata field. Hence, if the vtable is not
    # referenced directly, we have to check also for this case.
    for xref_obj in idautils.XrefsTo(vtable_addr, 0):
        if (xref_obj.type == IDA_XrefTypes.Data_Offset
            or xref_obj.type == IDA_XrefTypes.Data_Read):

            # We are only interested in xrefs that reside in the
            # executable segments.
            for segment in exec_segments:
                if (idc.SegStart(segment)
                    <= xref_obj.frm
                    <= idc.SegEnd(segment)):

                    vtables_xrefs[vtable_addr + 0x18][-0x18].add(xref_obj.frm)

for vtable_addr in vtables_0x20_set:
    # For example, Mysqld on Linux uses virtual
    # inheritance which adds a so called vbase offset
    # to the metadata field. However, some vtables are
    # also referenced by assuming an additional field.
    # I do not know why.
    for xref_obj in idautils.XrefsTo(vtable_addr, 0):
        if (xref_obj.type == IDA_XrefTypes.Data_Offset
            or xref_obj.type == IDA_XrefTypes.Data_Read):

            # We are only interested in xrefs that reside in the
            # executable segments.
            for segment in exec_segments:
                if (idc.SegStart(segment)
                    <= xref_obj.frm
                    <= idc.SegEnd(segment)):

                    vtables_xrefs[vtable_addr + 0x20][-0x20].add(xref_obj.frm)

# Remove vtables without xrefs if activated.
if vtbl_remove_without_xrefs:
    to_remove = set()
    for vtable_addr in vtables_xrefs.keys():
        if (not vtables_xrefs[vtable_addr][0]
            and not vtables_xrefs[vtable_addr][-0x10]
            and not vtables_xrefs[vtable_addr][-0x18]
            and not vtables_xrefs[vtable_addr][-0x20]
            and not has_got_xref(vtables_got, vtable_addr)):

            to_remove.add(vtable_addr)
    for vtable_addr in to_remove:
        del vtables_xrefs[vtable_addr]
        del vtables_file_entry[vtable_addr]
        try:
            vtables_set.remove(vtable_addr)
        except:
            pass
        try:
            vtables_0x10_set.remove(vtable_addr)
        except:
            pass
        try:
            vtables_0x18_set.remove(vtable_addr)
        except:
            pass
        try:
            vtables_0x20_set.remove(vtable_addr)
        except:
            pass
        try:
            del vtables_got[vtable_addr]
        except:
            pass

# Export vtable xrefs.
with open(current_file, 'w') as f:

    # Write Module name to file.
    # NOTE: We consider the file name == module name.
    f.write("%s\n" % idc.GetInputFile())

    for vtable_addr in vtables_xrefs.keys():
        f.write("%x" % vtable_addr)
        for offset, xref_addrs_set in vtables_xrefs[vtable_addr].iteritems():
            for xref_addr in xref_addrs_set:
                f.write(" %x %d" % (xref_addr, offset))
        f.write("\n")

# Export icall addrs.
with open(idc.GetInputFile() + '_icalls.txt', 'w') as f:

    # Write Module name to file.
    # NOTE: We consider the file name == module name.
    f.write("%s\n" % idc.GetInputFile())

    for icall_addr in export_icalls_set:
        f.write("%x\n" % icall_addr)

# Rewrite vtables file if it is activated.
if vtbl_remove_without_xrefs:
    current_file = idc.GetInputFile() + "_vtables.txt"

    with open(current_file, 'w') as f:
        # Write Module name to file.
        # NOTE: We consider the file name == module name.
        f.write("%s\n" % idc.GetInputFile())

        for _, vtable_file_entry in vtables_file_entry.iteritems():
            f.write("%s\n" % " ".join(vtable_file_entry))

print("Finished in %.2f seconds." % (time.time() - start_time))