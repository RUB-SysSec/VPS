
from idc import NextNotTail, PrevHead, NextHead, GetMnem, isCode, GetFlags, GetOpnd, BADADDR
from idaapi import FlowChart, get_func, o_void, is_ret_insn
from idautils import CodeRefsFrom, DecodeInstruction

from copy import deepcopy

from .. import block, operands, instruction
from ..operands import AccessType

from ida_interface import *

from ..arch import RegistersTricore, RegistersX64
import __builtin__


__all__ = ['decode_function']


def normalize_access(operand):
    ops = []

    if operand.access == AccessType.ReadWrite:
        target = deepcopy(operand)
        target._access = AccessType.Write
        ops.append(target)

        operand._access = AccessType.Read
        ops.append(operand)
    else:
        ops.append(operand)

    return ops


def normalize_operand(operand):
    ops = []
    if isinstance(__builtin__.REGISTERS, RegistersTricore):
        ops = tricore_normalize_extended_registers(operand)
    else:
        ops.append(operand)
    return [x for o in ops for x in normalize_access(o)]


def tricore_normalize_extended_registers(operand):
    ops = []

    if isinstance(operand.operand, operands.Register) and \
            __builtin__.REGISTERS.e0 <= operand.operand.index and \
            operand.operand.index <= __builtin__.REGISTERS.e14:
        data_lo = ((operand.operand.index - __builtin__.REGISTERS.e0) *
            2 + __builtin__.REGISTERS.d0)
        data_hi = data_lo + 1

        hi = deepcopy(operand)
        hi.operand._index = data_hi
        ops.append(hi)

        lo = deepcopy(operand)
        lo.operand._index = data_lo
        ops.append(lo)

    else:
        ops.append(operand)

    return ops


def decode_instruction(address):

    # DEBUG
    #print("Decoding instruction: 0x%x" % address)

    i = DecodeInstruction(address)

    mnemonic = i.get_canon_mnem()
    ops = []

    ignore_ops = False
    if isinstance(__builtin__.REGISTERS, RegistersX64):
        # uses floating point register "st" which has
        # overlapping index with "rax" and so on
        ignore_ops = mnemonic in ["fabs,", "fadd", "faddp", "fbld", "fbstp",
            "fchs", "fclex", "fcmov", "fcmovb", "fcmovbe", "fcmove", "fcmovnb",
            "fcmovnbe", "fcmovne", "fcmovnu", "fcmovu", "fcom", "fcomi",
            "fcomip", "fcomp", "fcompp", "fdecstp", "fdiv", "fdivp",
            "fdivr", "fdivrp", "ffree", "fiadd", "ficom", "ficomp",
            "fidiv", "fidivr", "fild", "fimul", "fincstp", "finit", "fist",
            "fistp", "fisub", "fisubr", "fld," "fld1", "fldcw", "fldenv",
            "fldenvw", "fldl2e", "fldl2t", "fldlg2", "fldln2", "fldpi",
            "fldz", "fmul", "fmulp", "fnclex", "fndisi", "fneni", "fninit",
            "fnop", "fnsave", "fnsavew", "fnstcw", "fnstenv", "fnstenvw",
            "fnstsw", "fpatan", "fprem", "fptan", "frndint", "frstor",
            "frstorw", "fsave", "fsavew", "fscale", "fsqrt", "fst",
            "fstcw", "fstenv", "fstenvw", "fstp", "fstsw", "fsub",
            "fsubp", "fsubr", "fsubrp", "ftst", "fucomi", "fucomip",
            "fwait", "fxam", "fxch", "fxtract", "fyl2x", "fyl2xp1"]

    if not ignore_ops:
        for o in range(6):
            if i[o].type == o_void:
                break

            # NOTE: for x64 we only consider 64 bit granularity at the moment.
            ida_operand_str = GetOpnd(address, o)
            # Some instructions like "stosq" do not have string operands
            # => ignore for now.
            if ida_operand_str == "":
                break

            # DEBUG
            #print(ida_operand_str)

            operand = instruction.Operand(get_operand_access_type(i, o),
                                          i[o],
                                          ida_operand_str=ida_operand_str,
                                          address=address,
                                          op_num=o)

            normalized = normalize_operand(operand)
            ops.extend(normalized)

    is_control_flow = is_ret_insn(address) or \
                      len(list(CodeRefsFrom(address, 1))) > 1

    return instruction.Instruction(address, mnemonic, ops, is_control_flow)


def decode_block(start, end):
    if isinstance(__builtin__.REGISTERS, RegistersTricore):
        return tricore_decode_block(start, end)
    elif isinstance(__builtin__.REGISTERS, RegistersX64):
        return x64_decode_block(start, end)
    else:
        raise NotImplementedError("Do not know how to decode block.")


def decode_function(function):
    ida_function = get_func(function._address)
    assert ida_function, 'Cannot match given address to existing function.'

    ida_blocks = list(FlowChart(ida_function))

    # Make strict basic blocks.
    block_tuples = list()
    for b in ida_blocks:
        address = b.startEA
        block_start = b.startEA
        block_end = b.endEA

        # DEBUG
        #print("Block start: 0x%x" % block_start)
        #print("Block end: 0x%x" % block_end)

        while address != BADADDR and address < block_end:
            # Maybe use CodeRefsTo, any edge cases?
            if GetMnem(address).startswith('call'):
                address = NextHead(address)
                block_tuples.append((block_start, address))
                block_start = address
            else:
                address = NextHead(address)

        if block_start != block_end:
            block_tuples.append((block_start, block_end))

    # Decode basic blocks.
    block_vas = set([b[0] for b in block_tuples])
    for b in block_tuples:
        block_ = decode_block(b[0], b[1])
        function._blocks[b[0]] = block_

        for c in filter(lambda x: x in block_vas,
                        CodeRefsFrom(PrevHead(b[1]), 1)):

            function._successors[b[0]].add(c)
            block_.add_successor(c)


def tricore_decode_block(start, end):
    b = block.Block(start, end)

    # Reads from/writes to return value register retv.
    ret_r = instruction.Operand(AccessType.Read,
                    operand=operands.Register(
                    index=__builtin__.REGISTERS.retval))
    ret_w = instruction.Operand(AccessType.Write,
                    operand=operands.Register(
                    index=__builtin__.REGISTERS.retval))

    a2_w = instruction.Operand(AccessType.Write,
                   operand=operands.Register(index=__builtin__.REGISTERS.a2))
    d2_w = instruction.Operand(AccessType.Write,
                   operand=operands.Register(index=__builtin__.REGISTERS.d2))

    a2_r = instruction.Operand(AccessType.Read,
                   operand=operands.Register(index=__builtin__.REGISTERS.a2))
    d2_r = instruction.Operand(AccessType.Read,
                   operand=operands.Register(index=__builtin__.REGISTERS.d2))

    # Parameters.
    a4_r = instruction.Operand(AccessType.Read,
                   operand=operands.Register(index=__builtin__.REGISTERS.a4))
    d4_r = instruction.Operand(AccessType.Read,
                   operand=operands.Register(index=__builtin__.REGISTERS.d4))

    current = start
    while current < end:
        instr = decode_instruction(current)
        if instr._mnemonic.startswith('ret'):
            instr._operands.append(deepcopy(a2_r))
            instr._operands.append(deepcopy(d2_r))

            b.add_instruction(instr)

        elif instr._mnemonic.startswith('call'):
            instr._operands.insert(0, deepcopy(ret_w))
            instr._operands.extend([deepcopy(a4_r), deepcopy(d4_r)])

            b.add_instruction(instr)

            return_a2 = instruction.CallingConvention(instr.address,
                                                      [deepcopy(a2_w),
                                                       deepcopy(ret_r)])
            return_d2 = instruction.CallingConvention(instr.address,
                                                      [deepcopy(d2_w),
                                                       deepcopy(ret_r)])

            b.add_instruction(return_a2)
            b.add_instruction(return_d2)

        else:
            b.add_instruction(instr)

        current = NextNotTail(current)
    return b


def x64_decode_block(start, end):

    # DEBUG
    #print("Decode block start: 0x%x" % start)
    #print("Decode block end: 0x%x" % end)

    b = block.Block(start, end)

    rax_r = instruction.Operand(AccessType.Read,
                   operand=operands.Register(index=__builtin__.REGISTERS.rax))
    rax_w = instruction.Operand(AccessType.Write,
                   operand=operands.Register(index=__builtin__.REGISTERS.rax))

    rdi_r = instruction.Operand(AccessType.Read,
                   operand=operands.Register(index=__builtin__.REGISTERS.rdi))
    rsi_r = instruction.Operand(AccessType.Read,
                   operand=operands.Register(index=__builtin__.REGISTERS.rsi))
    rdx_r = instruction.Operand(AccessType.Read,
                   operand=operands.Register(index=__builtin__.REGISTERS.rdx))
    rcx_r = instruction.Operand(AccessType.Read,
                   operand=operands.Register(index=__builtin__.REGISTERS.rcx))
    r8_r = instruction.Operand(AccessType.Read,
                   operand=operands.Register(index=__builtin__.REGISTERS.r8))
    r9_r = instruction.Operand(AccessType.Read,
                   operand=operands.Register(index=__builtin__.REGISTERS.r9))

    current = start
    while current < end:

        if not isCode(GetFlags(current)):
            print("WARNING: 0x%x not considered as code " % current
                + "but inside basic block. Skipping.")
            current = NextNotTail(current)
            continue

        instr = decode_instruction(current)
        if instr._mnemonic.startswith('ret'):
            instr._operands.append(deepcopy(rax_r))

            b.add_instruction(instr)

        elif instr._mnemonic.startswith('call'):
            instr._operands.insert(0, deepcopy(rax_w))

            # TODO consider only System V AMD64 ABI at the moment.
            instr._operands.extend([deepcopy(rdi_r), deepcopy(rsi_r),
                deepcopy(rdx_r), deepcopy(rcx_r), deepcopy(r8_r),
                deepcopy(r9_r)])

            b.add_instruction(instr)

        else:
            b.add_instruction(instr)

        current = NextNotTail(current)
    return b