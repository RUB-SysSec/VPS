
from idaapi import CF_USE1, CF_USE2, CF_USE3, CF_USE4, CF_USE5, CF_USE6
from idaapi import CF_CHG1, CF_CHG2, CF_CHG3, CF_CHG4, CF_CHG5, CF_CHG6
from idaapi import o_reg, o_imm, o_near, o_far, o_mem, o_displ, o_phrase, o_idpspec0, o_idpspec1
from idc import op_hex, GetOpnd

import __builtin__
import re
import ctypes

from ..operands import AccessType
from .. import operands
from ..arch import RegistersTricore, RegistersX64

__all__ = [
    'is_pre_increment', 'is_post_increment',
    'is_effective_address', 'get_operand_access_type', 'parse_ida_operand',
]


_OPERAND_READ = [CF_USE1, CF_USE2, CF_USE3, CF_USE4, CF_USE5, CF_USE6]
_OPERAND_WRITE = [CF_CHG1, CF_CHG2, CF_CHG3, CF_CHG4, CF_CHG5, CF_CHG6]





def is_pre_increment(operand):
    return (operand.specflag1 & 2) != 0


def is_post_increment(operand):
    return (operand.specflag1 & 4) != 0


def is_effective_address(operand):
    if isinstance(__builtin__.REGISTERS, RegistersTricore):
        return operand.type == o_idpspec0 and operand.dtyp == 0
    else:
        raise NotImplementedError("Do not know how to handle is_effective_address for architecture.")


def get_operand_access_type(instruction, operand_index):
    assert 0 <= operand_index < len(_OPERAND_READ), 'Invalid operand index.'

    f = instruction.get_canon_feature()
    access = AccessType.Unknown

    if (f & _OPERAND_READ[operand_index]) != 0:
        access = AccessType.Read

    if (f & _OPERAND_WRITE[operand_index]) != 0:
        if access == AccessType.Read:
            access = AccessType.ReadWrite
        else:
            access = AccessType.Write

    return access


def parse_ida_operand(ida_operand, ida_operand_str, address, op_num):

    def parse_mem(o, ida_operand_str, addr, op_num):

        # IDA does not give us an API to get the content of the memory
        # => we have to parse the string :/
        if isinstance(__builtin__.REGISTERS, RegistersX64):

            # Check if we have something special like this:
            # Example: ds:_ZZN15CRandomMersenne7BRandomEvE5mag01[rax*4]
            # Since "[" and "]" are not allowed in the names, check if
            # we end with it.
            if ida_operand_str[-1] == "]":
                start = ida_operand_str.find("[")+1
                end = len(ida_operand_str)-1
                temp_str = ida_operand_str[start:end]

                # Example: [rax*4] => rax
                memory_elements = temp_str.split("*")
                base_str = memory_elements[0]
                factor_str = memory_elements[1]
                try:
                    base_reg = __builtin__.REGISTERS.to_idx(base_str)
                except:
                    raise NotImplementedError("Do not know how to "
                        + "handle o_mem '%s'." % ida_operand_str)

                try:
                    index_factor = int(factor_str)
                except:
                    raise NotImplementedError("Do not know how to "
                        + "handle o_mem '%s'." % ida_operand_str)
                
                offset_obj = operands.Constant(o.addr or o.value)
                index_factor_obj = operands.Constant(index_factor)
                return operands.Memory(operands.Register(base_reg),
                                       offset=offset_obj,
                                       index_factor=index_factor_obj)

            # It seems we have a normal memory access like this:
            # Example: ds:_ZZN15CRandomMersenne7BRandomEvE5mag01
            else:
                return operands.Constant(o.addr or o.value)
        else:
            return operands.Constant(o.addr or o.value)

    def parse_phrase(o, ida_operand_str, addr, op_num):

        # IDA does not give us an API to get the content of the phrase
        # => we have to parse the string :/
        if isinstance(__builtin__.REGISTERS, RegistersX64):

            # DEBUG
            #print("phrase: ida_operand_str: %s" % ida_operand_str)

            # Example: [rdx+rcx] or [rax+rdx*8] or byte ptr [rsi+rdx]
            # Remove "[" and "]"
            start = ida_operand_str.find("[")+1
            end = len(ida_operand_str)-1
            temp_str = ida_operand_str[start:end]
            memory_elements = temp_str.split("+")

            # DEBUG
            #print("phrase: Memory elements: %d" % len(memory_elements))
            #print(memory_elements)

            # Example: [rdx+rcx] => rdx or [rax+rdx*8] => rax 
            base_str = memory_elements[0]
            try:
                base_reg = __builtin__.REGISTERS.to_idx(base_str)
            except:
                # In cases such as [rsp-50h+arg_48] our
                # string parsing fails. However, we can normalize this
                # to [rsp] and retry.
                if op_hex(addr, op_num):
                    new_str = GetOpnd(addr, op_num)
                    if ida_operand_str != new_str:
                        return parse_phrase(o,
                                            new_str,
                                            addr,
                                            op_num)

                raise NotImplementedError("Do not know how to "
                    + "handle o_phrase '%s'." % ida_operand_str)

            index_reg = None
            index_factor = None

            if len(memory_elements) == 2:
                index_split = memory_elements[1].split("*")

                # DEBUG
                #print("phrase: Index split: " + str(index_split))

                # Example: [rdx+rcx] => rcx or [rax+rdx*8] => rdx
                # Example: [rsp+0] => rsp
                index_str = index_split[0]
                factor_str = None
                if len(index_split) == 2:
                    # Example [rax+rdx*8] => 8
                    factor_str = index_split[1]
                elif len(index_split) > 1:

                    # In cases such as [rsp+0B0h+lbarray+78h] our
                    # string parsing fails. However, we can normalize this
                    # to [rsp] and retry.
                    if op_hex(addr, op_num):
                        new_str = GetOpnd(addr, op_num)
                        if ida_operand_str != new_str:
                            return parse_phrase(o,
                                                new_str,
                                                addr,
                                                op_num)

                    raise NotImplementedError("Do not know how to "
                        + "handle o_phrase '%s'." % ida_operand_str)

                # Example: [rsp+0]
                # Example: [rsp+s2] with r2 = 0
                try:
                    index_reg = __builtin__.REGISTERS.to_idx(index_str)
                except:
                    # DEBUG
                    #print("NOTE: phrase index string '%s' ignored."
                    #      % index_str)
                    index_reg = None

                if factor_str:
                    index_factor = int(factor_str)

                # Example: [rsp+0]
                if index_reg is None:
                    return operands.Memory(operands.Register(base_reg))
                # Example: [rax+rdx*8]
                elif factor_str:
                    return operands.Memory(operands.Register(base_reg),
                                           index=operands.Register(index_reg),
                                           index_factor=operands.Constant(
                                                                index_factor))
                # Example: [rdx+rcx]
                else:
                    return operands.Memory(operands.Register(base_reg),
                                           index=operands.Register(index_reg))

            # Example: [rsp+40h+var_40] => [rsp]
            # Example: [rsp+8+var_8] => [rsp]
            # Example: [rsp+rcx*2+var_s0] => [rsp+rcx*2]
            elif len(memory_elements) == 3:
                # IDA defines o_phrase as the following:
                # Memory Ref [Base Reg + Index Reg]
                # Therefore, a phrase does not have an offset.
                # The string construct built by IDA always adds up to 0.
                possible_number = memory_elements[1]
                has_hex_ending = possible_number[-1:] == "h"
                is_hex = bool(re.match(r'^[a-fA-F0-9]+$',
                                       possible_number[:-1]))
                is_number = bool(re.match(r'^[0-9]+$', possible_number))

                # Example: [rsp+40h+var_40] => [rsp]
                if has_hex_ending and is_hex:
                    return operands.Memory(operands.Register(base_reg))

                # Example: [rsp+8+var_8] => [rsp]
                elif is_number:
                    return operands.Memory(operands.Register(base_reg))

                # Example: [rsp+rcx*2+var_s0] => [rsp+rcx*2]
                else:

                    index_split = memory_elements[1].split("*")

                    # Example: [rsp+rcx*2+var_s0] => rcx
                    index_str = index_split[0]
                    factor_str = None
                    if len(index_split) == 2:
                        # Example [rax+rdx*8] => 8
                        factor_str = index_split[1]
                    elif len(index_split) > 1:

                        # In cases such as [rsp+0B0h+lbarray+78h] our
                        # string parsing fails. However, we can normalize this
                        # to [rsp] and retry.
                        if op_hex(addr, op_num):
                            new_str = GetOpnd(addr, op_num)
                            if ida_operand_str != new_str:
                                return parse_phrase(o,
                                                    new_str,
                                                    addr,
                                                    op_num)

                        raise NotImplementedError("Do not know how to "
                            + "handle o_phrase '%s'." % ida_operand_str)

                    try:
                        index_reg = __builtin__.REGISTERS.to_idx(index_str)
                    except:

                        # In cases such as [rsp+0B0h+lbarray+78h] our
                        # string parsing fails. However, we can normalize this
                        # to [rsp] and retry.
                        if op_hex(addr, op_num):
                            new_str = GetOpnd(addr, op_num)
                            if ida_operand_str != new_str:
                                return parse_phrase(o,
                                                    new_str,
                                                    addr,
                                                    op_num)

                        raise NotImplementedError("Do not know how to "
                            + "handle o_phrase '%s'." % ida_operand_str)

                    if factor_str:
                        index_factor = int(factor_str)

                    # Example: [rsp+rcx*2+var_s0]
                    if factor_str:
                        return operands.Memory(operands.Register(base_reg),
                                               index=operands.Register(
                                                                index_reg),
                                               index_factor=operands.Constant(
                                                                index_factor))
                    # Example: [rsp+rcx+var_s0]
                    else:
                        return operands.Memory(operands.Register(base_reg),
                                               index=operands.Register(
                                                                index_reg))

            # Example: [rsp+rdx*8+98h+var_98] => [rsp+rdx*8]
            elif len(memory_elements) == 4:
                # IDA defines o_phrase as the following:
                # Memory Ref [Base Reg + Index Reg]
                # Therefore, a phrase does not have an offset.
                # The string construct built by IDA always adds up to 0.
                possible_number = memory_elements[2]
                has_hex_ending = possible_number[-1:] == "h"
                is_hex = bool(re.match(r'^[a-fA-F0-9]+$',
                              possible_number[:-1]))

                if has_hex_ending and is_hex:
                    new_op_str = "[" + \
                                 memory_elements[0] + \
                                 "+" + \
                                 memory_elements[1] + \
                                 "]"
                    return parse_phrase(o, new_op_str, addr, op_num)
                else:

                    # In cases such as [rsp+0B0h+lbarray+78h] our
                    # string parsing fails. However, we can normalize this
                    # to [rsp] and retry.
                    if op_hex(addr, op_num):
                        new_str = GetOpnd(addr, op_num)
                        if ida_operand_str != new_str:
                            return parse_phrase(o,
                                                new_str,
                                                addr,
                                                op_num)

                    raise NotImplementedError("Do not know how to "
                        + "handle o_phrase '%s'." % ida_operand_str)

            elif len(memory_elements) > 4:

                # In cases such as [rsp+0B0h+lbarray+78h] our
                # string parsing fails. However, we can normalize this
                # to [rsp] and retry.
                if op_hex(addr, op_num):
                    new_str = GetOpnd(addr, op_num)
                    if ida_operand_str != new_str:
                        return parse_phrase(o,
                                            new_str,
                                            addr,
                                            op_num)

                raise NotImplementedError("Do not know how to handle "
                    + "o_phrase '%s'." % ida_operand_str)

            return operands.Memory(operands.Register(base_reg))
            
        else:

            raise NotImplementedError("Do not know how to handle o_phrase for architecture.")

    def parse_displ(o, ida_operand_str):

        # IDA does not give us an API to get the complete content of the displ
        # => we have to parse the string :/
        if isinstance(__builtin__.REGISTERS, RegistersX64):

            # DEBUG
            #print("displ: ida_operand_str: %s" % ida_operand_str)

            # Example: [rsp+rax*8+0B8h+readfds.fds_bits]
            # Remove "[" and "]"
            start = ida_operand_str.find("[")+1
            end = len(ida_operand_str)-1
            temp_str = ida_operand_str[start:end]
            temp_split = temp_str.split("+")

            memory_elements = list()
            for temp_element in temp_split:
                sub_split = temp_element.split("-")
                if len(sub_split) > 1:
                    for i in range(len(sub_split)):
                        if i == 0:
                            continue
                        sub_split[i] = "-" + sub_split[i]
                memory_elements.extend(sub_split)

            # DEBUG
            #print("displ: Memory elements: %d" % len(memory_elements))
            #print(memory_elements)

            # Example: [rsp+rax*8+0B8h+readfds.fds_bits] => rsp
            # Example: [rsp+0C8h+var_20] => rsp
            base_str = memory_elements[0]
            base_reg = __builtin__.REGISTERS.to_idx(base_str)
            index_reg = None
            index_factor = None

            if len(memory_elements) > 1:
                index_split = memory_elements[1].split("*")

                # DEBUG
                #print("displ: Index split: " + str(index_split))

                # Example: [rsp+rax*8+0B8h+readfds.fds_bits] => rax*8
                # Example: [rsp+0C8h+var_20] => 0C8h
                index_str = index_split[0]
                factor_str = None
                if len(index_split) == 2:
                    # Example [rsp+rax*8+0B8h+readfds.fds_bits] => 8
                    factor_str = index_split[1]
                elif len(index_split) > 1:
                    raise NotImplementedError("Do not know how to handle o_displ '%s'." % ida_operand_str)

                try:
                    # Example: [rsp+rax*8+0B8h+readfds.fds_bits] => rax
                    index_reg = __builtin__.REGISTERS.to_idx(index_str)
                except:
                    # Example: [rsp+0C8h+var_20] => 0C8h
                    possible_number = index_str
                    has_hex_ending = possible_number[-1:] == "h"
                    is_signed_hex = bool(re.match(r'^-?[a-fA-F0-9]+$',
                                           possible_number[:-1]))

                    is_signed_number = bool(re.match(r'^-?\d+$',
                                           possible_number))

                    if has_hex_ending and is_signed_hex:
                        index_reg = None
                    elif is_signed_number:
                        index_reg = None
                    else:
                        # DEBUG
                        #print("NOTE: displ index string '%s' ignored."
                        #      % index_str)
                        index_reg = None

                offset = ctypes.c_longlong(o.value or o.addr).value

                if factor_str:
                    index_factor = int(factor_str)

                # Example: [rsp+0C8h+var_20]
                # Example: [rbx-8]
                if index_reg is None:
                    return operands.Memory(operands.Register(o.reg),
                                           offset=operands.Constant(offset))
                # Example: [rsp+rax*8+0B8h+readfds.fds_bits]
                elif factor_str:
                    return operands.Memory(operands.Register(base_reg),
                                           index=operands.Register(index_reg),
                                           index_factor=operands.Constant(index_factor),
                                           offset=operands.Constant(offset))
                # Example: dword ptr [rax+rax+00000000h]
                else:
                    return operands.Memory(operands.Register(base_reg),
                                           index=operands.Register(index_reg),
                                           offset=operands.Constant(offset))
            # Example: ds:qword_4738C8[rax]
            else:
                return operands.Memory(operands.Register(base_reg))
        else:
            raise NotImplementedError("Do not know how to handle o_displ for architecture.")

    def parse_idpspec0(o):
        if isinstance(__builtin__.REGISTERS, RegistersTricore):
            return operands.Memory(operands.Register(o.reg),
                                   offset=operands.Constant(o.value),
                                   pre=is_pre_increment(o),
                                   post=is_post_increment(o))
        else:
            raise NotImplementedError("Do not know how to handle o_idpspec0 for architecture.")

    def parse_idpspec1(o):
        if isinstance(__builtin__.REGISTERS, RegistersTricore):
            return operands.Bit(o.value)
        else:
            raise NotImplementedError("Do not know how to handle o_idpspec1 for architecture.")

    def parse_undefined(o, arg_str):
        try:
            reg_idx = __builtin__.REGISTERS.to_idx(arg_str)
            return operands.Register(reg_idx)
        except:
            raise NotImplementedError('Undefined type %d when parsing operand.'
                                  % o.type
                                  + ' String operand: %s'
                                  % arg_str)

    '''
    o_void     =  0 # No Operand                           ----------
    o_reg      =  1 # General Register (al,ax,es,ds...)    reg
    o_mem      =  2 # Direct Memory Reference  (DATA)      addr
    o_phrase   =  3 # Memory Ref [Base Reg + Index Reg]    phrase
    o_displ    =  4 # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
    o_imm      =  5 # Immediate Value                      value
    o_far      =  6 # Immediate Far Address  (CODE)        addr
    o_near     =  7 # Immediate Near Address (CODE)        addr
    o_idpspec0 =  8 # Processor specific type
    o_idpspec1 =  9 # Processor specific type
    o_idpspec2 = 10 # Processor specific type
    o_idpspec3 = 11 # Processor specific type
    o_idpspec4 = 12 # Processor specific type
    o_idpspec5 = 13 # Processor specific type
    '''
    PARSE = {
        o_reg: lambda o, _, __, ___: operands.Register(o.reg),
        o_imm: lambda o, _, __, ___: operands.Constant(o.value or o.addr),
        o_near: lambda o, _, __, ___: operands.Constant(o.addr or o.value),
        o_far: lambda o, _, __, ___: operands.Constant(o.addr or o.value),
        o_mem: lambda o, arg_str, addr, op_num:
                                        parse_mem(o, arg_str, addr, op_num),
        #o_phrase: lambda o: operands.Memory(operands.Register(o.reg)),
        o_phrase: lambda o, arg_str, addr, op_num:
                                        parse_phrase(o, arg_str, addr, op_num),
        #o_displ: lambda o, _: operands.Memory(operands.Register(o.reg),
        #                                   offset=operands.Constant(o.value or o.addr)),
        o_displ: lambda o, arg_str, __, ___: parse_displ(o, arg_str),
        o_idpspec0: lambda o, _, __, ___: parse_idpspec0(o),
        o_idpspec1: lambda o, _, __, ___: parse_idpspec1(o),
        # Not defined by hex-rays, but still used by IDA.
        # We have to guess here.
        13: lambda o, arg_str, __, ___: parse_undefined(o, arg_str),
        14: lambda o, arg_str, __, ___: parse_undefined(o, arg_str),
    }

    handler = PARSE.get(ida_operand.type)
    if not handler:
        raise NotImplementedError('Unknown type %d when parsing operand.'
                                  % ida_operand.type
                                  + ' String operand: %s'
                                  % ida_operand_str)

    return handler(ida_operand, ida_operand_str, address, op_num)
