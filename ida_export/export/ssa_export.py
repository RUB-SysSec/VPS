
from lib.shovel.operands import AccessType

from ssa_export_pb2 import Functions as Functions_pb2

from lib.shovel.arch import RegistersTricore, RegistersX64

from lib.shovel.instruction import Instruction as BaseInstruction
from lib.shovel.instruction import CallingConvention
from lib.shovel.block import PhiNode

from lib.shovel.operands import Constant, Address, Register, Memory

__all__ = ['export_ssa_functions']


# operand = src
# register_pb2 = dst
def _process_register(architecture, operand, register_pb2, access_type):
    operand_type = type(operand)
    architecture_type = type(architecture)
    if operand_type is Register and architecture_type is RegistersX64:
        registerx64_pb2 = register_pb2.register_x64
        registerx64_pb2.index = operand.index
        if operand.phi_index is not None:
            registerx64_pb2.phi_index = operand.phi_index
        else:
            registerx64_pb2.phi_index = -1
        registerx64_pb2.access_type = access_type

    elif architecture is RegistersTricore:
        raise NotImplementedError("Tricore not implemented")

    else:
        raise NotImplementedError("Do not know how to handle operand type {}".format(operand.__class__))


# operand = src
# constant_pb2 = dst
def _process_constant(architecture, operand, constant_pb2, access_type):
    operand_type = type(operand)
    architecture_type = type(architecture)
    if operand_type is Address and architecture_type is RegistersX64:
        addressx64_pb2 = constant_pb2.address_x64
        addressx64_pb2.value = operand.value
        addressx64_pb2.access_type = access_type

    elif operand_type is Constant and architecture_type is RegistersX64:
        constantx64_pb2 = constant_pb2.constant_x64
        constantx64_pb2.value = operand.value
        constantx64_pb2.access_type = access_type

    elif architecture is RegistersTricore:
        raise NotImplementedError("Tricore not implemented")

    else:
        raise NotImplementedError("Do not know how to handle operand type {}".format(operand.__class__))


# operand = src
# memory_pb2 = dst
def _process_memory(architecture, operand, memory_pb2, access_type):
    operand_type = type(operand)
    architecture_type = type(architecture)
    if operand_type is Memory and architecture_type is RegistersX64:
        memoryx64_pb2 = memory_pb2.memory_x64

        _process_register(architecture, operand.base, memoryx64_pb2.base, AccessType.Read)
        _process_constant(architecture, operand.offset, memoryx64_pb2.offset, AccessType.Read)
        memoryx64_pb2.access_type = access_type
        if operand.index is not None:
            _process_register(architecture, operand.index, memoryx64_pb2.index, AccessType.Read)
        if operand.index_factor is not None:
             _process_constant(architecture, operand.index_factor, memoryx64_pb2.index_factor, AccessType.Read)

    elif architecture is RegistersTricore:
        raise NotImplementedError("Tricore not implemented")

    else:
        raise NotImplementedError("Do not know how to handle operand type {}".format(operand.__class__))


# operand = src
# operand_pb2 = dst
def _process_operand(architecture, operand, operand_pb2, access_type):
    operand_type = type(operand)
    architecture_type = type(architecture)
    if operand_type is Register and architecture_type is RegistersX64:
        _process_register(architecture, operand, operand_pb2.register, access_type)

    elif operand_type is Address and architecture_type is RegistersX64:
        _process_constant(architecture, operand, operand_pb2.constant, access_type)

    elif operand_type is Constant and architecture_type is RegistersX64:
        _process_constant(architecture, operand, operand_pb2.constant, access_type)

    elif operand_type is Memory and architecture_type is RegistersX64:
        _process_memory(architecture, operand, operand_pb2.memory, access_type)

    elif architecture is RegistersTricore:
        raise NotImplementedError("Tricore not implemented")

    else:
        raise NotImplementedError("Do not know how to handle operand type {}".format(
            operand.__class__))


# instruction = src
# instruction_pb2 = dst
def _process_instruction(architecture, instruction, instruction_pb2):
    instruction_type = type(instruction)
    if instruction_type is BaseInstruction:
        target_pb2 = instruction_pb2.instruction
        target_pb2.address = instruction.address
        target_pb2.mnemonic = instruction.mnemonic
        for operand in instruction.operands:
            _process_operand(architecture, operand.operand, target_pb2.operands.add(), operand.access)

    elif instruction_type is CallingConvention:

        raise NotImplementedError("Did not test calling convention implementation.")
        '''
        target_pb2 = instruction_pb2.calling_convention
        target_pb2.address = instruction.address
        target_pb2.mnemonic = "cconv"
        for operand in instruction._operands:
            _process_operand(architecture, operand, target_pb2.operands.add())
        '''

    elif instruction_type is PhiNode:
        target_pb2 = instruction_pb2.phi_node
        target_pb2.address = instruction.address
        target_pb2.mnemonic = "phi"

        # PhiNode do not have operands => emulate them.
        _process_operand(architecture, instruction.definition, target_pb2.operands.add(), AccessType.Write)
        for operand in instruction.register_uses:
            # TODO
            '''
            QUICK FIX
            class PhiNode generates number of slots (old framework None, new class Operand)
            in case of node+vtv basic block D608A8 does not have a predecessor and is not
            processed correctly which leads to phinode in basic block D60268 to have a None/Operand in the list
            '''
            if operand is not None:
                _process_operand(architecture, operand, target_pb2.operands.add(), AccessType.Read)

    else:
        raise NotImplementedError("Do not know how to handle instruction type {}".format(
            instruction.__class__))





def export_ssa_functions(architecture, functions, target_file):
    functions_pb2 = Functions_pb2()

    for _, function in functions.iteritems():
        function_pb2 = functions_pb2.functions.add()
        function_pb2.address = function.address

        for _, block in function.blocks.iteritems():
            block_pb2 = function_pb2.basic_blocks.add()
            block_pb2.address = block.address
            block_pb2.end = block.end

            for pred_addr in block.predecessors:
                block_pb2.predecessors.append(pred_addr)

            for succ_addr in block.successors:
                block_pb2.successors.append(succ_addr)

            # PhiNode is not in instruction list in old version.
            for _, phi_node in block._phi_nodes.iteritems():
                instruction_pb2 = block_pb2.instructions.add()
                _process_instruction(architecture, phi_node, instruction_pb2)

            for instruction in block.instructions():
                instruction_pb2 = block_pb2.instructions.add()
                _process_instruction(architecture, instruction, instruction_pb2)

    with open(target_file, "wb") as fp:
        fp.write(functions_pb2.SerializeToString())
