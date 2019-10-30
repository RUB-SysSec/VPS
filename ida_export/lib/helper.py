from shovel.instruction import Instruction
from shovel import operands
from config import _ARG_REGISTERS


# Gets the instructions that are using the given argument register (given by index).
def get_instrs_using_arg_reg(func, arg_reg_idx):
    used_arg_instrs = list()
    for _, block in func.blocks.iteritems():
        for instr in block.instructions():
            if isinstance(instr, Instruction):
                for use in instr.uses:
                    # Phi index is always 0 for the first usage.
                    if isinstance(use.operand, operands.Register) \
                        and use.operand.phi_index == 0:
                        if use.operand.index == arg_reg_idx:
                            used_arg_instrs.append(instr)
    return used_arg_instrs


# Get the argument registers that are used by the data flow (if any).
# Ignore "sub function calls" on the way.
def get_arg_reg_idxs_of_flow(relation, call_instr_op=None):
    used_arg_regs = list()
    for instr in relation:

        if not isinstance(instr, Instruction) or instr.mnemonic.startswith('call'):
            continue

        for use_op in instr.uses:
            # Phi index is always 0 for the first usage.
            if isinstance(use_op.operand, operands.Register) \
                and use_op.operand.phi_index == 0:
                if use_op.operand.index in _ARG_REGISTERS:
                    used_arg_regs.append( {"instr": instr,
                                            "arg_idx": use_op.operand.index} )
            elif isinstance(use_op.operand, operands.Memory) \
                and use_op.operand.base.phi_index == 0:
                if use_op.operand.base.index in _ARG_REGISTERS:
                    used_arg_regs.append( {"instr": instr,
                                            "arg_idx": use_op.operand.base.index} )

        # Also consider memory definitions (i.e., mov [rdi_0], <value>)
        # uses rdi_0 even if it is considered as a definition.
        for def_op in instr.definitions:
            if isinstance(def_op.operand, operands.Memory) \
                and def_op.operand.base.phi_index == 0:
                if def_op.operand.base.index in _ARG_REGISTERS:
                    used_arg_regs.append( {"instr": instr,
                                            "arg_idx": def_op.operand.base.index} )

    # Handle edge case in which we have to track an argument register
    # of a subcall/tailjmp.
    if call_instr_op is not None and isinstance(call_instr_op.operand, operands.Register):
        if call_instr_op.operand.index in _ARG_REGISTERS \
            and call_instr_op.operand.phi_index == 0:

            if len(relation) == 1:
                # Handle edge case in which we have to track an argument register
                # of a tailjmp which is also an argument register of the current function (i.e., rdi_0).
                for instr in relation:
                    if isinstance(instr, Instruction) \
                        and instr.mnemonic.startswith('jmp'):
                        used_arg_regs.append({"instr": instr,
                                              "arg_idx": call_instr_op.operand.index})

                    # Handle edge case in which we have to track an argument register
                    # of a subcall which is also an argument register of the current function (i.e., rdi_0).
                    elif isinstance(instr, Instruction) \
                        and instr.mnemonic.startswith('call') \
                        and call_instr_op in instr.uses:
                        used_arg_regs.append( {"instr": instr,
                                               "arg_idx": call_instr_op.operand.index} )

    return used_arg_regs


# Returns a list of dict that contains the call instruction and the target operand
# for all subcalls that are made in the graph.
def get_subcalls_of_flow(relation):
    used_subcalls = list()
    for instr in relation:

        if not isinstance(instr, Instruction) or not instr.mnemonic.startswith('call'):
            continue

        # Check if call instruction is starting node in graph or the only node.
        preds = list(relation.predecessors(instr))
        if preds or len(relation) == 1:
            continue

        # First use of call instruction is always the target.
        target_op = instr.uses[0]

        used_subcalls.append( {"instr": instr,
                               "target_op": target_op} )

    return used_subcalls


# Returns a list of dict that contains the return instruction and the return operand
# for all return instructions in the function.
def get_ret_instr_of_fct(func):
    used_ret_instrs = list()
    for _, block in func.blocks.iteritems():
        for instr in  block.instructions():
            if instr.mnemonic.startswith("ret"):
                used_ret_instrs.append({"instr": instr,
                                   "ret_op": instr.uses[0]})
    return used_ret_instrs


# Returns a set of call instructions to possible constructors.
def get_possible_ctors(relation):

    ctor_calls = set()
    for instr in relation:

        if not isinstance(instr, Instruction) or not instr.mnemonic.startswith("call"):
            continue

        # Only consider calls that are leafs in the graph.
        succs = list(relation.successors(instr))
        if succs:
            continue

        # Constructor is always called via a direct call.
        # First use of call instruction is always the target.
        if not isinstance(instr.uses[0].operand, operands.Constant):
            continue

        # Check if tracked value flows via first argument register into call
        # => possibly constructor.
        preds = list(relation.predecessors(instr))
        for pred_instr in preds:
            edge_data = relation.get_edge_data(pred_instr, instr)
            reg = edge_data["label"]
            if isinstance(reg, operands.Register) and reg.index == _ARG_REGISTERS[0]:
                ctor_calls.add(instr)
    return ctor_calls


# Searches for vtables pointers used by instructions.
def get_possible_vtables(relation, vtables):

    used_vtables = list()
    for instr in relation:
        if not isinstance(instr, Instruction):
            continue

        def_ops = instr.definitions
        use_ops = instr.uses

        if len(def_ops) != 1 or len(use_ops) != 1:
            continue

        if isinstance(def_ops[0].operand, operands.Memory) \
            and isinstance(use_ops[0].operand, operands.Constant):

            vtable_addr = use_ops[0].operand.value
            if vtable_addr in vtables.keys():
                instr.comment = "vtable"
                used_vtables.append({"instr": instr,
                                     "vtable_op": use_ops[0].operand,
                                     "vtable": use_ops[0].operand.value})
    return used_vtables