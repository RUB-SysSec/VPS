from shovel.instruction import Instruction, Operand
from shovel import operands
from graph_helper import remove_node_and_branches_from_graph
import networkx as nx


def augment_use(function, graph, initial_use, follow_memory=False):
    uses = function.uses if follow_memory else function.register_uses

    def connect_use(use):
        new_uses = set()
        defs = function.definitions.get(use)
        if defs is None:
            defs = set()

        # We kind of "overtaint" here.
        # Track both "rax" and "[rax-8]" in case of "mov [rax-8], rdi".
        if isinstance(use, operands.Memory):
            mem_defs = function.definitions.get(use.base)
            if mem_defs is not None:
                defs |= mem_defs

        if follow_memory:
            for d in defs:
                if not isinstance(d, Instruction):
                    continue
                for u in d.uses:
                    if isinstance(u.operand, operands.Memory):
                        # We kind of "overtaint" here.
                        # Track both "rax" and "[rax-8]" in case of "mov rdi, [rax-8]".
                        new_uses.add(u.operand)
                        new_uses.add(u.operand.base)
                    elif isinstance(u.operand, operands.Address):
                        new_uses.add(u.operand)

        for i in uses[use]:
            for d in defs:
                graph.add_edge(d, i, label=use)
                new_uses.update(d.register_uses)

        # We kind of "overtaint" here.
        # Track both "rax" and "[rax-8]" in case of "mov [rax-8], rdi".
        if isinstance(use, operands.Memory):
            for i in uses[use.base]:
                for d in defs:
                    graph.add_edge(d, i, label=use)
                    new_uses.update(d.register_uses)

        return new_uses

    seen = set()
    work_list = {initial_use}

    while work_list:
        use = work_list.pop()
        if use in seen:
            continue

        seen.add(use)
        new = connect_use(use)
        work_list.update(new)


# Given the instruction and the operand, create a graph that tracks the data flow back.
# The given start instruction is the only leaf in the node and call instructions are artificial
# stopping points for the beginning.
def track_data_flow_back(func, target_instr, target_op):

    if not isinstance(target_op, Operand) or not isinstance(target_instr, Instruction):
        raise ValueError("Wrong argument types for data flow tracking.")

    relation = nx.DiGraph()
    augment_use(func, relation, target_op.operand, follow_memory=True)

    # If operand could not be tracked (for example, if we start tracking rdi_0,
    # there is no definition of it in the function).
    if len(relation) == 0:
        relation.add_node(target_instr)

    # Remove all leaf nodes that are not the source from which we started.
    successors_dict = dict(relation.succ)
    for instr, succ in successors_dict.iteritems():
        if not succ.keys():
            if instr != target_instr:
                relation.remove_node(instr)

    # Make the starting instruction a leaf in the graph
    # (since we only are interested in back tracking).
    for succ_instr in list(relation.successors(target_instr)):
        relation.remove_edge(target_instr, succ_instr)

    # Mark all leaf instructions that are not the start instruction for removing.
    leaf_instr_remove = set()
    for instr, succ in relation.succ.iteritems():

        # Mark all leafs that are not the start instruction.
        if not succ.keys() and instr != target_instr:
            leaf_instr_remove.add(instr)

    # Remove all marked instructions from the graph.
    for leaf_instr in leaf_instr_remove:
        if leaf_instr in relation:
            remove_node_and_branches_from_graph(relation, leaf_instr)

    # Remove all nodes predecessing a call instruction (except the start instruction)
    # to have call instructions as an artificial boundary.
    for instr in list(relation):
        if instr not in relation:
            continue
        if isinstance(instr, Instruction) and instr.mnemonic.startswith("call") and instr != target_instr:
            for pred_instr in list(relation.predecessors(instr)):
                relation.remove_node(pred_instr)

    # Check if a path exists from all basic blocks to the target instruction.
    # This is done in order to prevent having instructions in the graph that
    # can not reach the target instruction because of missing memory SSA
    # (i.e., [rbp_2] is used somewhere at the end of the function).
    target_bb_addr = func.get_containing_block(target_instr.address).address
    source_bb_addrs = dict()
    for instr in relation:
        if instr == target_instr:
            continue
        bb_addr = func.get_containing_block(instr.address).address
        if bb_addr not in source_bb_addrs.keys():
            source_bb_addrs[bb_addr] = [instr]
        else:
            source_bb_addrs[bb_addr].append(instr)
    instr_remove = set()
    for bb_addr, instrs in source_bb_addrs.iteritems():
        if not nx.has_path(func.graph, bb_addr, target_bb_addr):
            instr_remove |= set(instrs)
    for instr in instr_remove:
        relation.remove_node(instr)

    # Remove parts of the graph that are no longer connected to the start instruction.
    for instr in list(relation):
        if instr == target_instr:
            continue
        if not nx.has_path(relation, instr, target_instr):
            relation.remove_node(instr)

    return relation