from shovel.instruction import Instruction
from shovel import operands
from config import _HIGHLIGHTING

try:
    from networkx.drawing.nx_pydot import to_pydot
except:
    print('pydot may be missing.')
    raise


def write_graph(graph, path):
    def fill_node(node, color):
        node.set_fillcolor(color)
        node.set_style('filled')

    font = 'Ubuntu Mono'
    dot = to_pydot(graph)

    for n in dot.get_node_list():
        n.set_fontname(font)
        n.set_shape('rect')

        for k, v in _HIGHLIGHTING.iteritems():
            if k in n.obj_dict["name"]:
                fill_node(n, v)
                break
        else:
            fill_node(n, '#fafafa')

    for e in dot.get_edge_list():
        e.set_fontname(font)
        if e.get('control'):
            e.set_style('dotted')

    dot.write(path)


# Removes the given node and all its branches
# (predecessor and successor nodes) from the graph as long
# as they do not influence other branches.
def remove_node_and_branches_from_graph(graph, start_instr, instrs_to_ignore=None):

    remove_instrs = set()
    remove_instrs.add(start_instr)

    # Remove all predecessors of the current instruction.
    working_set = list()
    for pred_instr in graph.predecessors(start_instr):
        working_set.append((pred_instr, start_instr))
    while working_set:
        curr_instr, succ_instr = working_set.pop(0)

        succ = set(graph.successors(curr_instr))
        succ -= remove_instrs

        # Only remove predecessors that do not have a successor remaining.
        if not succ:

            # Do not remove the instruction that starts the analysis.
            if instrs_to_ignore is not None and curr_instr in instrs_to_ignore:
                continue

            remove_instrs.add(curr_instr)

            for pred_instr in graph.predecessors(curr_instr):
                working_set.append((pred_instr, curr_instr))

    # Remove all successors of the current instruction.
    for succ_instr in graph.successors(start_instr):
        working_set.append((succ_instr, start_instr))
    while working_set:
        curr_instr, pred_instr = working_set.pop(0)

        pred = set(graph.predecessors(curr_instr))
        pred -= remove_instrs

        # Only remove successors that do not have a predecessor remaining.
        if not pred:

            # Do not remove the instruction that starts the analysis.
            if instrs_to_ignore is not None and curr_instr in instrs_to_ignore:
                continue

            remove_instrs.add(curr_instr)

            for succ_instr in graph.successors(curr_instr):
                working_set.append((succ_instr, curr_instr))

    for remove_instr in remove_instrs:
        graph.remove_node(remove_instr)

    # Return all nodes that were removed
    return remove_instrs


# Removes all leaf nodes that are not call instructions (and therefore no call to a constructor).
def prune_new_operator_graph(relation):

    leaf_instrs = set()
    for instr in relation:
        if not list(relation.successors(instr)):
            leaf_instrs.add(instr)

    for leaf_instr in leaf_instrs:

        if not isinstance(leaf_instr, Instruction) or leaf_instr.mnemonic.startswith("call"):
            continue

        remove_node_and_branches_from_graph(relation, leaf_instr)


# Removes all leaf nodes that are not vtable instructions.
# TODO: Can another instruction despite a leaf node contain a vtable?
def prune_vtables_graph(relation, vtables):

    leaf_instrs = set()
    for instr in relation:
        if not list(relation.successors(instr)):
            leaf_instrs.add(instr)

    for leaf_instr in leaf_instrs:

        if not isinstance(leaf_instr, Instruction):
            remove_node_and_branches_from_graph(relation, leaf_instr)
            continue

        def_ops = leaf_instr.definitions
        use_ops = leaf_instr.uses

        if len(def_ops) != 1 or len(use_ops) != 1:
            remove_node_and_branches_from_graph(relation, leaf_instr)
            continue

        if isinstance(def_ops[0].operand, operands.Memory) \
            and isinstance(use_ops[0].operand, operands.Constant):

            vtable_addr = use_ops[0].operand.value
            if vtable_addr not in vtables.keys():
                remove_node_and_branches_from_graph(relation, leaf_instr)
        else:
            remove_node_and_branches_from_graph(relation, leaf_instr)