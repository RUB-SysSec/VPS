from shovel.block import PhiNode
from shovel.instruction import Instruction
from shovel import operands
from collections import defaultdict
from copy import copy
from config import _CTOR_CALL_DEPTH, _ARG_REGISTERS, DEBUG_GRAPHS_DUMP_ALL
from graph_helper import write_graph, prune_vtables_graph, prune_new_operator_graph
from helper import get_instrs_using_arg_reg, get_possible_vtables, get_possible_ctors, get_ret_instr_of_fct
from types import TrackingType
import networkx as nx
import __builtin__


def augment_definition(function, graph, definition_address, seen=None,
                       instr=None, terminate_at_mnemonic=None):
    if not seen:
        seen = defaultdict(set)

    block = function.get_containing_block(definition_address)
    assert block is not None, 'Definition not found in any block' \
                              ' (%08x).' % function.address

    if instr is None:
        instr = block.instructions(definition_address).next()
        if len(instr.definitions) == 0:  # Tail jump.
            return

    if isinstance(instr, PhiNode):
        definition = instr.definition

        work_list = [(block, definition_address, {definition})]
        source = {definition: instr}
    else:
        definition = instr.definitions[0]

        work_list = [(block, definition_address, {definition.operand})]
        source = {definition.operand: instr}

    while work_list:
        b, current_start, to_track = work_list.pop()

        # Do not track same register set into a block we have already
        # seen with this configuration.
        if to_track.issubset(seen[b.address]):
            continue

        skip_definition = False
        for instr in b.instructions(current_start):
            skip_definition = terminate_at_mnemonic and \
                    isinstance(instr, Instruction) and \
                    instr._mnemonic.startswith(terminate_at_mnemonic)

            uses = (u for u in instr.uses
                    if isinstance(u.operand, (operands.Register,
                                              operands.Memory,
                                              operands.Address,
                                              operands.Constant)))

            for u in uses:
                if u.operand in to_track:
                    graph.add_edge(source[u.operand], instr,
                                   label=u.operand)

                    if skip_definition:
                        continue

                    for d in instr.definitions:

                        # Also track register inside memory expression.
                        # NOTE: we kind of overtaint because of this.
                        if isinstance(d.operand, operands.Memory):
                            source[d.operand.base] = instr
                            to_track.add(d.operand.base)

                        source[d.operand] = instr
                        to_track.add(d.operand)

                elif isinstance(u.operand, operands.Memory) and u.operand.base in to_track:
                    graph.add_edge(source[u.operand.base], instr,
                                   label=u.operand.base)

                    if skip_definition:
                        continue

                    for d in instr.definitions:

                        # Also track register inside memory expression.
                        # NOTE: we kind of overtaint because of this.
                        if isinstance(d.operand, operands.Memory):
                            source[d.operand.base] = instr
                            to_track.add(d.operand.base)

                        source[d.operand] = instr
                        to_track.add(d.operand)

                elif isinstance(u.operand, operands.Constant):

                    if skip_definition:
                        continue

                    for d in instr.definitions:

                        if isinstance(d.operand, operands.Memory) \
                            and d.operand.base in source.keys():

                            graph.add_edge(source[d.operand.base], instr,
                                           label=d.operand.base)

        seen[b.address].update(to_track)

        follow = False
        for successor in b.successors:
            s = function.blocks[successor]

            new_track = set()
            for t in to_track:
                if t in s._in or isinstance(t, (operands.Address, operands.Memory)):
                    # Track input and follow into new block.
                    follow = True
                    new_track.add(t)
                else:
                    for phi in s._phi_nodes.values():
                        if t in phi.slots:
                            # Add edge spanning phi node, track phi
                            # definition into new block.
                            source[phi.definition] = phi
                            graph.add_edge(source[t], phi, label=t)

                            follow = True
                            new_track.add(phi.definition)
                            break

            if follow:
                work_list.append((s, None, copy(new_track)))

    return


# Given the instruction, track data flow forwards (end at call instructions).
def track_data_flow_forward(func, target_instr):

    relation = nx.DiGraph()
    augment_definition(func, relation, target_instr.address,
                       terminate_at_mnemonic="call")

    return relation


def process_subcall(all_relations, icalls_vtables, work_list, unresolvable_icalls, functions, new_operator_addrs,
                    vtv_fct_addrs, vtables, func_obj, icall_instr, used_subcall, ctr, ctors_processed):
    target_op = used_subcall["target_op"]
    if isinstance(target_op.operand, operands.Constant):
        target_addr = target_op.operand.value

        if target_addr in new_operator_addrs:

            # Mark instruction as new operator call.
            used_subcall["instr"].comment = "new operator"

            forward_relation = track_data_flow_forward(func_obj, used_subcall["instr"])

            # DEBUG
            if DEBUG_GRAPHS_DUMP_ALL and __builtin__.DEBUG_CURRENT_GRAPH_DUMP_DIR is not None:
                write_graph(forward_relation, __builtin__.DEBUG_CURRENT_GRAPH_DUMP_DIR + "/%08x_%03d_new_%08x.dot" %
                            (icall_instr.address, ctr, used_subcall["instr"].address))

            # Search for vtables used
            # (for example inlined constructors or if function is a constructor itself).
            used_vtables = get_possible_vtables(forward_relation, vtables)

            # Store results of vtables used for icall.
            if used_vtables:
                if icall_instr.address in icalls_vtables.keys():
                    icalls_vtables[icall_instr.address] |= set(map(lambda x: x["vtable"], used_vtables))
                else:
                    icalls_vtables[icall_instr.address] = set(map(lambda x: x["vtable"], used_vtables))

            # Prune graph for output.
            vtable_relation = forward_relation.copy()
            prune_vtables_graph(vtable_relation, vtables)

            # DEBUG
            if DEBUG_GRAPHS_DUMP_ALL and __builtin__.DEBUG_CURRENT_GRAPH_DUMP_DIR is not None:
                write_graph(vtable_relation, __builtin__.DEBUG_CURRENT_GRAPH_DUMP_DIR + "/%08x_%03d_new_%08x_vtables.dot" %
                            (icall_instr.address, ctr, used_subcall["instr"].address))

            # DEBUG
            print("New operator at address 0x%x used vtables: " % used_subcall["instr"].address +
                  ", ".join(map(lambda x: "0x%x" % x["vtable"], used_vtables)))

            # TODO: Do we really need to go into the new operators with our analysis if we have found vtables?

            # Prune graph first before searching for possible ctors.
            prune_new_operator_graph(forward_relation)
            # DEBUG
            if DEBUG_GRAPHS_DUMP_ALL and __builtin__.DEBUG_CURRENT_GRAPH_DUMP_DIR is not None:
                write_graph(forward_relation, __builtin__.DEBUG_CURRENT_GRAPH_DUMP_DIR + "/%08x_%03d_new_%08x_ctors.dot" %
                            (icall_instr.address, ctr, used_subcall["instr"].address))
            possible_ctors = get_possible_ctors(forward_relation)

            # Glue graphs together.
            all_relations = nx.compose(all_relations, vtable_relation)
            all_relations = nx.compose(all_relations, forward_relation)

            # DEBUG
            print("New operator at address 0x%x possible constructor calls at: " %
                  used_subcall["instr"].address +
                  ", ".join(map(lambda x: "0x%x" % x.address, possible_ctors)))

            # Search each possible constructor for vtable uses.
            for possible_ctor_call in possible_ctors:

                # First use of call instruction is always the target.
                ctor_target_op = possible_ctor_call.uses[0]
                ctor_target_addr = ctor_target_op.operand.value

                if ctor_target_addr in ctors_processed:
                    print("WARNING: Possible constructor at address 0x%x already processed. Skipping."
                          % ctor_target_addr)
                    continue

                elif ctor_target_addr not in functions.keys():
                    print("WARNING: Possible constructor at address 0x%x not found in function list."
                          % ctor_target_addr)
                    continue

                ctors_processed.add(ctor_target_addr)
                ctor_dict = functions[ctor_target_addr]
                all_relations = track_ctor(all_relations, icalls_vtables, functions, vtables, ctor_dict["ssa"],
                                           possible_ctor_call, used_subcall["instr"], 0, ctors_processed, icall_instr,
                                           ctr)

        # Only needed if we analyze a program with vtv (for example to generate the ground truth).
        elif target_addr in vtv_fct_addrs:

            # Emulate VTV stub to verify vtable looks like this:
            # https://github.com/gcc-mirror/gcc/blob/master/libstdc%2B%2B-v3/libsupc%2B%2B/vtv_stubs.cc
            # const void*
            # __VLTVerifyVtablePointer(void**, const void* vtable_ptr)
            # { return vtable_ptr; }
            # => return value contains always vtable pointer


            used_subcall["instr"].comment = "VTV"
            vtv_arg_reg = {"instr": used_subcall["instr"], "arg_idx": _ARG_REGISTERS[1]}

            # DEBUG
            print("VTV call at address 0x%x used argument registers: %s" %
                  (used_subcall["instr"].address, __builtin__.REGISTERS.to_str(_ARG_REGISTERS[1])))

            work_list.append((used_subcall["instr"].address, vtv_arg_reg, TrackingType.caller))

        elif target_addr not in functions.keys():
            print("WARNING: Subcall target address 0x%x not found in function list." % target_addr)

        else:

            # DEBUG
            print("Subcall at address 0x%x with target address: 0x%x" %
                  (used_subcall["instr"].address, target_addr))

            subcall_dict = functions[target_addr]
            used_ret_instrs = get_ret_instr_of_fct(subcall_dict["ssa"])

            for used_ret_instr in used_ret_instrs:
                temp = {"instr": used_subcall["instr"],
                        "caller_target_op": used_subcall["target_op"],
                        "callee_ret_op": used_ret_instr["ret_op"]}
                work_list.append((used_ret_instr["instr"].address, temp, TrackingType.subcall))

    elif isinstance(target_op.operand, (operands.Memory, operands.Register)):
        # Try to resolve the icall with the help of used vtables.
        if used_subcall["instr"].address in icalls_vtables.keys():

            # If target operand is a register consider it a call to the first function in the vtable,
            # otherwise calculate index.
            index = 0
            if isinstance(target_op.operand, operands.Memory):
                index = target_op.operand.offset.value / 8

            for vtable_addr in icalls_vtables[used_subcall["instr"].address]:
                # Get function address for icall from vtable.
                function_entries = vtables[vtable_addr]
                if not (0 <= index < len(function_entries)):
                    print("WARNING: Index %d is out of bounds for vtable %08x for icall at address 0x%x. " %
                          (index, vtable_addr, used_subcall["instr"].address) +
                          "Skipping.")
                    continue
                target_addr = function_entries[index]
                if target_addr not in functions.keys():
                    print("WARNING: Subcall target address 0x%x (vtable %08x and index %d) not found in" %
                          (target_addr, vtable_addr, index) +
                          "function list. Skipping.")
                    continue

                # DEBUG
                print("Subcall at address 0x%x with target address: 0x%x (vtable %08x and index %d)" %
                      (used_subcall["instr"].address, target_addr, vtable_addr, index))

                subcall_dict = functions[target_addr]
                used_ret_instrs = get_ret_instr_of_fct(subcall_dict["ssa"])

                for used_ret_instr in used_ret_instrs:
                    temp = {"instr": used_subcall["instr"],
                            "caller_target_op": used_subcall["target_op"],
                            "callee_ret_op": used_ret_instr["ret_op"]}
                    work_list.append((used_ret_instr["instr"].address, temp, TrackingType.subcall))

        # We can not resolve this icall for the moment.
        else:
            print("WARNING: Do not know how to handle icall at address 0x%x. Skipping." %
                  used_subcall["instr"].address)

            # Store unresolvable icalls for a later analysis run.
            if used_subcall["instr"].address not in unresolvable_icalls.keys():
                unresolvable_icalls[used_subcall["instr"].address] = [{"start_icall": icall_instr.address}]
            else:
                unresolvable_icalls[used_subcall["instr"].address].append({"start_icall": icall_instr.address})
    else:
        raise NotImplementedError("Do not know how to handle type '%s' of target of subcall." %
                                  target_op.operand.__class__)

    return all_relations


# Recursively track constructor to find vtable usages.
def track_ctor(all_relations, icalls_vtables, functions, vtables, func, call_instr, new_instr, call_depth, ctors_processed, icall_instr, base_ctr=0, sub_ctr=0):

    icall_addr = icall_instr.address

    # TODO Still costs a lot. Is there a better way to stop tracking possible constructors? Like no vtable was found, do not go deeper?
    if _CTOR_CALL_DEPTH > 0 and call_depth >= _CTOR_CALL_DEPTH:
        print("WARNING: Call depth reached. Do not track constructor 0x%x" % func.address)
        return all_relations

    # DEBUG
    print("Tracking constructor at address: 0x%x" % func.address)

    used_arg_instrs = get_instrs_using_arg_reg(func, _ARG_REGISTERS[0])

    # Generate a graph that contains
    forward_relation = nx.DiGraph()
    ctor_node = "Ctor_%08x" % func.address
    forward_relation.add_node(ctor_node)
    for used_arg_instr in used_arg_instrs:

        relation = track_data_flow_forward(func, used_arg_instr)
        forward_relation = nx.compose(forward_relation, relation)
        forward_relation.add_edge(ctor_node, used_arg_instr, label="arg")

    # DEBUG
    if DEBUG_GRAPHS_DUMP_ALL and __builtin__.DEBUG_CURRENT_GRAPH_DUMP_DIR is not None:
        write_graph(forward_relation, __builtin__.DEBUG_CURRENT_GRAPH_DUMP_DIR + "/%08x_%03d_ctor_%08x.dot" %
                   (icall_addr, base_ctr, func.address))

    # Search for vtables used
    # (for example inlined constructors or if function is a constructor itself).
    used_vtables = get_possible_vtables(forward_relation, vtables)

    # Store results of vtables used for icall.
    if used_vtables:
        if icall_instr.address in icalls_vtables.keys():
            icalls_vtables[icall_instr.address] |= set(map(lambda x: x["vtable"], used_vtables))
        else:
            icalls_vtables[icall_instr.address] = set(map(lambda x: x["vtable"], used_vtables))

    # Artificially increase call depth in order to avoid state explosions during forward tracking.
    # (but still continue tracking in order to compensate for wrapper functions).
    if not used_vtables:
        call_depth += 1
    # Artifically decrease call depth if we have found a vtable in the current function (in order to find
    # a chain of vtables).
    else:
        call_depth -= 1

    # Prune graph for output.
    vtable_relation = forward_relation.copy()
    prune_vtables_graph(vtable_relation, vtables)

    # DEBUG
    if DEBUG_GRAPHS_DUMP_ALL and __builtin__.DEBUG_CURRENT_GRAPH_DUMP_DIR is not None:
        write_graph(vtable_relation, __builtin__.DEBUG_CURRENT_GRAPH_DUMP_DIR + "/%08x_%03d_new_%08x_vtables_%08x.dot" %
                    (icall_addr, base_ctr, new_instr.address, func.address))

    # DEBUG
    print("New operator at address 0x%x used vtables: " % new_instr.address +
          ", ".join(map(lambda x: "0x%x" % x["vtable"], used_vtables)))

    # TODO: Do we really need to go into the new operators with our analysis if we have found vtables?

    # Prune graph first before searching for possible ctors.
    prune_new_operator_graph(forward_relation)
    # DEBUG
    if DEBUG_GRAPHS_DUMP_ALL and __builtin__.DEBUG_CURRENT_GRAPH_DUMP_DIR is not None:
        write_graph(forward_relation, __builtin__.DEBUG_CURRENT_GRAPH_DUMP_DIR + "/%08x_%03d_new_%08x_ctors_%08x.dot" %
                    (icall_addr, base_ctr, new_instr.address, func.address))
    possible_ctors = get_possible_ctors(forward_relation)

    # Glue graphs together.
    all_relations = nx.compose(all_relations, vtable_relation)
    all_relations = nx.compose(all_relations, forward_relation)
    all_relations.add_edge(call_instr, ctor_node, label="call")

    # DEBUG
    if DEBUG_GRAPHS_DUMP_ALL and __builtin__.DEBUG_CURRENT_GRAPH_DUMP_DIR is not None:
        write_graph(all_relations, __builtin__.DEBUG_CURRENT_GRAPH_DUMP_DIR + "/%08x_%03d_all_ctor_%03d.dot" %
                    (icall_addr, base_ctr, sub_ctr))

    # DEBUG
    print("New operator at address 0x%x possible constructor calls at: " %
          new_instr.address +
          ", ".join(map(lambda x: "0x%x" % x.address, possible_ctors)))

    # Search each possible constructor for vtable uses.
    for possible_ctor_call in possible_ctors:
        sub_ctr += 1

        # First use of call instruction is always the target.
        ctor_target_op = possible_ctor_call.uses[0]
        ctor_target_addr = ctor_target_op.operand.value

        if ctor_target_addr in ctors_processed:
            print("WARNING: Possible constructor at address 0x%x already processed. Skipping."
                  % ctor_target_addr)
            continue

        elif ctor_target_addr not in functions.keys():
            print("WARNING: Possible constructor at address 0x%x not found in function list."
                  % ctor_target_addr)
            continue

        ctors_processed.add(ctor_target_addr)
        ctor_dict = functions[ctor_target_addr]
        all_relations = track_ctor(all_relations, icalls_vtables, functions, vtables, ctor_dict["ssa"],
                                   possible_ctor_call, new_instr, call_depth+1, ctors_processed, icall_instr, base_ctr,
                                   sub_ctr)

    return all_relations