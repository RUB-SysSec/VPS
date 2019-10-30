#include "vtable_backtrace_analysis.h"

using namespace std;


VtableBacktraceAnalysis::VtableBacktraceAnalysis(const std::string &module_name,
                        const std::string &target_dir,
                        Translator &translator,
                        const VCallFile &vcalls,
                        const VTableFile &vtables,
                        const std::unordered_set<uint64_t> &new_operators,
                        uint64_t start_addr)
    : BacktraceAnalysis(module_name,
                        target_dir,
                        "vtable_xrefs",
                        translator,
                        vcalls,
                        vtables,
                        new_operators,
                        start_addr) {

    // Prepare first instruction to track.
    TrackingInstruction start;
    start.addr = start_addr;
    start.type = TrackingTypeInstr;
    start.instr_type = SSAInstrTypeInstruction;

    // Get operand to track.
    const Function &start_func = translator.get_containing_function(start_addr);

    // `SSAInstrTypeInstruction` can only have one instruction returned
    // (otherwise the data structure is corrupted). Use the only instruction
    // from the set.
    const BaseInstructionSSAPtrSet temp_instrs =
                        start_func.get_instruction_ssa(start_addr,
                                                       SSAInstrTypeInstruction);
    const BaseInstructionSSAPtr *temp_instr_ptr = nullptr;
    for(const BaseInstructionSSAPtr &temp_instr : temp_instrs) {
        temp_instr_ptr = &temp_instr;
        break;
    }
    if(temp_instr_ptr == nullptr) {
        stringstream err_msg;
        err_msg << "Not able to find instruction with address "
                << hex << start_addr
                << " and type "
                << dec << SSAInstrTypeInstruction
                << " to process vtable xref.";
        throw runtime_error(err_msg.str().c_str());
    }
    const BaseInstructionSSAPtr &start_instr = *temp_instr_ptr;

    // Check if we have a definition.
    const OperandSSAPtrs &defs = start_instr->get_definitions();
    if(defs.empty()) {
        stringstream err_msg;
        err_msg << "Instruction "
             << *start_instr
             << " does not have definition.";
        throw runtime_error(err_msg.str().c_str());
    }
    start.operand = defs.at(0);

    // Get graph descriptors.
    GraphDataFlow::vertex_descriptor start_node =
                                  get_maybe_new_node_graph(
                                                          _graph,
                                                          _instr_graph_node_map,
                                                          start_instr);
    _graph[start_node].type = DataFlowNodeTypeStart;
    start.prev_node = 0;

    _work_queue.push(start);
}

void VtableBacktraceAnalysis::post_merge_graphs(
                                const GraphDataFlow &src_graph,
                                const NodeToNodeMap &old_new_map) {
}

void VtableBacktraceAnalysis::pre_obtain() {
}

void VtableBacktraceAnalysis::post_obtain() {
}

void VtableBacktraceAnalysis::pre_augment_use(GraphDataFlow&,
                                              InstrGraphNodeMap&,
                                              const Function&,
                                              const OperandSSAPtr&,
                                              const BaseInstructionSSAPtr&,
                                              const TrackingInstruction &) {
}

void VtableBacktraceAnalysis::post_augment_use(
                                     GraphDataFlow &graph,
                                     InstrGraphNodeMap &instr_graph_node_map,
                                     const Function&,
                                     const OperandSSAPtr &initial_use,
                                     const BaseInstructionSSAPtr &initial_instr,
                                     const TrackingInstruction &) {

    // Remove all unnecessary nodes from the current graph.
    remove_unnecessary_nodes(graph,
                             instr_graph_node_map,
                             initial_use,
                             initial_instr);

}

void VtableBacktraceAnalysis::get_next_tracking_instrs_child(
                            TrackingInstructionSet&,
                            const GraphDataFlow&,
                            const Function&,
                            const TrackingInstruction&,
                            const BaseInstructionSSAPtr&) {
}

void VtableBacktraceAnalysis::remove_unnecessary_nodes(
                                   GraphDataFlow &graph,
                                   InstrGraphNodeMap &instr_graph_node_map,
                                   const OperandSSAPtr &initial_use,
                                   const BaseInstructionSSAPtr &initial_instr) {

    // Change initial node type to `start`.
    GraphDataFlow::vertex_descriptor initial_node = get_node_graph(
                                                           graph,
                                                           instr_graph_node_map,
                                                           initial_instr);

    // Remove all incoming edges to the initial instruction that do not contain
    // the operand we are tracking currently and remove all outgoing edges
    // of the initial instruction.
    {
        auto in_edges = boost::in_edges(initial_node, graph);
        for(auto it = in_edges.first; it != in_edges.second;) {
            // Check both ways, if incoming edge contains the initial operand
            // or if the initial operand contains the incoming edge
            // (the latter can happen when we have "call [r15_6]#98" and an
            // incoming edge with r15_6).
            if(graph[*it].operand->contains_coarse(*initial_use)
               || initial_use->contains_coarse(*graph[*it].operand)) {
                ++it;
            }
            else {
                GraphDataFlow::edge_descriptor temp = *it;
                ++it;
                boost::remove_edge(temp, graph);
                in_edges = boost::in_edges(initial_node, graph);
            }
        }

        auto out_edges = boost::out_edges(initial_node, graph);
        while(out_edges.first != out_edges.second) {
            boost::remove_edge(*(out_edges.first), graph);
            out_edges = boost::out_edges(initial_node, graph);
        }
    }

    unordered_set<GraphDataFlow::vertex_descriptor> to_remove;
    auto vertices = boost::vertices(graph);
    for(auto it = vertices.first; it != vertices.second; ++it) {

        // Ignore the initial instruction since we want to
        // trace its data backwards.
        if(*it == initial_node) {
            continue;
        }

        // "call" instructions are the artificial boundary which end the
        // data flow backtracing. Remove all incoming edges of a "call"
        // instruction.
        if(graph[*it].instr->is_call()) {

            // Remove incoming edges.
            auto in_edges = boost::in_edges(*it, graph);
            while(in_edges.first != in_edges.second) {
                boost::remove_edge(*(in_edges.first), graph);
                in_edges = boost::in_edges(*it, graph);
            }
        }

        // Remove all instructions that have constants as only "use", like
        // "mov rax, 8888", since we are only interested in tracking
        // our initial vtable back. Tailjmp and call instructions
        // can still have constants as "use" operand.
        else if(graph[*it].instr->is_instruction()
                && !graph[*it].instr->is_unconditional_jmp()) {

            const OperandSSAPtrs uses = graph[*it].instr->get_uses();
            if(uses.size() == 1) {
                if(uses.at(0)->is_constant()) {
                    to_remove.insert(*it);
                }
            }
        }

        // Filter out certain instructions.
        else {
            const BaseInstructionSSAPtr &instr = graph[*it].instr;

            // Remove xor instruction that null the definition like
            // xor rcx_14 rcx_13 rcx_13
            if(instr->get_mnemonic() == "xor" // TODO architecture specific
               && *instr->get_operand(1) == *instr->get_operand(2)) {

                // Incoming and outgoing edges are handled by removing process.
                to_remove.insert(*it);
            }
        }

        // Remove edges in which the "definition" operand of the source node
        // and the "definition" operand of the destination node are different
        // memory objects, but connected via the same register operand in
        // the edge. For example, if the source is "mov [rbp_1-0x70], rax_59"
        // and the destination is "mov [rbp_1-0x60], rdi_5" and both nodes
        // are connected via "rbp_1". This happens because of our
        // "overtainting" in the augment_use() function.
        {
            // Only consider nodes where the "definition"
            // operand is a memory object.
            const OperandSSAPtrs &src_ops = graph[*it].instr->get_definitions();
            if(src_ops.empty()) {
                continue;
            }
            const OperandSSAPtr &src_op = src_ops.at(0);
            if(!src_op->is_memory()) {
                continue;
            }

            auto out_edges = boost::out_edges(*it, graph);
            auto next_it = out_edges.first;
            for(auto edge_it = next_it;
                edge_it != out_edges.second;
                edge_it = next_it) {
                ++next_it;

                // Only consider edges where the operand is a register.
                const OperandSSAPtr edge_op = graph[*edge_it].operand;
                if(!edge_op->is_register()) {
                    continue;
                }

                // Only continue if the edge belongs to the memory
                // "definition" operand
                if(!src_op->contains(*edge_op)) {
                    continue;
                }

                // Only consider nodes where the "definition" operand is
                // a memory object.
                GraphDataFlow::vertex_descriptor dst_node =
                                                 boost::target(*edge_it, graph);
                const OperandSSAPtrs &dst_ops =
                                       graph[dst_node].instr->get_definitions();
                if(dst_ops.empty()) {
                    continue;
                }
                const OperandSSAPtr &dst_op = dst_ops.at(0);
                if(!dst_op->is_memory()) {
                    continue;
                }

                // We are only interested in different memory operands.
                if(*src_op == *dst_op) {
                    continue;
                }

                // Only continue if the edge belongs to the memory
                // "definition" operand
                if(!dst_op->contains(*edge_op)) {
                    continue;
                }

                // Ignore if the destination node has the operand as a
                // "use" operand.
                bool skip = false;
                for(const auto &use_op : graph[dst_node].instr->get_uses()) {
                    if(use_op->contains(*edge_op)) {
                        skip = true;
                        break;
                    }
                }
                if(skip) {
                    continue;
                }

                boost::remove_edge(*edge_it, graph);
            }
        }
    }

    // Remove all nodes and their incoming edges.
    for(const auto vertex : to_remove) {
        remove_node_graph(graph, instr_graph_node_map, vertex);
    }

    // Remove all leaf nodes that are not the source from which we started.
    bool changed = true;
    while(changed) {
        changed = false;
        to_remove.clear();
        vertices = boost::vertices(graph);
        for(auto it = vertices.first; it != vertices.second; ++it) {
            // Ignore the initial instruction.
            if(*it == initial_node) {
                continue;
            }

            // Mark node for removal that does not have outgoing edges.
            const auto edges = boost::out_edges(*it, graph);
            if(edges.first == edges.second) {
                to_remove.insert(*it);
                changed = true;
            }
        }

        // Remove all nodes and their incoming edges.
        for(const auto vertex : to_remove) {
            remove_node_graph(graph, instr_graph_node_map, vertex);
        }
    }

    // Check if each node has a path to the initial node.
    // If it does not have one then we have a component in the graph that
    // is not connected to the main component we are searching for. Remove
    // these nodes.
    vertices = boost::vertices(graph);
    to_remove.clear();
    boost::property_map<GraphDataFlow, boost::vertex_index_t>::type indexmap =
                                                         create_indexmap(graph);
    for(auto it = vertices.first; it != vertices.second; ++it) {

        // Ignore nodes that do not reach the initial node.
        if(to_remove.find(*it) != to_remove.end()) {
            continue;
        }

        // Bfs visitor is passed by value. To keep the state we have to
        // work on references.
        // http://www.boost.org/doc/libs/1_50_0/libs/graph/doc/breadth_first_search.html#1
        DataFlowVertexSet visited;
        BfsGraphDataFlowNodesVisited vis(visited);

        // Last argument uses bgl_named_params:
        // http://www.boost.org/doc/libs/1_58_0/libs/graph/doc/bgl_named_params.html
        // => argument "visitor" and "vertex_index_map" are passed.
        boost::breadth_first_search(graph,
                                    *it,
                                    visitor(vis).vertex_index_map(indexmap));

        // When the bfs did not visit the initial node,
        // it has no path to the initial node and thus can be removed.
        if(visited.find(initial_node) == visited.end()) {
            to_remove.insert(visited.begin(), visited.end());
        }
    }

    // Remove all nodes and their incoming edges.
    for(const auto vertex : to_remove) {
        remove_node_graph(graph, instr_graph_node_map, vertex);
    }
}

void VtableBacktraceAnalysis::finalize_graph_child(GraphDataFlow &,
                                                   InstrGraphNodeMap &) {
}
