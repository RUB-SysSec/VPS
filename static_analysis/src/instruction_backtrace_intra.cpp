#include "instruction_backtrace_intra.h"

using namespace std;

InstructionBacktraceIntra::InstructionBacktraceIntra(
                          const string &module_name,
                          const string &target_dir,
                          const string &dir_prefix,
                          Translator &translator,
                          const VCallFile &vcalls,
                          const VTableFile &vtables,
                          const unordered_set<uint64_t> &new_operators,
                          uint64_t start_addr)
    : BacktraceAnalysis(module_name,
                        target_dir,
                        dir_prefix,
                        translator,
                        vcalls,
                        vtables,
                        new_operators,
                        start_addr),
    _this_vtables(vtables.get_this_vtables()) {
}

InstructionBacktraceIntra::InstructionBacktraceIntra(
                             const string &module_name,
                             const string &target_dir,
                             Translator &translator,
                             const VCallFile &vcalls,
                             const VTableFile &vtables,
                             const unordered_set<uint64_t> &new_operators,
                             uint64_t start_addr,
                             uint32_t op_idx)
    : BacktraceAnalysis(module_name,
                        target_dir,
                        "instruction_backtrace_intra",
                        translator,
                        vcalls,
                        vtables,
                        new_operators,
                        start_addr),
    _this_vtables(vtables.get_this_vtables()) {

    // Prepare first instruction to track.
    TrackingInstruction start;
    start.addr = start_addr;
    start.type = TrackingTypeCaller;
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
                << " to process indirect call.";
        throw runtime_error(err_msg.str().c_str());
    }
    const BaseInstructionSSAPtr &start_instr = *temp_instr_ptr;

    start.operand = start_instr->get_operands().at(op_idx);

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

void InstructionBacktraceIntra::post_merge_graphs(
                                const GraphDataFlow &src_graph,
                                const NodeToNodeMap &old_new_map) {
}

void InstructionBacktraceIntra::pre_obtain() {
}

void InstructionBacktraceIntra::post_obtain() {
}

void InstructionBacktraceIntra::pre_augment_use(
                                    GraphDataFlow&,
                                    InstrGraphNodeMap&,
                                    const Function&,
                                    const OperandSSAPtr&,
                                    const BaseInstructionSSAPtr&,
                                    const TrackingInstruction &) {
}

void InstructionBacktraceIntra::post_augment_use(
                                     GraphDataFlow &graph,
                                     InstrGraphNodeMap &instr_graph_node_map,
                                     const Function&,
                                     const OperandSSAPtr &initial_use,
                                     const BaseInstructionSSAPtr &initial_instr,
                                     const TrackingInstruction&) {

    // Remove all unnecessary nodes from the current graph.
    remove_unnecessary_nodes(graph,
                             instr_graph_node_map,
                             initial_use,
                             initial_instr);

    // After all unnecessary nodes are removed from the graph,
    // process the current graph and mark specific nodes.
    auto vertices = boost::vertices(graph);
    for(auto it = vertices.first; it != vertices.second; ++it) {

        // Mark vtable usages.
        if(mark_node_vtable(graph, *it)) {
        }
    }
}

void InstructionBacktraceIntra::get_next_tracking_instrs_child(
                                   TrackingInstructionSet &out_next_instrs,
                                   const GraphDataFlow &graph,
                                   const Function&,
                                   const TrackingInstruction&,
                                   const BaseInstructionSSAPtr&) {

    // We do not want to track anything.
    out_next_instrs.clear();
}

void InstructionBacktraceIntra::finalize_graph_child(GraphDataFlow&,
                                                     InstrGraphNodeMap&) {
}

bool InstructionBacktraceIntra::mark_node_vtable(
                                     GraphDataFlow &graph,
                                     GraphDataFlow::vertex_descriptor node) {

    const BaseInstructionSSAPtr &current_instr = graph[node].instr;

    for(const auto &use_op : current_instr->get_uses()) {
        if(use_op->is_constant()) {

            uint64_t vtbl_candidate = 0;
            switch(use_op->get_type()) {
                case SSAOpTypeConstantX64: {
                    const ConstantX64SSA &temp =
                                static_cast<const ConstantX64SSA&>(*use_op);
                    vtbl_candidate = temp.get_value();
                    break;
                }
                case SSAOpTypeAddressX64: {
                    const AddressX64SSA &temp =
                                 static_cast<const AddressX64SSA&>(*use_op);
                    vtbl_candidate = temp.get_value();
                    break;
                }
                default:
                    throw runtime_error("Unknown SSA constant object.");
            }

            if(_this_vtables.find(vtbl_candidate) != _this_vtables.cend()) {

                // Only mark as vtable node if it is not the start node
                // of the analysis.
                if(_instr_graph_node_map.find(current_instr)
                        == _instr_graph_node_map.cend()
                   || _graph[node].type != DataFlowNodeTypeStart) {

                    graph[node].type = DataFlowNodeTypeVtable;
                    return true;
                }

            }
        }
    }
    return false;
}

void InstructionBacktraceIntra::remove_unnecessary_nodes(
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

    // "call" instructions are the artificial boundary which end the
    // data flow backtracing. Remove all incoming edges of a "call"
    // instruction.
    // Also, filter out certain instructions.
    auto vertices = boost::vertices(graph);
    for(auto it = vertices.first; it != vertices.second;) {
        GraphDataFlow::vertex_descriptor curr_node = *it;
        ++it;
        if(graph[curr_node].instr->is_call()) {

            // Ignore the initial instruction since we want to
            // trace its data backwards.
            if(curr_node == initial_node) {
                continue;
            }

            // Remove incoming edges.
            auto in_edges = boost::in_edges(curr_node, graph);
            while(in_edges.first != in_edges.second) {
                boost::remove_edge(*(in_edges.first), graph);
                in_edges = boost::in_edges(curr_node, graph);
            }
        }

        // Filter out certain instructions.
        else {
            const BaseInstructionSSAPtr &instr = graph[curr_node].instr;

            // Remove xor instruction that null the definition like
            // xor rcx_14 rcx_13 rcx_13
            if(instr->get_mnemonic() == "xor" // TODO architecture specific
               && *instr->get_operand(1) == *instr->get_operand(2)) {

                // Incoming and outgoing edges are handled by removing process.
                remove_node_graph(graph, instr_graph_node_map, curr_node);
            }
        }
    }

    // Remove all leaf nodes that are not the source from which we started.
    unordered_set<GraphDataFlow::vertex_descriptor> to_remove;
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
