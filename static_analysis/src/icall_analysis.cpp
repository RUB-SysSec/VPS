#include "icall_analysis.h"

using namespace std;


VtableCallInstruction::VtableCallInstruction(uint64_t addr,
                                             const VTable &vtable,
                                             const Function &function)
    : BaseInstructionSSA("vtable call", addr),
      _vtable(vtable),
      _function(function) {
    _type = SSAInstrTypeVtableCall;
}

VtableCallInstruction::VtableCallInstruction(const VtableCallInstruction &obj)
    : BaseInstructionSSA(obj),
      _vtable(obj.get_vtable()),
      _function(obj.get_function()) {
}

bool VtableCallInstruction::operator ==(const BaseInstructionSSA &other) const {
    if(_type != other.get_type()) {
        return false;
    }

    const VtableCallInstruction &other_typed =
                              static_cast<const VtableCallInstruction &>(other);

    const VTable &other_vtable = other_typed.get_vtable();
    if(this->get_mnemonic() == other.get_mnemonic()
       && this->get_address() == other_typed.get_address()
       && _vtable.index == other_vtable.index
       && _function.get_entry() == other_typed.get_function().get_entry()) {

        return true;
    }
    return false;
}

size_t VtableCallInstruction::hash() const {
    size_t h = this->get_type();
    std::hash_combine(h, std::hash<std::string>()(this->get_mnemonic()));
    std::hash_combine(h, this->get_address());
    std::hash_combine(h, _function.get_entry());
    std::hash_combine(h, _vtable.index);
    return h;
}

const VTable &VtableCallInstruction::get_vtable() const {
    return _vtable;
}

const Function &VtableCallInstruction::get_function() const {
    return _function;
}

ICallAnalysis::ICallAnalysis(const string &module_name,
                             const string &target_dir,
                             Translator &translator,
                             const VCallFile &vcalls,
                             const VTableFile &vtables,
                             const unordered_set<uint64_t> &new_operators,
                             const unordered_set<uint64_t> &vtv_verify_addrs,
                             uint64_t start_addr)
    : BacktraceAnalysis(module_name,
                        target_dir,
                        "icalls",
                        translator,
                        vcalls,
                        vtables,
                        new_operators,
                        start_addr),
    _vtv_verify_addrs(vtv_verify_addrs),
    _this_vtables(vtables.get_this_vtables()),
    _this_vtable_entries(vtables.get_this_vtable_entries()),
    _file_format(translator.get_file_format()) {

    switch(_file_format) {
        case FileFormatELF64:
        case FileFormatPE64:
            _addr_size = 8;
            break;
        default:
            throw runtime_error("Unknown file format.");
    }

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

    start.operand = start_instr->get_uses().at(0);

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

void ICallAnalysis::post_merge_graphs(
                                const GraphDataFlow &src_graph,
                                const NodeToNodeMap &old_new_map) {
}

void ICallAnalysis::pre_obtain() {
}

void ICallAnalysis::post_obtain() {
}

void ICallAnalysis::pre_augment_use(GraphDataFlow&,
                                    InstrGraphNodeMap&,
                                    const Function&,
                                    const OperandSSAPtr&,
                                    const BaseInstructionSSAPtr&,
                                    const TrackingInstruction &) {
}

void ICallAnalysis::post_augment_use(GraphDataFlow &graph,
                                     InstrGraphNodeMap &instr_graph_node_map,
                                     const Function &function,
                                     const OperandSSAPtr &initial_use,
                                     const BaseInstructionSSAPtr &initial_instr,
                                     const TrackingInstruction&) {

    // Remove all unnecessary nodes from the current graph.
    remove_unnecessary_nodes(graph,
                             instr_graph_node_map,
                             initial_use,
                             initial_instr);

    // Add artificial nodes for a call from a vtable.
    uint64_t func_addr = function.get_entry();
    if(_this_vtable_entries.find(func_addr) != _this_vtable_entries.cend()) {
        add_vtable_call_nodes(graph,
                              instr_graph_node_map,
                              function,
                              initial_use);
    }

    // After all unnecessary nodes are removed from the graph,
    // process the current graph and mark specific nodes.
    auto vertices = boost::vertices(graph);
    for(auto it = vertices.first; it != vertices.second; ++it) {

        // Mark vtv verify calls.
        if(mark_node_vtv(graph, *it)) {
        }
        // Mark vtable usages.
        else if(mark_node_vtable(graph, *it)) {
        }
    }
}

void ICallAnalysis::add_vtable_call_nodes(
                                        GraphDataFlow &graph,
                                        InstrGraphNodeMap &instr_graph_node_map,
                                        const Function &function,
                                        const OperandSSAPtr &initial_use) {

    struct VtableTarget {
        BaseInstructionSSAPtr instr;
        OperandSSAPtr operand;

        /*!
         * \brief Type that specifies how `VtableTarget` is hashed.
         */
        struct Hash {
            std::size_t operator() (const VtableTarget &e) const {
                size_t h = 0;
                std::hash_combine(h, e.instr->hash());
                std::hash_combine(h, e.operand->hash());
                return h;
            }
        };
        /*!
         * \brief Type that specifies how `VtableTarget` is compared.
         */
        struct Compare {
            size_t operator() (VtableTarget const &a,
                               VtableTarget const &b) const {
                if(*(a.instr) == *(b.instr)
                   && *(a.operand) == *(b.operand)) {
                    return true;
                }
                return false;
            }
        };
    };
    unordered_set<VtableTarget,
                  VtableTarget::Hash,
                  VtableTarget::Compare> vtable_targets;

    // Search nodes that use an argument register.
    auto vertices = boost::vertices(graph);
    for(auto it = vertices.first; it != vertices.second; ++it) {
        const BaseInstructionSSAPtr &instr = graph[*it].instr;

        // Ignore "call" instructions.
        if(instr->is_call()) {
            continue;
        }

        for(const OperandSSAPtr &use_op : instr->get_uses()) {
            if(use_op->is_arg_register()) {
                switch(use_op->get_type()) {
                    case SSAOpTypeRegisterX64: {

                        // Phi index is always 0 for the first usage.
                        const RegisterX64SSA &reg =
                                   static_cast<const RegisterX64SSA &>(*use_op);
                        if(reg.get_phi_index() == 0) {
                            VtableTarget target;
                            target.instr = instr;
                            target.operand = use_op;
                            vtable_targets.insert(target);
                        }
                        break;
                    }
                    default:
                        throw runtime_error("Unknown SSA register object.");
                }
            }

            else if(use_op->is_memory()) {
                switch(use_op->get_type()) {
                    case SSAOpTypeMemoryX64: {

                        // Phi index is always 0 for the first usage.
                        const MemoryX64SSA &mem =
                                     static_cast<const MemoryX64SSA &>(*use_op);
                        const RegisterX64SSA &reg = mem.get_base();
                        if(reg.get_phi_index() == 0
                           && reg.is_arg_register()) {
                            VtableTarget target;
                            target.instr = instr;
                            target.operand = use_op;
                            vtable_targets.insert(target);
                        }
                        break;
                    }
                    default:
                        throw runtime_error("Unknown SSA memory object.");
                }
            }
        }
    }

    // Special case in which we only have a tailjmp or call instruction
    // in the graph. Then also regard it for vtable calls.
    if(is_call_jmp_edge_case(graph)
       && initial_use->is_arg_register()) {
        vertices = boost::vertices(graph);
        for(auto it = vertices.first; it != vertices.second; ++it) {
            VtableTarget target;
            target.instr = graph[*it].instr;
            target.operand = initial_use;
            vtable_targets.insert(target);
            break;
        }
    }

    // Add an artificial vtable call node and connect it to the corresponding
    // argument register usages.
    for(const VtableTarget &target : vtable_targets) {
        GraphDataFlow::vertex_descriptor target_node = get_node_graph(
                                                           graph,
                                                           instr_graph_node_map,
                                                           target.instr);

        for(const VTable *vtbl_ptr :
                                _this_vtable_entries.at(function.get_entry())) {

            // Calculate address of function entry.
            size_t index = 0;
            bool found = false;
            for(size_t i = 0; i < vtbl_ptr->entries.size(); i++) {
                if(vtbl_ptr->entries.at(i) == function.get_entry()) {
                    index = i;
                    found = true;
                    break;
                }
            }
            assert(found
                   && "Not able to find function in vtable entries.");
            uint64_t addr = vtbl_ptr->addr + (index*_addr_size);

            VtableCallInstruction vtable_instr(addr, *vtbl_ptr, function);
            BaseInstructionSSAPtr vtable_instr_ptr =
                               make_shared<VtableCallInstruction>(vtable_instr);
            // Add node vtable call as node.
            GraphDataFlow::vertex_descriptor node =
                                  get_maybe_new_node_graph(graph,
                                                           instr_graph_node_map,
                                                           vtable_instr_ptr);
            graph[node].type = DataFlowNodeTypeVtableCall;

            // Add edge from vtable call to target instruction.
            GraphDataFlow::edge_descriptor edge =
                                get_maybe_new_edge_graph(graph,
                                                         node,
                                                         target_node,
                                                         target.operand);
            graph[edge].type = DataFlowEdgeTypeVtableCall;
        }
    }

    // When the function is a virtual function and we do not know any virtual
    // function xrefs for it, store function address as unresolvable virtual
    // function in order to repeat the analysis if we can resolve it afterwards.
    if(!vtable_targets.empty()
       && function.get_vfunc_xrefs().empty()) {
        _unresolvable_vfunc.insert(function.get_entry());
    }
}

void ICallAnalysis::remove_unnecessary_nodes(
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

bool ICallAnalysis::mark_node_vtable(GraphDataFlow &graph,
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
                graph[node].type = DataFlowNodeTypeVtable;
                return true;
            }
        }
    }
    return false;
}

bool ICallAnalysis::mark_node_vtv(GraphDataFlow &graph,
                                   GraphDataFlow::vertex_descriptor node) {

    // Only process "call" instructions that are also starting points
    // in the graph (but ignore a call instruction that is the start
    // of the current analysis pass).
    const BaseInstructionSSAPtr &call_instr = graph[node].instr;
    auto in_edges = boost::in_edges(node, graph);
    if(in_edges.first != in_edges.second
       || !call_instr->is_call()
       || graph[node].type == DataFlowNodeTypeStart) {
        return false;
    }

    // The first use of a call instruction is always the target.
    const OperandSSAPtr &target_op = call_instr->get_uses().at(0);

    // Only consider direct calls.
    if(!target_op->is_constant()) {
        return false;
    }

    uint64_t target_addr = 0;
    switch(target_op->get_type()) {
        case SSAOpTypeConstantX64: {
            const ConstantX64SSA &temp =
                             static_cast<const ConstantX64SSA&>(*target_op);
            target_addr = temp.get_value();
            break;
        }
        case SSAOpTypeAddressX64: {
            const AddressX64SSA &temp =
                              static_cast<const AddressX64SSA&>(*target_op);
            target_addr = temp.get_value();
            break;
        }
        default:
            throw runtime_error("Unknown SSA constant object.");
    }

    // If it is a call to a vtv verify, mark the node
    // in the final graph and track its argument back.
    if(_vtv_verify_addrs.find(target_addr) != _vtv_verify_addrs.cend()) {
        graph[node].type = DataFlowNodeTypeVTVVerifyCall;
        return true;
    }
    return false;
}

void ICallAnalysis::get_next_tracking_instrs_child(
                                   TrackingInstructionSet &out_next_instrs,
                                   const GraphDataFlow &graph,
                                   const Function&,
                                   const TrackingInstruction&,
                                   const BaseInstructionSSAPtr&) {

    auto vertices = boost::vertices(graph);
    for(auto it = vertices.first; it != vertices.second; ++it) {

        // Only process "call" instructions that are also starting points
        // in the graph (but ignore a call instruction that is the start
        // of the current analysis pass).
        const BaseInstructionSSAPtr &call_instr = graph[*it].instr;
        auto in_edges = boost::in_edges(*it, graph);
        if(in_edges.first != in_edges.second
           || !call_instr->is_call()
           || graph[*it].type == DataFlowNodeTypeStart) {
            continue;
        }

        // The first use of a call instruction is always the target.
        const OperandSSAPtr &target_op = call_instr->get_uses().at(0);

        // Only consider direct calls.
        if(!target_op->is_constant()) {
            continue;
        }

        uint64_t target_addr = 0;
        switch(target_op->get_type()) {
            case SSAOpTypeConstantX64: {
                const ConstantX64SSA &temp =
                                 static_cast<const ConstantX64SSA&>(*target_op);
                target_addr = temp.get_value();
                break;
            }
            case SSAOpTypeAddressX64: {
                const AddressX64SSA &temp =
                                  static_cast<const AddressX64SSA&>(*target_op);
                target_addr = temp.get_value();
                break;
            }
            default:
                throw runtime_error("Unknown SSA constant object.");
        }

        // If it is a call to a vtv verify, track its argument back.
        if(_vtv_verify_addrs.find(target_addr) != _vtv_verify_addrs.end()) {
            GraphDataFlow::vertex_descriptor call_node =
                                   get_maybe_new_node_graph(
                                                          _graph,
                                                          _instr_graph_node_map,
                                                          call_instr);

            // Add new tracking instruction that starts tracking at the
            // vtv verify call with the rsi argument register.
            // Emulate VTV stub to verify vtable looks like this:
            // https://github.com/gcc-mirror/gcc/blob/master/libstdc%2B%2B-v3/libsupc%2B%2B/vtv_stubs.cc
            // const void*
            // __VLTVerifyVtablePointer(void**, const void* vtable_ptr)
            // { return vtable_ptr; }
            // => return value contains always vtable pointer
            TrackingInstruction next;
            next.addr = call_instr->get_address();
            next.instr_type = call_instr->get_type();
            next.type = TrackingTypeCaller;
            next.prev_node = call_node;
            next.operand = call_instr->get_uses().at(2);
            out_next_instrs.insert(next);
        }
    }
}

void ICallAnalysis::incorporate_vtable_xref_graph(
                            const GraphDataFlow &graph,
                            const InstrGraphNodeMap &instr_graph_node_map,
                            const boost::property_map<GraphDataFlow,
                                    boost::vertex_index_t>::type &indexmap,
                            const BaseInstructionSSAPtr &root_instr,
                            GraphDataFlow::vertex_descriptor &out_join_node,
                            GraphDataFlow::vertex_descriptor &out_vtable_node) {

    GraphDataFlow::vertex_descriptor root_node = get_node_graph(
                                                           graph,
                                                           instr_graph_node_map,
                                                           root_instr);

    // Bfs visitor is passed by value. To keep the state we have to
    // work on references.
    // http://www.boost.org/doc/libs/1_50_0/libs/graph/doc/breadth_first_search.html#1
    DataFlowVertexSet to_copy;
    BfsGraphDataFlowNodesVisited vis(to_copy);

    // Last argument uses bgl_named_params:
    // http://www.boost.org/doc/libs/1_58_0/libs/graph/doc/bgl_named_params.html
    // => argument "visitor" and "vertex_index_map" are passed.
    boost::breadth_first_search(graph,
                                root_node,
                                visitor(vis).vertex_index_map(indexmap));

    // Copy nodes to new graph.
    map<GraphDataFlow::vertex_descriptor, GraphDataFlow::vertex_descriptor>
                                                                    old_new_map;
    const auto vertices = boost::vertices(graph);
    for(auto it = vertices.first; it != vertices.second; ++it) {
        // Only copy nodes into the new graph that were reachable by the BFS.
        if(to_copy.find(*it) == to_copy.cend()) {
            continue;
        }

        GraphDataFlow::vertex_descriptor new_node = get_maybe_new_node_graph(
                                                          _graph,
                                                          _instr_graph_node_map,
                                                          graph[*it].instr);

        // Change the type of the start node of the vtable xref
        // graph into vtable.
        if(graph[*it].type == DataFlowNodeTypeStart) {
            _graph[new_node].type = DataFlowNodeTypeVtable;
            out_vtable_node = new_node;
        }
        else {
            _graph[new_node].type = graph[*it].type;
        }
        _graph[new_node].is_join = graph[*it].is_join;
        _graph[new_node].comment = graph[*it].comment;

        old_new_map[*it] = new_node;
    }

    // Copy edges to new graph.
    const auto edges = boost::edges(graph);
    for(auto it = edges.first; it != edges.second; ++it) {
        GraphDataFlow::vertex_descriptor old_src =
                                                 boost::source(*it, graph);
        GraphDataFlow::vertex_descriptor old_dst =
                                                 boost::target(*it, graph);

        // Only copy edges into the new graph that were reachable by the BFS.
        if(old_new_map.find(old_src) == old_new_map.cend()
           || old_new_map.find(old_dst) == old_new_map.cend()) {
            continue;
        }

        GraphDataFlow::vertex_descriptor new_src = old_new_map[old_src];
        GraphDataFlow::vertex_descriptor new_dst = old_new_map[old_dst];

        GraphDataFlow::edge_descriptor new_edge = get_maybe_new_edge_graph(
                                                       _graph,
                                                       new_src,
                                                       new_dst,
                                                       graph[*it].operand);
        _graph[new_edge].type = graph[*it].type;
        _graph[new_edge].comment = graph[*it].comment;
    }

    // Declare the node which is used to merge both graphs as join node.
    out_join_node = get_maybe_new_node_graph(_graph,
                                             _instr_graph_node_map,
                                             root_instr);
    _graph[out_join_node].is_join = true;
}

void ICallAnalysis::finalize_graph_child(GraphDataFlow&, InstrGraphNodeMap&) {
}

const std::unordered_set<uint64_t>&
                                ICallAnalysis::get_unresolvable_vfuncs() const {
    return _unresolvable_vfunc;
}
