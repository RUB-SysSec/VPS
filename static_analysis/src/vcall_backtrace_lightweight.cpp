#include "vcall_backtrace_lightweight.h"

using namespace std;

VCallBacktraceLightweight::VCallBacktraceLightweight(
                             const string &module_name,
                             const string &target_dir,
                             Translator &translator,
                             const VCallFile &vcalls,
                             const VTableFile &vtables,
                             const unordered_set<uint64_t> &new_operators,
                             const unordered_set<uint64_t> &vtv_verify_addrs,
                             uint64_t start_addr)
    : InstructionBacktraceIntra(module_name,
                        target_dir,
                        "vcall_lightweight",
                        translator,
                        vcalls,
                        vtables,
                        new_operators,
                        start_addr),
    _vtv_verify_addrs(vtv_verify_addrs) {

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
    _analysis_init_operand = VCallBacktraceOperandTarget;

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

void VCallBacktraceLightweight::post_merge_graphs(
                                const GraphDataFlow &src_graph,
                                const NodeToNodeMap &old_new_map) {

    // Store a mapping to know which node belongs to which icall operand
    // we traced.
    for(const auto &kv : old_new_map) {
        _node_init_operand_map[kv.second].insert(_analysis_init_operand);
    }
}

void VCallBacktraceLightweight::pre_obtain() {
}

void VCallBacktraceLightweight::post_obtain() {

    // We need to run the backtrace on the target of the indirect call
    // and the this pointer argument. When the operand that holds
    // the target is finished, start the analysis on the operand that
    // holds the this pointer.
    if(_analysis_init_operand == VCallBacktraceOperandTarget) {
        _analysis_init_operand = VCallBacktraceOperandThis;

        // Create a new start instruction.
        TrackingInstruction start;
        start.addr = _start_addr; // TODO architecture specific
        start.type = TrackingTypeCaller;
        start.instr_type = SSAInstrTypeInstruction;
        start.prev_node = 0;

        // Get operand to track.
        const Function &start_func = _translator.get_containing_function(
                                                                   _start_addr);

        // `SSAInstrTypeInstruction` can only have one instruction returned
        // (otherwise the data structure is corrupted). Use the only instruction
        // from the set.
        const BaseInstructionSSAPtrSet temp_instrs =
                        start_func.get_instruction_ssa(_start_addr,
                                                       SSAInstrTypeInstruction);
        const BaseInstructionSSAPtr *temp_instr_ptr = nullptr;
        for(const BaseInstructionSSAPtr &temp_instr : temp_instrs) {
            temp_instr_ptr = &temp_instr;
            break;
        }
        if(temp_instr_ptr == nullptr) {
            stringstream err_msg;
            err_msg << "Not able to find instruction with address "
                    << hex << _start_addr
                    << " and type "
                    << dec << SSAInstrTypeInstruction
                    << " to process indirect call.";
            throw runtime_error(err_msg.str().c_str());
        }
        const BaseInstructionSSAPtr &start_instr = *temp_instr_ptr;

        start.operand = start_instr->get_uses().at(1); // TODO architecture specific

        _work_queue.push(start);

        obtain(200); // TODO make rounds configurable
    }
}

void VCallBacktraceLightweight::pre_augment_use(
                                    GraphDataFlow&,
                                    InstrGraphNodeMap&,
                                    const Function&,
                                    const OperandSSAPtr&,
                                    const BaseInstructionSSAPtr&,
                                    const TrackingInstruction &) {
}

void VCallBacktraceLightweight::post_augment_use(
                                     GraphDataFlow &graph,
                                     InstrGraphNodeMap &instr_graph_node_map,
                                     const Function &function,
                                     const OperandSSAPtr &initial_use,
                                     const BaseInstructionSSAPtr &initial_instr,
                                     const TrackingInstruction &initial_track) {

    InstructionBacktraceIntra::post_augment_use(graph,
                                                instr_graph_node_map,
                                                function,
                                                initial_use,
                                                initial_instr,
                                                initial_track);

    // After all unnecessary nodes are removed from the graph,
    // process the current graph and mark specific nodes.
    auto vertices = boost::vertices(graph);
    for(auto it = vertices.first; it != vertices.second; ++it) {

        // Mark vtv verify calls.
        if(mark_node_vtv(graph, *it)) {
        }
    }
}

void VCallBacktraceLightweight::get_next_tracking_instrs_child(
                                   TrackingInstructionSet &out_next_instrs,
                                   const GraphDataFlow &graph,
                                   const Function&,
                                   const TrackingInstruction&,
                                   const BaseInstructionSSAPtr&) {

    // We do not want to track anything new except a vtv call.
    out_next_instrs.clear();

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

void VCallBacktraceLightweight::finalize_graph_child(
                                      GraphDataFlow &graph,
                                      InstrGraphNodeMap &instr_graph_node_map) {

    // Special call instructions that handle only return instructions are added
    // at the "finalize_graph()" function and therefore we do not have
    // a mapping to which init operand analysis it belongs to. We have to
    // add it manually.
    auto vertices = boost::vertices(graph);
    unordered_set<GraphDataFlow::vertex_descriptor> all_vertices;
    for(auto it = vertices.first; it != vertices.second; ++it) {

        if(_graph[*it].instr->is_call()
           && _graph[*it].instr->get_type() == SSAInstrTypeCallOfRet) {

            auto out_edges = boost::out_edges(*it, graph);
            for(auto edge_it = out_edges.first;
                edge_it != out_edges.second;
                ++edge_it) {

                GraphDataFlow::vertex_descriptor dst_node =
                                                 boost::target(*edge_it, graph);

                // Copy init operand type from destination node.
                for(auto init_op : _node_init_operand_map.at(dst_node)) {
                    _node_init_operand_map[*it].insert(init_op);
                }
            }
        }

        all_vertices.insert(*it);
    }

    // While addind the specialized call instruction for returns, it can
    // happen that the original call instruction is removed from the graph
    // but is still in this map. Therefore, we have to remove it manually.
    for(auto it = _node_init_operand_map.begin();
        it != _node_init_operand_map.end();) {

        if(all_vertices.find(it->first) == all_vertices.end()) {
            it = _node_init_operand_map.erase(it);
        }
        else {
            ++it;
        }
    }
}

bool VCallBacktraceLightweight::mark_node_vtv(
                                        GraphDataFlow &graph,
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

const NodeInitOperandMap &VCallBacktraceLightweight::get_node_init_op_map()
                                                                         const {
    return _node_init_operand_map;
}
