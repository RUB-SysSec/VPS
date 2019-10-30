#include "backtrace_analysis.h"

using namespace std;


CallOfRetInstruction::CallOfRetInstruction(
                                      const ssa::BaseInstruction &instruction)
    : InstructionSSA(instruction) {
    _type = SSAInstrTypeCallOfRet;
}

CallOfRetInstruction::CallOfRetInstruction(const InstructionSSA &instruction)
    : InstructionSSA(instruction) {
    _type = SSAInstrTypeCallOfRet;
}

CallOfRetInstruction::CallOfRetInstruction(const CallOfRetInstruction &obj)
    : InstructionSSA(obj) {
}

BacktraceAnalysis::BacktraceAnalysis(
                                   const string &module_name,
                                   const string &target_dir,
                                   const string &dir_prefix,
                                   Translator &translator,
                                   const VCallFile &vcalls,
                                   const VTableFile &vtables,
                                   const unordered_set<uint64_t> &new_operators,
                                   uint64_t start_addr) :
    _module_name(module_name),
    _target_dir(target_dir),
    _translator(translator),
    _functions(_translator.get_functions()),
    _vtables(vtables),
    _vcalls(vcalls),
    _new_operators(new_operators),
    _graph(_master_graph),
    _instr_graph_node_map(_master_instr_graph_node_map) {

    basic_ctor(start_addr, dir_prefix);
}

BacktraceAnalysis::BacktraceAnalysis(
                              const std::string &module_name,
                              const std::string &target_dir,
                              const string &dir_prefix,
                              Translator &translator,
                              const VCallFile &vcalls,
                              const VTableFile &vtables,
                              const std::unordered_set<uint64_t> &new_operators,
                              uint64_t start_addr,
                              GraphDataFlow &target_graph,
                              InstrGraphNodeMap &instr_graph_node_map) :
    _module_name(module_name),
    _target_dir(target_dir),
    _translator(translator),
    _functions(_translator.get_functions()),
    _vtables(vtables),
    _vcalls(vcalls),
    _new_operators(new_operators),
    _graph(target_graph),
    _instr_graph_node_map(instr_graph_node_map) {

    basic_ctor(start_addr, dir_prefix);
}

void BacktraceAnalysis::basic_ctor(uint64_t start_addr,
                                   const string &dir_prefix) {
    _start_addr = start_addr;

    // Create directory for graph dumps.
    stringstream dump_dir;
    dump_dir << _target_dir
             << "/engels_"
             << _module_name
             << "/"
             << dir_prefix
             << "/"
             << setfill('0') << setw(8) << hex << start_addr
             << "/";
    _graph_dump_dir = dump_dir.str();
    try {
        boost::filesystem::create_directories(_graph_dump_dir.c_str());
    }
    catch(...) {
        stringstream err_msg;
        err_msg << "Not able to create directory: " << _graph_dump_dir;
        throw runtime_error(err_msg.str().c_str());
    }
}

void BacktraceAnalysis::draw_final_edge(
                                      const TrackingInstruction &curr,
                                      const BaseInstructionSSAPtr &curr_instr) {
    if(curr.prev_node != 0) {
        switch(curr.type) {
            case TrackingTypeCaller: {
                GraphDataFlow::vertex_descriptor curr_node =
                                   get_maybe_new_node_graph(
                                                          _graph,
                                                          _instr_graph_node_map,
                                                          curr_instr);
                GraphDataFlow::edge_descriptor new_edge =
                                    get_maybe_new_edge_graph(_graph,
                                                             curr_node,
                                                             curr.prev_node,
                                                             curr.operand);
                _graph[new_edge].type = DataFlowEdgeTypeCall;
                break;
            }

            case TrackingTypeTailjmp: {
                GraphDataFlow::vertex_descriptor curr_node =
                          get_maybe_new_node_graph(_graph,
                                                   _instr_graph_node_map,
                                                   curr_instr);
                // Since pre_processing_tailjmp() already adds a node and
                // an edge for the tailjmp instruction we only have to
                // add an edge if augment_use() was able to track the
                // data flow back.
                if(curr_node != curr.prev_node) {
                    GraphDataFlow::edge_descriptor new_edge =
                                    get_maybe_new_edge_graph(_graph,
                                                             curr_node,
                                                             curr.prev_node,
                                                             curr.operand);
                    _graph[new_edge].type = DataFlowEdgeTypeJmp;
                }
                break;
            }

            case TrackingTypeInstr: {
                GraphDataFlow::vertex_descriptor curr_node =
                               get_maybe_new_node_graph(_graph,
                                                        _instr_graph_node_map,
                                                        curr_instr);

                // We have no information about the edge we have to draw.
                // But it is safe to assume that the definition of the
                // operand of the current instruction is flowing to the
                // previous instruction. Therefore use them to draw the
                // edge.
                for(const OperandSSAPtr &def_op
                    : curr_instr->get_definitions()) {

                    get_maybe_new_edge_graph(_graph,
                                             curr_node,
                                             curr.prev_node,
                                             def_op);
                }
                break;
            }

            case TrackingTypeRet: {
                GraphDataFlow::vertex_descriptor curr_node =
                                   get_maybe_new_node_graph(
                                                          _graph,
                                                          _instr_graph_node_map,
                                                          curr_instr);
                GraphDataFlow::edge_descriptor new_edge =
                                    get_maybe_new_edge_graph(_graph,
                                                             curr_node,
                                                             curr.prev_node,
                                                             curr.operand);
                _graph[new_edge].type = DataFlowEdgeTypeRet;
                break;
            }

            default:
                throw runtime_error("Do not know tracking type.");
        }
    }
}

bool BacktraceAnalysis::obtain(uint32_t num_rounds) {

    // Execute specialization specific pre obtain function.
    pre_obtain();

    uint32_t max_rounds = _round + num_rounds;

    // Process until either the work_queue is empty or our limit is reached.
    while(!_work_queue.empty() && _round < max_rounds) {

        // Get current instruction we have to process (do not process
        // same instruction twice).
        TrackingInstruction curr = _work_queue.front();
        _work_queue.pop();

        const Function &curr_func =
                                 _translator.get_containing_function(curr.addr);

        // Find the correct instruction we want to trace back
        // (since multiple instructions can have the same address like
        // multiple phi nodes).
        const BaseInstructionSSAPtrSet temp_instrs =
                                 curr_func.get_instruction_ssa(curr.addr,
                                                               curr.instr_type);
        const BaseInstructionSSAPtr *temp_instr_ptr = nullptr;
        for(const BaseInstructionSSAPtr &temp_instr : temp_instrs) {
            // If we were searching for a SSA instruction, we can only
            // get one back (otherwise the data ist corrupted).
            if(curr.instr_type == SSAInstrTypeInstruction) {
                temp_instr_ptr = &temp_instr;
                break;
            }

            // If it is not a SSA instruction (i.e., phi node, calling
            // convention), we can get multiple back and have to
            // search for the correct one.
            else {
                for(const auto &op : temp_instr->get_uses()) {
                    if(*(curr.operand) == *op) {
                        temp_instr_ptr = &temp_instr;
                        break;
                    }
                }
            }
            if(temp_instr_ptr != nullptr) {
                break;
            }
        }
        if(temp_instr_ptr == nullptr) {
            stringstream err_msg;
            err_msg << "Not able to find instruction with address "
                    << hex << curr.addr
                    << " and type "
                    << dec << curr.instr_type
                    << " for backtrace analysis.";
            throw runtime_error(err_msg.str().c_str());
        }
        const BaseInstructionSSAPtr &curr_instr = *temp_instr_ptr;

        // Check if we already processed the instruction
        // for the given register in order to avoid recursion infinity loops.
        if(_processed_instrs.find(curr) != _processed_instrs.end()) {

            // Compare of `TrackingInstruction` does not consider prev_node.
            // Therefore, we manually draw an edge from the previous node
            // to the current processed one (if it already exists, nothing
            // will change in the final graph).
            draw_final_edge(curr, curr_instr);

            continue;
        }
        _processed_instrs.insert(curr);

#if DEBUG_PRINT
        cout << "Round: " << dec << _round
             << "; Current instruction: " << hex << curr.addr
             << "; Current Operand: " << *curr.operand
             << "; Current Type: " << curr.type
             << "; Function address: " << hex << curr_func.get_entry() << "\n";
#endif

        // Go through all preprocessing for the corresponding tracking type.
        TrackingInstructionSet next_instrs;
        switch(curr.type) {
            case TrackingTypeTailjmp: {
                // Preprocess tailjmp and let the preprocessing decide
                // if we track the current tracking job or if we do not
                // track it but have new ones to track.
                bool process = pre_processing_tailjmp(next_instrs,
                                                      curr,
                                                      curr_func,
                                                      curr_instr);
                for(const auto &next_instr : next_instrs) {
                    _work_queue.push(next_instr);

                }

                // Finalize round.
                if(!process) {
                    _round++;
                    continue;
                }
                break;
            }
            default:
                break;
        }

        // Give the analysis contol over the graph we want to create
        // before we track the operand back.
        GraphDataFlow curr_graph;
        InstrGraphNodeMap curr_instr_graph_node_map;
        pre_augment_use(curr_graph,
                        curr_instr_graph_node_map,
                        curr_func,
                        curr.operand,
                        curr_instr,
                        curr);

#if DEBUG_DUMP_GRAPHS
        stringstream pre_dump_file;
        pre_dump_file << setfill('0') << setw(3) << dec << _round
                 << "_type_"
                 << dec << curr.type
                 << "_func_"
                 << setfill('0') << setw(8) << hex << curr_func.get_entry()
                 << "_instr_"
                 << setfill('0') << setw(8) << hex << curr.addr
                 << "_op_"
                 << *curr.operand
                 << "_pre_augment_use.dot";
        dump_graph(curr_graph, pre_dump_file.str());
#endif

        // Track the operand for the given instruction back.
        augment_use(curr_graph,
                    curr_instr_graph_node_map,
                    curr_func,
                    curr.operand,
                    curr_instr);

#if DEBUG_DUMP_GRAPHS
        stringstream dump_file;
        dump_file << setfill('0') << setw(3) << dec << _round
                 << "_type_"
                 << dec << curr.type
                 << "_func_"
                 << setfill('0') << setw(8) << hex << curr_func.get_entry()
                 << "_instr_"
                 << setfill('0') << setw(8) << hex << curr.addr
                 << "_op_"
                 << *curr.operand
                 << "_augment_use.dot";
        dump_graph(curr_graph, dump_file.str());
#endif

        // Give the analysis contol over the graph we created
        // (for example for pruning it).
        post_augment_use(curr_graph,
                         curr_instr_graph_node_map,
                         curr_func,
                         curr.operand,
                         curr_instr,
                         curr);

#if DEBUG_DUMP_GRAPHS
        stringstream post_dump_file;
        post_dump_file << setfill('0') << setw(3) << dec << _round
                 << "_type_"
                 << dec << curr.type
                 << "_func_"
                 << setfill('0') << setw(8) << hex << curr_func.get_entry()
                 << "_instr_"
                 << setfill('0') << setw(8) << hex << curr.addr
                 << "_op_"
                 << *curr.operand
                 << "_post_augment_use.dot";
        dump_graph(curr_graph, post_dump_file.str());
#endif

        // Merge graph into final graph.
        merge_graphs(curr_graph);

        // Add edge between the final graph and the newly merged component.
        draw_final_edge(curr, curr_instr);

#if DEBUG_DUMP_GRAPHS
        stringstream merge_dump_file;
        merge_dump_file << setfill('0') << setw(3) << dec << _round
                 << "_type_"
                 << dec << curr.type
                 << "_func_"
                 << setfill('0') << setw(8) << hex << curr_func.get_entry()
                 << "_instr_"
                 << setfill('0') << setw(8) << hex << curr.addr
                 << "_op_"
                 << *curr.operand
                 << "_merged.dot";
        dump_graph(_graph, merge_dump_file.str());
#endif

        // Get next instructions that we should track.
        get_next_tracking_instrs(next_instrs,
                                 curr_graph,
                                 curr_func,
                                 curr,
                                 curr_instr);

        // Get next instructions from our specializations.
        get_next_tracking_instrs_child(next_instrs,
                                       curr_graph,
                                       curr_func,
                                       curr,
                                       curr_instr);

        // Finalize round.
        for(const auto &next_instr : next_instrs) {
            _work_queue.push(next_instr);
        }
        _round++;
    }

    // Finalize graph.
    finalize_graph();

    // Finalize graph of our specialization.
    finalize_graph_child(_graph, _instr_graph_node_map);

    // Update indexmap of graph before finishing analysis.
    update_indexmap();

    // Dump final graph.
    dump_graph(_graph, "final.dot");

    // Execute specialization specific post obtain function.
    post_obtain();

    return _work_queue.empty();
}

void BacktraceAnalysis::finalize_graph() {

    // Make a specialization of the call instruction that
    // only handles incoming edges of return instructions.
    struct AnonymFunction {
        GraphDataFlow::vertex_descriptor operator()(
                                   BacktraceAnalysis *this_ptr,
                                   GraphDataFlow &graph,
                                   InstrGraphNodeMap &instr_graph_node_map,
                                   GraphDataFlow::vertex_descriptor curr_node) {

            InstructionSSA &instr = static_cast<InstructionSSA&>(
                                              *graph[curr_node].instr);
            BaseInstructionSSAPtr call_of_ret =
                               make_shared<CallOfRetInstruction>(instr);
            GraphDataFlow::vertex_descriptor call_of_ret_node =
                                 this_ptr->get_maybe_new_node_graph(graph,
                                                          instr_graph_node_map,
                                                          call_of_ret);
            graph[call_of_ret_node].type = graph[curr_node].type;

            return call_of_ret_node;
        }
    } create_call_of_ret_node;


    // Split call instruction nodes into two:
    // 1) special call instructions that handle only return instructions,
    // 2) normal call instructions that call functions.
    auto vertices = boost::vertices(_graph);
    for(auto it = vertices.first; it != vertices.second;) {
        GraphDataFlow::vertex_descriptor curr_node = *it;
        ++it;

        // Skip the start node of the graph.
        if(_graph[curr_node].type == DataFlowNodeTypeStart) {
            continue;
        }

        if(_graph[curr_node].instr->is_call()
           && _graph[curr_node].instr->get_type() != SSAInstrTypeCallOfRet
           && _graph[curr_node].type != DataFlowNodeTypeVTVVerifyCall) {
            GraphDataFlow::vertex_descriptor call_of_ret_node = nullptr;

            auto in_edges = boost::in_edges(curr_node, _graph);
            for(auto edge_it = in_edges.first;
                edge_it != in_edges.second;) {

                GraphDataFlow::edge_descriptor curr_edge = *edge_it;
                ++edge_it;

                if(_graph[curr_edge].type == DataFlowEdgeTypeRet) {

                    // Make a specialization of the call instruction that
                    // only handles incoming edges of return instructions.
                    if(call_of_ret_node == nullptr) {
                        call_of_ret_node = create_call_of_ret_node(
                                                          this,
                                                          _graph,
                                                          _instr_graph_node_map,
                                                          curr_node);
                    }

                    // Copy edge to the new specialized call instruction node.
                    GraphDataFlow::vertex_descriptor src_node =
                                               boost::source(curr_edge, _graph);
                    GraphDataFlow::edge_descriptor new_edge =
                            get_maybe_new_edge_graph(_graph,
                                                     src_node,
                                                     call_of_ret_node,
                                                     _graph[curr_edge].operand);
                    _graph[new_edge].type = _graph[curr_edge].type;
                    _graph[new_edge].comment = _graph[curr_edge].comment;

                    boost::remove_edge(curr_edge, _graph);
                    in_edges = boost::in_edges(curr_node, _graph);
                }
            }

            auto out_edges = boost::out_edges(curr_node, _graph);
            for(auto edge_it = out_edges.first;
                edge_it != out_edges.second;) {

                GraphDataFlow::edge_descriptor curr_edge = *edge_it;
                ++edge_it;

                // Outgoing edges that are not of type call belong to the
                // return value of the call instruction and hence belong
                // to the specialization of the call instruction node.
                if(_graph[curr_edge].type != DataFlowEdgeTypeCall) {

                    // Make a specialization of the call instruction that
                    // only handles incoming edges of return instructions.
                    if(call_of_ret_node == nullptr) {
                        call_of_ret_node = create_call_of_ret_node(
                                                          this,
                                                          _graph,
                                                          _instr_graph_node_map,
                                                          curr_node);
                    }

                    // Copy edge to the new specialized
                    // call instruction node.
                    GraphDataFlow::vertex_descriptor dst_node =
                                           boost::target(curr_edge, _graph);
                    GraphDataFlow::edge_descriptor new_edge =
                            get_maybe_new_edge_graph(
                                                  _graph,
                                                  call_of_ret_node,
                                                  dst_node,
                                                  _graph[curr_edge].operand);
                    _graph[new_edge].type = _graph[curr_edge].type;
                    _graph[new_edge].comment = _graph[curr_edge].comment;

                    boost::remove_edge(curr_edge, _graph);
                    out_edges = boost::out_edges(curr_node, _graph);
                }
            }

            // Remove node if it does not have any edges anymore.
            in_edges = boost::in_edges(curr_node, _graph);
            out_edges = boost::out_edges(curr_node, _graph);
            if(in_edges.first == in_edges.second
               && out_edges.first == out_edges.second) {
                remove_node_graph(_graph,
                                  _instr_graph_node_map,
                                  curr_node);
            }
        }
    }
}

const RegisterX64SSA &BacktraceAnalysis::pre_processing_tailjmp_get_reg(
                                                      const OperandSSAPtr &op) {
    if(op->is_register()) {
        switch(op->get_type()) {
            case SSAOpTypeRegisterX64:
                return static_cast<const RegisterX64SSA&>(*op);
                break;

            default:
                throw runtime_error("Unknown SSA register object.");
        }
    }
    else if (op->is_memory()) {
        switch(op->get_type()) {
            case SSAOpTypeMemoryX64:
                return (static_cast<const MemoryX64SSA&>(*op)).get_base();
                break;

            default:
                throw runtime_error("Unknown SSA memory object.");
        }
    }

    throw runtime_error("Unknown SSA register object.");
}

bool BacktraceAnalysis::pre_processing_tailjmp(
                                      TrackingInstructionSet &out_next_instrs,
                                      const TrackingInstruction &curr,
                                      const Function &function,
                                      const BaseInstructionSSAPtr &curr_instr) {

    // Check that we have to track a register back for the tailjmp.
    if(!curr.operand->is_register()
       && !curr.operand->is_memory()) {
        throw runtime_error("Backtracking of tailjmps only for register and "\
                            "memory objects possible.");
    }

    // Add jmp instruction and edge to the final graph.
    GraphDataFlow::vertex_descriptor curr_node =
                                   get_maybe_new_node_graph(
                                                          _graph,
                                                          _instr_graph_node_map,
                                                          curr_instr);
    GraphDataFlow::edge_descriptor curr_edge = get_maybe_new_edge_graph(
                                                                 _graph,
                                                                 curr_node,
                                                                 curr.prev_node,
                                                                 curr.operand);
    _graph[curr_edge].type = DataFlowEdgeTypeJmp;

    const RegisterX64SSA &curr_reg = pre_processing_tailjmp_get_reg(
                                                                  curr.operand);
    const BlockSSAPtr &curr_block = function.get_containing_block_ssa(
                                                     curr_instr->get_address());
    queue<uint64_t> work_queue;
    work_queue.push(curr_block->get_address());
    set<uint64_t> processed_block_addrs;

    // Add artificial entry/exit block addresses as already processed.
    processed_block_addrs.insert(ID_ENTRY_BLOCK_SSA);
    processed_block_addrs.insert(ID_EXIT_BLOCK_SSA);

    // Search a definition for the register we want to track back
    // (since the tailjmp instruction does not have the definition of the
    // register).
    bool def_instr_found = false;
    while(!work_queue.empty()) {
        uint64_t &addr = work_queue.front();
        work_queue.pop();
        if(processed_block_addrs.find(addr)
           != processed_block_addrs.end()) {
            continue;
        }
        processed_block_addrs.insert(addr);

        const BlockSSAPtr &block = function.get_containing_block_ssa(addr);
        bool found = false;
        for(const OperandSSAPtr &def_op : block->get_definitions()) {
            if(def_op->is_register()) {
                switch(def_op->get_type()) {
                    case SSAOpTypeRegisterX64: {
                        const RegisterX64SSA &temp =
                                    static_cast<const RegisterX64SSA&>(*def_op);
                        if(temp.get_index() == curr_reg.get_index()) {
                            found = true;
                        }
                        break;
                    }

                    default:
                        throw runtime_error("Unknown SSA register object.");
                }
            }
            if(found) {
                break;
            }
        }

        // We found a definition of the register we are
        // searching for => get the corresponding instruction.
        if(found) {

            // Search the instruction we start our backtracking from.
            // Iterate the block's instructions in a reverse order to
            // find the latest definition of the register we are searching for.
            const BaseInstructionSSAPtrs &instrs = block->get_instructions();
            for(auto it = instrs.crbegin();
                it != instrs.crend();
                ++it) {
                for(const OperandSSAPtr &def_op : (*it)->get_definitions()) {
                    if(def_op->is_register()) {
                        switch(def_op->get_type()) {
                            case SSAOpTypeRegisterX64: {
                                const RegisterX64SSA &temp =
                                    static_cast<const RegisterX64SSA&>(*def_op);
                                if(temp.get_index() == curr_reg.get_index()) {

                                    // If the definition is done by a call
                                    // instruction we have to track
                                    // the subcall back.
                                    if((*it)->is_call()) {

                                        // TODO
                                        assert("Subcall directly before "\
                                               "tailjmp not tested yet.");

                                        // Use return instructions of the target
                                        // function as next tracking
                                        // instructions.
                                        prepare_ret_tracking_instrs(
                                                                out_next_instrs,
                                                                *it);
                                    }

                                    // Since we found the corresponding
                                    // definition, we create new tracking jobs
                                    // for its uses.
                                    else {
                                        for(const OperandSSAPtr &use_op
                                            : (*it)->get_uses()) {
                                            TrackingInstruction new_track;
                                            new_track.addr =
                                                           (*it)->get_address();
                                            new_track.prev_node = curr_node;
                                            new_track.operand = use_op;
                                            new_track.type = TrackingTypeInstr;
                                            new_track.instr_type =
                                                              (*it)->get_type();
                                            out_next_instrs.insert(new_track);
                                        }
                                    }
                                    def_instr_found = true;
                                }
                                break;
                            }

                            default:
                                throw runtime_error("Unknown SSA register"\
                                                    "object.");
                        }
                    }
                    if(def_instr_found) {
                        break;
                    }
                }
                if(def_instr_found) {
                    break;
                }
            }
            // This should never happen. However, to be on the
            // safe side check it nevertheless.
            if(!def_instr_found) {
                throw runtime_error("Not able to find instruction "\
                                    "corresponding to operand "\
                                    "definition.");
            }

            // Since we found the instruction we were looking for,
            // do not continue searching.
            break;
        }

        // We did not find any definition of the register we are
        // searching for => try preceding basic blocks next.
        else {
            for(uint64_t pred_addr : block->get_predecessors()) {
                work_queue.push(pred_addr);
            }
        }
    }

    if(def_instr_found) {
        // We do not track the current tracking job.
        return false;
    }

    else {
        // We continue to track the current tracking job.
        return true;
    }
}

void BacktraceAnalysis::augment_use(
                                   GraphDataFlow &graph,
                                   InstrGraphNodeMap &instr_graph_node_map,
                                   const Function &function,
                                   const OperandSSAPtr &initial_use,
                                   const BaseInstructionSSAPtr &initial_instr) {

    queue<OperandSSAPtr> work_queue;
    OperandsSSAset seen;

    work_queue.push(initial_use);
    while(true) {
        if(work_queue.empty()) {
            break;
        }

        OperandSSAPtr &use_op = work_queue.front();

        if(seen.find(use_op) != seen.end()) {
            work_queue.pop();
            continue;
        }

        seen.insert(use_op);

        BaseInstructionSSAPtrSet def_instrs =
                                      function.get_instrs_define_op_ssa(use_op);

        // Set of operand uses we want to track.
        OperandsSSAset use_ops;
        use_ops.insert(use_op);

        // Follow also the memory base register definition.
        // We kind of "overtaint" here.
        // Track both "rax" and "[rax-8]" in case of "mov [rax-8], rdi".
        if(use_op->is_memory()) {
            switch(use_op->get_type()) {
                case SSAOpTypeMemoryX64: {
                    const RegisterX64SSA &temp =
                          static_cast<const MemoryX64SSA &>(*use_op).get_base();
                    OperandSSAPtr base =
                                        make_shared<const RegisterX64SSA>(temp);
                    const BaseInstructionSSAPtrSet &mem_instrs =
                                        function.get_instrs_define_op_ssa(base);
                    def_instrs.insert(mem_instrs.begin(), mem_instrs.end());

                    // Consider base of memory also as "use" (this is important
                    // for example if we start our backtrace analysis from
                    // a "definition" via memory object like mov [rax-8], rdi
                    // where [rax-8] is our starting operand).
                    use_ops.insert(base);
                    break;
                }
                default:
                    throw runtime_error("Unknown SSA memory object.");
            }
        }

        for(const OperandSSAPtr &track_op : use_ops) {
            for(const BaseInstructionSSAPtr &use_instr :
                                     function.get_instrs_use_op_ssa(track_op)) {
                for(const BaseInstructionSSAPtr &def_instr : def_instrs) {

                    // Only draw an edge with the operand if the definition
                    // instruction actually defines the operand. For example,
                    // mov rbx_69, [rbp_11-f0] -> mov rsi_88, [rbx_69+0]
                    // would otherwise draw an edge with "rbx_69" and
                    // "[rbx_69+0]". We only want the edge with "rbx_69".
                    bool skip_edge = true;
                    for(const OperandSSAPtr &op : def_instr->get_definitions()) {
                        if(*op == *track_op) {
                            skip_edge = false;
                            break;
                        }
                    }
                    if(skip_edge) {
                        continue;
                    }

                    // Add edge def_instruction -> use_instruction.
                    GraphDataFlow::vertex_descriptor use_node =
                                            get_maybe_new_node_graph(
                                                           graph,
                                                           instr_graph_node_map,
                                                           use_instr);
                    graph[use_node].type = DataFlowNodeTypeNormal;
                    GraphDataFlow::vertex_descriptor def_node =
                                            get_maybe_new_node_graph(
                                                           graph,
                                                           instr_graph_node_map,
                                                           def_instr);
                    graph[def_node].type = DataFlowNodeTypeNormal;

                    // Ignore cases in which the def and use node are the same.
                    // This can happen because in cases of "[rbp_11-f0]"
                    // we track also "rbp_11" back and therefore
                    // instructions like mov "[rbp_11-f0], rcx_72"
                    // have also a edge to itself with "rbp_11".
                    if(def_node == use_node) {
                        continue;
                    }

                    GraphDataFlow::edge_descriptor new_edge =
                                                  get_maybe_new_edge_graph(
                                                                      graph,
                                                                      def_node,
                                                                      use_node,
                                                                      track_op);
                    graph[new_edge].type = DataFlowEdgeTypeOperand;

                    // Add definitions to operand uses to track next.
                    for(const OperandSSAPtr next_op : def_instr->get_uses()) {

                        work_queue.push(next_op);

                        // Follow also the memory base register definition.
                        // We kind of "overtaint" here.
                        // Track both "rax" and "[rax-8]"
                        // in case of "mov [rax-8], rdi".
                        if(next_op->is_memory()) {
                            switch(next_op->get_type()) {
                                case SSAOpTypeMemoryX64: {
                                    const RegisterX64SSA &temp =
                                          static_cast<const MemoryX64SSA &>(
                                                           *next_op).get_base();
                                    work_queue.push(
                                           make_shared<const RegisterX64SSA>(
                                                                         temp));
                                    break;
                                }
                                default:
                                    throw runtime_error("Unknown SSA memory "\
                                                        "object.");
                            }
                        }
                    }
                }
            }
        }

        // Pop current processed operand.
        work_queue.pop();
    }

    // If operand could not be tracked (for example, if we start tracking rdi_0,
    // there is no definition of it in the function) => add initial instruction
    // manually.
    if(graph.num_vertices() == 0) {
        get_maybe_new_node_graph(graph, instr_graph_node_map, initial_instr);
    }

    // Change initial node type to `Start`.
    GraphDataFlow::vertex_descriptor initial_node = get_node_graph(
                                                           graph,
                                                           instr_graph_node_map,
                                                           initial_instr);
    graph[initial_node].type = DataFlowNodeTypeStart;
}

GraphDataFlow::vertex_descriptor BacktraceAnalysis::get_maybe_new_node_graph(
                                        GraphDataFlow &graph,
                                        InstrGraphNodeMap &instr_graph_node_map,
                                        const BaseInstructionSSAPtr &instr) {

    // Check graph for corruption.
    assert(graph.num_vertices() == instr_graph_node_map.size()
           && "Graph corrupt. Does not have the same size as instruction map.");

    // Check if we already have the given instruction in our graph.
    if(instr_graph_node_map.find(instr) != instr_graph_node_map.end()) {

        GraphDataFlow::vertex_descriptor node = instr_graph_node_map[instr];

        stringstream err_msg;
        if(*(graph[node].instr) != *instr) {
            err_msg << "Graph corrupt. Expected Instruction: "
                    << *instr
                    << " Found Instruction: "
                    << *(graph[node].instr);
            throw runtime_error(err_msg.str().c_str());
        }

        return node;
    }

    // If we work on the final graph object, set indexmap as dirty.
    if(&graph == &_graph) {
        _indexmap_dirty = true;
    }

    // Create new cfg node.
    GraphDataFlow::vertex_descriptor new_vertex = boost::add_vertex(graph);
    graph[new_vertex].instr = instr;
    instr_graph_node_map[instr] = new_vertex;
    return new_vertex;
}

GraphDataFlow::edge_descriptor BacktraceAnalysis::get_maybe_new_edge_graph(
                                    GraphDataFlow &graph,
                                    const GraphDataFlow::vertex_descriptor &src,
                                    const GraphDataFlow::vertex_descriptor &dst,
                                    const OperandSSAPtr &operand) {

    // To make it more efficient we first check if no edge exists
    // and create a new one if it does not.
    auto edge = boost::edge(src, dst, graph);
    if(!edge.second) {
        GraphDataFlow::edge_descriptor new_edge =
                                         boost::add_edge(src, dst, graph).first;
        graph[new_edge].operand = operand;
        return new_edge;
    }

    // Check if the found edge is the one we are searching for and return
    // it if it is.
    if(*(graph[edge.first].operand) == *operand) {
        return edge.first;
    }

    // Since we can have multiple edges with different metadata, search
    // the edge manually (slow path).
    const auto edges = boost::out_edges(src, graph);
    for(auto it = edges.first; it != edges.second; ++it) {
        GraphDataFlow::vertex_descriptor temp_src = boost::source(*it, graph);
        GraphDataFlow::vertex_descriptor temp_dst = boost::target(*it, graph);
        if(temp_src == src
           && temp_dst == dst
           && *(graph[*it].operand) == *operand) {
            return *it;
        }
    }

    // If we reach this point we could not find an edge with the same metadata
    // and therefore create a new one.
    GraphDataFlow::edge_descriptor new_edge =
                                     boost::add_edge(src, dst, graph).first;
    graph[new_edge].operand = operand;
    return new_edge;
}

void BacktraceAnalysis::dump_graph(const GraphDataFlow &graph,
                                   const std::string &file_name) {
    ofstream dump_file;
    stringstream target_file;
    target_file << _graph_dump_dir
             << "/"
             << file_name;
    dump_file.open(target_file.str().c_str());
    FullDataFlowNodeWriter<GraphDataFlow> node_writer(graph);
    FullDataFlowEdgeWriter<GraphDataFlow> edge_writer(graph);
    boost::write_graphviz(dump_file, graph, node_writer, edge_writer);
    dump_file.close();
}

GraphDataFlow::vertex_descriptor BacktraceAnalysis::get_node_graph(
                                  const GraphDataFlow &graph,
                                  const InstrGraphNodeMap &instr_graph_node_map,
                                  const BaseInstructionSSAPtr &target_instr) {

    // Check graph for corruption.
    assert(graph.num_vertices() == instr_graph_node_map.size()
           && "Graph corrupt. Does not have the same size as instruction map.");

    stringstream err_msg;
    try {
        GraphDataFlow::vertex_descriptor node =
                                          instr_graph_node_map.at(target_instr);

        if(*(graph[node].instr) != *target_instr) {
            err_msg << "Graph corrupt. Expected Instruction: "
                    << *target_instr
                    << " Found Instruction: "
                    << *(graph[node].instr);
            throw runtime_error(err_msg.str().c_str());
        }

        return node;
    }
    catch(...) {
        err_msg << "Not able to find node with instruction: "
                << *target_instr;
        throw runtime_error(err_msg.str().c_str());
    }
}

void BacktraceAnalysis::merge_graphs(const GraphDataFlow &graph) {
    NodeToNodeMap old_new_map;

    // Copy all nodes to the final graph.
    const auto vertices = boost::vertices(graph);
    for(auto it = vertices.first; it != vertices.second; ++it) {
        GraphDataFlow::vertex_descriptor new_vertex = get_maybe_new_node_graph(
                                                          _graph,
                                                          _instr_graph_node_map,
                                                          graph[*it].instr);

        // Do not overwrite attributes of start node.
        if(_graph[new_vertex].type != DataFlowNodeTypeStart) {
            _graph[new_vertex].comment = graph[*it].comment;
            _graph[new_vertex].is_join = graph[*it].is_join;

            // Only copy node type if it is _NOT_ `start`.
            if(graph[*it].type != DataFlowNodeTypeStart) {
                _graph[new_vertex].type = graph[*it].type;
            }
        }

        old_new_map[*it] = new_vertex;
    }

    // Copy all edges to the final graph.
    const auto edges = boost::edges(graph);
    for(auto it = edges.first; it != edges.second; ++it) {
        GraphDataFlow::vertex_descriptor old_src = boost::source(*it, graph);
        GraphDataFlow::vertex_descriptor old_dst = boost::target(*it, graph);
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

    // Execute specialization function after graphs are merged.
    post_merge_graphs(graph, old_new_map);
}

void BacktraceAnalysis::get_next_tracking_instrs(
                                   TrackingInstructionSet &out_next_instrs,
                                   const GraphDataFlow &graph,
                                   const Function &function,
                                   const TrackingInstruction &initial_track,
                                   const BaseInstructionSSAPtr &initial_instr) {

    // Get all next tracking instructions that are connected via xrefs
    // to this function namely calls and tailjmps
    // (e.g., when rdi_0 is used then get all calls to that function that
    // use rdi as an argument register).
    prepare_xref_tracking_instrs(out_next_instrs,
                                 graph,
                                 function,
                                 initial_track,
                                 initial_instr);

    // Find all subcalls that are made by the current function and
    // start the next analysis from their "ret" instructions.
    prepare_subcall_tracking_instrs(out_next_instrs,
                                    graph);
}

void BacktraceAnalysis::prepare_xref_tracking_instrs(
                                   TrackingInstructionSet &out_next_instrs,
                                   const GraphDataFlow &graph,
                                   const Function &function,
                                   const TrackingInstruction &initial_track,
                                   const BaseInstructionSSAPtr &initial_instr) {

    struct XrefTarget {
        BaseInstructionSSAPtr instr;
        OperandSSAPtr reg;

        /*!
         * \brief Type that specifies how `XrefTarget` is hashed.
         */
        struct Hash {
            std::size_t operator() (const XrefTarget &e) const {
                size_t h = 0;
                std::hash_combine(h, e.instr->hash());
                std::hash_combine(h, e.reg->hash());
                return h;
            }
        };
        /*!
         * \brief Type that specifies how `XrefTarget` is compared.
         */
        struct Compare {
            size_t operator() (XrefTarget const &a,
                               XrefTarget const &b) const {
                if(*(a.instr) == *(b.instr)
                   && *(a.reg) == *(b.reg)) {
                    return true;
                }
                return false;
            }
        };
    };
    unordered_set<XrefTarget,
                  XrefTarget::Hash,
                  XrefTarget::Compare> xref_targets;

    // Get the registers that are used by the data flow (if any).
    auto vertices = boost::vertices(graph);
    for(auto it = vertices.first; it != vertices.second; ++it) {
        const BaseInstructionSSAPtr &instr = graph[*it].instr;

        // Ignore "call" instructions and all instructions that are not
        // of type instruction (e.g., phi nodes).
        if(instr->is_call()
           || instr->get_type() != SSAInstrTypeInstruction) {
            continue;
        }

        for(const OperandSSAPtr &use_op : instr->get_uses()) {
            if(use_op->is_register()) {
                switch(use_op->get_type()) {
                    case SSAOpTypeRegisterX64: {

                        // Phi index is always 0 for the first usage.
                        const RegisterX64SSA &reg =
                                   static_cast<const RegisterX64SSA &>(*use_op);
                        if(reg.get_phi_index() == 0) {

                            XrefTarget target;
                            target.instr = instr;
                            target.reg = use_op;
                            xref_targets.insert(target);
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
                        if(reg.get_phi_index() == 0) {

                            XrefTarget target;
                            target.instr = instr;
                            target.reg = make_shared<RegisterX64SSA>(reg);
                            xref_targets.insert(target);
                        }
                        break;
                    }
                    default:
                        throw runtime_error("Unknown SSA memory object.");
                }
            }
        }
    }

    // Handle edge case in which we have to track an argument register
    // of a call/tailjmp (if argument registers are checked
    // in prepare_xref_tracking_instr() for calls).
    if(initial_track.operand->is_register() && is_call_jmp_edge_case(graph)) {
        switch(initial_track.operand->get_type()) {
            case SSAOpTypeRegisterX64: {

                // Phi index is always 0 for the first usage.
                const RegisterX64SSA &reg =
                           static_cast<const RegisterX64SSA &>(
                                                        *initial_track.operand);
                if(reg.get_phi_index() == 0) {

                    // Handle edge case in which we have to track a
                    // register of a call/jmp which is also a
                    // register of the current function (i.e., rdi_0).
                    if(initial_instr->is_call()
                       || initial_instr->is_unconditional_jmp()) {

                        XrefTarget target;
                        target.instr = initial_instr;
                        target.reg = initial_track.operand;
                        xref_targets.insert(target);
                    }
                }
                break;
            }
            default:
                throw runtime_error("Unknown SSA register object.");
        }
    }

    if(xref_targets.empty()) {
        return;
    }

    // If we tracked a return instruction, we do not want to track all
    // call instruction xrefs, we only want to track the originating
    // call instruction (make an exception if we do not have a
    // previous node in the final graph for example if we start our
    // backtracking at a return instruction). This also handles
    // indirect call instruction for which we do not have a xref and
    // return instructions that have a tail jump in between.
    const set<uint64_t> *xref_addrs_ptr = nullptr;
    set<uint64_t> orig_caller_addr;
    if(initial_track.transition_order.size() != 0) {
        orig_caller_addr.insert(initial_track.transition_order.back());
        xref_addrs_ptr = &orig_caller_addr;
    }
    else {
        xref_addrs_ptr = &function.get_xrefs();
    }
    const set<uint64_t> &xref_addrs = *xref_addrs_ptr;
    const Function *xref_func_ptr = nullptr;

    // Check xrefs to our extracted targets in order to get
    // the next instructions to track.
    for(uint64_t xref_addr : xref_addrs) {

        // Get function object.
        try {
            xref_func_ptr = &_translator.get_containing_function(xref_addr);
        }
        catch(...) {
#if DEBUG_PRINT
            cerr << "No function for address "
                 << hex << xref_addr
                 << " was found. Skipping." << "\n";
#endif
            continue;
        }
        const Function &xref_func = *xref_func_ptr;

        // `SSAInstrTypeInstruction` can only have one instruction returned
        // (otherwise the data structure is corrupted). Use the only instruction
        // from the set.
        const BaseInstructionSSAPtrSet temp_instrs =
                         xref_func.get_instruction_ssa(xref_addr,
                                                       SSAInstrTypeInstruction);
        const BaseInstructionSSAPtr *temp_instr_ptr = nullptr;
        for(const BaseInstructionSSAPtr &temp_instr : temp_instrs) {
            temp_instr_ptr = &temp_instr;
            break;
        }
        if(temp_instr_ptr == nullptr) {
            stringstream err_msg;
            err_msg << "Not able to find instruction with address "
                    << hex << xref_addr
                    << " and type "
                    << dec << SSAInstrTypeInstruction
                    << " to process xrefs.";
            throw runtime_error(err_msg.str().c_str());
        }
        const BaseInstructionSSAPtr &xref_instr = *temp_instr_ptr;

        // Process "call" instruction.
        if(xref_instr->is_call()) {

            // Check corresponding candidates for next
            for(const auto &target : xref_targets) {

                // For a "call" instruction as xref to our current function
                // only allow argument registers.
                if(!target.reg->is_arg_register()) {
                    continue;
                }

                TrackingInstruction next;
                next.type = TrackingTypeCaller;

                // If we have a transition order we have to follow,
                // copy it and pop the top element since we just processed it.
                if(initial_track.transition_order.size() > 1) {
                    next.transition_order = initial_track.transition_order;
                    next.transition_order.pop_back();
                }

                // Get corresponding argument register for "call" instruction.
                bool found = false;
                for(const OperandSSAPtr &use_op : xref_instr->get_uses()) {
                    // First use of call instruction can be a constant
                    // (direct call) or memory object.
                    if(!use_op->is_register()) {
                        continue;
                    }
                    switch(use_op->get_type()) {
                        case SSAOpTypeRegisterX64: {
                            const RegisterX64SSA &use_op_reg =
                                    static_cast<const RegisterX64SSA&>(*use_op);
                            const RegisterX64SSA &target_reg =
                                        static_cast<const RegisterX64SSA&>(
                                                                 *(target.reg));
                            if(use_op_reg.get_index()
                               == target_reg.get_index()) {

                                next.operand = use_op;
                                next.addr = xref_instr->get_address();
                                next.instr_type = xref_instr->get_type();

                                // Get the descriptor in the final graph for the
                                // current instruction. This also creates the
                                // node if it does not exist yet.
                                // Since the current graph will be copied
                                // into the final graph, this instruction
                                // will get its edges afterwards.
                                next.prev_node = get_maybe_new_node_graph(
                                                          _graph,
                                                          _instr_graph_node_map,
                                                          target.instr);

                                out_next_instrs.insert(next);
                                found = true;
                            }
                            break;
                        }

                        default:
                            throw runtime_error("Unknown SSA register object.");
                    }
                    if(found) {
                        break;
                    }
                }
                if(!found) {
                    stringstream err_msg;
                    err_msg << "Did not find an argument register "
                            << "for instruction '"
                            << *xref_instr
                            << "' and operand '"
                            << *(target.reg)
                            << "'.";
                    throw runtime_error(err_msg.str().c_str());
                }
            }
        }

        // Process "tailjmp" instruction.
        else if(xref_instr->is_unconditional_jmp()) {
            for(const auto &target : xref_targets) {
                TrackingInstruction next;
                next.type = TrackingTypeTailjmp;
                next.operand = target.reg;
                next.addr = xref_instr->get_address();
                next.instr_type = xref_instr->get_type();

                // Get the descriptor in the final graph for the current
                // instruction. This also creates the node if it does not
                // exist yet. Since the current graph will be copied into the
                // final graph, this instruction will get its edges afterwards.
                next.prev_node = get_maybe_new_node_graph(_graph,
                                                          _instr_graph_node_map,
                                                          target.instr);

                // If we have a transition order we have to follow,
                // copy it and pop the top element since we just processed it.
                if(initial_track.transition_order.size() > 1) {
                    next.transition_order = initial_track.transition_order;
                    next.transition_order.pop_back();
                }

                out_next_instrs.insert(next);
            }
        }

        else {
#if DEBUG_PRINT
            cerr << "Do not know how to handle xref instruction: "
                 << *xref_instr << "\n";
#endif
            continue;
        }
    }
}

void BacktraceAnalysis::prepare_subcall_tracking_instrs(
                                   TrackingInstructionSet &out_next_instrs,
                                   const GraphDataFlow &graph) {

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

        // Extract return instructions for target function for
        // next instruction tracking round.
        prepare_ret_tracking_instrs(out_next_instrs, call_instr);
    }
}

void BacktraceAnalysis::prepare_ret_tracking_instrs(
                                   TrackingInstructionSet &out_next_instrs,
                                   const BaseInstructionSSAPtr &call_instr) {

    struct TargetAddr {
        uint64_t addr;
        vector<uint64_t> transition_order;
    };

    // A list of target addresses we have to process.
    vector<TargetAddr> target_addrs;

    // The first use of a call instruction is always the target.
    const OperandSSAPtr &target_op = call_instr->get_uses().at(0);

    // Handle indirect call: try to resolve it or come back later when we
    // can resolve it.
    if(!target_op->is_constant()) {

        // If we do not know if the indirect call is a virtual callsite,
        // mark it as unresolvable and stop processing it.
        if(!_vcalls.is_known_vcall(call_instr->get_address())) {
            _unresolvable_icalls.insert(call_instr->get_address());
            return;
        }

        // Get vcall targets.
        const VCall &vcall = _vcalls.get_vcall(call_instr->get_address());
        for(uint32_t vtbl_idx : vcall.vtbl_idxs) {
            const VTable &vtbl = _vtables.get_vtable(vtbl_idx);

            // Check if we have an overestimation in our vcall object
            // and the vtable can actually not be used at this vcall
            // (vtable can also be a .bss vtable which does not have
            // entries at the moment).
            if(vcall.entry_index >= vtbl.entries.size()) {
                continue;
            }

            TargetAddr init_target_obj;
            init_target_obj.addr = vtbl.entries.at(vcall.entry_index);
            init_target_obj.transition_order.push_back(
                                                     call_instr->get_address());
            target_addrs.push_back(init_target_obj);
        }
    }

    // Handle direct call.
    else {
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

        // If it is a call to one of the new operators, just mark the node
        // in the final graph and do not start tracking in it.
        if(_new_operators.find(target_addr) != _new_operators.end()) {
            GraphDataFlow::vertex_descriptor call_node =
                                       get_maybe_new_node_graph(
                                                          _graph,
                                                          _instr_graph_node_map,
                                                          call_instr);
            _graph[call_node].type = DataFlowNodeTypeNewOperator;
            return;
        }

        // Create init target object with call instruction as first element
        // in the transition order.
        TargetAddr init_target_obj;
        init_target_obj.addr = target_addr;
        init_target_obj.transition_order.push_back(call_instr->get_address());
        target_addrs.push_back(init_target_obj);
    }

    GraphDataFlow::vertex_descriptor call_node =
                               get_maybe_new_node_graph(_graph,
                                                        _instr_graph_node_map,
                                                        call_instr);

    // Process function target address.
    unordered_set<uint64_t> processed_addrs;
    while(!target_addrs.empty()) {

        // Get function target address to process next.
        TargetAddr target_obj = target_addrs.back();
        uint64_t func_target_addr = target_obj.addr;
        vector<uint64_t> transition_order = target_obj.transition_order;
        target_addrs.pop_back();

        // Check if we already processed the target function in order to
        // avoid infinity loops.
        if(processed_addrs.find(func_target_addr) != processed_addrs.end()) {
            continue;
        }
        processed_addrs.insert(func_target_addr);

        // Get target function (if exists).
        const Function *target_func_ptr = nullptr;
        try {
            target_func_ptr = &_translator.cget_function(func_target_addr);
        }
        catch(...) {
    #if DEBUG_PRINT
            cerr << "Did not find a function for address "
                 << hex << func_target_addr << "\n";
    #endif
            continue;
        }
        const Function &target_func = *target_func_ptr;

        // Search all return instructions of the called function
        // of the subcall and add their uses to the instructions
        // that are tracked next. Additionally, if the called function has a
        // tail jump into another function, we have to process the
        // return instructions of this function too.
        for(const auto &kv : target_func.get_blocks_ssa()) {
            const BlockSSAPtr &block = kv.second;
            const BaseInstructionSSAPtrs &instrs = block->get_instructions();
            if(instrs.empty()) {
                continue;
            }
            // Return instruction is always the
            // last instruction of a basic block.
            const BaseInstructionSSAPtr &last_instr = instrs.back();
            if(last_instr->is_ret()) {
                for(const OperandSSAPtr &use_op : last_instr->get_uses()) {
                    TrackingInstruction new_track;
                    new_track.addr = last_instr->get_address();
                    new_track.instr_type = last_instr->get_type();
                    new_track.prev_node = call_node;
                    new_track.operand = use_op;
                    new_track.type = TrackingTypeRet;
                    new_track.transition_order = transition_order;
                    out_next_instrs.insert(new_track);
                }
            }

            // Process tail jumps.
            else if(last_instr->is_unconditional_jmp()) {

                // Extract target address of jump operand.
                const OperandSSAPtr &jmp_op = last_instr->get_operand(0);
                uint64_t jmp_target_addr = 0;
                switch(jmp_op->get_type()) {
                    case SSAOpTypeConstantX64: {
                        const ConstantX64SSA &temp =
                                    static_cast<const ConstantX64SSA&>(*jmp_op);
                        jmp_target_addr = temp.get_value();
                        break;
                    }
                    case SSAOpTypeAddressX64: {
                        const AddressX64SSA &temp =
                                     static_cast<const AddressX64SSA&>(*jmp_op);
                        jmp_target_addr = temp.get_value();
                        break;
                    }
                    default:
                        break;
                }

                // Check if we have a tail jump in the function.
                if(jmp_target_addr != 0
                   && !target_func.contains_address(jmp_target_addr)) {

                    // Add target function to the processing list.
                    // NOTE: This overestimates the reached return instructions.
                    // For example, the tail jump can jump into the last
                    // basic block of a function that has a return instruction.
                    // Because we process the whole function, we add all
                    // return instructions of the function as a possible
                    // next instruction.
                    try {
                        const Function &jmp_func =
                           _translator.get_containing_function(jmp_target_addr);
                        TargetAddr next_target;
                        next_target.addr = jmp_func.get_entry();
                        next_target.transition_order = transition_order;

                        // Use jump instruction address as next transition order
                        // address.
                        next_target.transition_order.push_back(
                                                     last_instr->get_address());

                        target_addrs.push_back(next_target);
                    }
                    catch(...) {
#if DEBUG_PRINT
                        cerr << "Did not find a function for tail jump target "
                             << hex << jmp_target_addr << "\n";
#endif
                    }
                }
            }
        }
    }
}

bool BacktraceAnalysis::is_call_jmp_edge_case(const GraphDataFlow &graph) {
    uint32_t num_vertices = 0;
    auto vertices = boost::vertices(graph);
    for(auto it = vertices.first; it != vertices.second; ++it) {
        switch(graph[*it].type) {
            case DataFlowNodeTypeNormal:
            case DataFlowNodeTypeStart:
            case DataFlowNodeTypeVTVVerifyCall:
            case DataFlowNodeTypeVtable:
            case DataFlowNodeTypeNewOperator:
                num_vertices++;
                if(!graph[*it].instr->is_call()
                   && !graph[*it].instr->is_unconditional_jmp()) {
                   return false;
                }
            default:
                break;
        }
        if(num_vertices > 2) {
            return false;
        }
    }
    if(num_vertices == 1) {
        return true;
    }
    return false;
}

const GraphDataFlow &BacktraceAnalysis::get_graph() const {
    return _graph;
}

void BacktraceAnalysis::dump_graph(const std::string &file_name) {
    dump_graph(_graph, file_name);
}

const std::string &BacktraceAnalysis::get_graph_dump_dir() {
    return _graph_dump_dir;
}

void BacktraceAnalysis::remove_node_graph(
                                 GraphDataFlow &graph,
                                 InstrGraphNodeMap &instr_graph_node_map,
                                 const GraphDataFlow::vertex_descriptor &node) {

    // Remove all incoming and outgoing edges to the node
    // (Boost does not offer a function for directed graphs
    // for this operation :( ).
    auto in_edges = boost::in_edges(node, graph);
    while(in_edges.first != in_edges.second) {
        boost::remove_edge(*(in_edges.first), graph);
        in_edges = boost::in_edges(node, graph);
    }
    auto out_edges = boost::out_edges(node, graph);
    while(out_edges.first != out_edges.second) {
        boost::remove_edge(*(out_edges.first), graph);
        out_edges = boost::out_edges(node, graph);
    }
    instr_graph_node_map.erase(graph[node].instr);
    boost::remove_vertex(node, graph);

    // If we work on the final graph object, set indexmap to dirty.
    if(&graph == &_graph) {
        _indexmap_dirty = true;
    }
}

void BacktraceAnalysis::remove_node_graph(
                                        GraphDataFlow &graph,
                                        InstrGraphNodeMap &instr_graph_node_map,
                                        const BaseInstructionSSAPtr &instr) {
    GraphDataFlow::vertex_descriptor node = instr_graph_node_map[instr];
    remove_node_graph(graph, instr_graph_node_map, node);
}

uint64_t BacktraceAnalysis::get_start_addr() const {
    return _start_addr;
}

const boost::property_map<GraphDataFlow,
                    boost::vertex_index_t>::type&
                                       BacktraceAnalysis::get_graph_indexmap() {
    if(_indexmap_dirty) {
        _indexmap = create_indexmap(_graph);
        _indexmap_dirty = false;
    }
    return _indexmap;
}

const boost::property_map<GraphDataFlow,
                    boost::vertex_index_t>::type&
                                 BacktraceAnalysis::get_graph_indexmap() const {
    if(_indexmap_dirty) {
        throw runtime_error("Indexmap dirty.");
    }
    return _indexmap;
}

boost::property_map<GraphDataFlow, boost::vertex_index_t>::type
                      BacktraceAnalysis::create_indexmap(GraphDataFlow &graph) {
    // Since "VertexList=listS" does not have an internal vertex_index
    // property, we have to create one manually
    // for the boost algorithms to work.
    // http://www.boost.org/doc/libs/1_50_0/libs/graph/doc/breadth_first_search.html
    // http://www.boost.org/doc/libs/1_64_0/libs/graph/example/dijkstra-example-listS.cpp
    auto vertices = boost::vertices(graph);
    boost::property_map<GraphDataFlow, boost::vertex_index_t>::type indexmap =
                                         boost::get(boost::vertex_index, graph);
    int index = 0;
    for(auto it = vertices.first; it != vertices.second; ++it) {
        indexmap[*it] = index;
        index++;
    }

    return indexmap;
}

void BacktraceAnalysis::update_indexmap() {
    if(_indexmap_dirty) {
        _indexmap = create_indexmap(_graph);
        _indexmap_dirty = false;
    }
}

const InstrGraphNodeMap &BacktraceAnalysis::get_graph_instr_map() const {
    return _instr_graph_node_map;
}

const std::unordered_set<uint64_t>
                           &BacktraceAnalysis::get_unresolvable_icalls() const {
    return _unresolvable_icalls;
}
