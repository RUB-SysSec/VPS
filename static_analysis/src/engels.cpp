#include "engels.h"

using namespace std;

queue<uint64_t> queue_icall_addrs;
mutex queue_icall_mtx;

queue<uint64_t> queue_vcall_addrs;
mutex queue_vcall_mtx;

unordered_set<uint64_t> repeat_icall_addrs;
unordered_map<uint64_t, unordered_set<uint64_t>> icall_addr_unresolvable_map;
unordered_map<uint64_t, unordered_set<uint64_t>> vfunc_addr_unresolvable_map;
mutex repeat_icall_mtx;

queue<uint64_t> queue_vtable_xref_addrs;
mutex queue_vtable_xref_mtx;
mutex vtable_xref_data_mtx;
BlockPtr ret_block_ptr;

void engels_analysis(const string &target_file,
                     const string &module_name,
                     const string &target_dir,
                     EngelsAnalysisObjects &analysis_obj,
                     uint32_t num_threads) {

    // Create special basic block that performs a return instruction.
    unsigned char ret_instr_bytes = '\xc3'; // TODO architecture specific
    size_t real_end = 0;
    const IRSB &translated_block = analysis_obj.vex.translate(&ret_instr_bytes,
                                                              0,
                                                              1,
                                                              &real_end);
    IRSB *irsb_ptr = deepCopyIRSB_Heap(&translated_block);
    Terminator terminator;
    terminator.type = TerminatorReturn;
    terminator.target = 0;
    terminator.fall_through = 0;
    ret_block_ptr = make_shared<Block>(0, irsb_ptr, terminator, 1);

    // Import all icall addrs.
    ICallSet icall_set = import_icalls(target_file);

    // Set up queue with all icall addresses that have to be analyzed.
    queue_icall_mtx.lock();
    for(uint64_t icall_addr : icall_set) {
        queue_icall_addrs.push(icall_addr);
    }
    queue_icall_mtx.unlock();

    // Set up all vtable xrefs that have to be analyzed.
    EngelsVTableXrefAnalysis vtable_xref_data;
    const VTableMap &this_vtables = analysis_obj.vtable_file.get_this_vtables();
    queue_vtable_xref_mtx.lock();
    vtable_xref_data_mtx.lock();
    for(const auto &kv : this_vtables) {
        for(uint64_t xref_addr : kv.second->xrefs) {
            queue_vtable_xref_addrs.push(xref_addr);
            vtable_xref_data.xref_vtable_idx_map[xref_addr] = kv.second->index;
        }
    }
    vtable_xref_data_mtx.unlock();
    queue_vtable_xref_mtx.unlock();

    // Analyze all icalls in a fast way to find possible vcalls.
    // For debugging purposes do not spawn any thread.
    if(num_threads == 1) {
        engels_vcall_lightweight_analysis(module_name,
                                    target_dir,
                                    analysis_obj,
                                    0);
    }
    else {
        thread *all_threads = new thread[num_threads];
        for(uint32_t i = 0; i < num_threads; i++) {
            all_threads[i] = thread(engels_vcall_lightweight_analysis,
                                    module_name,
                                    target_dir,
                                    ref(analysis_obj),
                                    i);
        }
        for(uint32_t i = 0; i < num_threads; i++) {
            all_threads[i].join();
        }
        delete [] all_threads;
    }

    // Get all as vcall identified addresses for our heavy analysis pass.
    const PossibleVCalls &possible_vcalls =
                                   analysis_obj.vcall_file.get_possible_vcall();

    queue_vcall_mtx.lock();
    for(uint64_t vcall_addr : possible_vcalls) {
        queue_vcall_addrs.push(vcall_addr);
    }
    queue_vcall_mtx.unlock();

    // Analyze all vtable xrefs.
    // For debugging purposes do not spawn any thread.
    if(num_threads == 1) {
        engels_vtable_xref_analysis(module_name,
                                    target_dir,
                                    analysis_obj,
                                    vtable_xref_data,
                                    0);
    }
    else {
        thread *all_threads = new thread[num_threads];
        for(uint32_t i = 0; i < num_threads; i++) {
            all_threads[i] = thread(engels_vtable_xref_analysis,
                                    module_name,
                                    target_dir,
                                    ref(analysis_obj),
                                    ref(vtable_xref_data),
                                    i);
        }
        for(uint32_t i = 0; i < num_threads; i++) {
            all_threads[i].join();
        }
        delete [] all_threads;
    }

    while(true) {

        // Analyze all icalls.
        // For debugging purposes do not spawn any thread.
        if(num_threads == 1) {
            engels_icall_analysis(module_name,
                               target_dir,
                               analysis_obj,
                               vtable_xref_data,
                               0);
        }
        else {
            thread *all_threads = new thread[num_threads];
            for(uint32_t i = 0; i < num_threads; i++) {
                all_threads[i] = thread(engels_icall_analysis,
                                        module_name,
                                        target_dir,
                                        ref(analysis_obj),
                                        ref(vtable_xref_data),
                                        i);
            }
            for(uint32_t i = 0; i < num_threads; i++) {
                all_threads[i].join();
            }
            delete [] all_threads;
        }

        // Copy all engel results into our vcall result object
        // and add them to the function xrefs.
        analysis_obj.results_mtx.lock();
        Translator &translator = analysis_obj.translator;
        for(const auto &kv : analysis_obj.results) {
            uint64_t icall_addr = kv.first;
            for(const EngelsResult &result : kv.second) {

                // Check the sanity of the result (i.e., .bss vtables
                // do not have entries at the moment).
                const VTable &vtable = analysis_obj.vtable_file.get_vtable(
                                                             result.vtable_idx);
                if(result.entry_idx >= vtable.entries.size()) {
                    continue;
                }

                // Add vcall data.
                analysis_obj.vcall_file.add_vcall(icall_addr,
                                                  result.vtable_idx,
                                                  result.entry_idx);

                // Add function xref data.
                uint64_t fct_addr = vtable.entries.at(result.entry_idx);
                try {
                    translator.add_function_vfunc_xref(fct_addr, icall_addr);
                }
                catch(...) {
                    cerr << "Not able to add callsite xref from function "
                         << hex << fct_addr
                         << " to callsite "
                         << hex << icall_addr
                         << ". Function does not exist."
                         << "\n";
                }
                // Add also all known vtables from the hierarchy.
                const HierarchiesVTable &hierarchies =
                              analysis_obj.vtable_hierarchies.get_hierarchies();
                for(const DependentVTables &hierarchy : hierarchies) {
                    if(hierarchy.find(result.vtable_idx) != hierarchy.cend()) {
                        for(uint32_t hier_vtbl_idx : hierarchy) {
                            const VTable &hier_vtbl =
                                    analysis_obj.vtable_file.get_vtable(
                                                                 hier_vtbl_idx);
                            if(result.entry_idx >= hier_vtbl.entries.size()) {
                                continue;
                            }
                            fct_addr = hier_vtbl.entries.at(result.entry_idx);
                            try {
                                translator.add_function_vfunc_xref(fct_addr,
                                                                   icall_addr);
                            }
                            catch(...) {
                            }
                        }
                        break;
                    }
                }
            }
        }
        analysis_obj.results_mtx.unlock();

        // Stop icall analysis if we do not have any icall which analysis
        // should be repeated.
        if(repeat_icall_addrs.empty()) {
            break;
        }

        // Process icall candidates whose analysis should be repeated.
        else {
            queue_vcall_mtx.lock();
            repeat_icall_mtx.lock();

            uint32_t ctr_icall_resolvable = 0;
            uint32_t ctr_vfunc_resolvable = 0;
            for(auto it = repeat_icall_addrs.begin();
                it != repeat_icall_addrs.end();) {

                // Mark icall as repeatable if we can now resolve its
                // unresolvable icall instructions during the
                // data flow analysis.
                bool is_repeatable = false;
                for(uint64_t unresolvable_icall_addr :
                    icall_addr_unresolvable_map.at(*it)) {

                    if(analysis_obj.vcall_file.is_known_vcall(
                                                 unresolvable_icall_addr)) {
                        ctr_icall_resolvable++;
                        is_repeatable = true;
                        icall_addr_unresolvable_map[*it].clear();
                        break;
                    }
                }

                // Mark icall as repeatable if we can now resolve its
                // unresolvable virtual functions during the data flow analysis.
                for(uint64_t unresolvable_vfunc_addr :
                    vfunc_addr_unresolvable_map.at(*it)) {

                    try {
                        const Function &vfunc = translator.cget_function(
                                                   unresolvable_vfunc_addr);
                        if(!vfunc.get_vfunc_xrefs().empty()) {
                            ctr_vfunc_resolvable++;
                            is_repeatable = true;
                            vfunc_addr_unresolvable_map[*it].clear();
                            break;
                        }
                    }
                    catch(...) {
                    }
                }

                // Add icall to queue if it is marked as repeatable.
                if(is_repeatable) {
                    queue_vcall_addrs.push(*it);
                    it = repeat_icall_addrs.erase(it);
                }
                else {
                    ++it;
                }
            }

            cout << "Number of virtual callsites now resolvable: "
                 << dec << ctr_icall_resolvable
                 << "\n";
            cout << "Number of virtual functions now resolvable: "
                 << dec << ctr_vfunc_resolvable
                 << "\n";

            repeat_icall_mtx.unlock();
            queue_vcall_mtx.unlock();

            // Stop processing if we do not have any new icall that
            // can deliver new results.
            if(queue_vcall_addrs.empty()) {
                break;
            }

            cout << "Re-analyzing "
                 << dec
                 << queue_vcall_addrs.size()
                 << " indirect calls."
                 << "\n";
        }
    }
}

void engels_vtable_xref_analysis(const string &module_name,
                                 const string &target_dir,
                                 EngelsAnalysisObjects &analysis_obj,
                                 EngelsVTableXrefAnalysis &vtable_xref_data,
                                 uint32_t thread_number) {

    cout << "Starting vtable xref analysis (Thread: "
         << dec << thread_number
         << ")"
         << endl;

    while(true) {

        // Get next vtable xref that has to be analyzed.
        uint64_t vtable_xref_addr;
        queue_vtable_xref_mtx.lock();
        if(queue_vtable_xref_addrs.empty()) {
            queue_vtable_xref_mtx.unlock();
            break;
        }
        vtable_xref_addr = queue_vtable_xref_addrs.front();
        queue_vtable_xref_addrs.pop();
        cout << "Analyzing vtable xref at address: "
             << hex << vtable_xref_addr
             << ". Remaining vtable xrefs to analyze: "
             << dec << queue_vtable_xref_addrs.size()
             << " (Thread: " << dec << thread_number << ")"
             << endl;
        queue_vtable_xref_mtx.unlock();

        // Make sure the function object for the vtable xref address exists.
        const Function *temp_start_func = nullptr;
        try {
            temp_start_func = &analysis_obj.translator.get_containing_function(
                                                              vtable_xref_addr);
        }
        catch(...) {
            cerr << "Function for vtable xref address "
                 << hex << vtable_xref_addr
                 << " not found. Skipping."
                 << "\n";
            continue;
        }
        const Function &start_func = *temp_start_func;

        const BaseInstructionSSAPtr *temp_instr_ptr = nullptr;
        try {
            // `SSAInstrTypeInstruction` can only have one instruction returned
            // (otherwise the data structure is corrupted). Use the only
            // instruction from the set.
            const BaseInstructionSSAPtrSet temp_instrs =
                                start_func.get_instruction_ssa(
                                                       vtable_xref_addr,
                                                       SSAInstrTypeInstruction);
            for(const BaseInstructionSSAPtr &temp_instr : temp_instrs) {
                temp_instr_ptr = &temp_instr;
                break;
            }
            if(temp_instr_ptr == nullptr) {
                throw runtime_error("Not able to find instruction");
            }
        }
        catch(...) {
            cerr << "Not able to find instruction with address "
                 << hex << vtable_xref_addr
                 << " and type "
                 << dec << SSAInstrTypeInstruction
                 << " to process vtable xref. Skipping.";
            continue;
        }
        const BaseInstructionSSAPtr &start_instr = *temp_instr_ptr;

        // Check if we have a definition.
        const OperandSSAPtrs &defs = start_instr->get_definitions();
        if(defs.empty()) {
            cerr << "Instruction "
                 << *start_instr
                 << " does not have definition. Skipping.";
            continue;
        }

        // Create xref analysis object in a global data structure in order
        // to reuse its results during the icall analysis.
        vtable_xref_data_mtx.lock();
        vtable_xref_data.xref_analysis_map.emplace(
                                      vtable_xref_addr,
                                      std::make_shared<VtableBacktraceAnalysis>(
                                             module_name,
                                             target_dir,
                                             analysis_obj.translator,
                                             analysis_obj.vcall_file,
                                             analysis_obj.vtable_file,
                                             analysis_obj.new_operators,
                                             vtable_xref_addr));
        vtable_xref_data_mtx.unlock();
        VtableBacktraceAnalysisPtr &analysis =
                           vtable_xref_data.xref_analysis_map[vtable_xref_addr];

        analysis->obtain(400); // TODO make rounds configurable

        // Extract all root instructions of the vtable xref analysis
        // and store a specialized form of the generated graph.
        const GraphDataFlow &target_graph = analysis->get_graph();
        const auto vertices = boost::vertices(target_graph);
        for(auto it = vertices.first; it != vertices.second; ++it) {
            const auto in_edges = boost::in_edges(*it, target_graph);
            if(in_edges.first == in_edges.second) {

                const BaseInstructionSSAPtr &root_instr =
                                                        target_graph[*it].instr;
                vtable_xref_data_mtx.lock();
                vtable_xref_data.root_instr_xrefs_map[root_instr].insert(
                                                              vtable_xref_addr);
                vtable_xref_data_mtx.unlock();
            }
        }
    }

    cout << "Finished vtable xref analysis (Thread: "
         << dec << thread_number
         << ")"
         << endl;
}

void engels_vcall_lightweight_analysis(
                           const string &module_name,
                           const string &target_dir,
                           EngelsAnalysisObjects &analysis_obj,
                           uint32_t thread_number) {

    cout << "Starting vcall lightweight analysis (Thread: "
         << dec << thread_number
         << ")"
         << endl;

    while(true) {

        // Get next icall that has to be analyzed.
        uint64_t icall_addr;
        queue_icall_mtx.lock();
        if(queue_icall_addrs.empty()) {
            queue_icall_mtx.unlock();
            break;
        }
        icall_addr = queue_icall_addrs.front();
        queue_icall_addrs.pop();
        cout << "Analyzing icall at address: "
             << hex << icall_addr
             << ". Remaining icalls to analyze: "
             << dec << queue_icall_addrs.size()
             << " (Thread: " << dec << thread_number << ")"
             << endl;
        queue_icall_mtx.unlock();

        // Make sure the function object for the starting address exists.
        try {
            analysis_obj.translator.get_containing_function(icall_addr);
        }
        catch(...) {
            cerr << "Function for icall address "
                 << hex << icall_addr
                 << " not found. Skipping."
                 << "\n";
            continue;
        }

        VCallBacktraceLightweight analysis(module_name,
                               target_dir,
                               analysis_obj.translator,
                               analysis_obj.vcall_file,
                               analysis_obj.vtable_file,
                               analysis_obj.new_operators,
                               analysis_obj.vtv_verify_addrs,
                               icall_addr);

        analysis.obtain(200); // TODO make rounds configurable

        bool is_vcall = process_vcall_lightweight_analysis(analysis_obj,
                                                           analysis);
        if(is_vcall) {
            analysis_obj.vcall_file.add_possible_vcall(icall_addr);
        }
    }

    cout << "Finished vcall lightweight analysis (Thread: "
         << dec << thread_number
         << ")"
         << endl;
}

void engels_icall_analysis(const string &module_name,
                           const string &target_dir,
                           EngelsAnalysisObjects &analysis_obj,
                           EngelsVTableXrefAnalysis &vtable_xref_data,
                           uint32_t thread_number) {

    cout << "Starting icall analysis (Thread: "
         << dec << thread_number
         << ")"
         << endl;

    while(true) {

        // Get next icall that has to be analyzed.
        uint64_t icall_addr;
        queue_vcall_mtx.lock();
        if(queue_vcall_addrs.empty()) {
            queue_vcall_mtx.unlock();
            break;
        }
        icall_addr = queue_vcall_addrs.front();
        queue_vcall_addrs.pop();
        cout << "Analyzing icall at address: "
             << hex << icall_addr
             << ". Remaining icalls to analyze: "
             << dec << queue_vcall_addrs.size()
             << " (Thread: " << dec << thread_number << ")"
             << endl;
        queue_vcall_mtx.unlock();

        // Make sure the function object for the starting address exists.
        try {
            analysis_obj.translator.get_containing_function(icall_addr);
        }
        catch(...) {
            cerr << "Function for icall address "
                 << hex << icall_addr
                 << " not found. Skipping."
                 << "\n";
            continue;
        }

        ICallAnalysis analysis(module_name,
                               target_dir,
                               analysis_obj.translator,
                               analysis_obj.vcall_file,
                               analysis_obj.vtable_file,
                               analysis_obj.new_operators,
                               analysis_obj.vtv_verify_addrs,
                               icall_addr);

        //analysis.obtain(400); // TODO make rounds configurable
        analysis.obtain(200); // TODO make rounds configurable

        const GraphDataFlow &graph = analysis.get_graph();



        // TODO / DEBUG
        bool merged = false;



        // Copy vertex descriptors of the original graph since we can not
        // iterate over the graph while we are modifying it.
        auto vertices = boost::vertices(graph);
        unordered_set<GraphDataFlow::vertex_descriptor> orig_vertices;
        for(auto it = vertices.first; it != vertices.second; ++it) {
            orig_vertices.insert(*it);
        }

        // Check if the vtable xrefs have the same root instructions as
        // our current icall analysis pass.
        NodeToNodesMap join_to_vtables_map;
        for(const auto node : orig_vertices) {
            const auto in_edges = boost::in_edges(node, graph);
            if(in_edges.first == in_edges.second) {
                const BaseInstructionSSAPtr &root_instr = graph[node].instr;
                if(vtable_xref_data.root_instr_xrefs_map.find(root_instr)
                   != vtable_xref_data.root_instr_xrefs_map.cend()) {

                    // Incorporate all vtable xref graphs into the icall
                    // analysis graph.
                    for(uint64_t xref_addr :
                        vtable_xref_data.root_instr_xrefs_map.at(root_instr)) {

#if DEBUG_PRINT
                        cout << "Merging icall "
                             << hex << icall_addr
                             << " with vtable xref "
                             << hex << xref_addr
                             << " (Thread: " << thread_number << ")"
                             << "\n";
#endif

                        // Incorporate the vtable xref graph into the icall
                        // analysis results.
                        const VtableBacktraceAnalysisPtr &xref_analysis =
                               vtable_xref_data.xref_analysis_map.at(xref_addr);
                        const GraphDataFlow &vtbl_xref_graph =
                                xref_analysis->get_graph();
                        const InstrGraphNodeMap &vtbl_xref_instr_node_map =
                                xref_analysis->get_graph_instr_map();
                        const boost::property_map<GraphDataFlow,
                                boost::vertex_index_t>::type &indexmap =
                                            xref_analysis->get_graph_indexmap();

                        GraphDataFlow::vertex_descriptor join_node;
                        GraphDataFlow::vertex_descriptor vtable_node;
                        analysis.incorporate_vtable_xref_graph(
                                                 vtbl_xref_graph,
                                                 vtbl_xref_instr_node_map,
                                                 indexmap,
                                                 root_instr,
                                                 join_node, // out
                                                 vtable_node); // out

                        // Store the relation between the join node
                        // and the vtable assignment node.
                        join_to_vtables_map[join_node].insert(vtable_node);
                    }

                    // TODO / DEBUG
                    merged = true;
                }
            }
        }

        // TODO / DEBUG
        if(merged) {
            analysis.dump_graph("final_merged.dot");
        }

        process_icall_dataflow_graph(analysis_obj,
                                     analysis,
                                     vtable_xref_data,
                                     join_to_vtables_map);

    }

    cout << "Finished icall analysis (Thread: "
         << dec << thread_number
         << ")"
         << endl;
}

GraphDataFlow::vertex_descriptor get_last_node_in_function_on_path(
                                                   const Function &function,
                                                   const DataFlowPath &path,
                                                   const GraphDataFlow &graph,
                                                   uint32_t start_idx) {

    // Check first node in path manually.
    bool in_function = false;
    GraphDataFlow::vertex_descriptor prev_node = path.at(start_idx);
    uint64_t prev_addr = graph[prev_node].instr->get_address();
    if(function.contains_address(prev_addr)) {
        in_function = true;
    }

    // Follow path until we leave the given function.
    for(uint32_t i = start_idx+1; i < path.size(); i++) {
        GraphDataFlow::vertex_descriptor curr_node = path.at(i);
        uint64_t curr_addr = graph[curr_node].instr->get_address();
        if(function.contains_address(curr_addr)) {
            // If we found the first node on the path that resides
            // in the given function set flag for it.
            if(!in_function) {
                in_function = true;
            }
            prev_node = curr_node;
        }
        // If we leave the function on the path we do not have to search
        // any further.
        else if(in_function) {
            break;
        }
    }

    if(in_function) {
        return prev_node;
    }
    else {
        stringstream err_msg;
        err_msg << "Not able to find node on path that resides "
                << "in given function at address: "
                << hex << function.get_entry();
        throw runtime_error(err_msg.str().c_str());
    }
}

GraphDataFlow::vertex_descriptor get_last_node_after_root(
                                                   const Translator &translator,
                                                   const DataFlowPath &path,
                                                   const GraphDataFlow &graph) {
    GraphDataFlow::vertex_descriptor start_node = path.at(0);
    uint64_t start_addr = graph[start_node].instr->get_address();
    const Function &function = translator.get_containing_function(start_addr);
    return get_last_node_in_function_on_path(function, path, graph, 0);
}

bool have_control_flow_connection(const Function &function,
                                  uint64_t src_instr_addr,
                                  uint64_t dst_instr_addr) {

    const Block &src_block = function.get_containing_block(src_instr_addr);
    const Block &dst_block = function.get_containing_block(dst_instr_addr);
    uint64_t src_block_addr = src_block.get_address();
    uint64_t dst_block_addr = dst_block.get_address();

    // If both instructions reside in the same basic block, check that
    // the source instruction lies before the destination instruction.
    if(src_block_addr == dst_block_addr) {
        return (src_instr_addr <= dst_instr_addr);
    }

    // Get the corresponding nodes in the cfg for the source and destination
    // addresses.
    const GraphCfg &cfg = function.get_cfg();
    GraphCfg::vertex_descriptor src_cfg_node;
    GraphCfg::vertex_descriptor dst_cfg_node;
    bool src_cfg_node_found = false;
    bool dst_cfg_node_found = false;
    const auto cfg_vertices = boost::vertices(cfg);
    for(auto it = cfg_vertices.first;
        it != cfg_vertices.second;
        ++it) {

        if(cfg[*it]->get_address() == src_block_addr) {
            src_cfg_node = *it;
            src_cfg_node_found = true;
            if(src_cfg_node_found && dst_cfg_node_found) {
                break;
            }
        }
        else if(cfg[*it]->get_address() == dst_block_addr) {
            dst_cfg_node = *it;
            dst_cfg_node_found = true;
            if(src_cfg_node_found && dst_cfg_node_found) {
                break;
            }
        }
    }
    if(!src_cfg_node_found && !dst_cfg_node_found) {
        stringstream err_msg;
        err_msg << "Not able to find basic blocks in CFG. "
                << "Source Basic Block address: "
                << hex << src_block_addr
                << " Destination Basic Block address: "
                << hex << dst_block_addr;
        throw runtime_error(err_msg.str().c_str());
    }

    // Get indexmap in order to work with boost algorithms on the graph.
    const boost::property_map<
                        GraphCfg,
                        boost::vertex_index_t>::type &cfg_indexmap =
                                                    function.get_cfg_indexmap();

    // Generate a path from the source to the destination node.
    ControlFlowPath path_src_dst = create_controlflow_path(cfg,
                                                           cfg_indexmap,
                                                           src_cfg_node,
                                                           dst_cfg_node);

    if(path_src_dst.size() == 0) {
        return false;
    }
    return true;
}

vector<BlockPtr> create_artificial_block_vector(
                                      const EngelsAnalysisObjects &analysis_obj,
                                      const GraphDataFlow &graph,
                                      const DataFlowPath &data_flow_path) {

    // Since we only create basic blocks with one instruction and vex translates
    // the whole basic block, we do not want any optimization since we
    // can lose information otherwise (i.e., lea rdx [rip+0x10000], add rax, rdx
    // would only write the intermediate into rax).
    VexRegisterUpdates orig_iropt_register_updates_default =
                          analysis_obj.vex.get_iropt_register_updates_default();
    analysis_obj.vex.set_iropt_register_updates_default(
                                                    VexRegUpdAllregsAtEachInsn);

    const Memory &memory = analysis_obj.translator.get_memory();

    // Create a path of artificial basic blocks with just
    // the instruction of our data flow path.
    vector<BlockPtr> path_blocks;
    for(auto node : data_flow_path) {

        const BaseInstructionSSAPtr &instr = graph[node].instr;

        // Vex is not thread safe, so we have to lock this section.
        // NOTE: all attempts to make the Vex object thread safe
        // did not succeed.
        vex_mutex.lock();
        size_t real_end = 0;
        const IRSB &translated_block = analysis_obj.vex.translate(
                                           memory[instr->get_address()],
                                           instr->get_address(),
                                           1,
                                           &real_end);
        IRSB *irsb_ptr = deepCopyIRSB_Heap(&translated_block);
        vex_mutex.unlock();

        Terminator terminator;
        if(instr->is_call()) {
            terminator.type = TerminatorCall;
        }
        else if(instr->is_ret()) {
            terminator.type = TerminatorReturn;
        }
        else {
            terminator.type = TerminatorFallthrough;
        }
        terminator.target = 0;
        terminator.fall_through = 0;
        BlockPtr block = make_shared<Block>(instr->get_address(),
                                            irsb_ptr,
                                            terminator,
                                            1);
        path_blocks.push_back(block);
    }

    // Reset vex options.
    analysis_obj.vex.set_iropt_register_updates_default(
                                           orig_iropt_register_updates_default);

    return path_blocks;
}

void sym_execute_blocks(const EngelsAnalysisObjects &analysis_obj,
                        const vector<BlockPtr> &exec_blocks,
                        State &state) {

    const unordered_set<uint64_t> &vtv_verify_addrs =
                                                  analysis_obj.vtv_verify_addrs;
    const unordered_set<uint64_t> &new_operators = analysis_obj.new_operators;

    for(uint32_t i = 0; i < exec_blocks.size(); i++) {
        const BlockPtr &block_ptr = exec_blocks.at(i);

        // Symbolically execute block.
        BlockSemantics semantics(*block_ptr, state);
        state = semantics.get_state();

#if DEBUG_ENGELS_PRINT_SYM_EXEC_STATES
        cout << "Block address: " << hex << block_ptr->get_address() << endl;
        cout << "State:" << endl;
        cout << state << endl;
#endif

        // If the last instruction of the block was a call,
        // check if it is a call to a vtv verify function.
        bool is_vtv_verify = false;
        bool is_new_operator = false;
        bool is_call_not_taken = false;
        State::const_iterator ip_value;
        if(block_ptr->get_terminator().type == TerminatorCall
           && state.find(register_rip, ip_value)) { // TODO architecture specific
            ExpressionPtr call_target = ip_value->second;
            switch(call_target->type()) {
                case ExpressionConstant: {
                    Constant &const_temp = static_cast<Constant&>(
                                                          *call_target);
                    uint64_t target_addr = const_temp.value();

                    // Our artificial return basic block has the address 0x0,
                    // hence we can check if we skipped the call.
                    if((i+1) < exec_blocks.size()
                       && exec_blocks.at(i+1)->get_address() == 0x0) {
                        is_call_not_taken = true;
                    }
                    if(is_call_not_taken
                       && vtv_verify_addrs.find(target_addr)
                            != vtv_verify_addrs.cend()) {
                        is_vtv_verify = true;
                    }
                    else if(is_call_not_taken
                            && new_operators.find(target_addr)
                                != vtv_verify_addrs.cend()) {
                        is_new_operator = true;
                    }
                    break;
                }
                default:
                    break;
            }
        }

        // VTV stub to verify vtable looks like this:
        // https://github.com/gcc-mirror/gcc/blob/master/libstdc%2B%2B-v3/libsupc%2B%2B/vtv_stubs.cc
        // const void*
        // __VLTVerifyVtablePointer(void**, const void* vtable_ptr)
        // { return vtable_ptr; }
        //
        // Return value contains always vtable pointer
        // given by the second argument
        // => copy 2nd arg value to return value.
        if(is_vtv_verify) {
            const auto &second_arg_reg = system_v_arguments[1]; // TODO architecture specific
            State::const_iterator ret_value;
            if(state.find(second_arg_reg, ret_value)) {
                state.update(register_rax, ret_value->second); // TODO architecture specific
            }
        }

        // We do not follow new operators, but we need to simulate their
        // behavior to return a memory object.
        else if(is_new_operator) {
            stringstream symbol_name;
            symbol_name << "new_obj_" << hex << block_ptr->get_last_address();
            ExpressionPtr sym_obj_ptr = make_shared<Symbolic>(
                                                             symbol_name.str());
            state.update(register_rax, sym_obj_ptr); // TODO architecture specific
        }

        // When we did not take the call, we put a symbolic object
        // as return value.
        else if(is_call_not_taken) {
            stringstream symbol_name;
            symbol_name << "ret_" << hex << block_ptr->get_last_address();
            ExpressionPtr sym_obj_ptr = make_shared<Symbolic>(
                                                             symbol_name.str());
            state.update(register_rax, sym_obj_ptr); // TODO architecture specific
        }
    }
}

inline void get_path(DataFlowPath &out_path,
                     const DataFlowNodeConnections &backward_node_connections,
                     GraphDataFlow::vertex_descriptor src_node,
                     GraphDataFlow::vertex_descriptor dst_node) {
    GraphDataFlow::vertex_descriptor curr = dst_node;
    out_path.push_back(curr);
    while(true) {
        curr = backward_node_connections.at(curr);
        out_path.insert(out_path.begin(), curr);
        if(curr == src_node) {
            break;
        }
    }
}

vector<DataFlowPath> create_dataflow_paths(
                     EngelsAnalysisObjects &analysis_obj,
                     const GraphDataFlow &graph,
                     const boost::property_map<GraphDataFlow,
                                         boost::vertex_index_t>::type &indexmap,
                     GraphDataFlow::vertex_descriptor src_node,
                     GraphDataFlow::vertex_descriptor dst_node) {

    DataFlowNodeConnections backward_node_connections;

    GraphDataFlowFiltered filtered_graph(graph,
                                         BlacklistNodesEdgePredicate(
                                                     graph,
                                                     analysis_obj.new_operators,
                                                     backward_node_connections,
                                                     src_node));

    BfsGraphDataFlowFilteredNodesShortestPath vis(backward_node_connections,
                                          src_node,
                                          dst_node);

    // Last argument uses bgl_named_params:
    // http://www.boost.org/doc/libs/1_58_0/libs/graph/doc/bgl_named_params.html
    // => argument "visitor" and "vertex_index_map" are passed.
    bool node_found = false;
    try {
        boost::breadth_first_search(filtered_graph,
                                    src_node,
                                    visitor(vis).vertex_index_map(indexmap));
    }
    catch(NodeFound) {
        node_found = true;
    }

    // Build path starting from the destination node if we have found
    // a way from source to destination.
    DataFlowPath init_path;
    if(node_found) {
        get_path(init_path,
                 backward_node_connections,
                 src_node,
                 dst_node);
    }

    vector<DataFlowPath> work_list;
    vector<DataFlowPath> found_paths;
    unordered_set<DataFlowPath,
                  DataFlowPathSet::Hash,
                  DataFlowPathSet::Compare> processed_base_paths;
    if(init_path.size() > 0) {
        work_list.push_back(init_path);
        found_paths.push_back(init_path);
    }

    // Go backwards through each found path and try to find new paths
    // to the destination node at each return instruction.
    while(!work_list.empty()) {

        DataFlowPath curr_path = work_list.back();
        work_list.pop_back();

        DataFlowPath base_path = curr_path;

        // Skip the last node (since it is always the destination node).
        base_path.pop_back();

        // Process the path starting from the back.
        for(uint32_t i = base_path.size()-1; i >= 1; i--) {

            GraphDataFlow::vertex_descriptor curr_node = base_path.at(i);

            // Remove current node from the base path.
            base_path.pop_back();

            // Try to find another path through the dataflow at the
            // special call instructions that only handle return
            // instruction dataflow.
            if(graph[curr_node].instr->get_type() == SSAInstrTypeCallOfRet) {

                // Check if we have already processed this portion of the
                // current base path.
                // NOTE: the base path does not contain
                // the current node anymore.
                if(processed_base_paths.find(base_path)
                   != processed_base_paths.end()) {
                    break;
                }

                // Get all possible next nodes from the previous one
                // as new source nodes for our path search.
                GraphDataFlow::vertex_descriptor prev_node = base_path.at(i-1);
                unordered_set<GraphDataFlow::vertex_descriptor> to_process;
                auto out_edges = boost::out_edges(prev_node, graph);
                for(auto edge_it = out_edges.first;
                    edge_it != out_edges.second;
                    ++edge_it) {
                    GraphDataFlow::vertex_descriptor temp_node = boost::target(*edge_it, graph);
                    to_process.insert(temp_node);
                }

                // Start a path search from the new source node.
                for(auto new_src_node : to_process) {
                    if(new_src_node == curr_node) {
                        continue;
                    }

                    node_found = false;
                    try {
                        filtered_graph.m_edge_pred.set_src_node(new_src_node);
                        backward_node_connections.clear();
                        BfsGraphDataFlowFilteredNodesShortestPath
                                             temp_vis(backward_node_connections,
                                                      new_src_node,
                                                      dst_node);

                        boost::breadth_first_search(filtered_graph,
                                                    new_src_node,
                                                    visitor(temp_vis).vertex_index_map(indexmap));
                    }
                    catch(NodeFound) {
                        node_found = true;
                    }

                    if(node_found) {
                        DataFlowPath part_path;
                        get_path(part_path,
                                 backward_node_connections,
                                 new_src_node,
                                 dst_node);

                        // Add the base path to the beginning of the new
                        // found path.
                        for(int32_t j = base_path.size() - 1; j >= 0; j--) {
                            part_path.insert(part_path.begin(),
                                             base_path.at(j));
                        }

                        // Loop detection: check if each node is unique
                        // in the path and ignore if we have duplicates.
                        unordered_set<GraphDataFlow::vertex_descriptor>
                                                 unique_nodes(part_path.begin(),
                                                              part_path.end());
                        if(part_path.size() != unique_nodes.size()) {
                            continue;
                        }

                        // Add the newly found path as new base path
                        // for further processing.
                        work_list.push_back(part_path);
                        found_paths.push_back(part_path);
                    }
                }

                // Store as processed base path (NOTE: the base path
                // does not contain the current node anymore).
                processed_base_paths.insert(base_path);
            }
        }
    }

    return found_paths;
}

ControlFlowPath create_controlflow_path(
                     const GraphCfg &graph,
                     const boost::property_map<GraphCfg,
                                         boost::vertex_index_t>::type &indexmap,
                     GraphCfg::vertex_descriptor src_node,
                     GraphCfg::vertex_descriptor dst_node) {

    ControlFlowNodeConnections backward_node_connections;
    BfsGraphCfgNodesShortestPath vis(backward_node_connections,
                                     src_node,
                                     dst_node);

    // Last argument uses bgl_named_params:
    // http://www.boost.org/doc/libs/1_58_0/libs/graph/doc/bgl_named_params.html
    // => argument "visitor" and "vertex_index_map" are passed.
    bool node_found = false;
    try {
        boost::breadth_first_search(graph,
                                    src_node,
                                    visitor(vis).vertex_index_map(indexmap));
    }
    catch(NodeFound) {
        node_found = true;
    }

    // Build path starting from the destination node if we have found
    // a way from source to destination.
    ControlFlowPath path;
    if(node_found) {
        GraphCfg::vertex_descriptor curr = dst_node;
        path.push_back(curr);
        while(true) {
            curr = backward_node_connections[curr];
            path.insert(path.begin(), curr);
            if(curr == src_node) {
                break;
            }
        }
    }
    return path;
}

DataFlowPath create_symbolic_execution_path(
                                          const DataFlowPath &path_root_vtable,
                                          const DataFlowPath &path_root_icall) {

    DataFlowPath final_path;
    for(uint32_t i = 0; i < path_root_vtable.size(); i++) {
        final_path.push_back(path_root_vtable.at(i));
    }

    // Add nodes of the root->icall path to the final path as soon as they
    // diverge from the root->vtable path.
    bool path_diverged = false;
    for(uint32_t i = 0; i < path_root_icall.size(); i++) {
        GraphDataFlow::vertex_descriptor node = path_root_icall.at(i);
        if(!path_diverged && final_path.at(i) == node) {
            continue;
        }
        path_diverged = true;
        final_path.push_back(path_root_icall.at(i));
    }

    // TODO
    // Perhaps build the beginning of the execution path with little bit
    // more sophisticated. At the moment, it is assumed that the order of
    // the instructions do not matter. However, this have to be shown.
    // A better approach would be that the beginning instructions
    // that reside in the same function would be
    // ordered by the control flow until the function is left (by a call)
    // or the end is reached.

    return final_path;
}

DataFlowPath create_shorted_dataflow_path(const Translator &translator,
                                          const GraphDataFlow &graph,
                                          const DataFlowPath &path) {
    DataFlowPath shorted_path;
    /*
     * // TODO test path without phi first and then perhaps a shorter version
     * from src to dst node in same function
    GraphDataFlow::vertex_descriptor src_node;
    GraphDataFlow::vertex_descriptor dst_node;
    for(uint32_t i = 0; i < path.size();) {
        src_node = path.at(i);
        uint64_t src_instr_addr = graph[src_node].instr->get_address();
        const Function &src_func = translator.get_containing_function(
                                                                src_instr_addr);
        dst_node = get_last_node_in_function_on_path(src_func,
                                                     path,
                                                     graph,
                                                     i);

        // If the source node is also the last node in the function on the
        // path (i.e., a call instruction) then only add it and
        // continue processing at the next node.
        if(src_node == dst_node) {
            i++;
            shorted_path.push_back(src_node);
        }

        // Add both nodes to the path and continue processing at the next node.
        else {
            shorted_path.push_back(src_node);
            shorted_path.push_back(dst_node);

            // Skip all nodes until destination node (destination node
            // included).
            for(uint32_t j = i+1; j < path.size(); j++) {
                if(path.at(j) == dst_node) {
                    i = j+1;
                    break;
                }
            }
        }
    }
    */
    for(auto &node : path) {
        if(graph[node].instr->is_instruction()) {
            shorted_path.push_back(node);
        }
    }

    return shorted_path;

}

vector<BlockPtr> transform_dataflow_to_basic_blocks(
                                                   const Translator &translator,
                                                   const GraphDataFlow &graph,
                                                   const DataFlowPath &path) {

    DataFlowPath shorted_path = create_shorted_dataflow_path(translator,
                                                             graph,
                                                             path);

    vector<BlockPtr> bbs_path;
    if(shorted_path.empty()) {
        return bbs_path;
    }
    GraphDataFlow::vertex_descriptor src_node = shorted_path.at(0);

    // If we only have one node in the shorted path, then add the corresponding
    // basic block manually to the final basic block path.
    if(shorted_path.size() == 1) {
        uint64_t src_instr_addr = graph[src_node].instr->get_address();
        const Function &src_function = translator.get_containing_function(
                                                                src_instr_addr);
        const BlockPtr &src_block = src_function.get_containing_block_ptr(
                                                                src_instr_addr);
        GraphCfg::vertex_descriptor src_node_cfg = src_function.get_cfg_node(
                                                      src_block->get_address());
        const GraphCfg &cfg = src_function.get_cfg();
        bbs_path.push_back(cfg[src_node_cfg]);
    }

    // Create a basic block path from the shorted data flow path (data flow
    // path will only be processed if it has at least a size of 2).
    for(uint32_t i = 0; i < (shorted_path.size()-1); i++) {

        uint64_t src_instr_addr = graph[src_node].instr->get_address();
        const Function &src_function = translator.get_containing_function(
                                                                src_instr_addr);

        GraphDataFlow::vertex_descriptor dst_node = shorted_path.at(i+1);
        uint64_t dst_instr_addr = graph[dst_node].instr->get_address();

#if DEBUG_ENGELS_PRINT_VERBOSE
        cout << "Transform DF -> CF source: " << *graph[src_node].instr << "\n";
        cout << "Transform DF -> CF dst: " << *graph[dst_node].instr << "\n";
#endif

        // Transition leaves the function.
        if(!src_function.contains_address(dst_instr_addr)) { // Inter-Procedural
            const Function &dst_function = translator.get_containing_function(
                                                                dst_instr_addr);

            // Get basic blocks for source and destination instruction.
            const BlockPtr &src_block = src_function.get_containing_block_ptr(
                                                                src_instr_addr);
            const BlockPtr &dst_block = dst_function.get_containing_block_ptr(
                                                                dst_instr_addr);

            // Check if we have to add the src basic block to the final path
            // or if it is already the last basic block in the final path.
            if(bbs_path.empty()) {
                bbs_path.push_back(src_block);
            }
            else {
                uint64_t src_block_addr = src_block->get_address();
                if(bbs_path.back()->get_address() != src_block_addr) {
                    bbs_path.push_back(src_block);
                }
            }

            TerminatorType src_terminator = src_block->get_terminator().type;
            GraphCfg::vertex_descriptor src_node_cfg;
            GraphCfg::vertex_descriptor dst_node_cfg;

            // Handle calls into the destination function.
            if(src_terminator == TerminatorCall
               || src_terminator == TerminatorCallUnresolved) {

                // If destination basic block and destination function entry
                // are the same, then just add destination block to
                // the final basic block path and continue execution with
                // the next iteration.
                uint64_t dst_function_addr = dst_function.get_entry();
                if(dst_block->get_address() == dst_function_addr) {
                    bbs_path.push_back(dst_block);

                    // Make destination node to the next source node.
                    src_node = dst_node;

                    continue;
                }

                // Make function entry the source node in the cfg and
                // the destination block the destination node.
                else {
                    src_node_cfg = dst_function.get_cfg_node(dst_function_addr);
                    dst_node_cfg = dst_function.get_cfg_node(
                                                      dst_block->get_address());
                }
            }

            // Handle jmps into the destination function (extract source node
            // in the cfg).
            else if(src_terminator == TerminatorJump) {

                uint64_t jmp_target_addr = src_block->get_terminator().target;
                const Block &jmp_target_block =
                        dst_function.get_containing_block(jmp_target_addr);

                // If destination basic block and jmp target block
                // are the same, then just add destination block to
                // the final basic block path and continue execution with
                // the next iteration.
                if(dst_block->get_address() == jmp_target_block.get_address()) {
                    bbs_path.push_back(dst_block);

                    // Make destination node to the next source node.
                    src_node = dst_node;

                    continue;
                }

                // Make jmp target block source node in the cfg and
                // the destination block the destination node.
                else {
                    src_node_cfg = dst_function.get_cfg_node(
                                                jmp_target_block.get_address());
                    dst_node_cfg = dst_function.get_cfg_node(
                                                      dst_block->get_address());
                }
            }

            // Handle return instructions into the destination function
            // (extract source node in the cfg and next destination node).
            else if(src_terminator == TerminatorReturn) {

                // The destination of a return instruction has to be a
                // call instruction.
                if(!graph[dst_node].instr->is_call()) {
                    stringstream err_msg;
                    err_msg << "Not able to handle transition from "
                            << "return instruction '"
                            << *graph[src_node].instr
                            << "' to destination instruction '"
                            << *graph[dst_node].instr
                            << "'. Destination instruction has to "
                            << "be call instruction.";
                    throw runtime_error(err_msg.str().c_str());
                }

                // Use the basic block that follows the call instruction as
                // source basic block.
                uint64_t next_block_addr =
                        dst_block->get_terminator().fall_through;
                const BlockPtr &next_block =
                         dst_function.get_containing_block_ptr(next_block_addr);
                src_node_cfg = dst_function.get_cfg_node(next_block_addr);

                // If there is no node on the data flow path after the
                // call instruction, just add the basic block after the call
                // instruction to the final basic block path and continue
                // the loop iteration.
                if((i+2) >= shorted_path.size()) {
                    bbs_path.push_back(next_block);

                    // Make destination node to the next source node.
                    // In this case, we skipped the call instruction.
                    src_node = dst_node;

                    continue;
                }

                // Skip the call instruction as destination node and use the
                // node after that in the data flow path as destination.
                dst_node = shorted_path.at(i+2);
                dst_instr_addr = graph[dst_node].instr->get_address();
                // Odd data flow can happen, for example if we have a
                // -> retn in fct2 to fct1 (c9d3ae node+vtv)
                // -> call in fct1 to fct2 (ccba68 node+vtv)
                // -> (jmp to fct1 in fct1 that is not in data flow)
                // -> instr in fct2 (c9d1f6 node+vtv).
                // The data flow uses the call instruction to go back to fct2
                // even if this is not directly possible.
                // TODO Change data-flow generation by making 2 nodes for
                // the call instruction, one node for "ret target" and
                // one node for direct "calls".
                if(!dst_function.contains_address(dst_instr_addr)) {
                    cerr << "Odd data flow from source instruction '"
                         << *graph[src_node].instr
                         << "' to instruction '"
                         << *graph[shorted_path.at(i+1)].instr
                         << "' to instruction '"
                         << *graph[dst_node].instr
                         << "'. Not able to transform to control-flow."
                         << "\n";
                    bbs_path.clear();
                    return bbs_path;
                }
                const Block &next_dst_block =
                              dst_function.get_containing_block(dst_instr_addr);
                dst_node_cfg = dst_function.get_cfg_node(
                                                  next_dst_block.get_address());

                // Skip the call instruction to be the
                // next processed instruction.
                i++;

                // If the basic block after the call instruction and
                // the next node on the data flow path the same basic block
                // just add it to the final path and continue execution with
                // the next iteration.
                if(dst_node_cfg == src_node_cfg) {

                    bbs_path.push_back(next_block);

                    // Make destination node to the next source node.
                    // In this case, we skipped the call instruction.
                    src_node = dst_node;

                    continue;
                }
            }

            // If the terminator belongs to an unresolved control flow
            // transfer instruction, we can not create a control flow
            // for now.
            else if(src_terminator == TerminatorUnresolved) {
                bbs_path.clear();
                return bbs_path;
            }

            // Handle unknown terminator cases.
            else {
                stringstream err_msg;
                err_msg << "Not able to handle transition from "
                        << "source Basic Block address "
                        << hex << src_block->get_address()
                        << " to destination Basic Block address "
                        << hex << dst_block->get_address()
                        << ". Unknown terminator type: "
                        << dec << src_terminator;
                throw runtime_error(err_msg.str().c_str());
            }

            // Get cfg and indexmap.
            const GraphCfg &dst_cfg = dst_function.get_cfg();
            const auto &indexmap = dst_function.get_cfg_indexmap();

            // Find a control flow path between function entry/jmp target
            // and destination node from the data flow path.
            ControlFlowPath src_dst_path_cf = create_controlflow_path(
                                                                  dst_cfg,
                                                                  indexmap,
                                                                  src_node_cfg,
                                                                  dst_node_cfg);
            if(src_dst_path_cf.size() == 0) {
                cerr << "No path from basic block "
                     << hex << dst_cfg[src_node_cfg]->get_address()
                     << " to instruction '"
                     << *graph[dst_node].instr
                     << "' found."
                     << "\n";

                bbs_path.clear();
                return bbs_path;
            }

            // Generate a path of basic blocks from control flow path.
            for(uint32_t j = 0; j < src_dst_path_cf.size(); j++) {
                bbs_path.push_back(dst_cfg[src_dst_path_cf.at(j)]);
            }

            // Make destination node to the next source node.
            src_node = dst_node;
        }

        // Transition does not leave the function.
        else { // Intra-Procedural

            // Get basic blocks for source and destination instruction.
            const BlockPtr &src_block = src_function.get_containing_block_ptr(
                                                                src_instr_addr);
            const BlockPtr &dst_block = src_function.get_containing_block_ptr(
                                                                dst_instr_addr);

            // Get source and destination node in cfg.
            const GraphCfg &src_cfg = src_function.get_cfg();
            const auto &indexmap = src_function.get_cfg_indexmap();
            GraphCfg::vertex_descriptor src_node_cfg =
                                                src_function.get_cfg_node(
                                                      src_block->get_address());
            GraphCfg::vertex_descriptor dst_node_cfg =
                                                src_function.get_cfg_node(
                                                      dst_block->get_address());

            // If source and destination reside in the same basic block,
            // add it and continue processing with new source node.
            if(src_block->get_address() == dst_block->get_address()) {

                // Do not add the current source basic block if it is the same
                // as the last basic block of the final path.
                if(!bbs_path.empty()) {
                    if(bbs_path.back()->get_address()
                       != src_block->get_address()) {
                        bbs_path.push_back(src_cfg[src_node_cfg]);
                    }
                }
                else {
                    bbs_path.push_back(src_cfg[src_node_cfg]);
                }

                // Make destination node to the next source node.
                src_node = dst_node;
                continue;
            }

            // Find a control flow path between source and destination node
            // from the data flow path.
            ControlFlowPath src_dst_path_cf = create_controlflow_path(
                                                                  src_cfg,
                                                                  indexmap,
                                                                  src_node_cfg,
                                                                  dst_node_cfg);
            if(src_dst_path_cf.size() == 0) {
                cerr << "No path from instruction '"
                     << *graph[src_node].instr
                     << "' to instruction '"
                     << *graph[dst_node].instr
                     << "' found."
                     << "\n";

                bbs_path.clear();
                return bbs_path;
            }

            // Check if the first basic block of the current path is also the
            // last basic block of the final path => remove it before adding it
            // to the final path.
            if(!bbs_path.empty()) {
                uint64_t first_addr =
                                src_cfg[src_dst_path_cf.front()]->get_address();
                if(bbs_path.back()->get_address() == first_addr) {
                    src_dst_path_cf.erase(src_dst_path_cf.begin());
                }
            }

            // Generate a path of basic blocks from control flow path.
            for(uint32_t j = 0; j < src_dst_path_cf.size(); j++) {
                bbs_path.push_back(src_cfg[src_dst_path_cf.at(j)]);
            }

            // Make destination node to the next source node.
            src_node = dst_node;
        }
    }

    return bbs_path;
}

// Split both path into the parts they have in common and the divergent ones.
void split_paths(
        DataFlowPath &out_path_beginning,
        DataFlowPath &out_path_diverge_vtable,
        DataFlowPath &out_path_diverge_icall,
        const DataFlowPath &path_root_vtable_orig,
        const DataFlowPath &path_root_icall_orig) {

    // Get max size.
    uint32_t size_vtable = path_root_vtable_orig.size();
    uint32_t size_icall = path_root_icall_orig.size();
    uint32_t size_max = size_icall;
    if(size_vtable > size_icall) {
        size_max = size_vtable;
    }

    // Split our two paths into three.
    // 1) root -> diverge node
    // 2) diverge node -> vtable
    // 3) diverge node -> icall
    bool path_diverged = false;
    for(uint32_t i = 0; i < size_max; i++) {
        if(!path_diverged
           && i < size_icall
           && i < size_vtable
           && path_root_vtable_orig.at(i) == path_root_icall_orig.at(i)) {

            out_path_beginning.push_back(path_root_vtable_orig.at(i));
            continue;
        }
        path_diverged = true;
        if(i < size_vtable) {
            out_path_diverge_vtable.push_back(path_root_vtable_orig.at(i));
        }
        if(i < size_icall) {
            out_path_diverge_icall.push_back(path_root_icall_orig.at(i));
        }
    }
}

void glue_block_paths_together(vector<BlockPtr> &out_path_blocks,
                               const vector<BlockPtr> &path_blocks_adding,
                               const Function &join_function,
                               const BlockPtr &src_block) {

    const BlockPtr &dst_block = path_blocks_adding.front();

    // If the src basic block is not the same as the dst basic block of
    // the path to add, we have to find a path to it and add it also.
    if(src_block->get_address()
       != dst_block->get_address()) {

        const GraphCfg &cfg = join_function.get_cfg();
        const auto &indexmap = join_function.get_cfg_indexmap();

        GraphCfg::vertex_descriptor src_node_cfg = join_function.get_cfg_node(
                                                      src_block->get_address());
        GraphCfg::vertex_descriptor dst_node_cfg = join_function.get_cfg_node(
                                                      dst_block->get_address());
        ControlFlowPath src_dst_path_cf = create_controlflow_path(cfg,
                                                                  indexmap,
                                                                  src_node_cfg,
                                                                  dst_node_cfg);

        if(src_dst_path_cf.size() == 0) {
            cerr << "No path from basic block "
                 << hex << src_block->get_address()
                 << " to basic block "
                 << hex << dst_block->get_address()
                 << " found."
                 << "\n";
            out_path_blocks.clear();
            return;
        }

        // Add path from the src basic block of the final path
        // to the dst basic block (skip
        // the first basic block because it is already in the final
        // basic block path)
        for(uint32_t i = 1;
            i < src_dst_path_cf.size();
            i++) {

            out_path_blocks.push_back(cfg[src_dst_path_cf.at(i)]);
        }
    }

    // Add vtable path to the final basic block path
    // (skip the first basic block because it was either already added or
    // is the same as the src basic block of final path).
    for(uint32_t i = 1;
        i < path_blocks_adding.size();
        i++) {
        out_path_blocks.push_back(path_blocks_adding.at(i));
    }
}

ExpressionPtr extract_call_target(const State &state,
                                  const BaseInstructionSSAPtr &icall_instr) {

    // Extract the operand used by the icall instruction as target
    // and convert it into a vex register.
    const OperandSSAPtr &call_operand = icall_instr->get_uses().at(0);
    const shared_ptr<Register> *call_reg_ptr = nullptr;
    if(call_operand->is_memory()) {
        switch(call_operand->get_type()) {
            case SSAOpTypeMemoryX64: {
                const MemoryX64SSA &mem =
                            static_cast<const MemoryX64SSA &>(*call_operand);
                const RegisterX64SSA &base = mem.get_base();
                call_reg_ptr = &convert_ssa_reg_to_vex_reg(base.get_index());
                break;
            }
            default:
                throw runtime_error("Unknown SSA memory object.");
        }
    }
    else if(call_operand->is_register()) {
        switch(call_operand->get_type()) {
            case SSAOpTypeRegisterX64: {
                const RegisterX64SSA &reg =
                             static_cast<const RegisterX64SSA &>(*call_operand);
                call_reg_ptr = &convert_ssa_reg_to_vex_reg(reg.get_index());
                break;
            }
            default:
                throw runtime_error("Unknown SSA register object.");
        }
    }
    else {
        throw runtime_error("Do not know how to extract operand type after "\
                            "symbolic execution.");
    }
    if(call_reg_ptr == nullptr) {
        stringstream err_msg;
        err_msg << "Not able to get call target register of operand "
                << *call_operand
                << " for instruction "
                << *icall_instr;
        throw runtime_error(err_msg.str().c_str());
    }
    const shared_ptr<Register> &call_reg = *call_reg_ptr;

    // Get value of register used as call target.
    State::const_iterator call_reg_value;
    ExpressionPtr call_reg_expr_ptr;
    if(!state.find(call_reg, call_reg_value)) {
        call_reg_expr_ptr = make_shared<Unknown>();
    }
    else {
        call_reg_expr_ptr = call_reg_value->second;
    }

    // TODO / DEBUG
    cout << "icall instruction: " << *icall_instr << "\n";
    cout << "icall operand: " << *call_operand << "\n";
    cout << "icall operand register value: " << *call_reg_expr_ptr << "\n";

    return call_reg_expr_ptr;
}

void add_artificial_ret_blocks(vector<BlockPtr> &out_path_blocks,
                               const Translator &translator) {

    for(uint32_t i = 0; i < out_path_blocks.size()-1; i++) {
        const BlockPtr &curr_block = out_path_blocks.at(i);
        TerminatorType terminator_type = curr_block->get_terminator().type;

        // Check if block ends with a call instruction.
        if(terminator_type == TerminatorCall
           || terminator_type == TerminatorCallUnresolved) {

            // If the following block on the path resides in the same
            // function (=> call was skipped) add an artificial return block.
            const BlockPtr &next_block = out_path_blocks.at(i+1);
            const Function &curr_function =
                        translator.get_containing_function(
                                                     curr_block->get_address());
            if(curr_function.contains_address(next_block->get_address())) {
                out_path_blocks.insert(out_path_blocks.begin()+i+1,
                                       ret_block_ptr);

                // Skip next block since it is our artificial return block.
                i++;
            }
        }
    }
}

bool extract_vtbl_entry_index(uint64_t *out_entry_idx,
                              EngelsAnalysisObjects &analysis_obj,
                              const State &state,
                              uint32_t vtable_idx) {

    auto extract_index_abs_addr = [&](uint64_t *out_idx,
                                      uint64_t entry_addr,
                                      uint64_t vtbl_addr,
                                      uint64_t addr_size) -> bool {
        int64_t result = entry_addr - vtbl_addr;
        if(result < 0
           || (result % 8) != 0) {
            return false;
        }
        *out_idx = result / addr_size;
        return true;
    };

    uint64_t addr_size = analysis_obj.vtable_file.get_addr_size();

    // Get value of instruction pointer (since it contains the icall target).
    State::const_iterator ip_value;
    if(state.find(register_rip, ip_value)) { // TODO: architecture specific
        ExpressionPtr icall_target = ip_value->second;

#if DEBUG_ENGELS_PRINT_VERBOSE
        cout << "Extracting vtable entry index from: "
             << *icall_target << "\n";
#endif

        // Unpack and extract vtable index from instruction pointer value.
        switch(icall_target->type()) {
            case ExpressionIndirection: {
                Indirection &ind = static_cast<Indirection&>(*icall_target);

                switch(ind.address()->type()) {
                    // [(vtable_ptr + 0x10)]
                    // [(0x401d98 + 0x10)]
                    case ExpressionOperation: {
                        Operation &op = static_cast<Operation&>(*ind.address());

                        // At the moment we only handle expressions in which
                        // the rhs is a constant.
                        if(op.rhs()->type() != ExpressionConstant) {
                            stringstream err_msg;
                            err_msg << "During vtable index extraction: "
                                    << *icall_target
                                    << " Rhs of operation expected to be "
                                    << "constant expression. Is of type: "
                                    << dec << op.rhs()->type();
                            throw runtime_error(err_msg.str().c_str());
                        }

                        switch(op.lhs()->type()) {

                            // [(vtable_ptr + 0x10)]
                            case ExpressionSymbolic: {
                                Constant &rhs = static_cast<Constant&>(
                                                                     *op.rhs());

                                // We expect an add operation at this point.
                                if(op.operation() != OperationAdd) {
                                    stringstream err_msg;
                                    err_msg << "During vtable index "
                                            << "extraction: "
                                            << *icall_target
                                            << " Expected OperationAdd but "
                                            << "found type: "
                                            << dec << op.operation();
                                    throw runtime_error(
                                                     err_msg.str().c_str());
                                }

                                if(rhs.value() % addr_size != 0) {
                                    return false;
                                }
                                *out_entry_idx = rhs.value() / addr_size;
                                return true;
                            }

                            // [(0x401d98 + 0x10)]
                            case ExpressionConstant: {
                                Constant &lhs = static_cast<Constant&>(
                                                                     *op.lhs());
                                Constant &rhs = static_cast<Constant&>(
                                                                     *op.rhs());

                                uint64_t result = 0;
                                switch(op.operation()) {
                                    case OperationAdd:
                                        result = lhs.value() + rhs.value();
                                        break;
                                    case OperationSub:
                                        result = lhs.value() - rhs.value();
                                        break;
                                    case OperationAnd:
                                        result = lhs.value() & rhs.value();
                                        break;
                                    default:
                                        stringstream err_msg;
                                        err_msg << "During vtable index "
                                                << "extraction: "
                                                << *icall_target
                                                << " Do not know how to handle "
                                                << "operation of type: "
                                                << dec << op.operation();
                                        throw runtime_error(
                                                         err_msg.str().c_str());
                                }

                                const VTable& vtable_obj =
                                        analysis_obj.vtable_file.get_vtable(
                                                                    vtable_idx);

                                // Extract the index from the absolute address.
                                return extract_index_abs_addr(out_entry_idx,
                                                              result,
                                                              vtable_obj.addr,
                                                              addr_size);
                            }

                            // We had a case where an indirection was in the
                            // lhs. Just ignore this case.
                            case ExpressionIndirection: {
                                return false;
                            }

                            default: {
                                stringstream err_msg;
                                err_msg << "During vtable index extraction: "
                                        << *icall_target
                                        << " Do not know how to handle "
                                        << "lhs of operation of type: "
                                        << dec << op.lhs()->type();
                                throw runtime_error(err_msg.str().c_str());
                            }
                        }

                    }

                    // [vtable_ptr]
                    case ExpressionSymbolic: {
                        *out_entry_idx = 0;
                        return true;
                    }

                    // [0x401dc8]
                    case ExpressionConstant: {

                        Constant &cons = static_cast<Constant&>(*ind.address());

                        const VTable& vtable_obj =
                                analysis_obj.vtable_file.get_vtable(vtable_idx);

                        // Extract the index from the absolute address.
                        return extract_index_abs_addr(out_entry_idx,
                                                      cons.value(),
                                                      vtable_obj.addr,
                                                      addr_size);
                    }

                    default: {
                        stringstream err_msg;
                        err_msg << "During vtable index extraction: "
                                << *icall_target
                                << " Do not know how to handle "
                                << "expression in indirection of type: "
                                << dec << icall_target->type();
                        throw runtime_error(err_msg.str().c_str());
                    }
                }
                break;
            }

            default: {
                stringstream err_msg;
                err_msg << "During vtable index extraction: "
                        << *icall_target
                        << " Do not know how to handle "
                        << "icall target of type: "
                        << dec << icall_target->type();
                throw runtime_error(err_msg.str().c_str());
            }
        }
    }

    else {
        cerr << "Not able to get instruction pointer value." << "\n";
    }

    return false;
}

bool process_result(EngelsAnalysisObjects &analysis_obj,
                    const ExpressionPtr &call_reg_expr_ptr,
                    const BaseInstructionSSAPtr &icall_instr,
                    uint32_t vtable_idx,
                    const State &state) {

    bool has_result = false;

    const EntryVTablePtrsMap &this_vtable_entry_addrs =
            analysis_obj.vtable_file.get_this_vtable_entry_addrs();

    ExpressionPtr sym_vtable_ptr = make_shared<Symbolic>("vtable_ptr");

    // Extract the operand used by the icall instruction as target.
    const OperandSSAPtr &call_operand = icall_instr->get_uses().at(0);

    // Process call register expression.
    switch(call_reg_expr_ptr->type()) {

        // A constant can be directly in the call register expression.
        case ExpressionConstant: {
            const Constant &constant = static_cast<const Constant&>(
                                                            *call_reg_expr_ptr);

            // Only if the call operand is a memory expression, the constant
            // can be a vtable entry address. For example:
            // call [rax_18] with 0x110c3b0
            uint64_t entry_addr = constant.value();
            if(call_operand->is_memory()
               && this_vtable_entry_addrs.find(entry_addr)
                    != this_vtable_entry_addrs.cend()) {

#if DEBUG_ENGELS_PRINT
                cout << "Virtual callsite found: "
                     << *icall_instr
                     << "\n";
                cout << "Call register expression: "
                     << *call_reg_expr_ptr
                     << "\n";
#endif

                for(const VTable *vtbl_obj
                        : this_vtable_entry_addrs.at(entry_addr)) {

                    // Calculate entry index.
                    uint64_t entry_idx = 0;
                    bool has_entry_idx = extract_vtbl_entry_index(
                                                               &entry_idx,
                                                               analysis_obj,
                                                               state,
                                                               vtbl_obj->index);
                    if(!has_entry_idx) {
                        cerr << "Not able to extract vtable entry index for "
                             << "icall instruction: "
                             << *icall_instr
                             << " Skipping."
                             << "\n";
                        continue;
                    }
#if DEBUG_ENGELS_PRINT_VERBOSE
        cout << "Vtable entry index is: "
             << dec << entry_idx
             << "\n";
#endif

                    EngelsResult result;
                    result.icall_instr = icall_instr;
                    result.call_reg_expr_ptr = call_reg_expr_ptr;
                    result.vtable_idx = vtbl_obj->index;
                    result.entry_idx = entry_idx;

                    analysis_obj.results_mtx.lock();
                    analysis_obj.results[
                                  icall_instr->get_address()].push_back(result);
                    analysis_obj.results_mtx.unlock();
                    has_result = true;
                }
            }

            break;
        }

        case ExpressionSymbolic: {

            // Call register expression is directly our vtable_ptr symbol.
            // For example: call [rax_175]#10
            if(*call_reg_expr_ptr == *sym_vtable_ptr
               && call_operand->is_memory()) {

#if DEBUG_ENGELS_PRINT
                cout << "Virtual callsite found: "
                     << *icall_instr
                     << "\n";
                cout << "Call register expression: "
                     << *call_reg_expr_ptr
                     << "\n";
#endif

                // Calculate entry index.
                uint64_t entry_idx = 0;
                bool has_entry_idx = extract_vtbl_entry_index(&entry_idx,
                                                              analysis_obj,
                                                              state,
                                                              vtable_idx);
                if(!has_entry_idx) {
                    cerr << "Not able to extract vtable entry index for "
                         << "icall instruction: "
                         << *icall_instr
                         << " Skipping."
                         << "\n";
                    break;
                }
#if DEBUG_ENGELS_PRINT_VERBOSE
        cout << "Vtable entry index is: "
             << dec << entry_idx
             << "\n";
#endif

                EngelsResult result;
                result.icall_instr = icall_instr;
                result.call_reg_expr_ptr = call_reg_expr_ptr;
                result.vtable_idx = vtable_idx;
                result.entry_idx = entry_idx;

                analysis_obj.results_mtx.lock();
                analysis_obj.results[icall_instr->get_address()].push_back(
                                                                        result);
                analysis_obj.results_mtx.unlock();
                has_result = true;
            }
        }

        // The call register expression can contain an indirection.
        case ExpressionIndirection: {
            const Indirection &ind = static_cast<const Indirection&>(
                                                            *call_reg_expr_ptr);

            // A constant can be directly in the indirection.
            // For example: call rax_175 with [0x110c3b0]
            if(call_operand->is_register()
               && ind.address()->type() == ExpressionConstant) {
                const Constant &constant = static_cast<const Constant&>(
                                                                *ind.address());

                uint64_t entry_addr = constant.value();
                if(this_vtable_entry_addrs.find(entry_addr)
                        != this_vtable_entry_addrs.cend()) {

#if DEBUG_ENGELS_PRINT
                    cout << "Virtual callsite found: "
                         << *icall_instr
                         << "\n";
                    cout << "Call register expression: "
                         << *call_reg_expr_ptr
                         << "\n";
#endif

                    for(const VTable *vtbl_obj
                            : this_vtable_entry_addrs.at(entry_addr)) {

                        // Calculate entry index.
                        uint64_t entry_idx = 0;
                        bool has_entry_idx = extract_vtbl_entry_index(
                                                               &entry_idx,
                                                               analysis_obj,
                                                               state,
                                                               vtbl_obj->index);
                        if(!has_entry_idx) {
                            cerr << "Not able to extract vtable entry index "
                                 << "for icall instruction: "
                                 << *icall_instr
                                 << " Skipping."
                                 << "\n";
                            continue;
                        }
#if DEBUG_ENGELS_PRINT_VERBOSE
        cout << "Vtable entry index is: "
             << dec << entry_idx;
#endif

                        EngelsResult result;
                        result.icall_instr = icall_instr;
                        result.call_reg_expr_ptr = call_reg_expr_ptr;
                        result.vtable_idx = vtbl_obj->index;
                        result.entry_idx = entry_idx;

                        analysis_obj.results_mtx.lock();
                        analysis_obj.results[
                                  icall_instr->get_address()].push_back(result);
                        analysis_obj.results_mtx.unlock();
                        has_result = true;
                    }
                }
            }

            // An operation can be in the indirection.
            // For example: call rax_175 with [(0x110c3b0 + 0x0)]
            else if(call_operand->is_register()
                    && ind.address()->type() == ExpressionOperation) {

                const Operation &op = static_cast<const Operation&>(
                                                                *ind.address());

                // The symbol vtable_ptr can be overwritten during the execution
                // of the path and another vtable can be placed at its position.
                // For example call rax_175 with [(0x110c3b0 + 0x0)]
                if(op.lhs()->type() == ExpressionConstant
                   && op.rhs()->type() == ExpressionConstant) {

                    const Constant &lhs = static_cast<const Constant&>(
                                                                     *op.lhs());
                    const Constant &rhs = static_cast<const Constant&>(
                                                                     *op.rhs());

                    uint64_t entry_addr = lhs.value();
                    if(this_vtable_entry_addrs.find(entry_addr)
                            != this_vtable_entry_addrs.cend()) {
                        bool is_vtable_entry = false;
                        switch(op.operation()) {
                            case OperationAdd:
                            case OperationSub:
                                if(rhs.value() == 0x0) {
                                    is_vtable_entry = true;
                                }
                                break;
                            case OperationAnd:
                                if(rhs.value() == 0xffffffffffffffff) {
                                    is_vtable_entry = true;
                                }
                                break;
                            default:
                                break;
                        }

                        if(is_vtable_entry) {

#if DEBUG_ENGELS_PRINT
                            cout << "Virtual callsite found: "
                                 << *icall_instr
                                 << "\n";
                            cout << "Call register expression: "
                                 << *call_reg_expr_ptr
                                 << "\n";
#endif

                            for(const VTable *vtbl_obj
                                    : this_vtable_entry_addrs.at(entry_addr)) {

                                // Calculate entry index.
                                uint64_t entry_idx = 0;
                                bool has_entry_idx = extract_vtbl_entry_index(
                                                               &entry_idx,
                                                               analysis_obj,
                                                               state,
                                                               vtbl_obj->index);
                                if(!has_entry_idx) {
                                    cerr << "Not able to extract vtable entry "
                                         << "index for icall instruction: "
                                         << *icall_instr
                                         << " Skipping."
                                         << "\n";
                                    continue;
                                }
#if DEBUG_ENGELS_PRINT_VERBOSE
        cout << "Vtable entry index is: "
             << dec << entry_idx;
#endif

                                EngelsResult result;
                                result.icall_instr = icall_instr;
                                result.call_reg_expr_ptr = call_reg_expr_ptr;
                                result.vtable_idx = vtbl_obj->index;
                                result.entry_idx = entry_idx;

                                analysis_obj.results_mtx.lock();
                                analysis_obj.results[
                                  icall_instr->get_address()].push_back(result);
                                analysis_obj.results_mtx.unlock();
                                has_result = true;
                            }
                        }
                    }
                }

                // For example: call rax_175 with [(vtable_ptr + 0x60)]
                else if(*(op.lhs()) == *sym_vtable_ptr) {

#if DEBUG_ENGELS_PRINT
                    cout << "Virtual callsite found: "
                         << *icall_instr
                         << "\n";
                    cout << "Call register expression: "
                         << *call_reg_expr_ptr
                         << "\n";
#endif

                    // Calculate entry index.
                    uint64_t entry_idx = 0;
                    bool has_entry_idx = extract_vtbl_entry_index(&entry_idx,
                                                                  analysis_obj,
                                                                  state,
                                                                  vtable_idx);
                    if(!has_entry_idx) {
                        cerr << "Not able to extract vtable entry index for "
                             << "icall instruction: "
                             << *icall_instr
                             << " Skipping."
                             << "\n";
                        break;
                    }
#if DEBUG_ENGELS_PRINT_VERBOSE
        cout << "Vtable entry index is: "
             << dec << entry_idx;
#endif

                    EngelsResult result;
                    result.icall_instr = icall_instr;
                    result.call_reg_expr_ptr = call_reg_expr_ptr;
                    result.vtable_idx = vtable_idx;
                    result.entry_idx = entry_idx;

                    analysis_obj.results_mtx.lock();
                    analysis_obj.results[
                                  icall_instr->get_address()].push_back(result);
                    analysis_obj.results_mtx.unlock();
                    has_result = true;
                }
            }

            break;
        }

        default:
            cerr << "Do not know how to process result expression: "
                 << *call_reg_expr_ptr
                 << "\n";
            break;
    }

    return has_result;
}

bool process_vtable_call_nodes(
           EngelsAnalysisObjects &analysis_obj,
           ICallAnalysis &analysis,
           const GraphDataFlow &graph,
           GraphDataFlow::vertex_descriptor icall_node,
           unordered_set<GraphDataFlow::vertex_descriptor> &vtable_call_nodes) {

    bool has_overall_result = false;

    // Create indexmap in order to work with boost algorithms on the graph.
    boost::property_map<GraphDataFlow,
                        boost::vertex_index_t>::type indexmap =
                                                  analysis.get_graph_indexmap(); // TODO optimize indexmap creation by caching

    for(auto root_node : vtable_call_nodes) {

        vector<DataFlowPath> paths_root_icall = create_dataflow_paths(
                                                             analysis_obj,
                                                             graph,
                                                             indexmap,
                                                             root_node, // src
                                                             icall_node); // dst

        // Skip if we do not have a path from the root node to the icall node.
        if(paths_root_icall.size() == 0) {
            continue;
        }

#if DEBUG_ENGELS_PRINT
        cout << "Searching path from '"
             << *graph[root_node].instr
             << "' to '"
             << *graph[icall_node].instr
             << "'."
             << "\n";
#endif

        for(DataFlowPath &path_root_icall : paths_root_icall) {

#if DEBUG_ENGELS_PRINT_PATHS
            cout << "Size data flow path: "
                 << dec << path_root_icall.size() << "\n";
            for(auto &node : path_root_icall) {
                cout << "-> " << *graph[node].instr << "\n";
            }
            cout << "\n";
#endif

            vector<BlockPtr> path_blocks =
                    transform_dataflow_to_basic_blocks(analysis_obj.translator,
                                                       graph,
                                                       path_root_icall);

            // Skip if we do not have a path from the root node to the
            // icall node.
            if(path_blocks.size() == 0) {

                cerr << "No control flow from vtable call node '"
                     << *graph[root_node].instr
                     << "' to icall instruction '"
                     << *graph[icall_node].instr
                     << "' found. Skipping."
                     << "\n";

                continue;
            }

            // Add return basic blocks after each skipped call.
            add_artificial_ret_blocks(path_blocks,
                                      analysis_obj.translator);

#if DEBUG_ENGELS_PRINT_PATHS
            cout << "Size control flow path: "
                 << dec << path_blocks.size() << "\n";
            cout << "Final path:";
            for(auto &block : path_blocks) {
                cout << "-> " << hex << block->get_address() << "\n";
            }
            cout << "\n";
#endif

            // Symbolically execute the final path with a symbolic vtable ptr
            // in the this argument.
            State state;
            ExpressionPtr sym_vtable_ptr = make_shared<Symbolic>("vtable_ptr");
            State::const_iterator this_ptr_value;
            state.find(system_v_arguments[0], this_ptr_value); // TODO architecture specific
            ExpressionPtr this_ptr_indirect =
                    make_shared<Indirection>(this_ptr_value->second);
            state.update(this_ptr_indirect, sym_vtable_ptr);

            sym_execute_blocks(analysis_obj, path_blocks, state);

            // TODO / DEBUG
            cout << "Vtable call: " << *graph[root_node].instr << "\n";

            // Extract call register expression from symbolic execution state.
            const BaseInstructionSSAPtr &icall_instr = graph[icall_node].instr;
            ExpressionPtr call_reg_expr_ptr = extract_call_target(state,
                                                                  icall_instr);

            // Get used vtable.
            const VtableCallInstruction &vtable_call_instr =
                 static_cast<const VtableCallInstruction&>(*graph[root_node].instr);
            uint32_t vtable_idx = vtable_call_instr.get_vtable().index;

            bool has_result = process_result(analysis_obj,
                                             call_reg_expr_ptr,
                                             icall_instr,
                                             vtable_idx,
                                             state);

            has_overall_result |= has_result;

            // TODO / DEBUG
            cout << string(79, '=') << "\n" << "\n";

            // When we have found a result, check if it is a result
            // for our current vtable (otherwise continue the search).
            if(has_result) {
                has_result = false;
                for(const EngelsResult &result
                    : analysis_obj.results.at(icall_instr->get_address())) {

                    if(result.vtable_idx == vtable_idx) {
                        has_result = true;
                        break;
                    }
                }
                if(has_result) {
                    break;
                }
            }
        }
    }

    return has_overall_result;
}

void add_paths_to_rets(const Translator &translator,
                       vector<BlockPtr> &out_path_blocks) {

    // Extract all call instructions that do not have a corresponding return
    // in the path.
    vector<BlockPtr> call_stack;
    for(uint32_t i = 0; i < out_path_blocks.size()-1; i++) {

        const BlockPtr &curr_block = out_path_blocks.at(i);
        TerminatorType terminator_type = curr_block->get_terminator().type;

        // Check if block ends with a call instruction.
        if(terminator_type == TerminatorCall
           || terminator_type == TerminatorCallUnresolved) {

            const BlockPtr &next_block = out_path_blocks.at(i+1);
            const Function &curr_function =
                        translator.get_containing_function(
                                                     curr_block->get_address());

            if(curr_function.contains_address(next_block->get_address())) {
                // Skipped call instruction, artificial return basic block
                // is added later.
                continue;
            }
            call_stack.push_back(curr_block);
        }

        else if(terminator_type == TerminatorReturn) {
            if(call_stack.size() > 0) {
                call_stack.pop_back();
            }
            else {
                out_path_blocks.clear();
                cerr << "More return instructions than call instructions "
                     << "on the root->vtable basic block path. Not possible."
                     << "\n";
                return;
            }
        }
    }

    // Add to each call instructions that does not have a corresponding
    // return instruction a path to the next return instruction in the function.
    // Start from the last basic block in the given path.
    BlockPtr curr_block = out_path_blocks.back(); // Do not use reference here!
    while(call_stack.size() != 0) {
        const Function &curr_function = translator.get_containing_function(
                                                     curr_block->get_address());

        vector<BlockPtr> path_to_ret;
        const BlockVector &ret_blocks = curr_function.get_ret_blocks();
        // Create a path to the first best return basic block.
        bool has_path_to_ret = false;
        for(const BlockPtr &ret_block : ret_blocks) {
            vector<BlockPtr> destination_block;
            destination_block.push_back(ret_block);
            glue_block_paths_together(path_to_ret,
                                      destination_block,
                                      curr_function,
                                      curr_block);

            if(path_to_ret.size() == 0) {
                // Skip only if the current block is not the return block.
                if(curr_block->get_address() != ret_block->get_address()) {
                    continue;
                }
            }
            has_path_to_ret = true;
            break;
        }

        if(has_path_to_ret) {

            // Check if we have to add the current basic block to the final path
            // or if it is already the last basic block in the final path
            // since glue_block_paths_together() skips the source block.
            if(out_path_blocks.empty()) {
                out_path_blocks.push_back(curr_block);
            }
            else {
                uint64_t curr_block_addr = curr_block->get_address();
                if(out_path_blocks.back()->get_address() != curr_block_addr) {
                    out_path_blocks.push_back(curr_block);
                }
            }

            // Copy path to return basic block to the vtable path.
            for(uint32_t j = 0; j < path_to_ret.size(); j++) {
                out_path_blocks.push_back(path_to_ret.at(j));
            }

            // Pop the last call block from the stack (since we just have added
            // the corresponding return block for it).
            const BlockPtr &caller_block = call_stack.back();
            const Function &caller_function =
                    translator.get_containing_function(
                                                   caller_block->get_address());

            // Get the basic block following the call block as our next starting
            // point.
            uint64_t next_block_addr =
                                  caller_block->get_terminator().fall_through;

            const BlockPtr *next_block_ptr = nullptr;
            try {
                next_block_ptr = &caller_function.get_containing_block_ptr(
                                                               next_block_addr);
            }
            // We had cases in which the last instruction of a function was
            // the call instruction and the fall through basic block belonged
            // to another function because of a switch-case statement.
            // However, the fall through basic block should also belong
            // to the caller function. Therefore search for
            // it in another function.
            catch(...) {
                const Function &temp_fct = translator.get_containing_function(
                                                               next_block_addr);
                next_block_ptr = &temp_fct.get_containing_block_ptr(
                                                               next_block_addr);
            }
            const BlockPtr &next_block = *next_block_ptr;

            curr_block = next_block;
            call_stack.pop_back();
        }

        // If no path is possible, we have to try tail jumps and find a
        // corresponding return basic block there.
        else {

            vector<BlockPtr> path_to_tail_jmp;
            const BlockVector &tail_jmp_blocks =
                                            curr_function.get_tail_jmp_blocks();
            // Create a path to the first best tail jump basic block.
            bool has_path_to_tail_jmp = false;
            const BlockPtr *jmp_target_block_ptr = nullptr;
            for(const BlockPtr &tail_jmp_block : tail_jmp_blocks) {
                vector<BlockPtr> destination_block;
                destination_block.push_back(tail_jmp_block);
                glue_block_paths_together(path_to_tail_jmp,
                                          destination_block,
                                          curr_function,
                                          curr_block);

                if(path_to_tail_jmp.size() == 0) {
                    // Skip only if the current block is not the tail jmp block.
                    if(curr_block->get_address()
                            != tail_jmp_block->get_address()) {
                        continue;
                    }
                }

                uint64_t jmp_target_addr =
                                        tail_jmp_block->get_terminator().target;
                try {
                    const Function &jmp_target_function =
                        translator.get_containing_function(jmp_target_addr);
                    jmp_target_block_ptr =
                            &(jmp_target_function.get_containing_block_ptr(
                                                              jmp_target_addr));
                }
                catch(...) {
                    cerr << "No function for tail jump target "
                         << hex << jmp_target_addr
                         << " found."
                         << "\n";
                    continue;
                }

                has_path_to_tail_jmp = true;
                break;
            }

            if(!has_path_to_tail_jmp) {
                out_path_blocks.clear();
                cerr << "No path to return or tail jump basic block possible "
                     << "on the root->vtable basic block path."
                     << "\n";
                return;
            }

            // Check if we have to add the current basic block to the final path
            // or if it is already the last basic block in the final path
            // since glue_block_paths_together() skips the source block.
            if(out_path_blocks.empty()) {
                out_path_blocks.push_back(curr_block);
            }
            else {
                uint64_t curr_block_addr = curr_block->get_address();
                if(out_path_blocks.back()->get_address() != curr_block_addr) {
                    out_path_blocks.push_back(curr_block);
                }
            }

            // Copy path to tail jump basic block to the vtable path.
            for(uint32_t j = 0; j < path_to_tail_jmp.size(); j++) {
                out_path_blocks.push_back(path_to_tail_jmp.at(j));
            }

            // Continue processing from jmp target block (do not pop the call
            // stack).
            curr_block = *jmp_target_block_ptr;
        }
    }
}

bool process_root_vtable_icall_dataflow_path(
           EngelsAnalysisObjects &analysis_obj,
           const EngelsVTableXrefAnalysis &vtable_xref_data,
           const GraphDataFlow &graph,
           GraphDataFlow::vertex_descriptor icall_node,
           GraphDataFlow::vertex_descriptor vtable_node,
           const DataFlowPath &path_root_icall,
           const DataFlowPath &path_root_vtable) {

#if DEBUG_ENGELS_PRINT_PATHS
    cout << "Size root->vtable data flow path:" << "\n"
         << dec << path_root_vtable.size() << "\n";
    for(auto &node : path_root_vtable) {
        cout << "-> " << *graph[node].instr << "\n";
    }
    cout << "\n";
    cout << "Size root->icall data flow path:" << "\n"
         << dec << path_root_icall.size() << "\n";
    for(auto &node : path_root_icall) {
        cout << "-> " << *graph[node].instr << "\n";
    }
    cout << "\n";
#endif

    // Split the two paths (root->vtable and root->icall) into
    // three parts:
    // 1) path beginning: common beginning of root->vtable/root->icall
    // 2) diverged part root->vtable
    // 3) diverged part root->icall
    DataFlowPath path_beginning;
    DataFlowPath path_diverge_vtable;
    DataFlowPath path_diverge_icall;
    split_paths(path_beginning,
         path_diverge_vtable,
         path_diverge_icall,
         path_root_vtable,
         path_root_icall);

    // Check edge case in which the last common instruction is
    // a return instruction (and the diverged paths have different
    // call instructions).
    const auto last_node_beginning = path_beginning.back();
    if(graph[last_node_beginning].instr->is_ret()) {
        if(*(graph[path_diverge_vtable.front()].instr)
           != *(graph[path_diverge_icall.front()].instr)) {

#if DEBUG_ENGELS_PRINT_VERBOSE
            cerr << "Impossible control-flow. "
                 << "Path diverges after return instruction '"
                 << *graph[last_node_beginning].instr
                 << "' into different caller. Skipping."
                 << "\n";
#endif
            return false;
        }
    }

#if DEBUG_ENGELS_PRINT_VERBOSE
    cout << "Size beginning data flow path: "
         << dec << path_beginning.size() << "\n";
    for(auto &node : path_beginning) {
        cout << "-> " << *graph[node].instr << "\n";
    }
    cout << "\n";
    cout << "Size diverged root->vtable data flow path: "
         << dec << path_diverge_vtable.size() << "\n";
    for(auto &node : path_diverge_vtable) {
        cout << "-> " << *graph[node].instr << "\n";
    }
    cout << "\n";
    cout << "Size diverged root->icall data flow path: "
         << dec << path_diverge_icall.size() << "\n";
    for(auto &node : path_diverge_icall) {
        cout << "-> " << *graph[node].instr << "\n";
    }
    cout << "\n";
#endif

    // Transform data flow path into control flow path that contains
    // also all basic blocks in between.
    vector<BlockPtr> path_blocks_common_beginning =
            transform_dataflow_to_basic_blocks(analysis_obj.translator,
                                               graph,
                                               path_beginning);
    vector<BlockPtr> path_blocks_diverge_vtable =
            transform_dataflow_to_basic_blocks(analysis_obj.translator,
                                               graph,
                                               path_diverge_vtable);
    vector<BlockPtr> path_blocks_diverge_icall =
            transform_dataflow_to_basic_blocks(analysis_obj.translator,
                                               graph,
                                               path_diverge_icall);

#if DEBUG_ENGELS_PRINT_VERBOSE
    cout << "Size beginning control flow path: "
         << dec << path_blocks_common_beginning.size() << "\n";
    for(auto &block : path_blocks_common_beginning) {
        cout << "-> " << hex << block->get_address() << "\n";
    }
    cout << "\n";
    cout << "Size diverged root->vtable control flow path: "
         << dec << path_blocks_diverge_vtable.size() << "\n";
    for(auto &block : path_blocks_diverge_vtable) {
        cout << "-> " << hex << block->get_address() << "\n";
    }
    cout << "\n";
    cout << "Size diverged root->icall control flow path: "
         << dec << path_blocks_diverge_icall.size() << "\n";
    for(auto &block : path_blocks_diverge_icall) {
        cout << "-> " << hex << block->get_address() << "\n";
    }
    cout << "\n";
#endif

    // Skip if we do not have a complete path.
    if(path_blocks_common_beginning.size() == 0) {
        cerr << "No control flow for the beginning of the path found."
             << "\n";
        return false;
    }
    else if(path_blocks_diverge_vtable.size() == 0) {
        cerr << "No control flow for the vtable path found."
             << "\n";
        return false;
    }
    else if(path_blocks_diverge_icall.size() == 0) {
        cerr << "No control flow for the icall path found."
             << "\n";
        return false;
    }

    // The path to the vtable can have more call instructions
    // than corresponding return instructions. Therefore we
    // have to add a path to return instruction in the corresponding
    // function at the end. For example the path can look like this:
    // call1 -> call2 -> mov -> ret2 -> call3 -> mov
    // Then call3 and call1 do not have a corresponding return
    // instruction.
    add_paths_to_rets(analysis_obj.translator,
                      path_blocks_diverge_vtable);
    if(path_blocks_diverge_vtable.size() == 0) {
        cerr << "No control flow for the vtable path found."
             << "\n";
        return false;
    }

    vector<BlockPtr> path_blocks_first_part;

    // Check if the start basic block of our common beginning
    // is also the function entry, otherwise find a path from the
    // function entry to our start basic block.
    const BlockPtr &start_block = path_blocks_common_beginning.at(0);
    const Function &start_function =
            analysis_obj.translator.get_containing_function(
                                            start_block->get_address());
    if(start_function.get_entry() != start_block->get_address()) {
        const GraphCfg &start_cfg = start_function.get_cfg();
        const auto &start_indexmap = start_function.get_cfg_indexmap();

        // Search path from function entry to common start basic block.
        GraphCfg::vertex_descriptor src_node_cfg =
                start_function.get_cfg_node(start_function.get_entry());
        GraphCfg::vertex_descriptor dst_node_cfg =
                start_function.get_cfg_node(start_block->get_address());
        ControlFlowPath src_dst_path_cf = create_controlflow_path(
                                                         start_cfg,
                                                         start_indexmap,
                                                         src_node_cfg,
                                                         dst_node_cfg);
        if(src_dst_path_cf.size() == 0) {
            cerr << "No path from function entry "
                 << hex << start_function.get_entry()
                 << " to common start instruction '"
                 << *graph[path_beginning.at(0)].instr
                 << "' found."
                 << "\n";
            return false;
        }

        // Generate a path of basic blocks from control flow path
        // (skip last element since it will be copied from
        // path_blocks_common_beginning).
        for(uint32_t j = 0; j < src_dst_path_cf.size()-1; j++) {
            path_blocks_first_part.push_back(
                                      start_cfg[src_dst_path_cf.at(j)]);
        }
    }

    // Copy all common basic blocks to the first final path.
    for(BlockPtr &block_ptr : path_blocks_common_beginning) {
        path_blocks_first_part.push_back(block_ptr);
    }

    uint64_t join_function_addr;
    // In the edge case that the last common instruction was a call
    // instruction to the same function, we start our path search from
    // the entry basic block of the target function. An exception
    // exists when the call was not taken (for example if it was
    // the call instruction after a return instruction or a call
    // to the new operator which is then also a join node).
    const BaseInstructionSSAPtr &beginning_last_instr =
                                     graph[path_beginning.back()].instr;
    const Function &beginning_last_instr_fct =
            analysis_obj.translator.get_containing_function(
                                   beginning_last_instr->get_address());
    uint64_t first_vtable_path_block_addr =
                  path_blocks_diverge_vtable.front()->get_address();
    if(beginning_last_instr->is_call()
       && !beginning_last_instr_fct.contains_address(
                                        first_vtable_path_block_addr)) {

        // Get the address of one basic block in the called function
        // to extract the new join function.
        const Function &join_function =
                analysis_obj.translator.get_containing_function(
                                          first_vtable_path_block_addr);
        join_function_addr = join_function.get_entry();

        // Get the first basic block of the join function.
        const Block &first_block =
                            join_function.get_containing_block(
                                                    join_function_addr);
        const BlockPtr first_block_ptr =
                                        make_shared<Block>(first_block);

        // Add first block of function manually since it will be
        // our source block to glue together both parts and the source
        // block will not be added to the path by the function.
        path_blocks_first_part.push_back(first_block_ptr);

        glue_block_paths_together(path_blocks_first_part,
                                  path_blocks_diverge_vtable,
                                  join_function,
                                  first_block_ptr);
    }

    // In the edge case that the last common instruction was a jmp
    // instruction to the same function, we start our path search from
    // the target basic block of the target function.
    else if(beginning_last_instr->is_unconditional_jmp()) {

        const BlockPtr &jmp_block = path_blocks_common_beginning.back();
        uint64_t jmp_target_addr = jmp_block->get_terminator().target;

        // Get the address of one basic block in the jumped to function
        // to extract the new join function.
        const Function &join_function =
                analysis_obj.translator.get_containing_function(
                                                       jmp_target_addr);
        join_function_addr = join_function.get_entry();

        // Get the jmp target basic block in the join function.
        const Block &jmp_target_block =
                            join_function.get_containing_block(
                                                       jmp_target_addr);

        const BlockPtr jmp_target_block_ptr =
                                   make_shared<Block>(jmp_target_block);

        // Add jmp target block manually since it will be
        // our source block to glue together both parts and the source
        // block will not be added to the path by the function.
        path_blocks_first_part.push_back(jmp_target_block_ptr);

        glue_block_paths_together(path_blocks_first_part,
                                  path_blocks_diverge_vtable,
                                  join_function,
                                  jmp_target_block_ptr);
    }

    // Glue together beginning path and vtable path starting from
    // the last basic block of the beginning path.
    else {
        const BlockPtr &last_block_beginning =
                                          path_blocks_first_part.back();
        const Function &join_function =
                analysis_obj.translator.get_containing_function(
                                   last_block_beginning->get_address());

        join_function_addr = join_function.get_entry();

        glue_block_paths_together(path_blocks_first_part,
                                  path_blocks_diverge_vtable,
                                  join_function,
                                  last_block_beginning);
    }

    // Skip if we do not have a complete path.
    if(path_blocks_first_part.size() == 0) {
        cerr << "No control flow found that glues together the common "
             << "beginning and the vtable path."
             << "\n";
        return false;
    }

#if DEBUG_ENGELS_PRINT_VERBOSE
    cout << "Size merged beginning and root->vtable control flow path: "
         << dec << path_blocks_first_part.size() << "\n";
#endif

    const Function &join_function =
               analysis_obj.translator.get_function(join_function_addr);

    // Find the last basic block on the vtable path that resides in
    // the join function.
    BlockPtr &last_block_vtable_in_fct =
                                     path_blocks_diverge_vtable.front();
    for(uint32_t i = 1;
        i < path_blocks_diverge_vtable.size();
        i++) {
        const auto &block = path_blocks_diverge_vtable.at(i);
        if(join_function.contains_address(block->get_address())) {
            last_block_vtable_in_fct = path_blocks_diverge_vtable.at(i);
        }
        else {
            break;
        }
    }

    // Find the last basic block on the icall path that resides in
    // the join function and delete all basic blocks except this one.
    uint32_t counter = 0;
    for(uint32_t i = 1;
        i < path_blocks_diverge_icall.size();
        i++) {
        const auto &block = path_blocks_diverge_icall.at(i);
        if(join_function.contains_address(block->get_address())) {
            counter = i;
        }
        else {
            break;
        }
    }
    for(uint32_t i = 0; i < counter; i++) {
        path_blocks_diverge_icall.erase(
                                     path_blocks_diverge_icall.begin());
    }
    // Skip if the first block is not in the join function
    // (can happen if vtable assignment path skips this call in data
    // flow but icall is inside it. This is an impossible control flow,
    // i.e., node+vtv:
    // join: a72b3d, icall: a4d481, vtable assignment: ebc29f)
    if(counter == 0) {
        uint64_t first_block_addr =
                        path_blocks_diverge_icall.at(0)->get_address();
        if(!join_function.contains_address(first_block_addr)) {
            cerr << "First block of diverged icall path "
                 << hex << first_block_addr
                 << " not in join function as the source block "
                 << hex << last_block_vtable_in_fct->get_address()
                 << ". Skipping."
                 << "\n";
            return false;
        }
    }

#if DEBUG_ENGELS_PRINT_VERBOSE
    cout << "Size diverged root->icall control flow path after erase: "
         << dec << path_blocks_diverge_icall.size() << "\n";
    for(auto &block : path_blocks_diverge_icall) {
        cout << "-> " << hex << block->get_address() << "\n";
    }
    cout << "\n";
#endif

    // Generate the second part of the final path
    // by gluing together the icall path starting from the
    // last basic block of the vtable path that resides in the
    // join function.
    vector<BlockPtr> path_blocks_second_part;
    glue_block_paths_together(path_blocks_second_part,
                              path_blocks_diverge_icall,
                              join_function,
                              last_block_vtable_in_fct);

    // Skip if we do not have a complete path.
    if(path_blocks_second_part.size() == 0) {
        cerr << "No control flow found that glues together the first "
             << "part of the path and the icall path."
             << "\n";
        return false;
    }

    // Add return basic blocks after each skipped call.
    add_artificial_ret_blocks(path_blocks_first_part,
                              analysis_obj.translator);
    add_artificial_ret_blocks(path_blocks_second_part,
                              analysis_obj.translator);
    // Handle edge-case in which the last block of the first part
    // is a skipped call, therefore adding an artificial return block.
    const BlockPtr &last_block = path_blocks_first_part.back();
    if(last_block->get_address() != 0x0) {
        if(last_block->get_terminator().type == TerminatorCallUnresolved
           || last_block->get_terminator().type == TerminatorCall) {

            const BlockPtr &first_block =
                    path_blocks_second_part.front();
            const Function &last_function =
                    analysis_obj.translator.get_containing_function(
                                             last_block->get_address());
            if(last_function.contains_address(
                        first_block->get_address())) {
                path_blocks_first_part.push_back(ret_block_ptr);
            }
        }
    }

#if DEBUG_ENGELS_PRINT_PATHS
    cout << "Size final control flow path (first part): "
         << dec << path_blocks_first_part.size() << "\n";
    cout << "Final path:" << "\n";
    for(auto &block : path_blocks_first_part) {
        cout << "-> " << hex << block->get_address() << "\n";
    }
    cout << "\n";

    cout << "Size final control flow path (second part): "
         << dec << path_blocks_second_part.size() << "\n";
    cout << "Final path:" << "\n";
    for(auto &block : path_blocks_second_part) {
        cout << "-> " << hex << block->get_address() << "\n";
    }
    cout << "\n";
#endif

    // Symbolically execute the first part of the final path.
    State state;
    sym_execute_blocks(analysis_obj, path_blocks_first_part, state);

    // Replace the value of the vtable assignment
    // (which is the last executed in the last basic block of the
    // first part of the final path) with a symbolical vtable ptr value.
    const OperandSSAPtrs &use_ops =
                                   graph[vtable_node].instr->get_uses();
    const ConstantX64SSA &op = static_cast<const ConstantX64SSA&>(
                                                        *use_ops.at(0));
    int64_t vtable_value_raw = op.get_value();
    Constant vtable_value(vtable_value_raw);
    const auto &memory = state.get_memory_accesses();
    ExpressionPtr sym_vtable_ptr = make_shared<Symbolic>("vtable_ptr");
    for(const auto &kv_mem : memory) {
        if(*(kv_mem.second) == vtable_value) {
            state.update(kv_mem.first, sym_vtable_ptr);
        }
    }

    // Symbolically execute the second part of the final path.
    sym_execute_blocks(analysis_obj, path_blocks_second_part, state);

    // TODO / DEBUG
    cout << "Vtable assignment: " << *graph[vtable_node].instr << "\n";

    // Manually optimize state (sometimes we have rip -> [new_obj_400a11]
    // and [new_obj_400a11] -> vtable_ptr at this point).
    state.optimize();

    // Extract call register expression from symbolic execution state.
    const BaseInstructionSSAPtr &icall_instr = graph[icall_node].instr;
    ExpressionPtr call_reg_expr_ptr = extract_call_target(state,
                                                          icall_instr);

    // Get used vtable.
    uint64_t xref_addr = graph[vtable_node].instr->get_address();
    uint32_t vtable_idx =
                     vtable_xref_data.xref_vtable_idx_map.at(xref_addr);

    bool has_result = process_result(analysis_obj,
                                     call_reg_expr_ptr,
                                     icall_instr,
                                     vtable_idx,
                                     state);

    // TODO / DEBUG
    cout << string(79, '=') << "\n" << "\n";

    return has_result;
}

bool process_vtable_nodes(
           EngelsAnalysisObjects &analysis_obj,
           ICallAnalysis &analysis,
           const EngelsVTableXrefAnalysis &vtable_xref_data,
           const GraphDataFlow &graph,
           GraphDataFlow::vertex_descriptor icall_node,
           const NodeToNodesMap &join_to_vtables_map) {

    bool has_overall_result = false;

    // Create indexmap in order to work with boost algorithms on the graph.
    boost::property_map<GraphDataFlow,
                        boost::vertex_index_t>::type indexmap =
                                              analysis.get_graph_indexmap();

    for(const auto &kv_nodes : join_to_vtables_map) {

        GraphDataFlow::vertex_descriptor root_node = kv_nodes.first;
        vector<DataFlowPath> paths_root_icall = create_dataflow_paths(
                                                             analysis_obj,
                                                             graph,
                                                             indexmap,
                                                             root_node, // src
                                                             icall_node); // dst

        // Skip if we do not have any path from the root node to the icall node.
        if(paths_root_icall.size() == 0) {
            continue;
        }

        for(auto vtable_node : kv_nodes.second) {

            vector<DataFlowPath> paths_root_vtable = create_dataflow_paths(
                                                            analysis_obj,
                                                            graph,
                                                            indexmap,
                                                            root_node, // src
                                                            vtable_node); // dst

            // Skip if we do not have a path from the join node to the
            // vtable node.
            if(paths_root_vtable.size() == 0) {
                continue;
            }

#if DEBUG_ENGELS_PRINT
            cout << "Searching path from '"
                 << *graph[root_node].instr
                 << "' to '"
                 << *graph[icall_node].instr
                 << "' via '"
                 << *graph[vtable_node].instr
                 << "'."
                 << "\n";
#endif

            const BaseInstructionSSAPtr &icall_instr =
                                            graph[icall_node].instr;
            uint64_t icall_addr = icall_instr->get_address();
            uint64_t xref_addr = graph[vtable_node].instr->get_address();
            uint32_t vtable_idx =
                             vtable_xref_data.xref_vtable_idx_map.at(xref_addr);

            // Process each combination of root->icall and root->vtable path.
            bool has_result = false;
            for(DataFlowPath &path_root_icall : paths_root_icall) {
                for(DataFlowPath &path_root_vtable : paths_root_vtable) {

                    // Try to find control flow paths for the found data flow
                    // paths and process them.
                    has_result = process_root_vtable_icall_dataflow_path(
                                                              analysis_obj,
                                                              vtable_xref_data,
                                                              graph,
                                                              icall_node,
                                                              vtable_node,
                                                              path_root_icall,
                                                              path_root_vtable);

                    has_overall_result |= has_result;

                    // When we have found a result, check if it is a result
                    // for our current vtable (otherwise continue the search).
                    if(has_result) {
                        has_result = false;
                        for(const EngelsResult &result
                            : analysis_obj.results.at(icall_addr)) {

                            if(result.vtable_idx == vtable_idx) {
                                has_result = true;
                                break;
                            }
                        }
                        if(has_result) {
                            break;
                        }
                    }
                }
                if(has_result) {
                    break;
                }
            }
        }
    }

    return has_overall_result;
}

void process_icall_dataflow_graph(
                               EngelsAnalysisObjects &analysis_obj,
                               ICallAnalysis &analysis,
                               const EngelsVTableXrefAnalysis &vtable_xref_data,
                               const NodeToNodesMap &join_to_vtables_map) {

    // TODO
    // 1) What if join node is vtable node?
    // 2) What if we do not have join nodes? <--- use root nodes
    // 3) Optimierung indem wir join->vtable node pairs machen anstatt alle mit allen versuchen zu verbinden?

    const GraphDataFlow &graph = analysis.get_graph();

    // Extract all vtable call nodes (from which we start our path generation),
    // and the icall node (which is our final destination).
    const auto vertices = boost::vertices(graph);
    unordered_set<GraphDataFlow::vertex_descriptor> vtable_call_nodes;
    GraphDataFlow::vertex_descriptor icall_node;
    for(auto it = vertices.first; it != vertices.second; ++it) {
        if(graph[*it].type == DataFlowNodeTypeStart) {
            icall_node = *it;
        }
        else if(graph[*it].type == DataFlowNodeTypeVtableCall) {
            vtable_call_nodes.insert(*it);
        }
    }

    bool has_result = false;

    if(vtable_call_nodes.size() != 0) {
        has_result |= process_vtable_call_nodes(analysis_obj,
                                                analysis,
                                                graph,
                                                icall_node,
                                                vtable_call_nodes);
    }

    if(join_to_vtables_map.size() != 0) {
        has_result |= process_vtable_nodes(analysis_obj,
                             analysis,
                             vtable_xref_data,
                             graph,
                             icall_node,
                             join_to_vtables_map);
    }

    // If we did not find any result, check if the icall analysis has
    // unresolvable icalls or virtual functions in its data flow graph
    // and repeat analysis when they are resolvable.
    if(!has_result) {
        if(!analysis.get_unresolvable_icalls().empty()
           || !analysis.get_unresolvable_vfuncs().empty()) {
            uint64_t start_addr = analysis.get_start_addr();
            repeat_icall_mtx.lock();
            repeat_icall_addrs.insert(start_addr);
            icall_addr_unresolvable_map[start_addr] =
                                             analysis.get_unresolvable_icalls();
            vfunc_addr_unresolvable_map[start_addr] =
                                             analysis.get_unresolvable_vfuncs();
            repeat_icall_mtx.unlock();
        }
    }
}

bool process_lightweight_result(const GraphDataFlow &graph,
                                EngelsAnalysisObjects &analysis_obj,
                                const State &state_this,
                                const State &state_target,
                                const DataFlowPath &path_target_icall) {

    State::const_iterator this_value;
    if(state_this.find(register_rdi, this_value)) { // TODO: architecture specific
        ExpressionPtr this_expr = this_value->second;

#if DEBUG_ENGELS_PRINT_VERBOSE
        cout << "This pointer expression: "
             << *this_expr
             << "\n";
#endif

        State::const_iterator ip_value;
        if(state_target.find(register_rip, ip_value)) { // TODO: architecture specific
            ExpressionPtr target_expr = ip_value->second;

#if DEBUG_ENGELS_PRINT_VERBOSE
            cout << "Target pointer expression: "
                 << *target_expr
                 << "\n";
#endif

            // THIS -> [(init_rdi + 0x28)]
            // TARGET -> [([[(init_rdi + 0x28)]] + 0x10)]
            if(target_expr->type() == ExpressionIndirection) {
                Indirection &ind = static_cast<Indirection&>(*target_expr);
                if(ind.address()->type() == ExpressionOperation) {
                    Operation &op = static_cast<Operation&>(*ind.address());
                    if(op.operation() != OperationAdd) {
                        return false;
                    }
                    if(op.rhs()->type() != ExpressionConstant) {
                        return false;
                    }
                    if(op.lhs()->type() != ExpressionIndirection) {
                        return false;
                    }
                    Constant &offset = static_cast<Constant&>(*op.rhs());
                    Indirection &inner_ind = static_cast<Indirection&>(
                                                                     *op.lhs());

                    if(*(inner_ind.address()) == *this_expr) {
                        return true;
                    }
                }
                // When the first vtable entry is used, there does not need
                // to be an operation.
                else if(ind.address()->type() == ExpressionIndirection) {
                    Indirection &inner_ind = static_cast<Indirection&>(
                                                                *ind.address());

                    if(*(inner_ind.address()) == *this_expr) {
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

bool process_lightweight_data_flow_separate(
                                  EngelsAnalysisObjects &analysis_obj,
                                  VCallBacktraceLightweight &analysis,
                                  GraphDataFlow::vertex_descriptor icall_node) {

    const GraphDataFlow &graph = analysis.get_graph();
    const NodeInitOperandMap &node_init_operand_map =
                                                analysis.get_node_init_op_map();

    // Get start instruction for "this" operand.
    unordered_set<GraphDataFlow::vertex_descriptor> nodes_visited;
    GraphDataFlow::vertex_descriptor start_this_op = icall_node;
    GraphDataFlow::vertex_descriptor last_instr_node = start_this_op;
    while(true) {
        const auto in_edges = boost::in_edges(start_this_op, graph);
        if(in_edges.first == in_edges.second) {
            break;
        }

        bool found_prev = false;
        for(auto edge_it = in_edges.first;
            edge_it != in_edges.second;
            ++edge_it) {

            GraphDataFlow::vertex_descriptor src_node = boost::source(*edge_it,
                                                                      graph);

            if(nodes_visited.find(src_node) != nodes_visited.end()) {
                continue;
            }

            const auto init_operand_set = node_init_operand_map.at(src_node);
            // When we have more than one operand type, we have found the
            // merge of the data flows.
            if(init_operand_set.size() > 1) {
                continue;
            }
            // Check if we have only the "this" operand type and follow it.
            else if(init_operand_set.find(VCallBacktraceOperandThis)
                    != init_operand_set.cend()) {

                nodes_visited.insert(src_node);
                // Store the last instruction node in order to avoid problems
                // with phi nodes and loops in the data flow graph.
                if(graph[start_this_op].instr->is_instruction()) {
                    last_instr_node = start_this_op;
                }
                start_this_op = src_node;
                found_prev = true;
                break;
            }
        }
        if(!found_prev) {
            // Use the last instruction node we found if we have problems
            // with phi nodes and loops.
            start_this_op = last_instr_node;
            break;
        }
    }
    // If the last node we found was not a phi node, restore the last
    // instruction node we found.
    if(!graph[start_this_op].instr->is_instruction()) {
        start_this_op = last_instr_node;
    }

    // Get start instruction for "target" operand.
    nodes_visited.clear();
    GraphDataFlow::vertex_descriptor start_target_op = icall_node;
    last_instr_node = start_target_op;
    while(true) {
        const auto in_edges = boost::in_edges(start_target_op, graph);
        if(in_edges.first == in_edges.second) {
            break;
        }

        bool found_prev = false;
        for(auto edge_it = in_edges.first;
            edge_it != in_edges.second;
            ++edge_it) {

            GraphDataFlow::vertex_descriptor src_node = boost::source(*edge_it,
                                                                      graph);

            if(nodes_visited.find(src_node) != nodes_visited.end()) {
                continue;
            }

            const auto init_operand_set = node_init_operand_map.at(src_node);
            // When we have more than one operand type, we have found the
            // merge of the data flows.
            if(init_operand_set.size() > 1) {
                continue;
            }
            // Check if we have only the "this" operand type and follow it.
            else if(init_operand_set.find(VCallBacktraceOperandTarget)
                    != init_operand_set.cend()) {

                nodes_visited.insert(src_node);
                // Store the last instruction node in order to avoid problems
                // with phi nodes and loops in the data flow graph.
                if(graph[start_target_op].instr->is_instruction()) {
                    last_instr_node = start_target_op;
                }
                start_target_op = src_node;
                found_prev = true;
                break;
            }
        }
        if(!found_prev) {
            // Use the last instruction node we found if we have problems
            // with phi nodes and loops.
            start_target_op = last_instr_node;
            break;
        }
    }
    // If the last node we found was not a phi node, restore the last
    // instruction node we found.
    if(!graph[start_target_op].instr->is_instruction()) {
        start_target_op = last_instr_node;
    }

    vector<DataFlowPath> paths_this_icall = create_dataflow_paths(
                                              analysis_obj,
                                              graph,
                                              analysis.get_graph_indexmap(),
                                              start_this_op, // src
                                              icall_node); // dst

    vector<DataFlowPath> paths_target_icall = create_dataflow_paths(
                                              analysis_obj,
                                              graph,
                                              analysis.get_graph_indexmap(),
                                              start_target_op, // src
                                              icall_node); // dst

    // Only one path from our start node to the icall node exists.
    DataFlowPath path_this_icall;
    if(paths_this_icall.empty()) {
        if(start_this_op == icall_node) {
            path_this_icall.push_back(start_this_op);
        }
        else {
            throw runtime_error("Not able to find a data flow path from "
                                "start node (\"this\" operand) to "
                                "icall node.");
        }
    }
    else {
        path_this_icall = paths_this_icall[0];
    }
    path_this_icall = create_shorted_dataflow_path(analysis_obj.translator,
                                                   graph,
                                                   path_this_icall);

    DataFlowPath path_target_icall;
    if(paths_target_icall.empty()) {
        if(start_target_op == icall_node) {
            path_target_icall.push_back(start_target_op);
        }
        else {
            throw runtime_error("Not able to find a data flow path from "
                                "start node (\"target\" operand) to "
                                "icall node.");
        }
    }
    else {
        path_target_icall = paths_target_icall[0];
    }
    path_target_icall = create_shorted_dataflow_path(analysis_obj.translator,
                                                     graph,
                                                     path_target_icall);

#if DEBUG_ENGELS_PRINT_PATHS
    cout << "Data flow path from merge node to icall (this operand):" << "\n";
    for(auto node : path_this_icall) {
        cout << *graph[node].instr << "\n";
    }

    cout << "Data flow path from merge node to icall (target operand):" << "\n";
    for(auto node : path_target_icall) {
        cout << *graph[node].instr << "\n";
    }
#endif

    State state_this;
    vector<BlockPtr> path_this_icall_blocks = create_artificial_block_vector(
                                                               analysis_obj,
                                                               graph,
                                                               path_this_icall);
    // Add artificial return basic blocks after calls we did not take.
    // Needed because we can have vtv verify calls and new operator calls.
    add_artificial_ret_blocks(path_this_icall_blocks,
                              analysis_obj.translator);
    sym_execute_blocks(analysis_obj,
                       path_this_icall_blocks,
                       state_this);

    State state_target;
    vector<BlockPtr> path_target_icall_blocks = create_artificial_block_vector(
                                                             analysis_obj,
                                                             graph,
                                                             path_target_icall);
    // Add artificial return basic blocks after calls we did not take.
    // Needed because we can have vtv verify calls and new operator calls.
    add_artificial_ret_blocks(path_target_icall_blocks,
                              analysis_obj.translator);
    sym_execute_blocks(analysis_obj,
                       path_target_icall_blocks,
                       state_target);

    return process_lightweight_result(graph,
                                      analysis_obj,
                                      state_this,
                                      state_target,
                                      path_target_icall);
}

bool process_lightweight_data_flow_merge(
                                  EngelsAnalysisObjects &analysis_obj,
                                  VCallBacktraceLightweight &analysis,
                                  GraphDataFlow::vertex_descriptor merge_node,
                                  GraphDataFlow::vertex_descriptor icall_node) {

    const GraphDataFlow &graph = analysis.get_graph();
    const NodeInitOperandMap &node_init_operand_map =
                                                analysis.get_node_init_op_map();

    // Get all the starting point of the "this" init operand path.
    GraphDataFlow::vertex_descriptor curr_node = merge_node;
    DataFlowVertexSet start_this_ops;
    GraphDataFlow::vertex_descriptor phi_node = nullptr;
    unordered_set<GraphDataFlow::vertex_descriptor> nodes_visited;
    while(true) {
        auto out_edges = boost::out_edges(curr_node, graph);
        phi_node = nullptr;
        for(auto edge_it = out_edges.first;
            edge_it != out_edges.second;
            ++edge_it) {

            GraphDataFlow::vertex_descriptor dst_node = boost::target(*edge_it,
                                                                      graph);

            if(nodes_visited.find(dst_node) != nodes_visited.end()) {
                continue;
            }

            const auto init_operand_set = node_init_operand_map.at(dst_node);
            // Edge case in which the node directly after the merge node
            // is the icall node.
            if(dst_node == icall_node) {
                start_this_ops.insert(dst_node);
            }
            else if(init_operand_set.size() > 1) {
                // Store phi node in order to search the starting point of the
                // path there if we do not find one at this node.
                if(graph[dst_node].instr->is_phinode()
                        && phi_node == nullptr) {

                    phi_node = dst_node;
                }
                continue;
            }
            else if(init_operand_set.find(VCallBacktraceOperandThis)
                    != init_operand_set.cend()) {

                // Store phi node in order to search the starting point of the
                // path there if we do not find one at this node.
                if(graph[dst_node].instr->is_phinode()) {
                    phi_node = dst_node;
                }
                else {
                    start_this_ops.insert(dst_node);
                }
            }
            else {
                continue;
            }
        }
        // Check if we have found our start nodes.
        if(start_this_ops.empty()) {
            if(phi_node == nullptr) {
                cerr << "Not able to find data flow \"this\" "
                     << "operand start node for path creation. "
                     << "Merge node is: "
                     << *graph[merge_node].instr
                     << "\n";
                return false;
            }
            else {
                curr_node = phi_node;
                nodes_visited.insert(curr_node);
            }
        }
        else {
            break;
        }
    }

    // Get all the starting point of the "target" init operand path.
    curr_node = merge_node;
    DataFlowVertexSet start_target_ops;
    phi_node = nullptr;
    nodes_visited.clear();
    while(true) {
        auto out_edges = boost::out_edges(curr_node, graph);
        phi_node = nullptr;
        for(auto edge_it = out_edges.first;
            edge_it != out_edges.second;
            ++edge_it) {

            GraphDataFlow::vertex_descriptor dst_node = boost::target(*edge_it,
                                                                      graph);

            if(nodes_visited.find(dst_node) != nodes_visited.end()) {
                continue;
            }

            const auto init_operand_set = node_init_operand_map.at(dst_node);
            // Edge case in which the node directly after the merge node
            // is the icall node.
            if(dst_node == icall_node) {
                start_target_ops.insert(dst_node);
            }
            else if(init_operand_set.size() > 1) {
                // Store phi node in order to search the starting point of the
                // path there if we do not find one at this node.
                if(graph[dst_node].instr->is_phinode()
                        && phi_node == nullptr) {

                    phi_node = dst_node;
                }
                continue;
            }
            else if(init_operand_set.find(VCallBacktraceOperandTarget)
                    != init_operand_set.cend()) {

                // Store phi node in order to search the starting point of the
                // path there if we do not find one at this node.
                if(graph[dst_node].instr->is_phinode()) {
                    phi_node = dst_node;
                }
                else {
                    start_target_ops.insert(dst_node);
                }
            }
            else {
                continue;
            }
        }
        // Check if we have found our start nodes.
        if(start_target_ops.empty()) {
            if(phi_node == nullptr) {
                cerr << "Not able to find data flow \"target\" "
                     << "operand start node for path creation. "
                     << "Merge node is: "
                     << *graph[merge_node].instr
                     << "\n";
                return false;
            }
            else {
                curr_node = phi_node;
                nodes_visited.insert(curr_node);
            }
        }
        else {
            break;
        }
    }

    // Try each combination of this and target start instructions in order to
    // not miss a vcall candidate (i.e., node+debug 0xc88e94 can be missed
    // if we do not try each combination since this start instruction
    // and target start instruction are both the icall instruction).
    bool is_vcall_candidate = false;
    for(auto start_this_op : start_this_ops) {
        for(auto start_target_op : start_target_ops) {

            vector<DataFlowPath> paths_this_icall = create_dataflow_paths(
                                                  analysis_obj,
                                                  graph,
                                                  analysis.get_graph_indexmap(),
                                                  start_this_op, // src
                                                  icall_node); // dst

            vector<DataFlowPath> paths_target_icall = create_dataflow_paths(
                                                  analysis_obj,
                                                  graph,
                                                  analysis.get_graph_indexmap(),
                                                  start_target_op, // src
                                                  icall_node); // dst

            // Only one path from our start node to the icall node exists.
            // We have to add the initial node manually.
            DataFlowPath path_this_icall;
            if(paths_this_icall.empty()) {
                if(start_this_op == icall_node) {
                    path_this_icall.push_back(start_this_op);
                }
                else {
                    throw runtime_error("Not able to find a data flow path "
                                        "from start node (\"this\" operand) to "
                                        "icall node.");
                }
            }
            else {
                path_this_icall = paths_this_icall[0];
            }
            path_this_icall.insert(path_this_icall.begin(), merge_node);
            path_this_icall = create_shorted_dataflow_path(
                                                        analysis_obj.translator,
                                                        graph,
                                                        path_this_icall);

            DataFlowPath path_target_icall;
            if(paths_target_icall.empty()) {
                if(start_target_op == icall_node) {
                    path_target_icall.push_back(start_target_op);
                }
                else {
                    throw runtime_error("Not able to find a data flow path "
                                        "from start node (\"target\" operand) "
                                        "to icall node.");
                }
            }
            else {
                path_target_icall = paths_target_icall[0];
            }
            path_target_icall.insert(path_target_icall.begin(), merge_node);
            path_target_icall = create_shorted_dataflow_path(
                                                        analysis_obj.translator,
                                                        graph,
                                                        path_target_icall);

#if DEBUG_ENGELS_PRINT_PATHS
            cout << "Data flow path from merge node to "
                 << "icall (this operand):" << "\n";
            for(auto node : path_this_icall) {
                cout << *graph[node].instr << "\n";
            }

            cout << "Data flow path from merge node to "
                 << "icall (target operand):" << "\n";
            for(auto node : path_target_icall) {
                cout << *graph[node].instr << "\n";
            }
#endif

            State state_this;
            vector<BlockPtr> path_this_icall_blocks =
                                        create_artificial_block_vector(
                                                               analysis_obj,
                                                               graph,
                                                               path_this_icall);
            // Add artificial return basic blocks after calls we did not take.
            // Needed because we can have vtv verify calls
            // and new operator calls.
            add_artificial_ret_blocks(path_this_icall_blocks,
                                      analysis_obj.translator);
            sym_execute_blocks(analysis_obj,
                               path_this_icall_blocks,
                               state_this);

            State state_target;
            vector<BlockPtr> path_target_icall_blocks =
                                        create_artificial_block_vector(
                                                             analysis_obj,
                                                             graph,
                                                             path_target_icall);
            // Add artificial return basic blocks after calls we did not take.
            // Needed because we can have vtv verify calls
            // and new operator calls.
            add_artificial_ret_blocks(path_target_icall_blocks,
                                      analysis_obj.translator);
            sym_execute_blocks(analysis_obj,
                               path_target_icall_blocks,
                               state_target);

            is_vcall_candidate = process_lightweight_result(graph,
                                                            analysis_obj,
                                                            state_this,
                                                            state_target,
                                                            path_target_icall);
            if(is_vcall_candidate) {
                break;
            }
        }
        if(is_vcall_candidate) {
            break;
        }
    }

    return is_vcall_candidate;
}

bool process_vcall_lightweight_analysis(EngelsAnalysisObjects &analysis_obj,
                                        VCallBacktraceLightweight &analysis) {

    const GraphDataFlow &graph = analysis.get_graph();
    const NodeInitOperandMap &node_init_operand_map =
                                                analysis.get_node_init_op_map();

    // Get icall instruction node.
    GraphDataFlow::vertex_descriptor icall_node = nullptr;
    const auto vertices = boost::vertices(graph);
    for(auto it = vertices.first; it != vertices.second; ++it) {
        if(graph[*it].type == DataFlowNodeTypeStart) {
            icall_node = *it;
            break;
        }
    }
    if(icall_node == nullptr) {
        throw runtime_error("Not able to find start node in graph.");
    }

    // Starting from the icall, go backwards the "this" operand data flow until
    // it merges with the "target" operand data flow.
    unordered_set<GraphDataFlow::vertex_descriptor> nodes_visited;
    unordered_set<GraphDataFlow::vertex_descriptor> merge_nodes;
    queue<GraphDataFlow::vertex_descriptor> work_queue;
    work_queue.push(icall_node);

    while(!work_queue.empty()) {

        GraphDataFlow::vertex_descriptor curr_node = work_queue.front();
        work_queue.pop();

        const auto in_edges = boost::in_edges(curr_node, graph);
        if(in_edges.first == in_edges.second) {
            continue;
        }

        for(auto edge_it = in_edges.first;
            edge_it != in_edges.second;
            ++edge_it) {

            GraphDataFlow::vertex_descriptor src_node = boost::source(
                                                                   *edge_it,
                                                                   graph);

            // Ignore already visited nodes.
            if(nodes_visited.find(src_node) != nodes_visited.end()) {
                continue;
            }

            const auto init_operand_set = node_init_operand_map.at(src_node);
            // When we have more than one operand type, we have found the
            // merge of the data flows.
            if(init_operand_set.size() > 1) {
                nodes_visited.insert(src_node);

                // Do not consider phi nodes as merge node but continue
                // analysis there.
                if(graph[src_node].instr->is_phinode()) {
                    work_queue.push(src_node);
                }
                else {
                    merge_nodes.insert(src_node);
                }

                continue;
            }
            // Check if we have only the "this" operand type and follow it.
            else if(init_operand_set.find(VCallBacktraceOperandThis)
                    != init_operand_set.cend()) {

                nodes_visited.insert(src_node);
                work_queue.push(src_node);
            }
        }
    }

    bool is_vcall = false;

    // Process merging data flow paths.
    if(!merge_nodes.empty()) {

        for(GraphDataFlow::vertex_descriptor curr_node : merge_nodes) {

#if DEBUG_ENGELS_PRINT_VERBOSE
    cout << "Data flow merges at instruction: "
         << *graph[curr_node].instr
         << "\n";
#endif

            is_vcall = process_lightweight_data_flow_merge(analysis_obj,
                                                           analysis,
                                                           curr_node,
                                                           icall_node);
            if(is_vcall) {
                break;
            }
        }
    }

    // Process separate data flow paths.
    else {

#if DEBUG_ENGELS_PRINT_VERBOSE
    cout << "No data flow merge point found. Processing paths separately."
         << "\n";
#endif

        is_vcall = process_lightweight_data_flow_separate(analysis_obj,
                                                          analysis,
                                                          icall_node);
    }

#if DEBUG_ENGELS_PRINT
    if(is_vcall) {
        cout << *graph[icall_node].instr
             << " is a vcall."
             << "\n";
    }
    else {
        cout << *graph[icall_node].instr
             << " is no vcall."
             << "\n";
    }
#endif

    return is_vcall;
}
