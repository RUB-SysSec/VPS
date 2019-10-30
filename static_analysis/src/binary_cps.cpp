#include "binary_cps.h"

using namespace std;

queue<BinaryCPSVfunc> queue_vfunc_addrs;
mutex queue_vfunc_mtx;
vector<BinaryCPSVfunc> dtor_candidates;
mutex dtor_candidates_mtx;

void binary_cps_analysis(const string &target_file,
                         const string &module_name,
                         const string &target_dir,
                         EngelsAnalysisObjects &analysis_obj,
                         uint32_t num_threads) {

    // Set up queue with all virtual function addresses
    // that have to be analyzed.
    queue_vfunc_mtx.lock();
    for(const auto &kv : analysis_obj.vtable_file.get_this_vtables()) {
        for(uint64_t entry : kv.second->entries) {

            BinaryCPSVfunc candidate;
            candidate.vtbl_idx = kv.second->index;
            candidate.addr = entry;
            queue_vfunc_addrs.push(candidate);
        }
    }
    queue_vfunc_mtx.unlock();

    // TODO FOR DEBUGGING
    num_threads = 1;

    // Analyze all virtual functions.
    // For debugging purposes do not spawn any thread.
    if(num_threads == 1) {
        binary_cps_dtor_analysis(module_name,
                                    target_dir,
                                    analysis_obj,
                                    0);
    }
    else {
        thread *all_threads = new thread[num_threads];
        for(uint32_t i = 0; i < num_threads; i++) {
            all_threads[i] = thread(binary_cps_dtor_analysis,
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
}

void binary_cps_dtor_analysis(const string &module_name,
                              const string &target_dir,
                              EngelsAnalysisObjects &analysis_obj,
                              uint32_t thread_number) {

    cout << "Starting dtor analysis (Thread: "
         << dec << thread_number
         << ")"
         << "\n";

    while(true) {

        // Get next virtual function that has to be analyzed.
        BinaryCPSVfunc candidate;
        queue_vfunc_mtx.lock();
        if(queue_vfunc_addrs.empty()) {
            queue_vfunc_mtx.unlock();
            break;
        }
        candidate = queue_vfunc_addrs.front();
        uint64_t vfunc_addr = candidate.addr;
        queue_vfunc_addrs.pop();
        cout << "Analyzing virtual function at address: "
             << hex << vfunc_addr
             << ". Remaining virtual functions to analyze: "
             << dec << queue_vfunc_addrs.size()
             << " (Thread: " << dec << thread_number << ")"
             << "\n";
        queue_vfunc_mtx.unlock();


        // Check if we have a vtable write into the this ptr object.
        if(has_vtable_write(module_name,
                            target_dir,
                            analysis_obj,
                            candidate)) {

            dtor_candidates_mtx.lock();
            dtor_candidates.push_back(candidate);
            dtor_candidates_mtx.unlock();
        }

    }

    cout << "Finished dtor analysis (Thread: "
         << dec << thread_number
         << ")"
         << "\n";
}

bool has_vtable_write(const string &module_name,
                      const string &target_dir,
                      EngelsAnalysisObjects &analysis_obj,
                      const BinaryCPSVfunc &candidate) {

    const VTable &vtable = analysis_obj.vtable_file.get_vtable(
                                                            candidate.vtbl_idx);
    if(vtable.xrefs.empty()) {
        return false;
    }

    const Translator &translator = analysis_obj.translator;
    const Function *function_ptr = nullptr;
    try {
        function_ptr = &translator.cget_function(candidate.addr);
    }
    catch(...) {
        cerr << "No function object for virtual function "
             << hex << candidate.addr
             << " found. Skipping."
             << "\n";
        return false;
    }
    const Function &function = *function_ptr;

    // Check if we have a vtable write of the vtable this possible dtor
    // belongs to.
    uint64_t start_addr = 0;
    for(uint64_t xref_addr : vtable.xrefs) {
        if(function.contains_address(xref_addr)) {
            start_addr = xref_addr;
            break;
        }
    }
    if(start_addr == 0) {
        return false;
    }

    InstructionBacktraceIntra analysis(module_name,
                           target_dir,
                           analysis_obj.translator,
                           analysis_obj.vcall_file,
                           analysis_obj.vtable_file,
                           analysis_obj.new_operators,
                           start_addr, // start instruction address
                           0); // operand index

    analysis.obtain(200); // TODO make rounds configurable

    // Extract all root instructions of the virtual function analysis.
    unordered_set<GraphDataFlow::vertex_descriptor> root_nodes;
    GraphDataFlow::vertex_descriptor vtable_node;
    const GraphDataFlow &graph = analysis.get_graph();
    const auto vertices = boost::vertices(graph);
    for(auto it = vertices.first; it != vertices.second; ++it) {
        const auto in_edges = boost::in_edges(*it, graph);
        if(in_edges.first == in_edges.second) {
            root_nodes.insert(*it);
        }
        if(graph[*it].type == DataFlowNodeTypeStart) {
            vtable_node = *it;
        }
    }

    // Create paths through the data flow graph from the root node
    // to the vtable node.
    const Memory &memory = translator.get_memory();
    for(auto root_node : root_nodes) {
        vector<DataFlowPath> paths_root_vtable = create_dataflow_paths(
                                                  analysis_obj,
                                                  graph,
                                                  analysis.get_graph_indexmap(),
                                                  root_node, // src
                                                  vtable_node); // dst

        // Build manual path with only one node if vtable and start node
        // are the same.
        if(paths_root_vtable.empty()
           && root_node == vtable_node) {
            DataFlowPath path;
            path.push_back(vtable_node);
            paths_root_vtable.push_back(path);
        }

        // Symbolically execute the instructions of the data flow path.
        for(const DataFlowPath &path : paths_root_vtable) {

            // Prepare state.
            State state;
            ExpressionPtr sym_this_ptr = make_shared<Symbolic>("this_ptr");
            state.update(system_v_arguments[0], sym_this_ptr);

            ExpressionPtr sym_this_ptr_indirect =
                                         make_shared<Indirection>(sym_this_ptr);

            // Create a path of artificial basic blocks with just
            // the instruction of our data flow path.
            vector<BlockPtr> path_blocks = create_artificial_block_vector(
                                                                   analysis_obj,
                                                                   graph,
                                                                   path);

            sym_execute_blocks(analysis_obj,
                               path_blocks,
                               state);

            Constant vtable_value(vtable.addr);
            const auto &state_memory = state.get_memory_accesses();
            for(const auto &kv_mem : state_memory) {
                if(*(kv_mem.second) == vtable_value) {

                    // [this_ptr] or [(this_ptr + 0x0)]
                    if(kv_mem.first->type() == ExpressionIndirection) {
                        const Indirection &ind =
                                 static_cast<const Indirection&>(*kv_mem.first);
                        switch(ind.address()->type()) {

                            // [this_ptr] => this_ptr
                            case ExpressionSymbolic:
                                if(*ind.address() == *sym_this_ptr) {
                                    return true;
                                }
                                break;

                            // [(this_ptr + 0x0)] => (this_ptr + 0x0)
                            case ExpressionOperation: {
                                const Operation &op =
                                        static_cast<const Operation&>(
                                                                *ind.address());
                                if(op.lhs()->type() == ExpressionSymbolic
                                   && op.rhs()->type() == ExpressionConstant
                                   && *(op.lhs()) == *sym_this_ptr) {

                                    const Constant &const_expr =
                                            static_cast<const Constant&>(
                                                                     *op.rhs());
                                    if(const_expr.value() == 0) {
                                        return true;
                                    }
                                }
                                break;
                            }

                            default:
                                break;
                        }
                    }
                }
            }
        }
    }

    return false;
}
