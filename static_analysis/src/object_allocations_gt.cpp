#include "object_allocations_gt.h"

using namespace std;

queue<uint64_t> queue_vtable_print_addrs;
mutex queue_vtable_print_addrs_mtx;

ObjectAllocationGTFile::ObjectAllocationGTFile(const std::string &module_name)
    : _module_name(module_name){
}

const VtablePrintXrefMap &ObjectAllocationGTFile::get_vtable_xrefs() const {
    return _vtable_print_xrefs_map;
}

const unordered_set<uint64_t>&
                        ObjectAllocationGTFile::get_vtable_print_xrefs() const {
    return _vtable_print_xrefs;
}

void ObjectAllocationGTFile::add_vtable_xref(uint64_t vtbl_xref_addr,
                                             uint64_t vtbl_print_xref_addr) {
    lock_guard<mutex> _(_mtx);

    _vtable_print_xrefs_map[vtbl_print_xref_addr].insert(vtbl_xref_addr);
}

bool ObjectAllocationGTFile::parse_vtable_print(const std::string &target_file) {

    ifstream file(target_file + "_vtable_print_xrefs.txt");
    if(!file) {
        cerr << "Not able to open '_vtable_print_xrefs.txt' file." << "\n";
        return false;
    }

    string line;

    // Parse first line manually.
    getline(file, line);
    istringstream header_parser(line);

    // First entry of file is always the module name.
    string module_name;
    header_parser >> module_name;
    if(header_parser.fail()) {
        cerr << "Parsing error in "
             << "'_vtable_print_xrefs.txt' file."
             << "\n";
    }

    while(getline(file, line)) {
        istringstream parser(line);
        uint64_t func_xref_addr = 0;

        parser >> hex >> func_xref_addr;
        if(parser.fail()) {
            cerr << "Parsing error in "
                 << "'_vtable_print_xrefs.txt' file."
                 << "\n";
            return false;
        }

        _vtable_print_xrefs.insert(func_xref_addr);
    }
    return true;
}

void ObjectAllocationGTFile::export_vtable_xrefs(const std::string &target_dir) {
    lock_guard<mutex> _(_mtx);

    stringstream temp_str;
    temp_str << target_dir << "/" << _module_name << "_vtables_xrefs_gt.txt";
    string target_file = temp_str.str();

    ofstream export_file;
    export_file.open(target_file);

    export_file << _module_name << "\n";
    for(const auto &kv : _vtable_print_xrefs_map) {
        for(uint64_t vtable_xref_addr : kv.second) {
            export_file << hex << vtable_xref_addr
                        << " "
                        << hex << kv.first
                        << "\n";
        }
    }

    export_file.close();
}

void object_allocation_analysis_gt_thread(const string &module_name,
                                          const string &target_dir,
                                          const VCallFile &vcalls,
                                          const VTableFile &vtables,
                                          Translator &translator,
                                          ObjectAllocationGTFile &obj_alloc_gt_file,
                                          uint32_t thread_number) {

    cout << "Starting object allocation GT analysis (Thread: "
         << dec << thread_number
         << ")"
         << endl;

    while(true) {

        // Get next vtable address that has to be analyzed.
        uint64_t vtable_print_addr;
        queue_vtable_print_addrs_mtx.lock();
        if(queue_vtable_print_addrs.empty()) {
            queue_vtable_print_addrs_mtx.unlock();
            break;
        }
        vtable_print_addr = queue_vtable_print_addrs.front();
        queue_vtable_print_addrs.pop();
        cout << "Analyzing vtable print at address: "
             << hex << vtable_print_addr
             << ". Remaining vtables to analyze: "
             << dec << queue_vtable_print_addrs.size()
             << " (Thread: " << dec << thread_number << ")"
             << endl;
        queue_vtable_print_addrs_mtx.unlock();

        const Function *function_ptr = nullptr;
        try {
            translator.get_containing_function(vtable_print_addr);
        }
        catch(...) {
            cerr << "No function for vtable print instruction "
                 << hex << vtable_print_addr
                 << " found. Skipping."
                 << "\n";
            continue;
        }

        unordered_set<uint64_t> new_operators;
        InstructionBacktraceIntra analysis(module_name,
                               target_dir,
                               translator,
                               vcalls,
                               vtables,
                               new_operators,
                               vtable_print_addr, // start instruction address
                               2); // operand index
        analysis.obtain(20);

        // Get start instruction of data flow graph.
        const GraphDataFlow &graph = analysis.get_graph();
        auto vertices = boost::vertices(graph);
        GraphDataFlow::vertex_descriptor vtable_xref_node;
        bool found = false;
        for(auto it = vertices.first; it != vertices.second;) {
            auto in_edges = boost::in_edges(*it, graph);
            if(in_edges.first == in_edges.second) {
                vtable_xref_node = *it;
                found = true;
                break;
            }
            ++it;
        }
        if(!found) {
            cerr << "Not able to find start node of data flow graph "
                 << "for vtable print at address: "
                 << hex << vtable_print_addr
                 << endl;
            continue;
        }

        // Check if operand holds constant value.
        const BaseInstructionSSAPtr &instr = graph[vtable_xref_node].instr;
        const OperandSSAPtr &op = instr->get_operand(1);
        if(op->is_constant()) {
            obj_alloc_gt_file.add_vtable_xref(
                                   graph[vtable_xref_node].instr->get_address(),
                                   vtable_print_addr);
        }
        else {
            cerr << "Not able to find start instruction that holds a constant "
                 << "for vtable print at address: "
                 << hex << vtable_print_addr
                 << endl;
        }
    }

    cout << "Finished object allocation GT analysis (Thread: "
         << dec << thread_number
         << ")"
         << endl;
}

void object_allocation_gt_analysis(const std::string &module_name,
                                   const std::string &target_dir,
                                   const VCallFile &vcalls,
                                   const VTableFile &vtables,
                                   Translator &translator,
                                   ObjectAllocationGTFile &obj_alloc_gt_file,
                                   uint32_t num_threads) {

    // Set up queue with all vtable addresses that have to be analyzed.
    queue_vtable_print_addrs_mtx.lock();
    for(uint64_t addr : obj_alloc_gt_file.get_vtable_print_xrefs()) {
        queue_vtable_print_addrs.push(addr);
    }
    queue_vtable_print_addrs_mtx.unlock();

    // Analyze all vtable xrefs to find all vtable pointer init instructions.
    // For debugging purposes do not spawn any thread.
    if(num_threads == 1) {
        object_allocation_analysis_gt_thread(module_name,
                                             target_dir,
                                             vcalls,
                                             vtables,
                                             translator,
                                             obj_alloc_gt_file,
                                             0);
    }
    else {
        thread *all_threads = new thread[num_threads];
        for(uint32_t i = 0; i < num_threads; i++) {
            all_threads[i] = thread(object_allocation_analysis_gt_thread,
                                    module_name,
                                    target_dir,
                                    ref(vcalls),
                                    ref(vtables),
                                    ref(translator),
                                    ref(obj_alloc_gt_file),
                                    i);
        }
        for(uint32_t i = 0; i < num_threads; i++) {
            all_threads[i].join();
        }
        delete [] all_threads;
    }
}
