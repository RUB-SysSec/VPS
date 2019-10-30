
#include <iostream>
#include <cstring>
#include <sstream>
#include <cstddef>
#include <fstream>
#include <unordered_set>
#include <algorithm>
#include <cassert>
#include <future>
#include <condition_variable>
#include <mutex>
#include <algorithm>
#include <queue>
#include <execinfo.h>

#include "vex.h"
#include "translator.h"

//#include "custom_analysis.h"
#include "vtable_file.h"
#include "overwrite_analysis.h"
#include "vtable_hierarchy.h"
#include "vtable_update.h"
#include "module_plt.h"
#include "external_functions.h"
#include "return_value.h"
#include "got.h"
#include "idata.h"
#include "blacklist_functions.h"
#include "new_operators.h"
#include "vtv_vcall_gt.h"
#include "ssa.h"

#include "function_xrefs.h"
#include "engels.h"
#include "binary_cps.h"
#include "object_allocations.h"
#include "object_allocations_gt.h"

#define DEBUG_BUILD 1

using namespace std;

const bool on_demand = false;
queue<uint64_t> queue_func_address;
mutex queue_func_mtx;

struct AnalysisObjects {
    const FileFormatType file_format;
    const Memory &memory;
    const VTableFile &vtable_file;
    const VTableMap &this_vtables;
    const ModulePlt &module_plt;
    const ExternalFunctions &external_funcs;
    const unordered_set<uint64_t> &new_operators;
    const unordered_set<uint64_t> &vtv_verify_addrs;
    const GotMap &got_map;
    const IDataMap &idata_map;
    Translator &translator;
    FctVTableUpdates &fct_vtable_updates;
    VCallFile &vcall_file;
    FctReturnValuesFile &fct_return_values;

    AnalysisObjects(const FileFormatType format,
                    const Memory &mem,
                    const VTableFile &vtbl_file,
                    const VTableMap &this_vtbls,
                    const ModulePlt &mod_plt,
                    const ExternalFunctions &ext_funcs,
                    const unordered_set<uint64_t> &new_ops,
                    const unordered_set<uint64_t> &vtv_verifies,
                    const GotMap &got,
                    const IDataMap &idata,
                    Translator &trans,
                    FctVTableUpdates &fct_vtbl_updates,
                    VCallFile &vcalls,
                    FctReturnValuesFile &fct_ret_values)
                      : file_format(format),
                        memory(mem),
                        vtable_file(vtbl_file),
                        this_vtables(this_vtbls),
                        module_plt(mod_plt),
                        external_funcs(ext_funcs),
                        new_operators(new_ops),
                        vtv_verify_addrs(vtv_verifies),
                        got_map(got),
                        idata_map(idata),
                        translator(trans),
                        fct_vtable_updates(fct_vtbl_updates),
                        vcall_file(vcalls),
                        fct_return_values(fct_ret_values) {}
};


void playground(const string &config_file) {

    // Parse config file.
    ifstream file(config_file);
    if(!file) {
        throw runtime_error("Opening config file failed.");
    }

    string module_name; // File name == module name
    string target_dir;
    string file_format_str;
    FileFormatType file_format;
    unordered_set<uint64_t> new_operators;
    unordered_set<uint64_t> vtv_verify_addrs;
    vector<string> ext_modules;
    uint32_t num_threads = 1;

    string line;
    while(getline(file, line)) {
        istringstream parser(line);

        string option;
        parser >> option;
        if(parser.fail()) {
            throw runtime_error("Parsing config file failed.");
        }
        transform(option.begin(),
                  option.end(),
                  option.begin(),
                  ::toupper);

        if(option == "MODULENAME") {
            parser >> module_name;
            if(parser.fail()) {
                throw runtime_error("Parsing config file failed.");
            }
        }
        else if(option == "TARGETDIR") {
            parser >> target_dir;
            if(parser.fail()) {
                throw runtime_error("Parsing config file failed.");
            }
        }
        else if(option == "NEWOPERATORS") {
            uint32_t number;
            parser >> dec >> number;
            if(parser.fail()) {
                throw runtime_error("Parsing config file failed.");
            }
            for(uint32_t i = 0; i < number; i++) {
                uint64_t new_op_addr;
                parser >> hex >> new_op_addr;
                if(parser.fail()) {
                    throw runtime_error("Parsing config file failed.");
                }
                new_operators.insert(new_op_addr);
            }
        }
        else if(option == "EXTERNALMODULES") {
            uint32_t number;
            parser >> dec >> number;
            if(parser.fail()) {
                throw runtime_error("Parsing config file failed.");
            }
            for(uint32_t i = 0; i < number; i++) {
                string ext_module;
                parser >> ext_module;
                if(parser.fail()) {
                    throw runtime_error("Parsing config file failed.");
                }
                ext_modules.push_back(ext_module);
            }
        }
        else if(option == "FORMAT") {
            parser >> file_format_str;
            if(parser.fail()) {
                throw runtime_error("Parsing config file failed.");
            }
            transform(file_format_str.begin(),
                      file_format_str.end(),
                      file_format_str.begin(),
                      ::toupper);
            if(file_format_str == "PE64") {
                file_format = FileFormatPE64;
            }
            else if(file_format_str == "ELF64") {
                file_format = FileFormatELF64;
            }
            else {
                throw runtime_error("Format not known.");
            }
        }
        else if(option == "NUMTHREADS") {
            parser >> dec >> num_threads;
            if(parser.fail()) {
                throw runtime_error("Parsing config file failed.");
            }
        }
        else if(option == "VTVVERIFY") {
            uint32_t number;
            parser >> dec >> number;
            if(parser.fail()) {
                throw runtime_error("Parsing config file failed.");
            }
            for(uint32_t i = 0; i < number; i++) {
                uint64_t vtv_verify_addr;
                parser >> hex >> vtv_verify_addr;
                if(parser.fail()) {
                    throw runtime_error("Parsing config file failed.");
                }
                vtv_verify_addrs.insert(vtv_verify_addr);
            }
        }
        else {
            throw runtime_error("Config option not known.");
        }
    }

    stringstream temp_str;
    temp_str << target_dir << "/" << module_name;
    string target_file = temp_str.str();

    Vex &vex = Vex::get_instance();

    // We encountered problems when a basic block does not end in an
    // control transferring instruction, but was split because of a loop
    // pointing to the following instruction. Then vex would take the
    // following instructions into account when translating and would not
    // commit the changes at actual last instruction but leave it in
    // temporary variables. This will lead to errors in the symbolic execution.
    // Example:
    // BB1:
    // lea rbx, [rsp + 0x240]
    // BB2:
    // sub rbx, 0x60
    // [...]
    // VEX would not commit the changes done on rbx in BB1 because it
    // takes the instruction in BB2 into account.
    VexRegisterUpdates orig_iropt_register_updates_default =
                                       vex.get_iropt_register_updates_default();
    vex.set_iropt_register_updates_default(VexRegUpdAllregsAtEachInsn);
    Translator translator(vex, target_file, file_format, on_demand);
    const auto &memory = translator.get_memory();

    // Parse exported ssa data.
    ModuleSSA ssa;
    if(!ssa.parse(target_file, translator)) {
        throw runtime_error("Cannot parse ssa files " + target_file + ".");
    }

    // Parse exported function xref data.
    ModuleFunctionXrefs func_xrefs;
    if(!func_xrefs.parse(target_file, translator)) {
        throw runtime_error("Cannot parse function xref files "
                            + target_file + ".");
    }

    // Finalize translator object in order to make it read-only.
    translator.finalize();

    // Import all vtable files.
    VTableFile vtable_file(module_name, file_format);
    if(!vtable_file.parse(target_file)) {
        throw runtime_error("Cannot parse vtables file " + target_file + ".");
    }
    for(const auto &it : ext_modules) {
        if(!vtable_file.parse(it)) {
            throw runtime_error("Cannot parse vtables file '" + it + "'.");
        }
    }
    vtable_file.finalize();

    // Import all plt entries.
    ModulePlt module_plt(module_name);
    switch(file_format) {
        case FileFormatELF64:
            // Import all plt entries.
            if(!module_plt.parse(target_file)) {
                throw runtime_error("Cannot parse module plt file "
                                    + target_file + ".");
            }
            break;
        case FileFormatPE64:
            break;
        default:
            throw runtime_error("Do not know how to "\
                                "handle file format.");
    }

    // Import all functions of other modules.
    ExternalFunctions external_funcs;
    for(const auto &it : ext_modules) {
        if(!external_funcs.parse(it)) {
            throw runtime_error("Cannot parse external functions file '" + it + "'.");
        }
    }
    external_funcs.finalize();

    // Import blacklisted functions (for example pure virtual function).
    // These functions are ignored during the main analysis iteration
    // (but a sub analysis on them is started)
    // and will be ignored as a function for the vtable contains
    // same virtual function heuristic.
    const BlacklistFuncsSet funcs_blacklist = import_blacklist_funcs(
                                                                   target_file);

    // Import all known hierarchies.
    VTableHierarchies vtable_hierarchies(file_format,
                                         vtable_file,
                                         module_name,
                                         external_funcs,
                                         module_plt,
                                         funcs_blacklist,
                                         -1);
    vtable_hierarchies.import_hierarchy(target_dir + "/" + module_name);
    for(const auto &it : ext_modules) {
        vtable_hierarchies.import_hierarchy(it);
    }

    // Create vtable hierarchies used by the threads.
    vector<VTableHierarchies*> thread_vtbl_hierarchies;
    for(uint32_t i = 0; i < num_threads; i++) {
        VTableHierarchies *temp = new VTableHierarchies(file_format,
                                                        vtable_file,
                                                        module_name,
                                                        external_funcs,
                                                        module_plt,
                                                        funcs_blacklist,
                                                        i);
        thread_vtbl_hierarchies.push_back(temp);
    }

    NewOperators new_operators_candidates = NewOperators(module_name,
                                                         vtable_file,
                                                         vtable_hierarchies);

    // Create new operators used by the threads.
    vector<NewOperators*> thread_new_operators;
    for(uint32_t i = 0; i < num_threads; i++) {
        NewOperators *temp = new NewOperators(module_name,
                                              vtable_file,
                                              vtable_hierarchies);
        thread_new_operators.push_back(temp);
    }

    VTVVcallsFile vtv_vcalls_file = VTVVcallsFile(module_name);

    // Create vtv vcalls used by the threads.
    vector<VTVVcallsFile*> thread_vtv_vcalls;
    for(uint32_t i = 0; i < num_threads; i++) {
        VTVVcallsFile *temp = new VTVVcallsFile(module_name);
        thread_vtv_vcalls.push_back(temp);
    }

    // Import all vtable updates that are made in external functions.
    FctVTableUpdates fct_vtable_updates(vtable_file,
                                        module_name);
    for(const auto &it : ext_modules) {
        fct_vtable_updates.import_updates(it);
    }

    // Import .got / .data entries.
    GotMap got_map;
    IDataMap idata_map;
    switch(file_format) {
        case FileFormatELF64:
            got_map = import_got(target_file);
            break;
        case FileFormatPE64:
            idata_map = import_idata(target_file);
            break;
        default:
            throw runtime_error("Do not know how to "\
                                "handle file format.");
    }

    VCallFile vcall_file(module_name,
                         vtable_hierarchies,
                         vtable_file);

    // Import return values of this modules .plt functions.
    FctReturnValuesFile fct_return_values(module_name,
                                          vtable_file,
                                          module_plt,
                                          external_funcs);
    for(const auto &it : ext_modules) {
        fct_return_values.import_ext_return_values(it);
    }
    fct_return_values.finalize_ext_return_values();

    // Get all object allocation sites.
    ObjectAllocationFile obj_alloc_file(module_name);
    object_allocation_analysis(module_name,
                               vtable_file,
                               translator,
                               vex,
                               obj_alloc_file,
                               num_threads);

    // Export analysis results directly.
    obj_alloc_file.export_object_allocations(target_dir);

    EngelsAnalysisObjects analysis_obj(file_format,
                                       vtable_file,
                                       vtable_hierarchies,
                                       new_operators,
                                       vtv_verify_addrs,
                                       translator,
                                       vex,
                                       vcall_file);

    // engels analysis
    engels_analysis(target_file,
                    module_name,
                    target_dir,
                    analysis_obj,
                    num_threads);

    // Export results.
    analysis_obj.vcall_file.export_vcalls(target_dir);

    // TODO / DEBUG
    cout << "Possible vcalls: " << "\n";
    for(uint64_t vcall_addr : analysis_obj.vcall_file.get_possible_vcall()) {
        cout << hex << vcall_addr << "\n";
    }
    cout << "\n";
    for(const auto &kv : analysis_obj.results) {
        cout << "Result for vcall: " << *kv.second.at(0).icall_instr << "\n";
        for(const auto &result : kv.second) {
            cout << *result.call_reg_expr_ptr << "\n";
        }
        cout << "" << "\n";
    }
    cout << "\n";
    cout << "Computer processable vcall result:" << "\n";
    for(const auto &kv : analysis_obj.results) {
        cout << hex << kv.second.at(0).icall_instr->get_address();
        unordered_set<uint32_t> unique_vtable_idxs;
        for(const auto &result : kv.second) {
            unique_vtable_idxs.insert(result.vtable_idx);
        }
        for(auto vtable_idx : unique_vtable_idxs) {
            const VTable &vtable = vtable_file.get_vtable(vtable_idx);
            cout << " " << hex << vtable.addr;
        }
        cout << "\n";
    }
}

void handle_exception(const char *message) {
    cerr << "Exception occurred: " << message << endl;
}

int main(int argc, char* argv[]) {

    if(argc != 2) {
        cerr << "Usage: "
             << argv[0]
             << " <path_to_config>"
             << "\n";
        return 0;
    }

#if DEBUG_BUILD
    playground(argv[1]);
#else
    try {
        playground(argv[1]);
    } catch(const exception &e) {
        handle_exception(e.what());
    }
#endif

    cout << "Done." << endl;

    return 0;
}
