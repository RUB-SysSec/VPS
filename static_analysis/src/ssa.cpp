
#include "ssa.h"

using namespace std;


ModuleSSA::ModuleSSA() {
}

const ssa::Function &ModuleSSA::get_ssa_function(const ssa::Functions &ssa_functions,
                                                 uintptr_t address) {
    for(int i = 0; i < ssa_functions.functions_size(); i++) {
        const ssa::Function &ssa_function = ssa_functions.functions(i);
        if(ssa_function.address() == address) {
            return ssa_function;
        }
    }
    stringstream err_msg;
    err_msg << "Can not find SSA data for function with address: "
            << hex << address << ".";
    throw runtime_error(err_msg.str().c_str());
}

bool ModuleSSA::parse(const string &target_file, Translator &translator) {

    // Import all protobuf data (it was split into several parts because
    // of IDAs 32 bit memory restriction => glue it together again).
    ssa::Functions ssa_functions;
    uint32_t file_ctr = 0;
    while(true) {
        string input_file = target_file + "_ssa.pb2_part" + to_string(file_ctr);
        ifstream file(input_file);
        if(!file) {
            break;
        }
        file_ctr++;

        ssa::Functions temp_functions;
        if(!temp_functions.ParseFromIstream(&file)) {
            cerr << "Failed to parse pb2 file: " << input_file << "\n";
            return false;
        }

        // Glue imported data together.
        for(int i = 0; i < temp_functions.functions_size(); i++) {
            ssa::Function *ssa_function = ssa_functions.add_functions();
            ssa_function->CopyFrom(temp_functions.functions(i));
        }
    }

    for(auto &kv_func : translator.get_functions_mutable()) {
        Function &function = kv_func.second;

        const ssa::Function &ssa_function = get_ssa_function(ssa_functions,
                                                          function.get_entry());

        // Add SSA information to function object.
        for(int i = 0; i < ssa_function.basic_blocks_size(); i++) {
            const ssa::BasicBlock &basic_block = ssa_function.basic_blocks(i);
            function.add_block_ssa(basic_block);
        }
    }

    google::protobuf::ShutdownProtobufLibrary();

    return true;
}
