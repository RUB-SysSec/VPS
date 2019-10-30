
#include "function_xrefs.h"

using namespace std;


ModuleFunctionXrefs::ModuleFunctionXrefs() {
}

bool ModuleFunctionXrefs::parse(const std::string &target_file,
                                Translator &translator) {

    map<uintptr_t, Function> &functions = translator.get_functions_mutable();

    ifstream file(target_file + "_funcs_xrefs.txt");
    if(!file) {
        cerr << "Not able to open '_funcs_xrefs.txt' file." << "\n";
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
             << "'_funcs_xrefs.txt' file."
             << "\n";
    }

    while(getline(file, line)) {
        istringstream parser(line);
        uint64_t func_addr = 0;
        uint64_t func_xref_addr = 0;

        parser >> hex >> func_addr;
        if(parser.fail()) {
            cerr << "Parsing error in "
                 << "'_funcs_xrefs.txt' file."
                 << "\n";
            return false;
        }

        Function &function = functions.at(func_addr);

        while(parser >> hex >> func_xref_addr) {
            if(parser.fail()) {
                cerr << "Parsing error in "
                     << "'_funcs_xrefs.txt' file."
                     << "\n";
                return false;
            }

            function.add_xref(func_xref_addr);
        }
    }

    return true;
}
