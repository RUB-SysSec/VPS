#include "icalls.h"

using namespace std;

ICallSet import_icalls(const string &target_file) {

    ifstream file(target_file + "_icalls.txt");
    if(!file) {
        throw runtime_error("Opening '_icalls.txt' file failed.");
    }

    string line;

    // Parse first line manually.
    getline(file, line);
    istringstream header_parser(line);

    // First entry of file is always the module name.
    string import_module_name;
    header_parser >> import_module_name;
    if(header_parser.fail()) {
        throw runtime_error("Parsing '_icalls.txt' file failed.");
    }

    ICallSet icall_set;

    while(getline(file, line)) {
        istringstream parser(line);
        uint64_t icall_addr = 0;

        parser >> hex >> icall_addr;
        if(parser.fail()) {
            throw runtime_error("Parsing '_icalls.txt' file failed.");
        }

        icall_set.insert(icall_addr);
    }

    return icall_set;
}

