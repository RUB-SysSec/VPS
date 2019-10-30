/*

Make sure to have ptrace scoping disabled:
    echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

Build the pintool using either command:
    make instrument.test TARGET=i32 [or]
    clear && make obj-ia32/instrument.so TARGET=ia32

Compile the sample and update the policy three.txt accordingly:
    g++ -g -m32 -O0 three.cpp -othree

Finally, instrument the sample using the pintool:
    pin -t obj-ia32/instrument.so -callsite_info three.txt -- ./three 1>/dev/null

Policy three.txt allows all vtables found by the static analysis, whereas
bad_three.txt misses a valid vtable for testing purposes.

*/

#include <iostream>
#include <cassert>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <map>
#include <set>
#include <unistd.h>

#include <pin.H>

using namespace std;

/* Future work, both architecture and compiler setting may influence how we
instrument the binary. */
enum COMPILERS {
    COMPILER_GCC,
    COMPILER_MSVC
};

enum ARCHITECTURES {
    ARCH_X86,
    ARCH_X64
};

const ARCHITECTURES architecture = ARCH_X64;
const COMPILERS     compiler     = COMPILER_GCC;

/* Set if we append the process's pid to the files
 written back (needed when starting multiple processes
 for analysis). */
const bool append_pid = true;

/* Set if we should write back our data everytime it changes.
This will consume a lot of performance, however it avoids
data loss on crashing. */
const bool always_write_back = true;

ADDRINT module_lo = 0, module_hi = 0;
ofstream out_file;

typedef set<ADDRINT> AddressSet;

AddressSet global_vtables;
AddressSet global_vcall_candidates;
AddressSet global_positive_vcalls;
AddressSet global_negative_vcalls;
AddressSet global_candidate_vcalls;

string module_name = "";

void write_back_files();

// Helper class for pretty-printing.
class SaneHex {
public:
    ADDRINT _value;
    SaneHex(ADDRINT value) : _value(value) { }
};

inline ostream &operator<<(ostream &stream, const SaneHex &sane) {
    return stream << showbase << setfill('0') << setw(sizeof(ADDRINT) / 8)
        << hex << sane._value;
}

inline SaneHex hex(ADDRINT value) {
    return SaneHex(value);
}

// get this pointer for x86 cdecl
inline ADDRINT get_this_pointer_x86(CONTEXT * context) {

    // get content of esp
    ADDRINT stack_pointer, this_pointer;
    PIN_GetContextRegval(context, REG_ESP,
        reinterpret_cast<UINT8*>(&stack_pointer));

    if(PIN_SafeCopy(&this_pointer, reinterpret_cast<void*>(stack_pointer),
        sizeof(this_pointer)) != sizeof(this_pointer)) {
        return 0;
    }

    return this_pointer;

}

// GCC x86_64 => this in RDI
inline ADDRINT get_this_pointer_x64(CONTEXT * context) {
    // get content of rdi
    ADDRINT this_pointer;
    PIN_GetContextRegval(context, REG_RDI,
        reinterpret_cast<UINT8*>(&this_pointer));

    return this_pointer;
}

// wrapper function for all architectures
inline ADDRINT get_this_pointer(CONTEXT * context) {
    switch(architecture) {
        case ARCH_X86:
            return get_this_pointer_x86(context);
        case ARCH_X64:
            return get_this_pointer_x64(context);
        default:
            PIN_ExitApplication(-1);
    }
    
}

void verify_call(ADDRINT instr_addr, ADDRINT target_addr,
    CONTEXT *context) {

    // Only process vcall candidates.
    if(global_candidate_vcalls.find(instr_addr)
       == global_candidate_vcalls.end()) {
        return;
    }

    // Ignore call instruction if we already consider it as _NOT_ a vcall.
    if(global_negative_vcalls.find(instr_addr)
       != global_negative_vcalls.end()) {
        return;
    }

    // Ignore call instruction if we already consider it as vcall.
    if(global_positive_vcalls.find(instr_addr)
       != global_positive_vcalls.end()) {
        return;
    }

    // get this pointer candidate for the current context
    ADDRINT this_pointer = get_this_pointer(context);
    ADDRINT vtbl_pointer;

    /* If we are unable to retrieve the vtable for a valid virtual callsite
    (as all callsites given at the command line are considered valid),
    abort the program. */
    if(this_pointer == 0) {

        out_file << "Cannot get this pointer for candidate 0x"
                 << hex << instr_addr
                 << ". Removing candidate."
                 << endl;

        global_negative_vcalls.insert(instr_addr);

        // Check if we should write back our files directly.
        if(always_write_back) {
            write_back_files();
        }

        return;
    }

    if(PIN_SafeCopy(&vtbl_pointer, reinterpret_cast<void*>(this_pointer),
        sizeof(vtbl_pointer)) != sizeof(vtbl_pointer)) {

        out_file << "Cannot read vtable pointer at 0x"
            << hex << this_pointer
            << " for candidate 0x"
            << hex << instr_addr
            << ". Removing candidate."
            << endl;

        global_negative_vcalls.insert(instr_addr);

        // Check if we should write back our files directly.
        if(always_write_back) {
            write_back_files();
        }

        return;
    }

    // Check if vtable is known.
    if(global_vtables.find(vtbl_pointer) != global_vtables.end()) {

        out_file << "Vtable pointer at 0x"
            << hex << vtbl_pointer
            << " for candidate 0x"
            << hex << instr_addr
            << " known. Adding candidate."
            << endl;

        global_positive_vcalls.insert(instr_addr);

        // Check if we should write back our files directly.
        if(always_write_back) {
            write_back_files();
        }
    }

    // Otherwise we do not consider it a vcall.
    else {
        out_file << "Vtable pointer at 0x"
            << hex << vtbl_pointer
            << " for candidate 0x"
            << hex << instr_addr
            << " not known. Removing candidate."
            << endl;

        global_negative_vcalls.insert(instr_addr);

        // Check if we should write back our files directly.
        if(always_write_back) {
            write_back_files();
        }
    }
}

bool is_inside_module(ADDRINT address) {
    return address >= module_lo && address <= module_hi;
}

void on_instruction(INS instruction, void*) {

    // Only instrument if we know which module we have to look at.
    if(!module_lo || !module_lo) {
        return;
    }

    if(INS_IsCall(instruction) &&
        INS_IsIndirectBranchOrCall(instruction)) {

        ADDRINT address = INS_Address(instruction);

        if(is_inside_module(address)) {

            INS_InsertCall(instruction, IPOINT_BEFORE,
                reinterpret_cast<AFUNPTR>(&verify_call),
                IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR,
                IARG_CONST_CONTEXT, IARG_END);
        }
    }
}

void on_start(void*) {
    // We assume the first image PIN returns to be the
    // main module of our application.
    IMG image = APP_ImgHead();
    if(!IMG_Valid(image)) {
        return;
    }

    module_lo = IMG_LowAddress(image);
    module_hi = IMG_HighAddress(image);
}

KNOB<string> knob_vtable_file(
    KNOB_MODE_WRITEONCE,
    "pintool",
    "in_vtables",
    "",
    "*_vtables.txt file generated by engels.");

KNOB<string> knob_output_file(
    KNOB_MODE_WRITEONCE,
    "pintool",
    "out_log",
    "profiling_output.log",
    "Specify log output file name.");

KNOB<string> knob_positive_vcalls_file(
    KNOB_MODE_WRITEONCE,
    "pintool",
    "inout_positive_vcalls",
    "",
    "Specify file with confirmed vcalls.");

KNOB<string> knob_negative_vcalls_file(
    KNOB_MODE_WRITEONCE,
    "pintool",
    "inout_negative_vcalls",
    "",
    "Specify file with confirmed NOT vcalls.");

KNOB<string> knob_candidate_vcalls_file(
    KNOB_MODE_WRITEONCE,
    "pintool",
    "in_candidate_vcalls",
    "",
    "Specify file with candidate vcalls.");

int usage() {
    cerr << "This tool instruments the callsites and checks the associated"\
        " vtables." << endl;

    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

bool parse_vtables_file(const char *input_file) {
    global_vtables.clear();

    ifstream file(input_file);
    string line;

    bool first = true;
    while(std::getline(file, line)) {
        istringstream parser(line);
        if(first) {
            parser >> module_name;
            first = false;
            continue;
        }
        
        ADDRINT vtable_addr = 0;

        parser >> hex >> vtable_addr;
        if(parser.fail()) {
            return false;
        }

        global_vtables.insert(vtable_addr);
    }

    return true;
}

bool parse_candidates_file(const char *input_file, AddressSet &candidates) {
    candidates.clear();

    ifstream file(input_file);
    string line;

    bool first = true;
    while(std::getline(file, line)) {
        istringstream parser(line);
        if(first) {
            string temp_name;
            parser >> temp_name;
            if(temp_name != module_name) {
                return false;
            }

            first = false;
            continue;
        }
        
        ADDRINT icall_addr = 0;

        parser >> hex >> icall_addr;
        if(parser.fail()) {
            return false;
        }

        candidates.insert(icall_addr);
    }

    return true;
}

void write_candidates_file(const char *input_file,
                           AddressSet &candidates) {

    ofstream candidates_file;

    // Only append process's pid if activated.
    char target_file[1024];
    if(append_pid) {
        snprintf(target_file,
                1023,
                "%s_%d",
                input_file,
                getpid());
    }
    else {
        snprintf(target_file,
                1023,
                "%s",
                input_file);
    }
    target_file[1023] = '\0';
    candidates_file.open(target_file);

    candidates_file << module_name
                    << "\n";
    for(AddressSet::iterator it = candidates.begin();
        it != candidates.end();
        ++it) {

        ADDRINT addr = *it;
        candidates_file << hex << addr
                        << "\n";
    }

    candidates_file.close();

}

void write_back_files() {
    write_candidates_file(knob_positive_vcalls_file.Value().c_str(),
                          global_positive_vcalls);
    write_candidates_file(knob_negative_vcalls_file.Value().c_str(),
                          global_negative_vcalls);
}

void on_fini(int32_t code, void*) {
    out_file.close();
    write_back_files();
    cout << "Done." << endl;
}

int main(int argc, char *argv[]) {
    assert(compiler == COMPILER_GCC && architecture == ARCH_X64 &&
        "Unsupported configuration.");

    if(PIN_Init(argc, argv)) {
        return usage();
    }

    if(knob_vtable_file.Value() == "") {
        cerr << "-in_vtables parameter is required." << endl;
        return usage();
    }

    if(!parse_vtables_file(knob_vtable_file.Value().c_str())) {
        cerr << "Could not parse the vtables file."
             << endl;
        return -1;
    }
    
    if(knob_positive_vcalls_file.Value() == "") {
        cerr << "-inout_positive_vcalls parameter is required." << endl;
        return usage();
    }

    if(!parse_candidates_file(knob_positive_vcalls_file.Value().c_str(),
                              global_positive_vcalls)) {
        cerr << "Could not parse the vtables file."
             << endl;
        return -1;
    }

    if(knob_negative_vcalls_file.Value() == "") {
        cerr << "-inout_negative_vcalls parameter is required." << endl;
        return usage();
    }

    if(!parse_candidates_file(knob_negative_vcalls_file.Value().c_str(),
                              global_negative_vcalls)) {
        cerr << "Could not parse the vtables file."
             << endl;
        return -1;
    }

    if(knob_candidate_vcalls_file.Value() == "") {
        cerr << "-in_candidate_vcalls parameter is required." << endl;
        return usage();
    }

    if(!parse_candidates_file(knob_candidate_vcalls_file.Value().c_str(),
                              global_candidate_vcalls)) {
        cerr << "Could not parse the vtables file."
             << endl;
        return -1;
    }

    if(knob_output_file.Value() == "") {
        cerr << "-out_log parameter is required." << endl;
        return usage();
    }

    // Only append process's pid if activated.
    char target_file[1024];
    if(append_pid) {
        snprintf(target_file,
                1023,
                "%s_%d",
                knob_output_file.Value().c_str(),
                getpid());
    }
    else {
        snprintf(target_file,
                1023,
                "%s",
                knob_output_file.Value().c_str());
    }
    target_file[1023] = '\0';
    out_file.open(target_file);

    PIN_AddApplicationStartFunction(on_start, 0);
    PIN_AddFiniFunction(on_fini, 0);

    INS_AddInstrumentFunction(on_instruction, 0);
    PIN_StartProgram();
    return 0;
}
