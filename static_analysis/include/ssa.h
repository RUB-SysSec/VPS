#ifndef SSA_H
#define SSA_H

#include "ssa_export.pb.h"
#include "translator.h"

#include <fstream>
#include <sstream>
#include <iostream>
#include <string>

class ModuleSSA {

private:

    const ssa::Function &get_ssa_function(const ssa::Functions &ssa_functions,
                                          uintptr_t address);

public:
    ModuleSSA();

    bool parse(const std::string &target_file, Translator &translator);

};


#endif // SSA_H
