#ifndef FUNCTION_XREFS_H
#define FUNCTION_XREFS_H

#include "translator.h"

#include <fstream>
#include <sstream>
#include <iostream>
#include <string>


class ModuleFunctionXrefs {

public:
    ModuleFunctionXrefs();

    bool parse(const std::string &target_file, Translator &translator);

};


#endif // FUNCTION_XREFS_H
