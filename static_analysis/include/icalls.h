#ifndef ICALLS_H
#define ICALLS_H

#include <set>
#include <string>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>

typedef std::set<uint64_t> ICallSet;

ICallSet import_icalls(const std::string &target_file);

#endif
