
#include "vtable_file.h"

using namespace std;

/*!
 * \brief Constructs a new `VtableFile` object.
 * \param vtable_file The filename of the `_vtables.txt` and `_vtables_xref.txt` file
 * (as produced by the exporter script).
 */
VTableFile::VTableFile(const string &this_module_name,
                       const FileFormatType file_format)
    : _file_format(file_format) {
      _this_module_name = this_module_name;
      _vtables.clear();
      _index = 0;

    switch(_file_format) {
        case FileFormatELF64:
        case FileFormatPE64:
            _addr_size = 8;
            break;
        default:
            throw runtime_error("Unknown file format.");
    }

}

bool VTableFile::parse(const string &vtables_file) {

    // Make sure that we parse files only if object was not finalized yet.
    if(_is_finalized) {
        cerr << "Parse attempt after VTableFile object was finalized."
             << "\n";
        return false;
    }

    ifstream file(vtables_file + "_vtables.txt");
    if(!file) {
        cerr << "Not able to open '_vtables.txt' file." << "\n";
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
             << "'_vtables.txt' file."
             << "\n";
    }

    // Check if we already parsed a vtables file for this module.
    if(_managed_modules.find(module_name) != _managed_modules.cend()) {
        cerr << "A vtables file for this module was already parsed." << "\n";
        return false;
    }

    bool has_vtables = false;
    while(getline(file, line)) {
        has_vtables = true;
        istringstream parser(line);
        uint64_t vtable_addr = 0;
        uint64_t vtable_ref_addr = 0;
        uint64_t vtable_entry = 0;
        uint32_t bss_offset = 0;
        uint32_t bss_size = 0;
        string vtable_name = "";
        int offset_to_top = 0;
        VTableType type = VTableTypeNormal;

        parser >> hex >> vtable_addr;
        if(parser.fail()) {
            cerr << "Parsing error in "
                 << "'_vtables.txt' file."
                 << "\n";
            return false;
        }

        string temp;
        parser >> temp;
        if(parser.fail()) {
            return false;
        }
        // Value says that it is a .bss entry.
        if(temp == "bss") {

            // Since a copy relocation just copies the plain
            // data from the shared object to the .bss section,
            // it does not contain any information about
            // sub-vtables. Therefore, we have to assume that
            // at each entry a new sub-vtable begins
            // and hence we have the same vtable multiple times.
            parser >> dec >> bss_offset;
            if(parser.fail()) {
                return false;
            }

            parser >> dec >> bss_size;
            if(parser.fail()) {
                return false;
            }

            parser >> vtable_name;
            if(parser.fail()) {
                return false;
            }

            type = VTableTypeBss;
        }
        // Value says that it is a got_reloc entry.
        else if(temp == "got_reloc") {
            parser >> vtable_name;
            if(parser.fail()) {
                return false;
            }

            type = VTableTypeGotReloc;
        }
        // Value says that it is a .got entry.
        else if(temp == "got") {
            parser >> hex >> vtable_ref_addr;
            if(parser.fail()) {
                return false;
            }

            type = VTableTypeGot;
        }
        // Value is a decimal value which gives the offset to top.
        else {
            std::stringstream temp_stream;
            temp_stream << temp;
            temp_stream >> dec >> offset_to_top;
        }

        VTable vtable;
        vtable.type = type;
        vtable.addr = vtable_addr;
        vtable.offset_to_top = offset_to_top;
        vtable.module_name = module_name;
        vtable.name = vtable_name;
        vtable.bss_offset = bss_offset;
        vtable.bss_size = bss_size;
        vtable.vtbl_ref_addr = vtable_ref_addr;
        vtable.vtbl_ref_idx = 0;

        // NOTE: Index is a unique identifier for all vtables in all modules.
        vtable.index = _index;

        while(parser >> hex >> vtable_entry) {
            if(parser.fail()) {
                cerr << "Parsing error in "
                     << "'_vtables.txt' file."
                     << "\n";
                return false;
            }

            vtable.entries.push_back(vtable_entry);
        }

        _vtables.push_back(vtable);
        assert(_vtables[_index].module_name == vtable.module_name
               && _vtables[_index].addr == vtable.addr
               && _vtables[_index].index == vtable.index
               && "Index of vtable and index in vector are not the same.");

        _index++;
    }

    // Resolve .got vtable references to existing vtables.
    for(auto &it : _vtables) {
        if(it.type == VTableTypeGot) {
            bool found = false;
            for(auto &it_ref : _vtables) {
                if(it_ref.addr == it.vtbl_ref_addr
                   && it_ref.module_name == it.module_name) {
                    it.vtbl_ref_idx = it_ref.index;
                    found = true;
                    break;
                }
            }
            if(!found) {
                cerr << "Reference vtable "
                     << hex << it.vtbl_ref_addr
                     <<" of .got vtable "
                     << hex << it.addr
                     << " not found. Corrupt data."
                     << endl;
                return false;
            }
        }
    }

    // Only parse xrefs file and if it has at least one vtable.
    if(has_vtables) {

        // Only add module to managed modules if it has at least one vtable.
        _managed_modules.insert(module_name);

        // Parse xrefs file.
        file = ifstream(vtables_file + "_vtables_xrefs.txt");
        if(!file) {
            cerr << "Not able to open '_vtables_xrefs.txt' file." << "\n";
            return false;
        }

        // Parse first line manually.
        getline(file, line);
        header_parser = istringstream(line);

        // First entry of file is always the module name.
        string module_name_xrefs;
        header_parser >> module_name_xrefs;
        if(header_parser.fail()) {
            cerr << "Parsing error in "
                 << "'_vtables_xrefs.txt' file."
                 << "\n";
            return false;
        }

        if(module_name_xrefs != module_name) {
            cerr << "Module name of '_vtables.txt' and "
                 << "'_vtables_xrefs.txt' different."
                 << "\n";
            return false;
        }

        while(getline(file, line)) {
            istringstream parser(line);
            uint64_t vtable_addr = 0;
            uint64_t vtable_xref_addr = 0;
            int32_t offset = 0;

            parser >> hex >> vtable_addr;
            if(parser.fail()) {
                cerr << "Parsing error in "
                     << "'_vtables_xrefs.txt' file."
                     << "\n";
                return false;
            }

            // Add xrefs to vtable object.
            bool found = false;
            for(auto &it : _vtables) {
                if(it.module_name == module_name_xrefs
                   && it.addr == vtable_addr) {
                    found = true;
                    while(parser >> hex >> vtable_xref_addr) {
                        if(parser.fail()) {
                            cerr << "Parsing error in "
                                 << "'_vtables_xrefs.txt' file."
                                 << "\n";
                            return false;
                        }

                        // Xref file makes a distinction between
                        // a direct xref (offset 0) and an indirect
                        // xref (offset -16) which is used for .got and .bss.
                        parser >> dec >> offset;
                        if(offset == 0) {
                            it.xrefs.insert(vtable_xref_addr);
                        }
                        else {
                            it.indirect_xrefs[offset].insert(vtable_xref_addr);
                        }
                    }
                    break;
                }
            }
            if(!found) {
                cerr << "Vtable from '_vtables_xrefs.txt' file "
                     << "not in '_vtables.txt' file."
                     << "\n";
                return false;
            }
        }

    }

    return true;
}


const EntryVTablePtrsMap& VTableFile::get_this_vtable_entries() const {

    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("VTableFile object was not finalized.");
    }

    return _module_vtable_entries_map.at(_this_module_name);
}

const EntryVTablePtrsMap& VTableFile::get_this_vtable_entry_addrs() const {

    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("VTableFile object was not finalized.");
    }

    return _module_vtable_entry_addrs_map.at(_this_module_name);
}

const VTableMap& VTableFile::get_this_vtables() const {

    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("VTableFile object was not finalized.");
    }

    return *(_module_vtables_map.at(_this_module_name));
}

const VTableMap& VTableFile::get_vtables(const string &module_name) const {

    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("VTableFile object was not finalized.");
    }

    if(_module_vtables_map.find(module_name) == _module_vtables_map.cend()) {
        throw runtime_error("VTableFile object does not know module name.");
    }

    return *(_module_vtables_map.at(module_name));
}

const VTableVector& VTableFile::get_all_vtables() const {

    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("VTableFile object was not finalized.");
    }

    return _vtables;
}

void VTableFile::finalize() {

    // Make sure that we only finalize this object once.
    if(_is_finalized) {
        throw runtime_error("VTableFile object was already finalized.");
    }
    _is_finalized = true;

    if(_managed_modules.find(_this_module_name) == _managed_modules.cend()) {
        throw runtime_error("VTableFile object has no data for the "\
                            "module to analyze.");
    }

    // Build up a vector that contains a mapping for each module
    // that maps from vtable address to vtable object.
    uint32_t idx = 0;
    for(auto &module_it : _managed_modules) {
        for(auto &vtbl_it : _vtables) {
            if(vtbl_it.module_name != module_it) {
                continue;
            }

            if(_module_vtables.size() <= idx) {
                VTableMap temp;
                temp[vtbl_it.addr] = &vtbl_it;
                _module_vtables.push_back(temp);
            }
            else {
                _module_vtables[idx][vtbl_it.addr] = &vtbl_it;
            }
        }
        idx++;
    }

    // Build up a mapping that maps a module name to its vtable address
    // to vtable object map.
    idx = 0;
    for(auto &module_it : _managed_modules) {
        _module_vtables_map[module_it] = &_module_vtables[idx];
        idx++;
    }

    // Sanity check if module mapping is completely correct
    // (Added for now to exclude this as error source)
    for(auto &module_it : _managed_modules) {
        const auto &vtable_map = *(_module_vtables_map.at(module_it));
        for(const auto &vtbl_kv : vtable_map) {
            if(vtbl_kv.second->module_name != module_it) {
                throw runtime_error("Error while finalizing vtable mapping.");
            }
        }
    }

    // Build up a map for each module that maps each vtable entry
    // and vtable entry address to the vtable object.
    // Since one entry can be in multiple vtables,
    // the entry maps to a set of vtable ptrs.
    for(auto &module_it : _managed_modules) {
        EntryVTablePtrsMap &entry_map = _module_vtable_entries_map[module_it];
        EntryVTablePtrsMap &entry_addr_map =
                                      _module_vtable_entry_addrs_map[module_it];

        for(auto &vtbl_it : _vtables) {
            if(vtbl_it.module_name != module_it) {
                continue;
            }

            uint32_t counter = 0;
            for(const auto entry : vtbl_it.entries) {
                entry_map[entry].insert(&vtbl_it);
                entry_addr_map[vtbl_it.addr + (counter * _addr_size)].insert(
                                                                      &vtbl_it);
                counter++;
            }
        }
    }

    return;
}

bool VTableFile::is_finalized() const {
    return _is_finalized;
}

const VTable* VTableFile::get_vtable_ptr(const std::string &module_name,
                                        uint64_t addr) const {

    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("VTableFile object was not finalized.");
    }

    if(_module_vtables_map.at(module_name)->find(addr)
            != _module_vtables_map.at(module_name)->cend()) {

        return (_module_vtables_map.at(module_name)->at(addr));
    }
    return nullptr;
}

const VTable& VTableFile::get_vtable(const std::string &module_name,
                                     uint64_t addr) const {

    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("VTableFile object was not finalized.");
    }

    return *(_module_vtables_map.at(module_name)->at(addr));

}

const VTable& VTableFile::get_vtable(uint32_t index) const {

    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("VTableFile object was not finalized.");
    }

    if(_vtables.size() <= index) {
        throw runtime_error("Vtable index is out of range.");
    }

    return _vtables[index];
}

uint32_t VTableFile::get_addr_size() const {
    return _addr_size;
}
