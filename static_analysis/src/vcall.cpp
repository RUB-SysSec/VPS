
#include "vcall.h"
#include "expression.h"

using namespace std;


VCallFile::VCallFile(const string &module_name,
                     const VTableHierarchies &vtable_hierarchies,
                     const VTableFile &vtable_file)
    : _module_name(module_name),
      _vtable_hierarchies(vtable_hierarchies),
      _vtable_file(vtable_file) {}

const VCalls &VCallFile::get_vcalls() const {
    lock_guard<mutex> _(_mtx);

    return _vcalls;
}

const VCall &VCallFile::get_vcall(uint64_t icall_addr) const {
    lock_guard<mutex> _(_mtx);

    if(_vcall_addrs.find(icall_addr) != _vcall_addrs.cend()) {
        for(auto &it : _vcalls) {
            if(it.addr == icall_addr) {
                return it;
            }
        }
    }
    stringstream err_msg;
    err_msg << "Vcall with address "
            << hex << icall_addr
            << " does not exist.";
    throw runtime_error(err_msg.str().c_str());
}

void VCallFile::add_possible_vcall(uint64_t icall_addr) {
    lock_guard<mutex> _(_mtx);

    _possible_vcalls.insert(icall_addr);
}

void VCallFile::insert_vcall(uint64_t icall_addr,
                             uint32_t vtbl_idx,
                             size_t entry_index) {
    VCall vcall;
    vcall.vtbl_idxs.insert(vtbl_idx);
    vcall.addr = icall_addr;
    vcall.entry_index = entry_index;

    // Add also all known vtables from the hierarchy.
    const HierarchiesVTable &hierarchies =
                        _vtable_hierarchies.get_hierarchies();
    for(const DependentVTables &hierarchy : hierarchies) {
        if(hierarchy.find(vtbl_idx) != hierarchy.cend()) {
            for(uint32_t hier_vtbl_idx : hierarchy) {

                const VTable &hier_vtbl =
                        _vtable_file.get_vtable(hier_vtbl_idx);
                if(entry_index >= hier_vtbl.entries.size()) {
                    continue;
                }
                vcall.vtbl_idxs.insert(hier_vtbl_idx);
            }
            break;
        }
    }

    _vcalls.push_back(vcall);
    _vcall_addrs.insert(icall_addr);
}

void VCallFile::add_vcall(uint64_t icall_addr,
                          uint32_t vtbl_idx,
                          size_t entry_index) {
    lock_guard<mutex> _(_mtx);

    // Sanity check of the vcall (i.e., .bss vtables do not have
    // entries at the moment).
    const VTable &vtbl = _vtable_file.get_vtable(vtbl_idx);
    if(entry_index >= vtbl.entries.size()) {
        return;
    }

    // Check if we already know about the vcall and add it if we do not.
    if(_vcall_addrs.find(icall_addr) == _vcall_addrs.end()) {
        insert_vcall(icall_addr, vtbl_idx, entry_index);
    }

    // We know the vcall already. Hence we have to search it the slow way.
    else {
        for(auto &it : _vcalls) {
            if(it.addr == icall_addr) {
                it.vtbl_idxs.insert(vtbl_idx);

                // Add also all known vtables from the hierarchy.
                const HierarchiesVTable &hierarchies =
                                    _vtable_hierarchies.get_hierarchies();
                for(const DependentVTables &hierarchy : hierarchies) {
                    if(hierarchy.find(vtbl_idx) != hierarchy.cend()) {
                        for(uint32_t hier_vtbl_idx : hierarchy) {

                            const VTable &hier_vtbl =
                                    _vtable_file.get_vtable(hier_vtbl_idx);
                            if(entry_index >= hier_vtbl.entries.size()) {
                                continue;
                            }
                            it.vtbl_idxs.insert(hier_vtbl_idx);
                        }
                        break;
                    }
                }

                /* TODO Sometimes we have this case, what should we do about it?
                // Do a sanity check that the entry indexes have not changed.
                // (Intuition: Can never be different for the same vcall).
                if(it.entry_index != entry_index) {
                    cerr << "Different entry index at vcall 0x"
                         << hex << icall_addr << "\n";
                    cerr << "Old entry index: "
                         << dec << it.entry_index << "\n";
                    cerr << "New entry index: "
                         << dec << entry_index << "\n";
                    throw runtime_error("Different vtable entry indexes "\
                                        "for same vcall.");
                }
                */

                break;
            }
        }
    }
}

void VCallFile::export_vcalls(const string &target_dir) {
    lock_guard<mutex> _(_mtx);

    stringstream temp_str;
    temp_str << target_dir << "/" << _module_name << ".vcalls";
    string target_file = temp_str.str();

    ofstream vcall_file;
    vcall_file.open(target_file);

    stringstream temp_str_ext;
    temp_str_ext << target_dir << "/" << _module_name << ".vcalls_extended";
    string target_file_ext = temp_str_ext.str();

    ofstream vcall_file_ext;
    vcall_file_ext.open(target_file_ext);

    vcall_file << _module_name << "\n";
    vcall_file_ext << _module_name << "\n";

    const HierarchiesVTable &hierarchies =
                            _vtable_hierarchies.get_hierarchies();
    for(const auto &it : _vcalls) {

        // Do not consider all vtables used in this vcall as in one hierarchy.
        unordered_set<uint32_t> allowed_vtables;
        for(const auto idx : it.vtbl_idxs) {
            for(const auto dependent_vtbls : hierarchies) {
                if(dependent_vtbls.find(idx) != dependent_vtbls.cend()) {
                    for(uint32_t hier_idx : dependent_vtbls) {
                        allowed_vtables.insert(hier_idx);
                    }
                }
            }

            // Add vtable index manually afterwards in order to also export
            // vtables that do not belong to a hierarchy.
            allowed_vtables.insert(idx);
        }

        // Address of vcall in module.
        vcall_file << hex << it.addr;
        vcall_file_ext << hex << it.addr;

        // Index into vtable that is used by vcall.
        vcall_file_ext << " " << hex << it.entry_index;

        // Export the hierarchy in the following format:
        // <module_name:hex_addr_vtable> <module_name:hex_addr_function>
        for(const auto idx : allowed_vtables) {
            const VTable& temp = _vtable_file.get_vtable(idx);

            // Export vtable address.
            vcall_file << " "
                       << temp.module_name
                       << ":"
                       << hex << temp.addr;
            vcall_file_ext << " "
                           << temp.module_name
                           << ":"
                           << hex << temp.addr;

            // Export target function address.
            uint64_t target_func = 0;
            if(temp.entries.size() > it.entry_index) {
                target_func = temp.entries.at(it.entry_index);
            }
            vcall_file_ext << " "
                           << temp.module_name
                           << ":"
                           << hex << target_func;
        }

        vcall_file << "\n";
        vcall_file_ext << "\n";
    }

    vcall_file.close();
    vcall_file_ext.close();

    stringstream temp_str_poss;
    temp_str_poss << target_dir << "/" << _module_name << ".vcalls_possible";
    string target_file_poss = temp_str_poss.str();

    ofstream vcall_file_poss;
    vcall_file_poss.open(target_file_poss);

    vcall_file_poss << _module_name << "\n";

    for(const auto &it : _possible_vcalls) {

        // Address of possible vcall in module.
        vcall_file_poss << hex << it << "\n";
    }

    vcall_file_poss.close();
}

bool VCallFile::is_known_vcall(uint64_t icall_addr) const {
    lock_guard<mutex> _(_mtx);

    return (_vcall_addrs.find(icall_addr) != _vcall_addrs.cend());
}

const PossibleVCalls &VCallFile::get_possible_vcall() const {
    return _possible_vcalls;
}
