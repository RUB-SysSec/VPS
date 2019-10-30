#ifndef VCALL_H
#define VCALL_H

#include <fstream>
#include <sstream>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>
#include <mutex>

#include "vcall_types.h"
#include "vtable_hierarchy.h"
#include "vtable_file.h"

class VCallFile {
private:
    VCalls _vcalls;
    std::unordered_set<uint64_t> _vcall_addrs;
    PossibleVCalls _possible_vcalls;

    const std::string &_module_name;

    const VTableHierarchies &_vtable_hierarchies;
    const VTableFile &_vtable_file;

    mutable std::mutex _mtx;

private:
    void insert_vcall(uint64_t icall_addr,
                      uint32_t vtbl_idx,
                      size_t entry_index);

public:

    VCallFile(const std::string &module_name,
              const VTableHierarchies &vtable_hierarchies,
              const VTableFile &vtable_file);

    /*!
     * \brief Returns the found virtual callsites.
     * \return Returns the found virtual callsites.
     */
    const VCalls &get_vcalls() const;

    /*!
     * \brief Returns the information about the virtual callsite given
     * by address.
     * \return Returns a reference to the `VCall` object (throws runtime_error
     * exception if callsite does not exist).
     */
    const VCall &get_vcall(uint64_t icall_addr) const;

    void add_vcall(uint64_t icall_addr,
                   uint32_t vtbl_idx,
                   size_t entry_index);

    void add_possible_vcall(uint64_t icall_addr);

    const PossibleVCalls &get_possible_vcall() const;

    void export_vcalls(const std::string &target_dir);

    bool is_known_vcall(uint64_t icall_addr) const;
};

#endif
