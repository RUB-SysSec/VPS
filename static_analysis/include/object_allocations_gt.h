#ifndef OBJECT_ALLOCATIONS_GT_H
#define OBJECT_ALLOCATIONS_GT_H

#include <stdint.h>
#include <unordered_set>
#include <set>
#include <mutex>
#include <queue>
#include <string>

#include "instruction_backtrace_intra.h"
#include "translator.h"


extern std::queue<uint64_t> queue_vtable_print_addrs;
extern std::mutex queue_vtable_print_addrs_mtx;

typedef std::map<uint64_t, std::unordered_set<uint64_t>> VtablePrintXrefMap;

/*!
 * \brief Class collecting the results of the object allocation GT analysis.
 */
class ObjectAllocationGTFile {
private:
    const std::string &_module_name;
    VtablePrintXrefMap _vtable_print_xrefs_map;
    std::unordered_set<uint64_t> _vtable_print_xrefs;

    mutable std::mutex _mtx;

public:

    ObjectAllocationGTFile(const std::string &module_name);

    const VtablePrintXrefMap& get_vtable_xrefs() const;

    const std::unordered_set<uint64_t>& get_vtable_print_xrefs() const;

    void add_vtable_xref(uint64_t vtbl_xref_addr,
                         uint64_t vtbl_print_xref_addr);

    bool parse_vtable_print(const std::string &target_file);

    void export_vtable_xrefs(const std::string &target_dir);
};


void object_allocation_gt_analysis(const std::string &module_name,
                                   const std::string &target_dir,
                                   const VCallFile &vcalls,
                                   const VTableFile &vtables,
                                   Translator &translator,
                                   ObjectAllocationGTFile &obj_alloc_gt_file,
                                   uint32_t num_threads);

#endif //OBJECT_ALLOCATIONS_GT_H
