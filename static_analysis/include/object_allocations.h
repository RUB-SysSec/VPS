#ifndef OBJECT_ALLOCATIONS_H
#define OBJECT_ALLOCATIONS_H

#include <stdint.h>
#include <unordered_set>
#include <set>
#include <mutex>
#include <queue>
#include <string>

#include "vtable_file.h"
#include "translator.h"

#define DEBUG_OBJ_ALLOC_PRINT 0
#define DEBUG_OBJ_ALLOC_PRINT_VERBOSE 0

extern std::queue<uint64_t> queue_vtable_addrs;
extern std::mutex queue_vtable_addrs_mtx;


struct ObjectAllocation {
    uint64_t addr;
    std::unordered_set<uint32_t> vtbl_idxs;
    std::unordered_set<uint64_t> vtbl_xref_addrs;

    /*!
     * \brief Type that specifies how `ObjectAllocation` is hashed.
     */
    struct Hash {
        std::size_t operator() (const ObjectAllocation &e) const {
            size_t h = 0;
            std::hash_combine(h, e.addr);
            for(uint32_t idx : e.vtbl_idxs) {
                std::hash_combine(h, idx);
            }
            for(uint64_t xref_addr : e.vtbl_xref_addrs) {
                std::hash_combine(h, xref_addr);
            }
            return h;
        }
    };
    /*!
     * \brief Type that specifies how `ObjectAllocation` is compared.
     */
    struct Compare {
        size_t operator() (ObjectAllocation const &a,
                           ObjectAllocation const &b) const {
            if(a.addr == b.addr) {

                for(uint32_t a_idx : a.vtbl_idxs) {
                    if(b.vtbl_idxs.find(a_idx) == b.vtbl_idxs.cend()) {
                        return false;
                    }
                }

                for(uint64_t a_xref : a.vtbl_xref_addrs) {
                    if(b.vtbl_xref_addrs.find(a_xref)
                       == b.vtbl_xref_addrs.cend()) {

                        return false;
                    }
                }

                return true;
            }
            return false;
        }
    };
};


typedef std::map<uint64_t, ObjectAllocation> ObjectAllocationMap;


/*!
 * \brief Class collecting the results of the object allocation analysis.
 */
class ObjectAllocationFile {
private:
    const std::string &_module_name;
    ObjectAllocationMap _obj_allocs;

    mutable std::mutex _mtx;

public:

    ObjectAllocationFile(const std::string &module_name);

    const ObjectAllocationMap& get_object_allocations() const;

    void add_object_allocation(uint64_t vtable_init_addr,
                               uint32_t vtbl_idx,
                               uint64_t vtbl_xref_addr);

    void export_object_allocations(const std::string &target_dir);

};


void object_allocation_analysis(const std::string &module_name,
                                const VTableFile &vtable_file,
                                const Translator &translator,
                                Vex &vex,
                                ObjectAllocationFile &obj_alloc_file,
                                uint32_t num_threads);

#endif //OBJECT_ALLOCATIONS_H
