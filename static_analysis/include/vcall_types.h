#ifndef VCALL_TYPES_H
#define VCALL_TYPES_H

#include <vector>
#include <unordered_set>

struct VCall {
    uint64_t addr;
    std::unordered_set<uint32_t> vtbl_idxs;
    uint32_t entry_index;
};

typedef std::vector<VCall> VCalls;
typedef std::unordered_set<uint64_t> PossibleVCalls;

#endif
