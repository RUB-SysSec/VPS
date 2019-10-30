#ifndef BINARY_CPS_H
#define BINARY_CPS_H

#include "engels.h"
#include "instruction_backtrace_intra.h"
#include "block.h"

struct BinaryCPSVfunc {
    uint64_t addr;
    uint32_t vtbl_idx;
};

extern std::queue<BinaryCPSVfunc> queue_vfunc_addrs;
extern std::mutex queue_vfunc_mtx;
extern std::vector<BinaryCPSVfunc> dtor_candidates;
extern std::mutex dtor_candidates_mtx;

void binary_cps_analysis(const std::string &target_file,
                         const std::string &module_name,
                         const std::string &target_dir,
                         EngelsAnalysisObjects &analysis_obj,
                         uint32_t num_threads);

void binary_cps_dtor_analysis(const std::string &module_name,
                              const std::string &target_dir,
                              EngelsAnalysisObjects &analysis_obj,
                              uint32_t thread_number);

bool has_vtable_write(const std::string &module_name,
                      const std::string &target_dir,
                      EngelsAnalysisObjects &analysis_obj,
                      const BinaryCPSVfunc &candidate);

#endif // BINARY_CPS_H
