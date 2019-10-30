#ifndef ENGELS_H
#define ENGELS_H

#include <condition_variable>
#include <mutex>
#include <queue>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <map>
#include <thread>
#include "amd64_ssa.h"
#include "translator.h"
#include "new_operators.h"
#include "vtable_file.h"
#include "vcall.h"
#include "icall_analysis.h"
#include "vtable_backtrace_analysis.h"
#include "vcall_backtrace_lightweight.h"
#include "icalls.h"
#include "engels_boost.h"
#include "vtable_hierarchy.h"

#define DEBUG_ENGELS_PRINT_PATHS 0
#define DEBUG_ENGELS_PRINT_VERBOSE 0
#define DEBUG_ENGELS_PRINT_SYM_EXEC_STATES 0
#define DEBUG_ENGELS_PRINT 0

extern std::queue<uint64_t> queue_icall_addrs;
extern std::mutex queue_icall_mtx;

extern std::queue<uint64_t> queue_vcall_addrs;
extern std::mutex queue_vcall_mtx;

extern std::unordered_set<uint64_t> repeat_icall_addrs;
// key = address of the icall to analyze
// value = set of icall addresses that could not be resolved
extern std::unordered_map<uint64_t,
                          std::unordered_set<uint64_t>>
                                        icall_addr_unresolvable_map;
// key = address of the icall to analyze
// value = set of virtual function addresses that have no xref
extern std::unordered_map<uint64_t,
                          std::unordered_set<uint64_t>>
                                        vfunc_addr_unresolvable_map;
extern std::mutex repeat_icall_mtx;

extern std::queue<uint64_t> queue_vtable_xref_addrs;
extern std::mutex queue_vtable_xref_mtx;
extern std::mutex vtable_xref_data_mtx;

typedef std::unordered_map<GraphDataFlow::vertex_descriptor,
                           std::unordered_set<
                              GraphDataFlow::vertex_descriptor>> NodeToNodesMap;

typedef std::shared_ptr<VtableBacktraceAnalysis> VtableBacktraceAnalysisPtr;

struct DataFlowPathSet {
    /*!
     * \brief Type that specifies how `DataFlowPath` is hashed.
     */
    struct Hash {
        std::size_t operator() (const DataFlowPath &e) const {
            size_t h = e.size();
            for(const auto node : e) {
                std::hash_combine(h, reinterpret_cast<size_t>(node));
            }
            return h;
        }
    };
    /*!
     * \brief Type that specifies how `DataFlowPath` is compared.
     */
    struct Compare {
        size_t operator() (DataFlowPath const &a,
                           DataFlowPath const &b) const {
            if(a.size() == b.size()) {
                for(uint32_t i = 0; i < a.size(); i++) {
                    if(a.at(i) != b.at(i)) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }
    };
};

struct EngelsSymExecBlock {
    BlockPtr block_ptr;
    GraphDataFlow::vertex_descriptor node_df;
};

struct EngelsVTableXrefAnalysis {
    std::map<uint64_t, uint32_t> xref_vtable_idx_map;
    std::unordered_map<BaseInstructionSSAPtr,
                       std::set<uint64_t>,
                       SSAPtrDeref::Hash,
                       SSAPtrDeref::Compare> root_instr_xrefs_map;
    std::map<uint64_t, VtableBacktraceAnalysisPtr> xref_analysis_map;
};

struct EngelsResult {
    BaseInstructionSSAPtr icall_instr;
    ExpressionPtr call_reg_expr_ptr;
    uint32_t vtable_idx;
    uint32_t entry_idx;
};

typedef std::map<uint64_t, std::vector<EngelsResult>> EngelsResultMap;

struct EngelsAnalysisObjects {
    const FileFormatType file_format;
    const VTableFile &vtable_file;
    const VTableHierarchies &vtable_hierarchies;
    const std::unordered_set<uint64_t> &new_operators;
    const std::unordered_set<uint64_t> &vtv_verify_addrs;
    Translator &translator;
    Vex &vex;
    VCallFile &vcall_file;
    EngelsResultMap results;
    std::mutex results_mtx;

    EngelsAnalysisObjects(const FileFormatType format,
                          const VTableFile &vtbl_file,
                          const VTableHierarchies &hierarchies,
                          const std::unordered_set<uint64_t> &new_ops,
                          const std::unordered_set<uint64_t> &vtv_verifies,
                          Translator &trans,
                          Vex &vex_obj,
                          VCallFile &vcalls)
                          : file_format(format),
                            vtable_file(vtbl_file),
                            vtable_hierarchies(hierarchies),
                            new_operators(new_ops),
                            vtv_verify_addrs(vtv_verifies),
                            translator(trans),
                            vex(vex_obj),
                            vcall_file(vcalls) {}
};

void engels_analysis(const std::string &target_file,
                     const std::string &module_name,
                     const std::string &target_dir,
                     EngelsAnalysisObjects &analysis_obj,
                     uint32_t num_threads);

void engels_icall_analysis(const std::string &module_name,
                        const std::string &target_dir,
                        EngelsAnalysisObjects &analysis_obj,
                        EngelsVTableXrefAnalysis &vtable_xref_data,
                        uint32_t thread_number);

void engels_vtable_xref_analysis(const std::string &module_name,
                        const std::string &target_dir,
                        EngelsAnalysisObjects &analysis_obj,
                        EngelsVTableXrefAnalysis &vtable_xref_data,
                        uint32_t thread_number);

void engels_vcall_lightweight_analysis(
                           const std::string &module_name,
                           const std::string &target_dir,
                           EngelsAnalysisObjects &analysis_obj,
                           uint32_t thread_number);

DataFlowPath create_dataflow_path(
                     EngelsAnalysisObjects &analysis_obj,
                     const GraphDataFlow &graph,
                     const boost::property_map<GraphDataFlow,
                                         boost::vertex_index_t>::type &indexmap,
                     GraphDataFlow::vertex_descriptor src_node,
                     GraphDataFlow::vertex_descriptor dst_node);

ControlFlowPath create_controlflow_path(
                     const GraphCfg &graph,
                     const boost::property_map<GraphCfg,
                                         boost::vertex_index_t>::type &indexmap,
                     GraphCfg::vertex_descriptor src_node,
                     GraphCfg::vertex_descriptor dst_node);

void process_icall_dataflow_graph(
                               EngelsAnalysisObjects &analysis_obj,
                               ICallAnalysis &analysis,
                               const EngelsVTableXrefAnalysis &vtable_xref_data,
                               const NodeToNodesMap &join_to_vtables_map);

bool process_vcall_lightweight_analysis(EngelsAnalysisObjects &analysis_obj,
                                        VCallBacktraceLightweight &analysis);

std::vector<DataFlowPath> create_dataflow_paths(
                     EngelsAnalysisObjects &analysis_obj,
                     const GraphDataFlow &graph,
                     const boost::property_map<GraphDataFlow,
                                         boost::vertex_index_t>::type &indexmap,
                     GraphDataFlow::vertex_descriptor src_node,
                     GraphDataFlow::vertex_descriptor dst_node);

void sym_execute_blocks(const EngelsAnalysisObjects &analysis_obj,
                        const std::vector<BlockPtr> &exec_blocks,
                        State &state);

std::vector<BlockPtr> create_artificial_block_vector(
                                      const EngelsAnalysisObjects &analysis_obj,
                                      const GraphDataFlow &graph,
                                      const DataFlowPath &data_flow_path);

#endif // ENGELS_H
