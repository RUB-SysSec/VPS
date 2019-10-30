#ifndef ICALL_ANALYSIS_H
#define ICALL_ANALYSIS_H

#include "backtrace_analysis.h"
#include "backtrace_analysis_boost.h"
#include "vtable_file.h"

/*!
 * \brief VtableCallInstruction is a special instruction object
 * for the icall analysis.
 */
class VtableCallInstruction : public BaseInstructionSSA {
private:
    const VTable &_vtable;
    const Function &_function;

public:
    VtableCallInstruction(uint64_t addr,
                          const VTable &vtable,
                          const Function &function);
    VtableCallInstruction(const VtableCallInstruction &obj);
    virtual bool operator ==(const BaseInstructionSSA &other) const;
    virtual size_t hash() const;

    const VTable &get_vtable() const;
    const Function &get_function() const;
};

class ICallAnalysis : public BacktraceAnalysis {

private:
    const std::unordered_set<uint64_t> &_vtv_verify_addrs;
    const VTableMap &_this_vtables;
    const EntryVTablePtrsMap &_this_vtable_entries;
    const FileFormatType _file_format;
    std::unordered_set<uint64_t> _unresolvable_vfunc;
    uint32_t _addr_size;

private:

    void remove_unnecessary_nodes(GraphDataFlow &graph,
                                  InstrGraphNodeMap &instr_graph_node_map,
                                  const OperandSSAPtr &initial_use,
                                  const BaseInstructionSSAPtr &initial_instr);

    void add_vtable_call_nodes(GraphDataFlow &graph,
                               InstrGraphNodeMap &instr_graph_node_map,
                               const Function &function,
                               const OperandSSAPtr &initial_use);

    bool mark_node_vtable(GraphDataFlow &graph,
                          GraphDataFlow::vertex_descriptor node);

    bool mark_node_vtv(GraphDataFlow &graph,
                       GraphDataFlow::vertex_descriptor node);

protected:

    virtual void post_merge_graphs(const GraphDataFlow &src_graph,
                                   const NodeToNodeMap &old_new_map);

    virtual void pre_obtain();

    virtual void post_obtain();

    virtual void pre_augment_use(GraphDataFlow&,
                                 InstrGraphNodeMap &instr_graph_node_map,
                                 const Function&,
                                 const OperandSSAPtr&,
                                 const BaseInstructionSSAPtr&,
                                 const TrackingInstruction &);

    /*!
     * \brief Prune internal function data flow graph in such a way that
     * "call" functions are boundaries and each node has a path
     * to the initial instruction.
     */
    virtual void post_augment_use(GraphDataFlow &graph,
                                  InstrGraphNodeMap &instr_graph_node_map,
                                  const Function &function,
                                  const OperandSSAPtr &initial_use,
                                  const BaseInstructionSSAPtr &initial_instr,
                                  const TrackingInstruction &initial_track);

    virtual void finalize_graph_child(GraphDataFlow &, InstrGraphNodeMap &);

    virtual void get_next_tracking_instrs_child(
                                TrackingInstructionSet &out_next_instrs,
                                const GraphDataFlow &graph,
                                const Function&,
                                const TrackingInstruction&,
                                const BaseInstructionSSAPtr&);

public:

    ICallAnalysis(const std::string &module_name,
                  const std::string &target_dir,
                  Translator &translator,
                  const VCallFile &vcalls,
                  const VTableFile &vtables,
                  const std::unordered_set<uint64_t> &new_operators,
                  const std::unordered_set<uint64_t> &vtv_verify_addrs,
                  uint64_t start_addr);

    /*!
     * \brief Incorporates the given vtable xref graph into
     * the one of the analysis. It copies only the nodes that are reachable
     * by the given root instruction.
     */
    void incorporate_vtable_xref_graph(
                            const GraphDataFlow &graph,
                            const InstrGraphNodeMap &instr_graph_node_map,
                            const boost::property_map<GraphDataFlow,
                                        boost::vertex_index_t>::type &indexmap,
                            const BaseInstructionSSAPtr &root_instr,
                            GraphDataFlow::vertex_descriptor &out_join_node,
                            GraphDataFlow::vertex_descriptor &out_vtable_node);

    const std::unordered_set<uint64_t> &get_unresolvable_vfuncs() const;
};


#endif // ICALL_ANALYSIS_H
