#ifndef VTABLE_BACKTRACE_ANALYSIS_H
#define VTABLE_BACKTRACE_ANALYSIS_H

#include "backtrace_analysis.h"
#include "backtrace_analysis_boost.h"

class VtableBacktraceAnalysis : public BacktraceAnalysis {


private:

    void remove_unnecessary_nodes(GraphDataFlow &graph,
                                  InstrGraphNodeMap &instr_graph_node_map,
                                  const OperandSSAPtr &initial_use,
                                  const BaseInstructionSSAPtr &initial_instr);

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
                                TrackingInstructionSet&,
                                const GraphDataFlow&,
                                const Function&,
                                const TrackingInstruction&,
                                const BaseInstructionSSAPtr&);

public:

    VtableBacktraceAnalysis(const std::string &module_name,
                            const std::string &target_dir,
                            Translator &translator,
                            const VCallFile &vcalls,
                            const VTableFile &vtables,
                            const std::unordered_set<uint64_t> &new_operators,
                            uint64_t start_addr);

};


#endif
