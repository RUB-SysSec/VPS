#ifndef INSTRUCTION_BACKTRACE_INTRA_H
#define INSTRUCTION_BACKTRACE_INTRA_H

#include "backtrace_analysis.h"
#include "backtrace_analysis_boost.h"

class InstructionBacktraceIntra : public BacktraceAnalysis {

protected:

    const VTableMap &_this_vtables;

public:

    InstructionBacktraceIntra(
                           const std::string &module_name,
                           const std::string &target_dir,
                           Translator &translator,
                           const VCallFile &vcalls,
                           const VTableFile &vtables,
                           const std::unordered_set<uint64_t> &new_operators,
                           uint64_t start_addr,
                           uint32_t op_idx);

protected:

    /*!
     * \brief A passthrough constructor that just passes the parameter
     * through to the BacktraceAnalysis class. This should be used if
     * a sub-class inherits from this one and has its own constructor logic.
     */
    InstructionBacktraceIntra(
                        const std::string &module_name,
                        const std::string &target_dir,
                        const std::string &dir_prefix,
                        Translator &translator,
                        const VCallFile &vcalls,
                        const VTableFile &vtables,
                        const std::unordered_set<uint64_t> &new_operators,
                        uint64_t start_addr);

private:

    void remove_unnecessary_nodes(GraphDataFlow &graph,
                                  InstrGraphNodeMap &instr_graph_node_map,
                                  const OperandSSAPtr &initial_use,
                                  const BaseInstructionSSAPtr &initial_instr);

    bool mark_node_vtable(GraphDataFlow &graph,
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

};






#endif // INSTRUCTION_BACKTRACE_INTRA_H
