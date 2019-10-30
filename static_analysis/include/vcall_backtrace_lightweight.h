#ifndef VCALL_BACKTRACE_LIGHTWEIGHT_H
#define VCALL_BACKTRACE_LIGHTWEIGHT_H

#include "instruction_backtrace_intra.h"

struct EnumClassHash
{
    template <typename T>
    std::size_t operator()(T t) const
    {
        return static_cast<std::size_t>(t);
    }
};

enum VCallBacktraceOperand {
    VCallBacktraceOperandTarget = 0,
    VCallBacktraceOperandThis,
};

typedef std::unordered_map<GraphDataFlow::vertex_descriptor,
                           std::unordered_set<VCallBacktraceOperand,
                                              EnumClassHash>>
                                                             NodeInitOperandMap;

class VCallBacktraceLightweight : public InstructionBacktraceIntra {

private:
    const std::unordered_set<uint64_t> &_vtv_verify_addrs;
    VCallBacktraceOperand _analysis_init_operand;
    NodeInitOperandMap _node_init_operand_map;

public:

    VCallBacktraceLightweight(
                           const std::string &module_name,
                           const std::string &target_dir,
                           Translator &translator,
                           const VCallFile &vcalls,
                           const VTableFile &vtables,
                           const std::unordered_set<uint64_t> &new_operators,
                           const std::unordered_set<uint64_t> &vtv_verify_addrs,
                           uint64_t start_addr);

private:

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

    virtual void finalize_graph_child(GraphDataFlow &graph,
                                      InstrGraphNodeMap &instr_graph_node_map);

    virtual void get_next_tracking_instrs_child(
                                TrackingInstructionSet &out_next_instrs,
                                const GraphDataFlow &graph,
                                const Function&,
                                const TrackingInstruction&,
                                const BaseInstructionSSAPtr&);

public:

    const NodeInitOperandMap &get_node_init_op_map() const;

};

#endif // VCALL_BACKTRACE_LIGHTWEIGHT_H
