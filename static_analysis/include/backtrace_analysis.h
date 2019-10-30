#ifndef BACKTRACE_ANALYSIS_H
#define BACKTRACE_ANALYSIS_H


#include "ssa_instruction.h"
#include "translator.h"
#include "vcall.h"
#include "vtable_file.h"
#include <vector>
#include <queue>
#include <string>
#include <iomanip>
#include <boost/graph/graphviz.hpp>
#include <boost/graph/directed_graph.hpp>
#include <boost/filesystem.hpp>

#define DEBUG_DUMP_GRAPHS 0
#define DEBUG_PRINT 0

enum DataFlowNodeType {
    DataFlowNodeTypeNone = 0,
    DataFlowNodeTypeNormal,
    DataFlowNodeTypeStart,
    DataFlowNodeTypeVTVVerifyCall,
    DataFlowNodeTypeVtable,
    DataFlowNodeTypeNewOperator,
    DataFlowNodeTypeVtableCall,
};

inline DataFlowNodeType operator|(DataFlowNodeType a, DataFlowNodeType b) {
    return static_cast<DataFlowNodeType>(static_cast<uint32_t>(a)
                                         | static_cast<uint32_t>(b));
}

inline DataFlowNodeType operator&(DataFlowNodeType a, DataFlowNodeType b) {
    return static_cast<DataFlowNodeType>(static_cast<uint32_t>(a)
                                         & static_cast<uint32_t>(b));
}

inline DataFlowNodeType operator^(DataFlowNodeType a, DataFlowNodeType b) {
    return static_cast<DataFlowNodeType>(static_cast<uint32_t>(a)
                                         ^ static_cast<uint32_t>(b));
}

enum DataFlowEdgeType {
    DataFlowEdgeTypeNone = 0,
    DataFlowEdgeTypeOperand,
    DataFlowEdgeTypeRet,
    DataFlowEdgeTypeCall,
    DataFlowEdgeTypeJmp,
    DataFlowEdgeTypeVtableCall,
};

struct DataFlowNode {
    DataFlowNodeType type = DataFlowNodeTypeNone;
    bool is_join = false;
    BaseInstructionSSAPtr instr = nullptr;
    std::string comment = "";
};

struct DataFlowEdge {
    DataFlowEdgeType type = DataFlowEdgeTypeNone;
    OperandSSAPtr operand = nullptr;
    std::string comment = "";
};

typedef boost::directed_graph<DataFlowNode, DataFlowEdge> GraphDataFlow;
typedef std::unordered_map<BaseInstructionSSAPtr,
                           GraphDataFlow::vertex_descriptor,
                           SSAPtrDeref::Hash,
                           SSAPtrDeref::Compare> InstrGraphNodeMap;
typedef std::map<GraphDataFlow::vertex_descriptor,
                 GraphDataFlow::vertex_descriptor> NodeToNodeMap;

enum TrackingType {
    TrackingTypeCaller = 0,
    TrackingTypeRet,
    TrackingTypeTailjmp,
    TrackingTypeInstr,
};

struct TrackingInstruction {
    uint64_t addr = 0;
    InstructionTypeSSA instr_type;
    TrackingType type;
    OperandSSAPtr operand;
    GraphDataFlow::vertex_descriptor prev_node;
    std::vector<uint64_t> transition_order;

    /*!
     * \brief Type that specifies how `TrackingInstruction` is hashed.
     */
    struct Hash {
        std::size_t operator() (const TrackingInstruction &e) const {
            size_t h = e.type;
            std::hash_combine(h, e.addr);
            std::hash_combine(h, e.instr_type);
            std::hash_combine(h, e.operand->hash());
            for(uint64_t order_addr : e.transition_order) {
                std::hash_combine(h, order_addr);
            }
            return h;
        }
    };
    /*!
     * \brief Type that specifies how `TrackingInstruction` is compared.
     */
    struct Compare {
        size_t operator() (TrackingInstruction const &a,
                           TrackingInstruction const &b) const {
            if(a.addr == b.addr
               && a.instr_type == b.instr_type
               && a.type == b.type
               && *(a.operand) == *(b.operand)
               && a.transition_order.size() == b.transition_order.size()) {

                bool is_transition_order_equal = true;
                for(uint32_t i = 0; i < a.transition_order.size(); i++) {
                    if(a.transition_order.at(i) != b.transition_order.at(i)) {
                        is_transition_order_equal = false;
                        break;
                    }
                }

                return is_transition_order_equal;
            }
            return false;
        }
    };
};

typedef std::unordered_set<TrackingInstruction,
                           TrackingInstruction::Hash,
                           TrackingInstruction::Compare> TrackingInstructionSet;

template <class T>
class FullDataFlowNodeWriter {
public:
    FullDataFlowNodeWriter(const T &graph) : _graph(graph) {}
    template <class VertexOrEdge>
    void operator()(std::ostream& out, const VertexOrEdge& v) const {
        out << "["
            << "fontname=\"Ubuntu Mono\", "
            << "shape=rect, ";
        if(_graph[v].comment != "") {
            out << "label=\"" << *(_graph[v].instr)
                << " (comment: " << _graph[v].comment << ")\", "
                << "fillcolor=\"#fff668\", "
                << "style=filled";
        }
        else {
            out << "label=\"" << *(_graph[v].instr);
            if(_graph[v].is_join) {
                out << " (join)";
            }
            switch(_graph[v].type) {
                case DataFlowNodeTypeStart:
                    out << " (start_instr)\"";
                    if(_graph[v].is_join) {
                        out << ", "
                            << "fillcolor=\"#7436f4\", "
                            << "style=filled";
                    }
                    else {
                        out << ", "
                            << "fillcolor=\"#ffe4e1\", "
                            << "style=filled";
                    }
                    break;
                case DataFlowNodeTypeNewOperator:
                    out << " (new_operator)\"";
                    if(_graph[v].is_join) {
                        out << ", "
                            << "fillcolor=\"#7436f4\", "
                            << "style=filled";
                    }
                    else {
                        out << ", "
                            << "fillcolor=\"#d8f1c4\", "
                            << "style=filled";
                    }
                    break;
                case DataFlowNodeTypeVtable:
                    out << " (vtable)\"";
                    if(_graph[v].is_join) {
                        out << ", "
                            << "fillcolor=\"#7436f4\", "
                            << "style=filled";
                    }
                    else {
                        out << ", "
                            << "fillcolor=\"#c6e2ff\", "
                            << "style=filled";
                    }
                    break;
                case DataFlowNodeTypeVTVVerifyCall:
                    out << " (VTV_verify)\"";
                    if(_graph[v].is_join) {
                        out << ", "
                            << "fillcolor=\"#7436f4\", "
                            << "style=filled";
                    }
                    else {
                        out << ", "
                            << "fillcolor=\"#f1c4ed\", "
                            << "style=filled";
                    }
                    break;
                case DataFlowNodeTypeVtableCall:
                    out << "\"";
                    if(_graph[v].is_join) {
                        out << ", "
                            << "fillcolor=\"#7436f4\", "
                            << "style=filled";
                    }
                    else {
                        out << ", "
                            << "fillcolor=\"#a6f2ff\", "
                            << "style=filled";
                    }
                    break;
                default:
                    out << "\"";
                    if(_graph[v].is_join) {
                        out << ", "
                            << "fillcolor=\"#7436f4\", "
                            << "style=filled";
                    }
                    break;
            }
        }
        out << "]";
    }
private:
    const T &_graph;
};

template <class T>
class FullDataFlowEdgeWriter {
public:
    FullDataFlowEdgeWriter(const T &graph) : _graph(graph) {}
    template <class VertexOrEdge>
    void operator()(std::ostream& out, const VertexOrEdge& v) const {
        out << "["
            << "fontname=\"Ubuntu Mono\", ";
        if(_graph[v].comment != "") {
            out << "label=\"" << *(_graph[v].operand)
                << " (comment: " << _graph[v].comment << ")\"";
        }
        else {
            switch(_graph[v].type) {
                case DataFlowEdgeTypeCall:
                    out << "label=\"" << *(_graph[v].operand)
                        << " (call)\"";
                    break;
                case DataFlowEdgeTypeJmp:
                    out << "label=\"" << *(_graph[v].operand)
                        << " (jmp)\"";
                    break;
                case DataFlowEdgeTypeRet:
                    out << "label=\"" << *(_graph[v].operand)
                        << " (ret)\"";
                    break;
                case DataFlowEdgeTypeVtableCall:
                    out << "label=\"" << *(_graph[v].operand)
                        << " (vtable call)\"";
                    break;
                default:
                    out << "label=\"" << *(_graph[v].operand) << "\"";
            }
        }
        out << "]";
    }
private:
    const T &_graph;
};

/*!
 * \brief CallOfRetInstruction is a special instruction object for the
 * backtrace analysis that is used for call instructions that are the target
 * of return instructions. This is used in order to allow
 * to have the same call instruction twice in the same graph:
 * 1) as target for return instructions,
 * 2) as actual call instructions where the argument register is tracked.
 */
class CallOfRetInstruction : public InstructionSSA {
public:
    CallOfRetInstruction() = delete;
    CallOfRetInstruction(const ssa::BaseInstruction &instruction);
    CallOfRetInstruction(const InstructionSSA &instruction);
    CallOfRetInstruction(const CallOfRetInstruction &obj);
};

class BacktraceAnalysis {
private:
    const std::string &_module_name;
    const std::string &_target_dir;
    std::unordered_set<uint64_t> _unresolvable_icalls;
    std::string _graph_dump_dir;
    uint32_t _round = 0;
    GraphDataFlow _master_graph;
    InstrGraphNodeMap _master_instr_graph_node_map;
    boost::property_map<GraphDataFlow, boost::vertex_index_t>::type _indexmap;
    bool _indexmap_dirty = false;

protected:
    uint64_t _start_addr;
    const Translator &_translator;
    const std::map<uintptr_t, Function> &_functions;
    const VTableFile &_vtables;
    const VCallFile &_vcalls;
    const std::unordered_set<uint64_t> &_new_operators;
    std::queue<TrackingInstruction> _work_queue;
    TrackingInstructionSet _processed_instrs;
    GraphDataFlow &_graph;
    InstrGraphNodeMap &_instr_graph_node_map;

private:
    /*!
     * \brief Basic constructor preparations that is called by all
     * constructors internally.
     */
    void basic_ctor(uint64_t start_addr,
                    const std::string &dir_prefix);

    void augment_use(GraphDataFlow &graph,
                     InstrGraphNodeMap &instr_graph_node_map,
                     const Function &function,
                     const OperandSSAPtr &initial_use,
                     const BaseInstructionSSAPtr &initial_instr);

    /*!
     * \brief Preprocessing of tailjmps (e.g., search the definition of
     * the operand we want to track in the function).
     * \param `out_next_instrs` is given by reference and the next tracking
     * instructions are stored into the set.
     *
     * \return Returns `true` if the current tracking job should be continued
     * and `false` if the tracking job should be skipped.
     */
    bool pre_processing_tailjmp(TrackingInstructionSet &out_next_instrs,
                                const TrackingInstruction &curr,
                                const Function &function,
                                const BaseInstructionSSAPtr &curr_instr);

    const RegisterX64SSA &pre_processing_tailjmp_get_reg(
                                                       const OperandSSAPtr &op);

    void get_next_tracking_instrs(TrackingInstructionSet &out_next_instrs,
                                  const GraphDataFlow &graph,
                                  const Function &function,
                                  const TrackingInstruction &initial_track,
                                  const BaseInstructionSSAPtr &initial_instr);

    void prepare_xref_tracking_instrs(
                                    TrackingInstructionSet &out_next_instrs,
                                    const GraphDataFlow &graph,
                                    const Function &function,
                                    const TrackingInstruction &initial_track,
                                    const BaseInstructionSSAPtr &initial_instr);

    void prepare_subcall_tracking_instrs(
                                        TrackingInstructionSet &out_next_instrs,
                                        const GraphDataFlow &graph);

    void prepare_ret_tracking_instrs(TrackingInstructionSet &out_next_instrs,
                                     const BaseInstructionSSAPtr &call_instr);

    /*!
     * \brief Draws the edge between the previous node and the currently
     * tracked one into the final graph.
     */
    void draw_final_edge(const TrackingInstruction &curr,
                         const BaseInstructionSSAPtr &curr_instr);

protected:
    /*!
     * \brief Dumps the graph as .dot file to the given file name.
     */
    void dump_graph(const GraphDataFlow &graph, const std::string &file_name);

    /*!
     * \brief Returns the data flow descriptor for the given instruction.
     * Throws an exception if node does not exist.
     *
     * \return Data flow graph descriptor for the given instruction.
     */
    GraphDataFlow::vertex_descriptor get_node_graph(
                                  const GraphDataFlow &graph,
                                  const InstrGraphNodeMap &instr_graph_node_map,
                                  const BaseInstructionSSAPtr &target_instr);

    /*!
     * \brief Constructor of BacktraceAnalysis.
     */
    BacktraceAnalysis(const std::string &module_name,
                      const std::string &target_dir,
                      const std::string &dir_prefix,
                      Translator &translator,
                      const VCallFile &vcalls,
                      const VTableFile &vtables,
                      const std::unordered_set<uint64_t> &new_operators,
                      uint64_t start_addr);

    /*!
     * \brief Constructor of BacktraceAnalysis that allows to store the created
     * graph externally.
     */
    BacktraceAnalysis(const std::string &module_name,
                      const std::string &target_dir,
                      const std::string &dir_prefix,
                      Translator &translator,
                      const VCallFile &vcalls,
                      const VTableFile &vtables,
                      const std::unordered_set<uint64_t> &new_operators,
                      uint64_t start_addr,
                      GraphDataFlow &target_graph,
                      InstrGraphNodeMap &instr_graph_node_map);

    virtual void post_merge_graphs(const GraphDataFlow &src_graph,
                                   const NodeToNodeMap &old_new_map) = 0;

    virtual void pre_obtain() = 0;

    virtual void post_obtain() = 0;

    virtual void pre_augment_use(
                                GraphDataFlow &graph,
                                InstrGraphNodeMap &instr_graph_node_map,
                                const Function &function,
                                const OperandSSAPtr &initial_use,
                                const BaseInstructionSSAPtr &initial_instr,
                                const TrackingInstruction &initial_track) = 0;

    virtual void post_augment_use(
                                GraphDataFlow &graph,
                                InstrGraphNodeMap &instr_graph_node_map,
                                const Function &function,
                                const OperandSSAPtr &initial_use,
                                const BaseInstructionSSAPtr &initial_instr,
                                const TrackingInstruction &initial_track) = 0;

    /*!
     * \brief Finalizes the created graph before the function obtain() is
     * terminated.
     */
    void finalize_graph();

    /*!
     * \brief Finalizes the created graph before the function obtain() is
     * terminated. This function is called after `finalize_graph()`.
     */
    virtual void finalize_graph_child(
                                   GraphDataFlow &graph,
                                   InstrGraphNodeMap &instr_graph_node_map) = 0;


    /*!
     * \brief This function is called after `augment_use()` created the
     * current data flow graph and it is merged into the final one.
     * It is used to find the next tracking instructions.
     *
     * \param `out_next_instrs` is given by reference and the next tracking
     * instructions are stored into the set.
     * \param `graph` is the current graph that is created by `augment_use()`.
     * \param `function` is the reference to the current function object.
     * \param `initial_use` is the operand we tracked back.
     * \param `initial_instr` is the instruction from which we started
     * backtracking.
     */
    virtual void get_next_tracking_instrs_child(
                                TrackingInstructionSet &out_next_instrs,
                                const GraphDataFlow &graph,
                                const Function &function,
                                const TrackingInstruction &initial_track,
                                const BaseInstructionSSAPtr &initial_instr) = 0;

    /*!
     * \brief This function checks if the graph is the edge case in which
     * it has only a call or a tailjump instruction.
     * \return Returns `true` if the graph is the edge case in which it has
     * only a calll instruction or a tailjump instruction.
     */
    bool is_call_jmp_edge_case(const GraphDataFlow &graph);

    /*!
     * \brief Returns the data flow descriptor for the given instruction if it
     * exists. Otherwise a new node is created in the graph and the
     * corresponding descriptor is returned.
     *
     * \return Data flow graph descriptor for the given instruction.
     */
    GraphDataFlow::vertex_descriptor get_maybe_new_node_graph(
                                       GraphDataFlow &graph,
                                       InstrGraphNodeMap &instr_graph_node_map,
                                       const BaseInstructionSSAPtr &instr);

    /*!
     * \brief Returns the data flow descriptor for the given edge if it
     * exists. Otherwise a new edge is created in the graph and the
     * corresponding descriptor is returned.
     *
     * \return Data flow graph descriptor for the given edge.
     */
    GraphDataFlow::edge_descriptor get_maybe_new_edge_graph(
                                 GraphDataFlow &graph,
                                 const GraphDataFlow::vertex_descriptor &src,
                                 const GraphDataFlow::vertex_descriptor &dst,
                                 const OperandSSAPtr &operand);

    /*!
     * \brief Removes the given node from the graph.
     */
    void remove_node_graph(GraphDataFlow &graph,
                           InstrGraphNodeMap &instr_graph_node_map,
                           const GraphDataFlow::vertex_descriptor &node);

    /*!
     * \brief Removes the node with the given instruction from the graph.
     */
    void remove_node_graph(GraphDataFlow &graph,
                           InstrGraphNodeMap &instr_graph_node_map,
                           const BaseInstructionSSAPtr &instr);

    void merge_graphs(const GraphDataFlow &graph);

    boost::property_map<GraphDataFlow, boost::vertex_index_t>::type
                                          create_indexmap(GraphDataFlow &graph);

public:

    /*!
     * \brief This function is called in order to start the analysis and to
     * obtain the data flow graph.
     *
     * \param `num_rounds` gives the maximum of rounds the analysis spends
     * in analyzing the data flow before terminating it. The states are stored
     * in the object and the analysis can be continued at a later time.
     * \return Returns `true` if the analyzes completed and `false` if it has
     * reached its round limit.
     */
    bool obtain(uint32_t num_rounds);

    const GraphDataFlow &get_graph() const;

    /*!
     * \brief Dumps the graph as .dot file to the given file name.
     */
    void dump_graph(const std::string &file_name);

    /*!
     * \brief Returns the location where all graphs are dumped to.
     */
    const std::string &get_graph_dump_dir();

    uint64_t get_start_addr() const;

    /*!
     * \brief Returns a reference to the indexmap of the graph
     * (is needed for example if boost graph algorithms are performed
     * on the graph). If it does not exist yet, it creates it.
     */
    const boost::property_map<GraphDataFlow,
                        boost::vertex_index_t>::type &get_graph_indexmap();

    const boost::property_map<GraphDataFlow,
                       boost::vertex_index_t>::type &get_graph_indexmap() const;

    void update_indexmap();

    const InstrGraphNodeMap &get_graph_instr_map() const;

    const std::unordered_set<uint64_t> &get_unresolvable_icalls() const;
};

#endif // BACKTRACE_ANALYSIS_H
