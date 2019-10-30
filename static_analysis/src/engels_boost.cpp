#include "engels_boost.h"

using namespace std;


NodeFound::NodeFound(char const* const message) throw()
    : std::runtime_error(message)
{
}

BfsGraphDataFlowNodesShortestPath::BfsGraphDataFlowNodesShortestPath(
                                   DataFlowNodeConnections &backward_node_connections,
                                   GraphDataFlow::vertex_descriptor src_node,
                                   GraphDataFlow::vertex_descriptor dst_node)
    : _backward_node_connections(backward_node_connections) {
    _src_node = src_node;
    _dst_node = dst_node;
}

BfsGraphDataFlowNodesShortestPath::BfsGraphDataFlowNodesShortestPath(
                                   const BfsGraphDataFlowNodesShortestPath &obj)
    : _backward_node_connections(obj.get_backward_node_connections()) {
    if(obj.get_current_node_set()) {
        _current_node = obj.get_current_node();
    }
    _src_node = obj.get_source_node();
    _dst_node = obj.get_destination_node();
}

void BfsGraphDataFlowNodesShortestPath::discover_vertex(
                                        GraphDataFlow::vertex_descriptor vertex,
                                        const GraphDataFlow &graph) {

    if(!_current_node_set) {
        return;
    }

    _backward_node_connections[vertex] = _current_node;

    if(vertex == _dst_node) {
        throw NodeFound("");
    }
}

void BfsGraphDataFlowNodesShortestPath::examine_vertex(
                                        GraphDataFlow::vertex_descriptor vertex,
                                        const GraphDataFlow &graph) {

    _current_node_set = true;
    _current_node = vertex;
}

DataFlowNodeConnections &
      BfsGraphDataFlowNodesShortestPath::get_backward_node_connections() const {
    return _backward_node_connections;
}

GraphDataFlow::vertex_descriptor
                   BfsGraphDataFlowNodesShortestPath::get_current_node() const {
    return _current_node;
}

bool BfsGraphDataFlowNodesShortestPath::get_current_node_set() const {
    return _current_node;
}

GraphDataFlow::vertex_descriptor
                   BfsGraphDataFlowNodesShortestPath::get_source_node() const {
    return _src_node;
}

GraphDataFlow::vertex_descriptor
               BfsGraphDataFlowNodesShortestPath::get_destination_node() const {
    return _dst_node;
}

BfsGraphCfgNodesShortestPath::BfsGraphCfgNodesShortestPath(
                          ControlFlowNodeConnections &backward_node_connections,
                          GraphCfg::vertex_descriptor src_node,
                          GraphCfg::vertex_descriptor dst_node)
    : _backward_node_connections(backward_node_connections) {
    _src_node = src_node;
    _dst_node = dst_node;
}

BfsGraphCfgNodesShortestPath::BfsGraphCfgNodesShortestPath(
                                        const BfsGraphCfgNodesShortestPath &obj)
    : _backward_node_connections(obj.get_backward_node_connections()) {

    if(obj.get_current_node_set()) {
        _current_node = obj.get_current_node();
    }
    _src_node = obj.get_source_node();
    _dst_node = obj.get_destination_node();
}

void BfsGraphCfgNodesShortestPath::discover_vertex(
                                        GraphCfg::vertex_descriptor vertex,
                                        const GraphCfg &graph) {

    if(!_current_node_set) {
        return;
    }

    _backward_node_connections[vertex] = _current_node;

    if(vertex == _dst_node) {
        throw NodeFound("");
    }
}

void BfsGraphCfgNodesShortestPath::examine_vertex(
                                             GraphCfg::vertex_descriptor vertex,
                                             const GraphCfg &graph) {

    _current_node_set = true;
    _current_node = vertex;
}

ControlFlowNodeConnections &
           BfsGraphCfgNodesShortestPath::get_backward_node_connections() const {
    return _backward_node_connections;
}

GraphCfg::vertex_descriptor
                        BfsGraphCfgNodesShortestPath::get_current_node() const {
    return _current_node;
}

bool BfsGraphCfgNodesShortestPath::get_current_node_set() const {
    return _current_node;
}

GraphCfg::vertex_descriptor
                         BfsGraphCfgNodesShortestPath::get_source_node() const {
    return _src_node;
}

GraphCfg::vertex_descriptor
                    BfsGraphCfgNodesShortestPath::get_destination_node() const {
    return _dst_node;
}

BlacklistNodesEdgePredicate::BlacklistNodesEdgePredicate()
    : _graph_ptr(nullptr),
    _backward_node_connections_ptr(nullptr),
    _new_operators_ptr(nullptr) {

}

BlacklistNodesEdgePredicate::BlacklistNodesEdgePredicate(
                  const GraphDataFlow& graph,
                  const unordered_set<uint64_t> &new_operators,
                  const DataFlowNodeConnections &backward_node_connections,
                  GraphCfg::vertex_descriptor src_node)
    : _graph_ptr(&graph),
    _backward_node_connections_ptr(&backward_node_connections),
    _new_operators_ptr(&new_operators) {

    _src_node = src_node;
}

bool BlacklistNodesEdgePredicate::operator()(
                             const GraphDataFlow::edge_descriptor& edge) const {

    GraphDataFlow::vertex_descriptor dst_node = boost::target(edge,
                                                              *_graph_ptr);

    // Only inspect edges that belong to return instructions.
    if((*_graph_ptr)[edge].type == DataFlowEdgeTypeRet) {

        if(_backward_node_connections_ptr->empty()) {
            return true;
        }

        // Check if the target node
        if((*_graph_ptr)[dst_node].instr->get_type() == SSAInstrTypeCallOfRet) {

            // Create a path from the source node of the bfs algorithm to
            // the source node of this edge.
            DataFlowPath path;
            GraphDataFlow::vertex_descriptor curr = boost::source(edge,
                                                                  *_graph_ptr);

            path.push_back(curr);
            while(true) {

                if(curr == _src_node) {
                    break;
                }
                curr = (*_backward_node_connections_ptr).at(curr);
                path.insert(path.begin(), curr);
            }

            // Calculate the call stack on the path.
            vector<GraphDataFlow::vertex_descriptor> call_stack;
            for(uint32_t i = 0; i < path.size(); i++) {
                curr = path.at(i);

                const BaseInstructionSSAPtr &instr = (*_graph_ptr)[curr].instr;

                if(instr->get_type() != SSAInstrTypeInstruction
                   && instr->get_type() != SSAInstrTypeCallOfRet) {
                    continue;
                }

                // Process call but ignore calls to new operators.
                if(instr->is_call()
                   && instr->get_type() != SSAInstrTypeCallOfRet
                   && (*_new_operators_ptr).find(instr->get_address())
                        == (*_new_operators_ptr).cend()) {

                    call_stack.push_back(curr);
                }

                // Process return instructions.
                else if(instr->get_type() == SSAInstrTypeCallOfRet) {
                    if(call_stack.size() > 0) {
                        call_stack.pop_back();
                    }
                }
            }

            // Only process return instruction edge if we have a call stack.
            if(call_stack.size() > 0) {
                GraphDataFlow::vertex_descriptor last_call = call_stack.back();
                if((*_graph_ptr)[dst_node].instr->get_address()
                   != (*_graph_ptr)[last_call].instr->get_address()) {

                    return false;
                }
            }
        }
    }

    return true;
}

void BlacklistNodesEdgePredicate::set_src_node(
                                    GraphDataFlow::vertex_descriptor src_node) {
    _src_node = src_node;
}

BfsGraphDataFlowFilteredNodesShortestPath::BfsGraphDataFlowFilteredNodesShortestPath(
                             DataFlowNodeConnections &backward_node_connections,
                             GraphDataFlow::vertex_descriptor src_node,
                             GraphDataFlow::vertex_descriptor dst_node)
    : BfsGraphDataFlowNodesShortestPath(backward_node_connections,
                                        src_node,
                                        dst_node) {
}

BfsGraphDataFlowFilteredNodesShortestPath::BfsGraphDataFlowFilteredNodesShortestPath(
                           const BfsGraphDataFlowFilteredNodesShortestPath &obj)
    : BfsGraphDataFlowNodesShortestPath(obj) {
}

void BfsGraphDataFlowFilteredNodesShortestPath::discover_vertex(
                                        GraphCfg::vertex_descriptor vertex,
                                        const GraphDataFlowFiltered &graph) {

    if(!_current_node_set) {
        return;
    }

    _backward_node_connections[vertex] = _current_node;

    if(vertex == _dst_node) {
        throw NodeFound("");
    }
}

void BfsGraphDataFlowFilteredNodesShortestPath::examine_vertex(
                                           GraphCfg::vertex_descriptor vertex,
                                           const GraphDataFlowFiltered &graph) {

    _current_node_set = true;
    _current_node = vertex;
}
