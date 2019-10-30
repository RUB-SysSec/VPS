#ifndef ENGELS_BOOST_H
#define ENGELS_BOOST_H

#include <unordered_map>
#include <vector>
#include <boost/graph/breadth_first_search.hpp>
#include "backtrace_analysis_boost.h"
#include <boost/graph/filtered_graph.hpp>


typedef std::unordered_map<GraphDataFlow::vertex_descriptor,
                           GraphDataFlow::vertex_descriptor>
                                                        DataFlowNodeConnections;

typedef std::unordered_map<GraphDataFlow::vertex_descriptor,
                           GraphDataFlow::vertex_descriptor>
                                                     ControlFlowNodeConnections;

typedef std::vector<GraphDataFlow::vertex_descriptor> DataFlowPath;
typedef std::vector<GraphCfg::vertex_descriptor> ControlFlowPath;

class NodeFound : public std::runtime_error
{
public:
    NodeFound(char const* const message) throw();
};

class BlacklistNodesEdgePredicate {
private:
    const GraphDataFlow *_graph_ptr;
    const DataFlowNodeConnections *_backward_node_connections_ptr;
    const std::unordered_set<uint64_t> *_new_operators_ptr;
    GraphCfg::vertex_descriptor _src_node;

public:

    BlacklistNodesEdgePredicate();

    BlacklistNodesEdgePredicate(
                      const GraphDataFlow& graph,
                      const std::unordered_set<uint64_t> &new_operators,
                      const DataFlowNodeConnections &backward_node_connections,
                      GraphCfg::vertex_descriptor src_node);

    bool operator()(const GraphDataFlow::edge_descriptor& edge) const;

    void set_src_node(GraphDataFlow::vertex_descriptor src_node);
};

typedef boost::filtered_graph<GraphDataFlow,
                              BlacklistNodesEdgePredicate>
                                                          GraphDataFlowFiltered;

class BfsGraphDataFlowNodesShortestPath : public boost::default_bfs_visitor {
protected:
    GraphDataFlow::vertex_descriptor _current_node;
    bool _current_node_set = false;
    GraphDataFlow::vertex_descriptor _src_node;
    GraphDataFlow::vertex_descriptor _dst_node;
    DataFlowNodeConnections &_backward_node_connections;

public:

    BfsGraphDataFlowNodesShortestPath(
                             DataFlowNodeConnections &backward_node_connections,
                             GraphDataFlow::vertex_descriptor src_node,
                             GraphDataFlow::vertex_descriptor dst_node);
    BfsGraphDataFlowNodesShortestPath(
                                  const BfsGraphDataFlowNodesShortestPath &obj);

    void discover_vertex(GraphDataFlow::vertex_descriptor vertex,
                         const GraphDataFlow&);

    void examine_vertex(GraphDataFlow::vertex_descriptor vertex,
                           const GraphDataFlow&);

    DataFlowNodeConnections &get_backward_node_connections() const;

    GraphDataFlow::vertex_descriptor get_current_node() const;

    bool get_current_node_set() const;

    GraphDataFlow::vertex_descriptor get_source_node() const;

    GraphDataFlow::vertex_descriptor get_destination_node() const;

};

class BfsGraphDataFlowFilteredNodesShortestPath
        : public BfsGraphDataFlowNodesShortestPath {

public:

    BfsGraphDataFlowFilteredNodesShortestPath(
                             DataFlowNodeConnections &backward_node_connections,
                             GraphDataFlow::vertex_descriptor src_node,
                             GraphDataFlow::vertex_descriptor dst_node);
    BfsGraphDataFlowFilteredNodesShortestPath(
                          const BfsGraphDataFlowFilteredNodesShortestPath &obj);

    void discover_vertex(GraphDataFlow::vertex_descriptor vertex,
                         const GraphDataFlowFiltered&);

    void examine_vertex(GraphDataFlow::vertex_descriptor vertex,
                           const GraphDataFlowFiltered&);

};

class BfsGraphCfgNodesShortestPath : public boost::default_bfs_visitor {
private:
    GraphCfg::vertex_descriptor _current_node;
    bool _current_node_set = false;
    GraphCfg::vertex_descriptor _src_node;
    GraphCfg::vertex_descriptor _dst_node;
    ControlFlowNodeConnections &_backward_node_connections;

public:

    BfsGraphCfgNodesShortestPath(
                          ControlFlowNodeConnections &backward_node_connections,
                          GraphCfg::vertex_descriptor src_node,
                          GraphCfg::vertex_descriptor dst_node);
    BfsGraphCfgNodesShortestPath(const BfsGraphCfgNodesShortestPath &obj);

    void discover_vertex(GraphCfg::vertex_descriptor vertex,
                         const GraphCfg&);

    void examine_vertex(GraphCfg::vertex_descriptor vertex,
                           const GraphCfg&);

    ControlFlowNodeConnections &get_backward_node_connections() const;

    GraphCfg::vertex_descriptor get_current_node() const;

    bool get_current_node_set() const;

    GraphCfg::vertex_descriptor get_source_node() const;

    GraphCfg::vertex_descriptor get_destination_node() const;

};

#endif // ENGELS_BOOST_H
