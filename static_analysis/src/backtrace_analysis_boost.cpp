#include "backtrace_analysis_boost.h"

using namespace std;


BfsGraphDataFlowNodesVisited::BfsGraphDataFlowNodesVisited(
                                               DataFlowVertexSet &visited_nodes)
    : _visited_nodes(visited_nodes) {
}

BfsGraphDataFlowNodesVisited::BfsGraphDataFlowNodesVisited(
                                        const BfsGraphDataFlowNodesVisited &obj)
    : _visited_nodes(obj.get_visited_nodes()) {
}

void BfsGraphDataFlowNodesVisited::discover_vertex(
                                        GraphDataFlow::vertex_descriptor vertex,
                                        const GraphDataFlow&) {
    _visited_nodes.insert(vertex);
}

DataFlowVertexSet& BfsGraphDataFlowNodesVisited::get_visited_nodes() const {
    return _visited_nodes;
}

boost::property_map<GraphDataFlow, boost::vertex_index_t>::type
                                         create_indexmap(GraphDataFlow &graph) {
    // Since "VertexList=listS" does not have an internal vertex_index
    // property, we have to create one manually
    // for the boost algorithms to work.
    // http://www.boost.org/doc/libs/1_50_0/libs/graph/doc/breadth_first_search.html
    // http://www.boost.org/doc/libs/1_64_0/libs/graph/example/dijkstra-example-listS.cpp
    auto vertices = boost::vertices(graph);
    boost::property_map<GraphDataFlow, boost::vertex_index_t>::type indexmap =
                                         boost::get(boost::vertex_index, graph);
    int index = 0;
    for(auto it = vertices.first; it != vertices.second; ++it) {
        indexmap[*it] = index;
        index++;
    }

    return indexmap;
}
