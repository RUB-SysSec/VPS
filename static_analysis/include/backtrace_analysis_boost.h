#ifndef BACKTRACE_ANALYSIS_BOOST_H
#define BACKTRACE_ANALYSIS_BOOST_H

#include <unordered_set>
#include <boost/graph/breadth_first_search.hpp>
#include "backtrace_analysis.h"

typedef std::unordered_set<GraphDataFlow::vertex_descriptor> DataFlowVertexSet;

class BfsGraphDataFlowNodesVisited : public boost::default_bfs_visitor {
private:
    DataFlowVertexSet &_visited_nodes;

public:

    BfsGraphDataFlowNodesVisited(DataFlowVertexSet &visited_nodes);
    BfsGraphDataFlowNodesVisited(const BfsGraphDataFlowNodesVisited &obj);

    void discover_vertex(GraphDataFlow::vertex_descriptor vertex,
                         const GraphDataFlow&);

    DataFlowVertexSet& get_visited_nodes() const;
};

/*!
 * \brief Creates an indexmap for the given graph.
 * Since "VertexList=listS" does not have an internal vertex_index
 * property, we have to create one manually
 * for the boost algorithms to work correctly.
 * \return Returns a boost index map for the given graph.
 */
boost::property_map<GraphDataFlow, boost::vertex_index_t>::type
                                          create_indexmap(GraphDataFlow &graph);

#endif // BACKTRACE_ANALYSIS_BOOST_H
