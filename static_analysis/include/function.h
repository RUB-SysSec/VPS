#ifndef FUNCTION_H
#define FUNCTION_H

#include "block.h"
#include "expression.h"
#include "block_semantics.h"
#include "ssa_export.pb.h"
#include "ssa_block.h"

#include <map>
#include <set>
#include <vector>
#include <cstddef>
#include <functional>
#include <iostream>

extern "C" {
#include <valgrind/libvex.h>
}

#include <boost/graph/directed_graph.hpp>
#include <boost/graph/graphviz.hpp>

/*!
 * \brief A path describing how we reached a basic block in the function.
 *
 * A path is merely a vector of `bool`s. Each entry denotes how control flow
 * changed at each terminator/basic block, starting at the beginning of the
 * traversal (most commonly the function's entry point). Following a
 * fall-through or an unconditional jumps is recorded using `true`, whereas
 * the target of a conditional jump is recorded as `false`.
 */
typedef std::vector<bool> Path;

typedef std::shared_ptr<BlockSSA> BlockSSAPtr;
typedef std::shared_ptr<Block> BlockPtr;
typedef std::vector<BlockPtr> BlockVector;
typedef std::map<uintptr_t, BlockPtr> BlockMap;
typedef std::map<uintptr_t, BlockSSAPtr> BlockSSAMap;
typedef boost::directed_graph<BlockPtr> GraphCfg;

template <class T>
class SimpleCfgNodeWriter {
public:
    SimpleCfgNodeWriter(const T &graph) : _graph(graph) {}
    template <class VertexOrEdge>
    void operator()(std::ostream& out, const VertexOrEdge& v) const {
        out << "["
            << "fontname=\"Ubuntu Mono\", "
            << "shape=rect, "
            << "label=\"" << std::hex << _graph[v]->get_address() << "\""
            << "]";
    }
private:
    const T &_graph;
};

// Used to return references on empty sets.
static const BaseInstructionSSAPtrSet EMPTY_INSTRUCTION_SSA_PTR_SET =
                                                     BaseInstructionSSAPtrSet();

/*!
 * \brief The hash and compare function uses the object the pointer points to.
 * This means that if the object changes a value, the operation will generate
 * different hash values and will make problems with maps/sets. However,
 * OperandSSA objects are meant to be immutable and therefore do not offer
 * an interface to change values.
 */
typedef std::unordered_map<OperandSSAPtr,
                           BaseInstructionSSAPtrSet,
                           SSAPtrDeref::Hash,
                           SSAPtrDeref::Compare> DefUseSSAMap;

/*!
 * \brief A function called on each visited basic block in a traversal.
 *
 * \see `Function::traverse`
 */
typedef std::function<bool (void*, const Path&, const Block&)>
    TraversalCallback;

/*!
 * \brief A function called after a path has been fully traversed.
 *
 * \see `Function::traverse`
 */
typedef std::function<void (void*, const Path&)> PathCallback;

const uint8_t BRANCH_THRESHOLD = 0;

/*!
 * \brief Class representing a function translated to VEX.
 *
 * Objects of this class are to be instantiated by the `Translator` class (hence
 * the `friend` relationship).
 */
class Function {
private:
    uintptr_t _entry;
    uint8_t _branch_threshold = BRANCH_THRESHOLD;
    BlockMap _function_blocks;
    BlockVector _blocks_ret;
    BlockVector _blocks_tail_jmp;
    BlockSSAMap _function_blocks_ssa;
    std::set<uint64_t> _xrefs;
    std::set<uint64_t> _vfunc_xrefs;
    DefUseSSAMap _definitions;
    DefUseSSAMap _uses;
    std::set<uint64_t> _addresses;

    GraphCfg _cfg;
    boost::property_map<GraphCfg, boost::vertex_index_t>::type _indexmap;
    std::map<uint32_t, GraphCfg::vertex_descriptor> _addr_graph_node_map;

public:
    Function() = default;
    Function(uintptr_t entry, uint8_t branch_threshold=BRANCH_THRESHOLD);

    /*!
     * \brief Returns the function's entry address.
     * \return Returns the first virtual address in the function.
     */
    uintptr_t get_entry() const {
        return _entry;
    }

    bool can_be_fully_traversed() const;

    // FIXME: Cache this.
    /*!
     * \brief Returns the addresses of all known blocks.
     * \return Returns a vector of addresses.
     */
    std::vector<uintptr_t> get_block_addresses() const {
        std::vector<uintptr_t> result;
        for(const auto &kv : _function_blocks) {
            result.push_back(kv.first);
        }

        return result;
    }

    // FIXME: Cache this.
    /*!
     * \brief Returns the addresses of block's returning from the function
     * (i.e., those with a terminator of type `TerminatorReturn`).
     * \return Returns a vector of addresses.
     */
    std::vector<uintptr_t> get_return_block_addresses() const {
        std::vector<uintptr_t> result;
        for(const auto &kv : _function_blocks) {
            if(kv.second->get_terminator().type == TerminatorReturn) {
                result.push_back(kv.first);
            }
        }

        return result;
    }

    /*!
     * \brief Returns all blocks.
     * \return Returns a map containing all blocks of the function (key is the
     * block's address).
     */
    const BlockMap &get_blocks() const {
        return _function_blocks;
    }

    /*!
     * \brief Returns all SSA blocks.
     * \return Returns a map containing all SSA blocks of the function
     * (key is the block's address).
     */
    const BlockSSAMap &get_blocks_ssa() const {
        return _function_blocks_ssa;
    }

    /*!
     * \brief Returns if the function contains the given address.
     * \return Returns `true` if the function contains the given address.
     */
    bool contains_address(uint64_t addr) const;

    bool traverse(const TraversalCallback &block_callback,
                  const BlockPredicate &block_predicate,
                  const PathCallback &path_callback,
                  void *user_defined=nullptr) const;

    /*!
     * \brief Returns the block that contains the given address.
     *
     * \return A reference of type `Block` (throws runtime_error
     * exception if block does not exist).
     */
    const Block &get_containing_block(uint64_t addr) const;

    /*!
     * \brief Returns the block that contains the given address.
     *
     * \return A reference of type `BlockPtr` (throws runtime_error
     * exception if block does not exist).
     */
    const BlockPtr &get_containing_block_ptr(uint64_t addr) const;

    /*!
     * \brief Returns the blocks that terminate with a return.
     *
     * \return A reference to a vector of `BlockPtr`.
     */
    const BlockVector &get_ret_blocks() const;

    /*!
     * \brief Returns the blocks that terminate with a tail jump.
     *
     * \return A reference to a vector of `BlockPtr`.
     */
    const BlockVector &get_tail_jmp_blocks() const;

    /*!
     * \brief Returns the SSA block that contains the given address.
     *
     * \return A reference of type `BlockSSA` (throws runtime_error
     * exception if block does not exist).
     */
    const BlockSSAPtr &get_containing_block_ssa(uint64_t addr) const;

    /*!
     * \brief Returns the graph that contains the cfg.
     *
     * \return A reference of type `GraphCfg`.
     */
    const GraphCfg &get_cfg() const;

    /*!
     * \brief Returns the indexmap for the cfg.
     *
     * \return A reference to the indexmap of the cfg.
     */
    const boost::property_map<GraphCfg, boost::vertex_index_t>::type &
                                                       get_cfg_indexmap() const;

    /*!
     * \brief Returns the node for the cfg corresponding to the given address.
     * Throws an exception if node does not exist.
     *
     * \return A node descriptor for the cfg.
     */
    GraphCfg::vertex_descriptor get_cfg_node(uint64_t addr) const;

    /*!
     * \brief Dumps the cfg as dot file to the given file name.
     */
    void dump_cfg(const std::string &file_name) const;

    /*!
     * \brief Returns SSA instruction pointer given by the address.
     * \return Returns a set of SSA instruction pointer of the
     * function. Since for example multiple phi nodes can have the same address,
     * this function can return multiple instruction pointers.
     */
    const BaseInstructionSSAPtrSet get_instruction_ssa(
                                                 uint64_t addr,
                                                 InstructionTypeSSA type) const;

    /*!
     * \brief Returns SSA operand definitions.
     * \return Returns a reference to the SSA operand definitions
     * of the function.
     */
    const DefUseSSAMap &get_definitions_ssa() const;

    /*!
     * \brief Returns SSA operand uses.
     * \return Returns a reference to the SSA operand uses
     * of the function.
     */
    const DefUseSSAMap &get_uses_ssa() const;

    /*!
     * \brief Returns SSA instructions that define the given operand.
     * \return Returns a reference to the SSA instructions that define
     * the given operand.
     */
    const BaseInstructionSSAPtrSet &get_instrs_define_op_ssa(
                                                 const OperandSSAPtr &op) const;

    /*!
     * \brief Returns SSA instructions that use the given operand.
     * \return Returns a reference to the SSA instructions that use
     * the given operand.
     */
    const BaseInstructionSSAPtrSet &get_instrs_use_op_ssa(
                                                 const OperandSSAPtr &op) const;

    /*!
     * \brief Returns xref addresses that point to the function.
     * \return Returns a reference to xref set that contains the addresses.
     */
    const std::set<uint64_t> &get_xrefs() const;

    /*!
     * \brief Returns xref addresses that point to this as a virtual function.
     * \return Returns a reference to xref set that contains the addresses.
     */
    const std::set<uint64_t> &get_vfunc_xrefs() const;

    void finalize();

private:
    bool traverser(const TraversalCallback &callback,
                   void *user_defined=nullptr) const;

    void add_block(uintptr_t address, IRSB *block,
                   const Terminator &terminator);

    void add_block_ssa(const ssa::BasicBlock &basic_block);

    void add_xref(uint64_t xref_addr);

    void add_vfunc_xref(uint64_t xref_addr);

    /*!
     * \brief Returns the cfg descriptor for the given block if it exists.
     * Otherwise a new node is created in the cfg and the corresponding
     * descriptor is returned (needed for build_cfg()).
     *
     * \return Cfg descriptor for the given block.
     */
    GraphCfg::vertex_descriptor get_maybe_new_node_cfg(
                                           const std::shared_ptr<Block> &block);

    void build_cfg();

    friend class Translator;
    friend class ModuleSSA;
    friend class ModuleFunctionXrefs;
};

#endif // FUNCTION_H
