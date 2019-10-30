
#include "function.h"
#include "path_builder.h"

#include <map>
#include <set>
#include <deque>
#include <sstream>
#include <cstddef>
#include <cassert>
#include <iterator>
#include <algorithm>

using namespace std;

typedef set<uintptr_t> SeenBlocks;
typedef map<Path, SeenBlocks> PathBlocks;

/*!
 * \brief Creates a new instance of the class, explicitly setting its entry
 * address.
 * \param entry The (virtual) address where the function starts originally.
 * \param branch_threshold The number of branches inside a function that
 * trigger a switch to a more lightweight traversal method. Defaults to at
 * least 15.
 */
Function::Function(uintptr_t entry, uint8_t branch_threshold)
    : _entry(entry), _branch_threshold(branch_threshold) {
}

/*!
 * \brief Initial policy that checks feasibility of traversing all paths.
 *
 * This (initial) policy simply counts the number of indirect branches which
 * give a rough estimate of the number of paths through the function.
 *
 * \return `true`, if the function contains fewer than 15 branches; `false`
 * otherwise.
 */
bool Function::can_be_fully_traversed() const {
    auto branches = 0;
    for(const auto &kv : _function_blocks) {
        if(kv.second->get_terminator().type == TerminatorJcc) {
            branches++;
        }
    }

    return branches < _branch_threshold;
}

bool Function::contains_address(uint64_t addr) const {
    if(_addresses.find(addr) != _addresses.cend()) {
        return true;
    }
    return false;
}

const Block &Function::get_containing_block(uint64_t addr) const {
    for(const auto &kv : _function_blocks) {
        if(kv.second->contains_address(addr)) {
            return *kv.second;
        }
    }
    stringstream err_msg;
    err_msg << "Block with address "
            << hex << addr
            << " does not exist.";
    throw runtime_error(err_msg.str().c_str());
}

const BlockPtr &Function::get_containing_block_ptr(uint64_t addr) const {
    for(const auto &kv : _function_blocks) {
        if(kv.second->contains_address(addr)) {
            return kv.second;
        }
    }
    stringstream err_msg;
    err_msg << "Block with address "
            << hex << addr
            << " does not exist.";
    throw runtime_error(err_msg.str().c_str());
}

const BlockSSAPtr &Function::get_containing_block_ssa(uint64_t addr) const {
    for(const auto &kv : _function_blocks_ssa) {
        if(kv.second->contains_address(addr)) {
            return kv.second;
        }
    }
    stringstream err_msg;
    err_msg << "Block with address "
            << hex << addr
            << " does not exist.";
    throw runtime_error(err_msg.str().c_str());
}

/*!
 * \brief Traverses all paths through the function.
 *
 * Traverses all possible paths through the function and calls the supplied
 * callback on each encountered basic block. If it is infeasible to traverse
 * all possible paths (as determined by `can_be_fully_traversed`), logic
 * switches to a lightweight path generation algorithm. For this to work
 * properly, `block_predicate` has to be set.
 *
 * The traversal callback is passed several parameters:
 *
 * 1. a user-defined parameter (which can be used, e.g., to pass an additional
 * structure with data associated with the traversal, like a this pointer),
 * 2. the path describing the position of the currently visited basic block,
 * 3. the currently visited basic block itself, a `Block` reference.
 *
 * \param callback The function that is to be called on each basic block visit.
 * \param block_predicate A callback which decides whether a basic block is
 * deemed "interesting" for the current analysis and should be visited during
 * the traversal.
 * \param user_defined A user-defined parameter that is passed to the callback.
 * \return Always `true`.
 *
 * \todo Decide if the return type still makes sense in the current setup.
 */
bool Function::traverse(const TraversalCallback &block_callback,
                        const BlockPredicate &block_predicate,
                        const PathCallback &path_callback,
                        void *user_defined)
    const {
    if(can_be_fully_traversed()) {
        throw runtime_error("Path callbacks are not yet implemented for full"
                            " traversals.");
        return traverser(block_callback, user_defined);
    }

    if(!block_predicate) {
        throw runtime_error("Cannot switch to lightweight policy without a "
                            "valid block predicate.");
    }

    PathBuilder builder(*this, user_defined);
    const auto paths = builder.build_paths(block_predicate);

    // FIXME: This duplicates code from below.
    for(const auto &path : paths) {

        Path current_path;
        const Terminator *previous_terminator = nullptr;

        for(const auto &block : path) {
            const auto &needle = _function_blocks.find(block);
            if(needle == _function_blocks.cend()) {
                break;
            }

            if(previous_terminator) {
                bool annotation = false;

                const auto &terminator = *previous_terminator;
                switch(terminator.type) {
                case TerminatorJump:
                    annotation = true;
                    break;

                case TerminatorJcc: {
                    const auto current = needle->second->get_address();
                    if(terminator.target == current) {
                        annotation = false;
                        break;
                    }

                    assert(terminator.fall_through == current &&
                           "Cannot reconstruct annotation.");
                    annotation = true;
                }

                case TerminatorFallthrough:
                case TerminatorCallUnresolved:
                case TerminatorCall:
                    annotation = true;
                    break;

                default:
                    throw runtime_error("Lightweight policy: This should not"
                                        " happen.");
                    break;
                }

                current_path.push_back(annotation);
            }

            previous_terminator = &needle->second->get_terminator();
            if(!block_callback(user_defined, current_path, *needle->second)) {
                /* The callback has decided not to follow this path any
                 * further. */
                break;
            }
        }

        if(path_callback) {
            path_callback(user_defined, current_path);
        }
    }

    return true;
}

bool Function::traverser(const TraversalCallback &callback,
                         void *user_defined) const {

    deque<pair<uintptr_t, Path>> work_list;

    PathBlocks path_seen_blocks;
    work_list.push_back(make_pair(_entry, Path()));

    while(!work_list.empty()) {
        const auto pair = work_list.back();
        work_list.pop_back();

        uintptr_t current_address = pair.first;
        const Path &path = pair.second;

        SeenBlocks &seen_blocks = path_seen_blocks[path];
        if(seen_blocks.find(current_address) != seen_blocks.cend()) {
            continue;
        }

        const auto &needle = _function_blocks.find(current_address);
        if(needle == _function_blocks.cend()) {
            /* We cannot find a block with the given address that lies within
             * the current function. This is most likely the case due to the
             * invocation of a non-returning call. We must not follow these
             * anyway. */
            continue;
        }

        seen_blocks.insert(current_address);
        if(!callback(user_defined, path, *needle->second)) {
            /* The callback has decided not to follow this path any further. */
            continue;
        }

        // The current path may be extended by a true or false annotation.
        Path path_false = path, path_true = path;

        path_false.push_back(false);
        path_true.push_back(true);

        const Terminator &terminator = needle->second->get_terminator();

        switch(terminator.type) {
        case TerminatorJump:
            work_list.push_back(make_pair(terminator.target, path_true));
            path_seen_blocks[path_true] = seen_blocks;
            break;

        case TerminatorJcc:
            work_list.push_back(make_pair(terminator.target, path_false));
            path_seen_blocks[path_false] = seen_blocks;

        case TerminatorFallthrough:
        case TerminatorCallUnresolved:
        case TerminatorCall:
            work_list.push_back(make_pair(terminator.fall_through, path_true));
            path_seen_blocks[path_true] = seen_blocks;
            break;

        default:
            break;
        }
    }

    return true;
}

void Function::add_block(uintptr_t address, IRSB *block,
                         const Terminator &terminator) {
    _function_blocks[address] = make_shared<Block>(address, block, terminator);
}

void Function::add_block_ssa(const ssa::BasicBlock &basic_block) {
    const shared_ptr<BlockSSA> &bb_ssa = make_shared<BlockSSA>(basic_block);
    _function_blocks_ssa[basic_block.address()] = bb_ssa;

    // Build definitions/uses.
    for(const BaseInstructionSSAPtr &instr: bb_ssa->get_instructions()) {

        for(const OperandSSAPtr &op : instr->get_definitions()) {

            _definitions[op].insert(instr);
            // Add the base of the memory object also as use.
            if(op->is_memory()) {
                switch(op->get_type()) {
                    case SSAOpTypeMemoryX64: {
                        const RegisterX64SSA &temp =
                              static_cast<const MemoryX64SSA &>(*op).get_base();
                        _uses[make_shared<RegisterX64SSA>(temp)].insert(instr);
                        break;
                    }
                    default:
                        throw runtime_error("Unknown SSA memory object.");
                }
            }
        }

        for(const OperandSSAPtr &op : instr->get_uses()) {

            _uses[op].insert(instr);
            if(op->is_memory()) {
                switch(op->get_type()) {
                    case SSAOpTypeMemoryX64: {
                        const RegisterX64SSA &temp =
                              static_cast<const MemoryX64SSA &>(*op).get_base();
                        _uses[make_shared<RegisterX64SSA>(temp)].insert(instr);
                        break;
                    }
                    default:
                        throw runtime_error("Unknown SSA memory object.");
                }
            }
        }
    }
}

void Function::add_xref(uint64_t xref_addr) {
    _xrefs.insert(xref_addr);
}

void Function::add_vfunc_xref(uint64_t xref_addr) {
    _vfunc_xrefs.insert(xref_addr);

    // Virtual callsites are also handled like a normal xref.
    add_xref(xref_addr);
}

const std::set<uint64_t> &Function::get_xrefs() const {
    return _xrefs;
}

const std::set<uint64_t> &Function::get_vfunc_xrefs() const {
    return _vfunc_xrefs;
}

GraphCfg::vertex_descriptor Function::get_maybe_new_node_cfg(
                                               const shared_ptr<Block> &block) {

    // Check if block already exists in cfg => return this one.
    const auto vertices = boost::vertices(_cfg);
    for(auto it = vertices.first; it != vertices.second; ++it) {
        if(_cfg[*it] == block) {
            return *it;
        }
    }
    // Create new cfg node.
    GraphCfg::vertex_descriptor new_vertex = boost::add_vertex(_cfg);
    _cfg[new_vertex] = block;
    return new_vertex;
}

void Function::build_cfg() {
    for(const auto &kv : _function_blocks) {

        const shared_ptr<Block> current_block = kv.second;
        GraphCfg::vertex_descriptor current_node =
                                          get_maybe_new_node_cfg(current_block);

        const Terminator &terminator = current_block->get_terminator();
        switch(terminator.type) {
        case TerminatorJump:
            // If jump is not a tail jump and can be found in the basic blocks
            // add an edge between both.
            if(!terminator.is_tail) {
                for(const auto &sub_kv : _function_blocks) {
                    if(sub_kv.second->get_address() == terminator.target) {
                        GraphCfg::vertex_descriptor next_node =
                                          get_maybe_new_node_cfg(sub_kv.second);
                        boost::add_edge(current_node, next_node, _cfg);
                        break;
                    }
                }
            }
            break;

        case TerminatorJcc:
            // Add edge to target basic block.
            for(const auto &sub_kv : _function_blocks) {
                if(sub_kv.second->get_address() == terminator.target) {
                    GraphCfg::vertex_descriptor next_node =
                                          get_maybe_new_node_cfg(sub_kv.second);
                    boost::add_edge(current_node, next_node, _cfg);
                    break;
                }
            }

        case TerminatorFallthrough:
        case TerminatorCallUnresolved:
        case TerminatorCall:
            // Add edge to fall through basic block.
            for(const auto &sub_kv : _function_blocks) {
                if(sub_kv.second->get_address() == terminator.fall_through) {
                    GraphCfg::vertex_descriptor next_node =
                                          get_maybe_new_node_cfg(sub_kv.second);
                    boost::add_edge(current_node, next_node, _cfg);
                    break;
                }
            }
            break;

        default:
            break;
        }
    }

    // Since "VertexList=listS" does not have an internal vertex_index
    // property, we have to create one manually
    // for the boost algorithms to work.
    // http://www.boost.org/doc/libs/1_50_0/libs/graph/doc/breadth_first_search.html
    // http://www.boost.org/doc/libs/1_64_0/libs/graph/example/dijkstra-example-listS.cpp
    // Also generate address node mapping.
    auto vertices = boost::vertices(_cfg);
    _indexmap = boost::get(boost::vertex_index, _cfg);
    int index = 0;
    for(auto it = vertices.first; it != vertices.second; ++it) {
        _indexmap[*it] = index;
        index++;

        _addr_graph_node_map[_cfg[*it]->get_address()] = *it;
    }
}

const GraphCfg &Function::get_cfg() const {
    return _cfg;
}

const boost::property_map<GraphCfg, boost::vertex_index_t>::type &
                                            Function::get_cfg_indexmap() const {
    return _indexmap;
}

GraphCfg::vertex_descriptor Function::get_cfg_node(uint64_t addr) const {
    try {
        return _addr_graph_node_map.at(addr);
    }
    catch(...) {
        stringstream dump_dir;
        dump_dir << "/tmp/engels_cfg_"
                 << setfill('0') << setw(8) << hex << _entry
                 << ".dot";
        dump_cfg(dump_dir.str());

        stringstream err_msg;
        err_msg << "Node with address "
                << hex << addr
                << " does not exist in cfg. Dumping cfg to '"
                << dump_dir.str()
                << "'.";
        throw runtime_error(err_msg.str().c_str());
    }
}

void Function::dump_cfg(const string &file_name) const {
    ofstream dump_file;
    dump_file.open(file_name.c_str());
    SimpleCfgNodeWriter<GraphCfg> node_writer(_cfg);
    boost::write_graphviz(dump_file, _cfg, node_writer);
    dump_file.close();
}

const BaseInstructionSSAPtrSet Function::get_instruction_ssa(
                                                uint64_t addr,
                                                InstructionTypeSSA type) const {
    for(const auto &kv : _function_blocks_ssa) {
        if(kv.second->contains_address(addr)) {
            return kv.second->get_instruction(addr, type);
        }
    }
    BaseInstructionSSAPtrSet result;
    return result;
}

const DefUseSSAMap &Function::get_definitions_ssa() const {
    return _definitions;
}

const DefUseSSAMap &Function::get_uses_ssa() const {
    return _uses;
}

const BaseInstructionSSAPtrSet &Function::get_instrs_define_op_ssa(
                                                const OperandSSAPtr &op) const {
    if(_definitions.find(op) != _definitions.cend()) {
        return _definitions.at(op);
    }
    return EMPTY_INSTRUCTION_SSA_PTR_SET;
}

const BaseInstructionSSAPtrSet &Function::get_instrs_use_op_ssa(
                                                const OperandSSAPtr &op) const {
    if(_uses.find(op) != _uses.cend()) {
        return _uses.at(op);
    }
    return EMPTY_INSTRUCTION_SSA_PTR_SET;
}

void Function::finalize() {
    build_cfg();

    // Copy all addresses that are hold by this function.
    for(const auto &kv : _function_blocks) {
        const set<uint64_t> &block_addresses = kv.second->get_addresses();
        _addresses.insert(block_addresses.begin(), block_addresses.end());
    }

    // Store all return and tail jump basic blocks.
    for(const auto &kv : _function_blocks) {
        if(kv.second->get_terminator().type == TerminatorReturn) {
            _blocks_ret.push_back(kv.second);
        }
        else if(kv.second->get_terminator().type == TerminatorJump) {
            uint64_t target_addr = kv.second->get_terminator().target;
            if(_addresses.find(target_addr) == _addresses.end()) {
                _blocks_tail_jmp.push_back(kv.second);
            }
        }
    }
}

const BlockVector &Function::get_ret_blocks() const {
    return _blocks_ret;
}

const BlockVector &Function::get_tail_jmp_blocks() const {
    return _blocks_tail_jmp;
}
