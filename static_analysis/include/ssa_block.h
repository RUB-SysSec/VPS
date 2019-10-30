#ifndef SSA_BLOCK_H
#define SSA_BLOCK_H

#include "ssa_export.pb.h"
#include "ssa_instruction.h"
#include <unordered_set>
#include <sstream>

#define ID_ENTRY_BLOCK_SSA 0xffffffff
#define ID_EXIT_BLOCK_SSA 0xfffffffe

typedef std::vector<BaseInstructionSSAPtr> BaseInstructionSSAPtrs;

/*!
 * \brief The hash and compare function uses the object the pointer points to.
 * This means that if the object changes a value, the operation will generate
 * different hash values and will make problems with maps/sets. However,
 * BaseInstructionSSAPtrSet objects are meant to be immutable and
 * therefore do not offer an interface to change values.
 */
typedef std::unordered_set<BaseInstructionSSAPtr,
                           SSAPtrDeref::Hash,
                           SSAPtrDeref::Compare> BaseInstructionSSAPtrSet;

class BlockSSA {

private:
    uint64_t _address;
    uint64_t _last_address;
    BaseInstructionSSAPtrs _instructions;
    std::unordered_set<uint64_t> _predecessors;
    std::unordered_set<uint64_t> _successors;
    OperandsSSAset _definitions;
    OperandsSSAset _uses;

public:

    BlockSSA(const ssa::BasicBlock &basic_block);

    /*!
     * \brief get_address
     * \return Returns the block's virtual address.
     */
    uint64_t get_address() const;

    /*!
     * \brief get_last_address
     * \return Returns the block's last virtual address.
     */
    uint64_t get_last_address() const;

    /*!
     * \brief get_instructions
     * \return Returns the block's SSA instructions (key is the
     * instruction's address).
     */
    const BaseInstructionSSAPtrs &get_instructions() const;

    /*!
     * \brief get_instruction
     * \return Returns a set of the block's SSA instruction pointers.
     * Since for example phi nodes can have the same address, multiple
     * instructions can be returned.
     */
    const BaseInstructionSSAPtrSet get_instruction(
                                                 uint64_t addr,
                                                 InstructionTypeSSA type) const;

    /*!
     * \brief Returns if the block contains the given address.
     * \return Returns `true` if the block contains the given address.
     */
    bool contains_address(uint64_t addr) const;

    /*!
     * \brief Returns the block's operand definitions.
     * \return Returns a reference to an unordered set of OperandSSAPtr
     * of the block's operand definitions.
     */
    const OperandsSSAset &get_definitions() const;

    /*!
     * \brief Returns the block's operand uses.
     * \return Returns a reference to an unordered set of OperandSSAPtr
     * of the block's operand uses.
     */
    const OperandsSSAset &get_uses() const;

    /*!
     * \brief Returns the block's predecessor blocks.
     * \return Returns a reference to an unordered set of block addresses.
     */
    const std::unordered_set<uint64_t> &get_predecessors() const;

    /*!
     * \brief Returns the block's successor blocks.
     * \return Returns a reference to an unordered set of block addresses.
     */
    const std::unordered_set<uint64_t> &get_successors() const;

};


#endif // SSA_BLOCK_H
