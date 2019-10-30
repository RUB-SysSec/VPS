#ifndef BLOCK_H
#define BLOCK_H

#include <cstdint>
#include <functional>

#include "state.h"

extern "C" {
#include <valgrind/libvex.h>
}

class Block;

std::ostream &operator<<(std::ostream &stream, const Block &block);

/*!
 * \brief Enumerates all possible types of instructions terminating a basic
 * block (so called _terminators_).
 *
 * A terminator is _unresolved_ if its target cannot be determined statically.
 */
enum TerminatorType {
    //! Terminator is an instruction whose target could not be resolved
    //! (currently only set for unresolvable conditional or unconditional
    //! jumps).
    TerminatorUnresolved = 0,

    //! The next instruction is reached using a fall-through edge.
    TerminatorFallthrough,

     //! Terminator is a `ret` instruction.
    TerminatorReturn,

     //! Terminator is a `jmp` instruction.
    TerminatorJump,

     //! Terminator is a `call` instruction.
    TerminatorCall,

    //! Terminator is a `call` but its target cannot be resolved statically.
    //! Used separately to distinguish from unresolved jumps.
    TerminatorCallUnresolved,

     //! Terminator is a resolved conditional jump.
    TerminatorJcc,

    //! Terminator points to a non-returning target (such as `exit`).
    TerminatorNoReturn,
};

/*!
 * \brief Structure to describe a terminating instruction.
 */
struct Terminator {
    //! Type of the terminator. \see `TerminatorType`
    TerminatorType type;

    //! Fall-through address of the terminator. This value is set for calls,
    //! conditional jumps and fall-throughs. `nullptr`, if not set.
    uintptr_t fall_through;

    //! Target address of the terminator. Set for resolved jumps and calls,
    //! else `nullptr`.
    uintptr_t target;

    //! Boolean value indicating whether the given (resolvable) jump is a tail
    //! jump inlining another function. `false` for any other type.
    //! \see `Translator::detect_tail_jumps`
    bool is_tail;
};

/*!
 * \brief Class tieing together the underlying VEX block and additional
 * information such as block address and terminator.
 */
class Block {
private:
    uintptr_t _address;
    IRSB *_vex_block;
    Terminator _terminator;
    std::set<uint64_t> _addresses;
    uint32_t _num_instructions;

public:
    Block(uintptr_t address,
          IRSB *block,
          const Terminator &terminator);

    Block(uintptr_t address,
          IRSB *block,
          const Terminator &terminator,
          uint32_t num_instructions);

    /*!
     * \brief get_address
     * \return Returns the block's virtual address.
     */
    uintptr_t get_address() const {
        return _address;
    }

    /*!
     * \brief get_last_address
     * \return Returns the block's last virtual address
     * or 0 in case of an error.
     */
    uint64_t get_last_address() const;

    /*!
     * \brief get_terminator
     * \return Returns information about the terminator.
     */
    const Terminator &get_terminator() const {
        return _terminator;
    }

    /*!
     * \brief get_vex_block
     * \return Returns a (read-only) reference to the underlying VEX block.
     */
    const IRSB &get_vex_block() const {
        return *_vex_block;
    }

    /*!
     * \brief get_num_instructions
     * \return Returns the number of instructions this basic block holds.
     */
    uint32_t get_num_instructions() const {
        return _num_instructions;
    }

    void retrieve_semantics(State &state) const;

    /*!
     * \brief Returns if the block contains the given address.
     * \return Returns `true` if the block contains the given address.
     */
    bool contains_address(uint64_t addr) const;

    /*!
     * \brief Returns the addresses this basic block contains.
     * \return Returns a reference to a set of addresses.
     */
    const std::set<uintptr_t> &get_addresses() const;

private:
};

using BlockPredicate = std::function<bool (void*, const Block&)>;

#endif // BLOCK_H
