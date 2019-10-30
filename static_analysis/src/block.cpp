
#include "block.h"
#include "block_semantics.h"

using namespace std;

/*!
 * \brief Prints the basic block to the given output stream.
 * \param stream The output stream to which the instruction is printed.
 * \param block The `Block` itself.
 * \return The (modified) output stream `stream`.
 */
ostream &operator<<(ostream &stream, const Block &block) {

    stream << "Basic Block:\n";
    uint32_t counter = 0;
    const IRSB &vex_block = block.get_vex_block();
    for(int i = 0; i < vex_block.stmts_used; ++i) {
        const auto &current = *(vex_block.stmts[i]);
        if(current.tag == Ist_IMark) {
            stream << hex << current.Ist.IMark.addr;
            stream << "\n";
            counter++;
        }
        if(counter >= block.get_num_instructions()) {
            break;
        }
    }

    return stream;
}

/*!
 * \brief Constructs a `Block` object.
 * \param address Virtual address the block lies at.
 * \param block Pointer to an `IRSB` VEX block.
 * \param terminator Description of the block's terminator.
 * \param num_instructions Number of instructions this basic blocks hold.
 * Used if the vex blocks has been translated with more instructions than
 * we would like to store in this basic block.
 */
Block::Block(uintptr_t address,
      IRSB *block,
      const Terminator &terminator,
      uint32_t num_instructions)
    : _address(address), _vex_block(block), _terminator(terminator) {

    _num_instructions = num_instructions;
    uint32_t counter = 0;
    // Extracts addresses of all instructions.
    for(int i = 0; i < _vex_block->stmts_used; ++i) {
        const auto &current = *_vex_block->stmts[i];
        if(current.tag == Ist_IMark) {
            _addresses.insert(current.Ist.IMark.addr);
            counter++;
        }
        if(counter >= _num_instructions) {
            break;
        }
    }
}

/*!
 * \brief Constructs a `Block` object.
 * \param address Virtual address the block lies at.
 * \param block Pointer to an `IRSB` VEX block.
 * \param terminator Description of the block's terminator.
 */
Block::Block(uintptr_t address, IRSB *block, const Terminator &terminator)
    : _address(address), _vex_block(block), _terminator(terminator) {

    // Extracts addresses of all instructions.
    for(int i = 0; i < _vex_block->stmts_used; ++i) {
        const auto &current = *_vex_block->stmts[i];
        if(current.tag == Ist_IMark) {
            _addresses.insert(current.Ist.IMark.addr);
        }
    }
    _num_instructions = _addresses.size();
}

/*!
 * \brief Retrieves the block's semantics using an instance of `BlockSemantics`.
 *
 * \todo For now, there is no easy way to sub-class how the semantics are
 * retrieved, this should change by allowing custom semantic extractors.
 *
 * \param[in,out] state Initial state as used when computing the semantics. This
 * is updated with the resulting state which reflects the block's semantics.
 */
void Block::retrieve_semantics(State &state) const {
    BlockSemantics semantics(*this, state);
    state = semantics.get_state();
}

/*!
 * \brief get_last_address
 * \return Returns the block's last virtual address
 * or 0 in case of an error.
 */
uint64_t Block::get_last_address() const {
    return *(_addresses.rbegin());
}

bool Block::contains_address(uint64_t addr) const {

    if(_addresses.find(addr) != _addresses.cend()) {
        return true;
    }
    return false;
}

const std::set<uintptr_t> &Block::get_addresses() const {
    return _addresses;
}
