
#include "ssa_block.h"

using namespace std;


uint64_t BlockSSA::get_address() const {
    return _address;
}

uint64_t BlockSSA::get_last_address() const {
    return _last_address;
}

const BaseInstructionSSAPtrs &BlockSSA::get_instructions() const {
    return _instructions;
}

const BaseInstructionSSAPtrSet BlockSSA::get_instruction(
                                                uint64_t addr,
                                                InstructionTypeSSA type) const {
    BaseInstructionSSAPtrSet result;
    for(const BaseInstructionSSAPtr &instr : _instructions) {
        if(instr->get_address() == addr
           && instr->get_type() == type) {
            result.insert(instr);
        }
    }
    return result;
}

BlockSSA::BlockSSA(const ssa::BasicBlock &basic_block) {
    _address = basic_block.address();
    _last_address = basic_block.end();

    // Add predecessor and successor addresses.
    for(int i = 0; i < basic_block.predecessors_size(); i++) {
        _predecessors.insert(basic_block.predecessors(i));
    }
    for(int i = 0; i < basic_block.successors_size(); i++) {
        _successors.insert(basic_block.successors(i));
    }

    // Parse basic block instructions.
    for(int i = 0; i < basic_block.instructions_size(); i++) {
        const ssa::Instruction &instruction = basic_block.instructions(i);
        if(instruction.has_instruction()) {
            _instructions.push_back(
                        make_shared<InstructionSSA>(instruction.instruction()));
        }
        else if(instruction.has_phi_node()) {
            _instructions.push_back(
                               make_shared<PhiNodeSSA>(instruction.phi_node()));
        }
        else if(instruction.has_calling_convention()) {
            _instructions.push_back(
                    make_shared<CallingConventionSSA>(
                                             instruction.calling_convention()));
        }
        else {
            throw runtime_error("Imported SSA instruction has unknown type.");
        }
    }

    // Build definitions/uses set.
    for(const BaseInstructionSSAPtr &instr : _instructions) {
        for(const OperandSSAPtr &op : instr->get_definitions()) {
            _definitions.insert(op);
        }
        for(const OperandSSAPtr &op : instr->get_uses()) {
            _uses.insert(op);
        }
    }
}

bool BlockSSA::contains_address(uint64_t addr) const {
    for(const BaseInstructionSSAPtr &instr : _instructions) {
        if(instr->get_address() == addr) {
            return true;
        }
    }
    return false;
}

const OperandsSSAset &BlockSSA::get_definitions() const {
    return _definitions;
}

const OperandsSSAset &BlockSSA::get_uses() const {
    return _uses;
}

const std::unordered_set<uint64_t> &BlockSSA::get_predecessors() const {
    return _predecessors;
}

const std::unordered_set<uint64_t> &BlockSSA::get_successors() const {
    return _successors;
}
