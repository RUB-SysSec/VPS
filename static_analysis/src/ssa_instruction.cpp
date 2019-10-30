#include "ssa_instruction.h"
#include "icall_analysis.h"

using namespace std;

/*!
 * \brief Prints the instruction to the given output stream.
 * \param stream The output stream to which the instruction is printed.
 * \param instr The `BaseInstructionSSA` itself.
 * \return The (modified) output stream `stream`.
 */
ostream &operator<<(ostream &stream, const BaseInstructionSSA &instr) {
    stream << hex << instr.get_address()
           << " " << instr.get_mnemonic();
    switch(instr.get_type()) {
        case SSAInstrTypePhiNode: {
            int ctr = 0;
            for(const auto &op_ptr : instr.get_operands()) {
                if(ctr == 1) {
                    stream << " [" << *op_ptr;
                }
                else {
                    stream << " " << *op_ptr;
                }
                ctr++;
            }
            stream << "]";
            break;
        }

        case SSAInstrTypeVtableCall: {
            const VtableCallInstruction &instr_typed =
                               static_cast<const VtableCallInstruction&>(instr);
            const VTable &vtable = instr_typed.get_vtable();
            stream << " entry at: "
                   << hex << instr_typed.get_address()
                   << " vtable: "
                   << hex << vtable.addr;
            break;
        }

        case SSAInstrTypeCallOfRet: {
            stream << " (RET) ";
            for(const auto &op_ptr : instr.get_operands()) {
                stream << " " << *op_ptr;
            }
            break;
        }

        default:
            for(const auto &op_ptr : instr.get_operands()) {
                stream << " " << *op_ptr;
            }
            break;
    }

    return stream;
}

BaseInstructionSSA::BaseInstructionSSA(const std::string &mnemonic,
                                       uint64_t address)
    : _mnemonic(mnemonic) {
    _address = address;
}

BaseInstructionSSA::BaseInstructionSSA(const BaseInstructionSSA &obj)
    : _mnemonic(obj.get_mnemonic()) {
    _address = obj.get_address();
    _type = obj.get_type();

    // Copy operands.
    for(const OperandSSAPtr &op : obj.get_operands()) {
        switch(op->get_type()) {
            case SSAOpTypeRegisterX64:
                _operands.push_back(make_shared<const RegisterX64SSA>(
                                      static_cast<const RegisterX64SSA&>(*op)));
                break;

            case SSAOpTypeConstantX64:
                _operands.push_back(make_shared<const ConstantX64SSA>(
                                      static_cast<const ConstantX64SSA&>(*op)));
                break;

            case SSAOpTypeAddressX64:
                _operands.push_back(make_shared<const AddressX64SSA>(
                                       static_cast<const AddressX64SSA&>(*op)));
                break;

            case SSAOpTypeMemoryX64:
                _operands.push_back(make_shared<const MemoryX64SSA>(
                                        static_cast<const MemoryX64SSA&>(*op)));
                break;

            default:
                throw runtime_error("Unknown operand type.");
        }
    }

    // Build definitions and uses.
    for(const OperandSSAPtr &op : _operands) {
        add_use_definition(op);
    }
}

bool BaseInstructionSSA::operator!=(const BaseInstructionSSA &other) const {
    return !(*this == other);
}

bool BaseInstructionSSA::operator ==(const BaseInstructionSSA &other) const {
    if(_type != other.get_type()) {
        return false;
    }
    if(_mnemonic == other.get_mnemonic()
       && _address == other.get_address()
       && _operands.size() == other.get_operands().size()) {

        // Check operands for equality.
        for(size_t i = 0; i < _operands.size(); i++) {
            if(*_operands.at(i) != *other.get_operand(i)) {
                return false;
            }
        }

        return true;
    }
    return false;
}

size_t BaseInstructionSSA::hash() const {
    size_t h = _type;
    std::hash_combine(h, std::hash<std::string>()(_mnemonic));
    std::hash_combine(h, _address);
    for(const OperandSSAPtr &op : _operands) {
        std::hash_combine(h, op->hash());
    }
    return h;
}

uint64_t BaseInstructionSSA::get_address() const {
    return _address;
}

const std::string &BaseInstructionSSA::get_mnemonic() const {
    return _mnemonic;
}

InstructionTypeSSA BaseInstructionSSA::get_type() const {
    return _type;
}

const OperandSSAPtrs &BaseInstructionSSA::get_operands() const {
    return _operands;
}

const OperandSSAPtr &BaseInstructionSSA::get_operand(uint32_t idx) const {
    return _operands.at(idx);
}

const OperandSSAPtrs &BaseInstructionSSA::get_definitions() const {
    return _definitions;
}

const OperandSSAPtrs &BaseInstructionSSA::get_uses() const {
    return _uses;
}

void BaseInstructionSSA::add_operand(const ssa::Operand &operand) {
    if(operand.has_register_()) {
        const ssa::Register &reg = operand.register_();
        if(reg.has_register_x64()) {
            const OperandSSAPtr &op = make_shared<RegisterX64SSA>(
                                                            reg.register_x64());
            _operands.push_back(op);
            add_use_definition(op);

        }
        else {
            throw runtime_error("Imported SSA register has unknown type.");
        }
    }
    else if(operand.has_constant()) {
        const ssa::Constant &constant = operand.constant();
        if(constant.has_constant_x64()) {
            const OperandSSAPtr &op = make_shared<ConstantX64SSA>(
                                                       constant.constant_x64());
            _operands.push_back(op);
            add_use_definition(op);
        }
        else if(constant.has_address_x64()) {
            const OperandSSAPtr &op = make_shared<AddressX64SSA>(
                                                        constant.address_x64());
            _operands.push_back(op);
            add_use_definition(op);
        }
        else {
            throw runtime_error("Imported SSA constant has unknown type.");
        }
    }
    else if(operand.has_memory()) {
        const ssa::Memory &memory = operand.memory();
        if(memory.has_memory_x64()) {
            const OperandSSAPtr &op = make_shared<MemoryX64SSA>(
                                                           memory.memory_x64());
            _operands.push_back(op);
            add_use_definition(op);
        }
        else {
            throw runtime_error("Imported SSA memory has unknown type.");
        }
    }
    else {
        throw runtime_error("Imported SSA operand has unknown type.");
    }
}

void BaseInstructionSSA::add_use_definition(const OperandSSAPtr &op) {
    if(op->is_read()) {
        _uses.push_back(op);
    }
    if(op->is_written()) {
        _definitions.push_back(op);
    }
}

bool BaseInstructionSSA::is_instruction() const {
    return false;
}

bool BaseInstructionSSA::is_phinode() const {
    return false;
}

bool BaseInstructionSSA::is_callingconvention() const {
    return false;
}

bool BaseInstructionSSA::is_call() const {
    return false;
}

bool BaseInstructionSSA::is_unconditional_jmp() const {
    return false;
}

bool BaseInstructionSSA::is_ret() const {
    return false;
}

InstructionSSA::InstructionSSA(const ssa::BaseInstruction &instruction)
    : BaseInstructionSSA(instruction.mnemonic(), instruction.address()) {
    _type = SSAInstrTypeInstruction;

    if(instruction.mnemonic() == "call") { // TODO architecture specific
        _is_call = true;
    }
    else if(instruction.mnemonic() == "jmp") { // TODO architecture specific
        _is_unconditional_jmp = true;
    }
    else if(instruction.mnemonic() == "ret"
            || instruction.mnemonic() == "retn") { // TODO architecture specific
        _is_ret = true;
    }

    for(int i = 0; i < instruction.operands_size(); i++) {
        const ssa::Operand &operand = instruction.operands(i);
        add_operand(operand);
    }
}

InstructionSSA::InstructionSSA(const InstructionSSA &obj)
    : BaseInstructionSSA(obj) {

    if(obj.get_mnemonic() == "call") { // TODO architecture specific
        _is_call = true;
    }
    else if(obj.get_mnemonic() == "jmp") { // TODO architecture specific
        _is_unconditional_jmp = true;
    }
    else if(obj.get_mnemonic() == "ret"
            || obj.get_mnemonic() == "retn") { // TODO architecture specific
        _is_ret = true;
    }
}

bool InstructionSSA::is_instruction() const {
    return true;
}

bool InstructionSSA::is_call() const {
    return _is_call;
}

bool InstructionSSA::is_unconditional_jmp() const {
    return _is_unconditional_jmp;
}

bool InstructionSSA::is_ret() const {
    return _is_ret;
}

PhiNodeSSA::PhiNodeSSA(const ssa::PhiNode &phi_node)
    : BaseInstructionSSA(phi_node.mnemonic(), phi_node.address()) {
    _type = SSAInstrTypePhiNode;

    for(int i = 0; i < phi_node.operands_size(); i++) {
        const ssa::Operand &operand = phi_node.operands(i);
        add_operand(operand);
    }
}

PhiNodeSSA::PhiNodeSSA(const PhiNodeSSA &obj)
    : BaseInstructionSSA(obj) {
}

bool PhiNodeSSA::is_phinode() const {
    return true;
}

CallingConventionSSA::CallingConventionSSA(
                               const ssa::CallingConvention &calling_convention)
    : BaseInstructionSSA(calling_convention.mnemonic(),
                         calling_convention.address()) {

    _type = SSAInstrTypeCallingConvention;

    for(int i = 0; i < calling_convention.operands_size(); i++) {
        const ssa::Operand &operand = calling_convention.operands(i);
        add_operand(operand);
    }
}

CallingConventionSSA::CallingConventionSSA(const CallingConventionSSA &obj)
    : BaseInstructionSSA(obj) {
}

bool CallingConventionSSA::is_callingconvention() const {
    return true;
}
