#include "ssa_operand.h"

using namespace std;

/*!
 * \brief Prints the operand to the given output stream.
 * \param stream The output stream to which the operand is printed.
 * \param op The `OperandSSA` itself.
 * \return The (modified) output stream `stream`.
 */
ostream &operator<<(ostream &stream, const OperandSSA &op) {
    switch(op.get_type()) {
        case SSAOpTypeRegisterX64: {
            const RegisterX64SSA &typed = static_cast<const RegisterX64SSA&>(
                                                                            op);
            stream << AMD64_DISPLAY_REGISTERS_SSA[typed.get_index()]
                 << "_"
                 << dec << typed.get_phi_index();
            break;
        }
        case SSAOpTypeConstantX64: {
            const ConstantX64SSA &typed = static_cast<const ConstantX64SSA&>(
                                                                            op);
            int64_t value = typed.get_value();
            if(value < 0) {
                stream << "#-" << hex << (value * (-1));
            }
            else {
                stream << "#" << hex << value;
            }
            break;
        }
        case SSAOpTypeAddressX64: {
            const AddressX64SSA &typed = static_cast<const AddressX64SSA&>(op);
            stream << "%" << hex << typed.get_value();
            break;
        }
        case SSAOpTypeMemoryX64: {
            const MemoryX64SSA &typed = static_cast<const MemoryX64SSA&>(op);
            stream << "[" << typed.get_base();
            if(typed.has_index()) {
                stream << "+" << typed.get_index();
            }
            if(typed.has_index_factor()) {
                stream << "*" << typed.get_index_factor();
            }
            stream << "]" << typed.get_offset();
            break;
        }
    }

    return stream;
}

OperandTypeSSA OperandSSA::get_type() const {
    return _type;
}

OperandAccessTypeSSA OperandSSA::get_access_type() const {
    return _access_type;
}

bool OperandSSA::operator!=(const OperandSSA &other) const {
    return !(*this == other);
}

bool OperandSSA::is_written() const {
    return (_access_type == SSAAccessTypeWirte
            || _access_type == SSAAccessTypeReadWrite);
}

bool OperandSSA::is_read() const {
    return (_access_type == SSAAccessTypeRead
            || _access_type == SSAAccessTypeReadWrite);
}

bool OperandSSA::is_constant() const {
    return (_type == SSAOpTypeConstantX64
            || _type == SSAOpTypeAddressX64);
}

bool OperandSSA::is_memory() const {
    return _type == SSAOpTypeMemoryX64;
}

bool OperandSSA::is_register() const {
    return _type == SSAOpTypeRegisterX64;
}

bool OperandSSA::is_arg_register() const {
    return false;
}

RegisterX64SSA::RegisterX64SSA(const ssa::RegisterX64 &reg) {
    _type = SSAOpTypeRegisterX64;
    _access_type = static_cast<OperandAccessTypeSSA>(reg.access_type());
    _index = reg.index();
    _phi_index = reg.phi_index();
}

RegisterX64SSA::RegisterX64SSA() {
}

RegisterX64SSA::RegisterX64SSA(const RegisterX64SSA &obj) {
    _type = SSAOpTypeRegisterX64;
    _access_type = obj.get_access_type();
    _index = obj.get_index();
    _phi_index = obj.get_phi_index();
}

bool RegisterX64SSA::operator ==(const OperandSSA &other) const {
    if(_type != other.get_type()) {
        return false;
    }
    const RegisterX64SSA &other_typed = static_cast<const RegisterX64SSA&>(
                                                                         other);
    if(_index == other_typed.get_index()
       && _phi_index == other_typed.get_phi_index()) {
        return true;
    }
    return false;
}

size_t RegisterX64SSA::hash() const {
    size_t h = _type;
    std::hash_combine(h, _index);
    std::hash_combine(h, _phi_index);
    return h;
}

uint32_t RegisterX64SSA::get_index() const {
    return _index;
}

uint32_t RegisterX64SSA::get_phi_index() const {
    return _phi_index;
}

bool RegisterX64SSA::is_arg_register() const {
    if(std::find(AMD64_SYSTEM_V_ARG_REGS_SSA.begin(),
                 AMD64_SYSTEM_V_ARG_REGS_SSA.end(),
                 _index) != AMD64_SYSTEM_V_ARG_REGS_SSA.end()) {
        return true;
    }
    return false;
}

bool RegisterX64SSA::contains_coarse(const OperandSSA &other) const {
    if(_type != other.get_type()) {
        return false;
    }
    const RegisterX64SSA &other_typed = static_cast<const RegisterX64SSA&>(
                                                                         other);
    if(_index == other_typed.get_index()) {
        return true;
    }
    return false;
}

bool RegisterX64SSA::contains(const OperandSSA &other) const {
    return (*this == other);
}

ConstantX64SSA::ConstantX64SSA(const ssa::ConstantX64 &constant) {
    _type = SSAOpTypeConstantX64;
    _access_type = static_cast<OperandAccessTypeSSA>(constant.access_type());
    _value = constant.value();
}

ConstantX64SSA::ConstantX64SSA() {
}

ConstantX64SSA::ConstantX64SSA(const ConstantX64SSA &obj) {
    _type = SSAOpTypeConstantX64;
    _access_type = obj.get_access_type();
    _value = obj.get_value();
}

bool ConstantX64SSA::operator ==(const OperandSSA &other) const {
    if(_type != other.get_type()) {
        return false;
    }
    const ConstantX64SSA &other_typed = static_cast<const ConstantX64SSA&>(
                                                                         other);
    if(_value == other_typed.get_value()) {
        return true;
    }
    return false;
}

size_t ConstantX64SSA::hash() const {
    size_t h = _type;
    std::hash_combine(h, _value);
    return h;
}

int64_t ConstantX64SSA::get_value() const {
    return _value;
}

bool ConstantX64SSA::contains_coarse(const OperandSSA &other) const {
    return (*this == other);
}

bool ConstantX64SSA::contains(const OperandSSA &other) const {
    return (*this == other);
}

AddressX64SSA::AddressX64SSA(const ssa::AddressX64 &address) {
    _type = SSAOpTypeAddressX64;
    _access_type = static_cast<OperandAccessTypeSSA>(address.access_type());
    _value = address.value();
}

AddressX64SSA::AddressX64SSA(const AddressX64SSA &obj) {
    _type = SSAOpTypeAddressX64;
    _access_type = obj.get_access_type();
    _value = obj.get_value();
}

bool AddressX64SSA::operator ==(const OperandSSA &other) const {
    if(_type != other.get_type()) {
        return false;
    }
    const AddressX64SSA &other_typed = static_cast<const AddressX64SSA&>(other);
    if(_value == other_typed.get_value()) {
        return true;
    }
    return false;
}

size_t AddressX64SSA::hash() const {
    size_t h = _type;
    std::hash_combine(h, _value);
    return h;
}

uint64_t AddressX64SSA::get_value() const {
    return _value;
}

bool AddressX64SSA::contains_coarse(const OperandSSA &other) const {
    return (*this == other);
}

bool AddressX64SSA::contains(const OperandSSA &other) const {
    return (*this == other);
}

MemoryX64SSA::MemoryX64SSA(const ssa::MemoryX64 &memory)
    : _base(RegisterX64SSA(memory.base().register_x64())),
      _offset(ConstantX64SSA(memory.offset().constant_x64())) {
    _type = SSAOpTypeMemoryX64;
    _access_type = static_cast<OperandAccessTypeSSA>(memory.access_type());

    _has_index = false;
    _has_index_factor = false;
    if(memory.has_index()) {
        _index = RegisterX64SSA(memory.index().register_x64());
        _has_index = true;
    }
    if(memory.has_index_factor()) {
        _index_factor = ConstantX64SSA(memory.index_factor().constant_x64());
        _has_index_factor = true;
    }
}

MemoryX64SSA::MemoryX64SSA(const MemoryX64SSA &obj) {
    _type = SSAOpTypeMemoryX64;
    _access_type = obj.get_access_type();
    _has_index = obj.has_index();
    _has_index_factor = obj.has_index_factor();

    _base = RegisterX64SSA(obj.get_base());
    _offset = ConstantX64SSA(obj.get_offset());
    if(_has_index) {
        _index = RegisterX64SSA(obj.get_index());
    }
    if(_has_index_factor) {
        _index_factor = ConstantX64SSA(obj.get_index_factor());
    }
}

bool MemoryX64SSA::operator ==(const OperandSSA &other) const {
    if(_type != other.get_type()) {
        return false;
    }
    const MemoryX64SSA &other_typed = (const MemoryX64SSA &)other;
    if(_base == other_typed.get_base()
       && _offset == other_typed.get_offset()
       && _has_index == other_typed.has_index()
       && _has_index_factor == other_typed.has_index_factor()) {
        if(_has_index) {
            if(_index == other_typed.get_index()) {
                if(_has_index_factor) {
                    if(_index_factor == other_typed.get_index_factor()) {
                        return true;
                    }
                }
                else {
                    return true;
                }
            }
        }
        else {
            return true;
        }
    }
    return false;
}

size_t MemoryX64SSA::hash() const {
    size_t h = _type;
    std::hash_combine(h, _base.hash());
    std::hash_combine(h, _offset.hash());
    std::hash_combine(h, _has_index);
    std::hash_combine(h, _has_index_factor);
    if(_has_index) {
        std::hash_combine(h, _index.hash());
    }
    if(_has_index_factor) {
        std::hash_combine(h, _index_factor.hash());
    }
    return h;
}

const RegisterX64SSA &MemoryX64SSA::get_base() const {
    return _base;
}

const ConstantX64SSA &MemoryX64SSA::get_offset() const {
    return _offset;
}

const RegisterX64SSA &MemoryX64SSA::get_index() const {
    if(_has_index) {
        return _index;
    }
    throw runtime_error("MemoryX64SSA object has no index.");
}

const ConstantX64SSA &MemoryX64SSA::get_index_factor() const {
    if(_has_index_factor) {
        return _index_factor;
    }
    throw runtime_error("MemoryX64SSA object has no index factor.");
}

bool MemoryX64SSA::has_index() const {
    return _has_index;
}

bool MemoryX64SSA::has_index_factor() const {
    return _has_index_factor;
}

bool MemoryX64SSA::contains_coarse(const OperandSSA &other) const {
    switch(other.get_type()) {
        case SSAOpTypeRegisterX64:
            return (_base.contains_coarse(other)
                   || (_has_index && _index.contains_coarse(other)));
        case SSAOpTypeConstantX64:
            return (_offset.contains_coarse(other)
                   || (_has_index_factor && _index_factor.contains_coarse(other)));
        case SSAOpTypeMemoryX64:
            return (*this == other);
        default:
            return false;
    }
}

bool MemoryX64SSA::contains(const OperandSSA &other) const {
    switch(other.get_type()) {
        case SSAOpTypeRegisterX64:
            return (_base.contains(other)
                   || (_has_index && _index.contains(other)));
        case SSAOpTypeConstantX64:
            return (_offset.contains(other)
                   || (_has_index_factor && _index_factor.contains(other)));
        case SSAOpTypeMemoryX64:
            return (*this == other);
        default:
            return false;
    }
}
