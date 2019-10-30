#ifndef SSA_INSTRUCTION_H
#define SSA_INSTRUCTION_H

#include "ssa_export.pb.h"
#include "ssa_operand.h"
#include <string>
#include <unordered_set>

enum InstructionTypeSSA {
    SSAInstrTypeInstruction = 0,
    SSAInstrTypeCallingConvention,
    SSAInstrTypePhiNode,
    SSAInstrTypeVtableCall, // Special type for icall analysis.
    SSAInstrTypeCallOfRet, // Special type for backtrace analysis.
};

class BaseInstructionSSA;

//! A shared pointer used to hold an `BaseInstructionSSA`.
typedef std::shared_ptr<BaseInstructionSSA> BaseInstructionSSAPtr;

typedef std::vector<OperandSSAPtr> OperandSSAPtrs;

/*!
 * \brief The hash and compare function uses the object the pointer points to.
 * This means that if the object changes a value, the operation will generate
 * different hash values and will make problems with maps/sets. However,
 * OperandSSA objects are meant to be immutable and therefore do not offer
 * an interface to change values.
 */
typedef std::unordered_set<OperandSSAPtr,
                           SSAPtrDeref::Hash,
                           SSAPtrDeref::Compare> OperandsSSAset;

std::ostream &operator<<(std::ostream &stream, const BaseInstructionSSA &op);

/*!
 * \brief BaseInstructionSSA objects are meant to be immutable and therefore
 * do not offer an interface to change any values.
 */
class BaseInstructionSSA {

private:
    const std::string _mnemonic;
    uint64_t _address;
    OperandSSAPtrs _operands;
    OperandSSAPtrs _definitions;
    OperandSSAPtrs _uses;

    /*!
     * \brief Adds the operand ptr to the use and/or definitions (is called
     * after an operand is added).
     */
    void add_use_definition(const OperandSSAPtr &op);

protected:
    InstructionTypeSSA _type;

    BaseInstructionSSA(const std::string &mnemonic,
                       uint64_t address);
    BaseInstructionSSA(const BaseInstructionSSA &obj);

    /*!
     * \brief Adds the SSA operand to the operands of the instruction.
     */
    void add_operand(const ssa::Operand &operand);

public:
    BaseInstructionSSA() = delete;
    virtual bool operator ==(const BaseInstructionSSA &other) const;
    bool operator !=(const BaseInstructionSSA &other) const;
    virtual size_t hash() const;

    /*!
     * \brief get_address
     * \return Returns the instruction's virtual address.
     */
    uint64_t get_address() const;

    /*!
     * \brief get_mnemonic
     * \return Returns the instruction's mnemonic.
     */
    const std::string &get_mnemonic() const;

    /*!
     * \brief get_type
     * \return Returns the instruction's type.
     */
    InstructionTypeSSA get_type() const;

    /*!
     * \brief get_operands
     * \return Returns a reference to the instruction's operands.
     */
    const OperandSSAPtrs &get_operands() const;

    /*!
     * \brief get_operand
     * \return Returns a reference to the instruction's operand ptr
     * at the given index.
     */
    const OperandSSAPtr &get_operand(uint32_t idx) const;

    /*!
     * \brief get_definitions
     * \return Returns a reference to the instruction's operands that
     * are definitions.
     */
    const OperandSSAPtrs &get_definitions() const;

    /*!
     * \brief get_uses
     * \return Returns a reference to the instruction's operands that
     * are uses.
     */
    const OperandSSAPtrs &get_uses() const;

    virtual bool is_instruction() const;

    virtual bool is_phinode() const;

    virtual bool is_callingconvention() const;

    virtual bool is_call() const;

    virtual bool is_unconditional_jmp() const;

    virtual bool is_ret() const;
};

class InstructionSSA : public BaseInstructionSSA {
private:
    bool _is_call = false;
    bool _is_unconditional_jmp = false;
    bool _is_ret = false;

public:
    InstructionSSA() = delete;
    InstructionSSA(const ssa::BaseInstruction &instruction);
    InstructionSSA(const InstructionSSA &obj);

    virtual bool is_instruction() const;

    virtual bool is_call() const;

    virtual bool is_unconditional_jmp() const;

    virtual bool is_ret() const;
};

class PhiNodeSSA : public BaseInstructionSSA {
public:
    PhiNodeSSA() = delete;
    PhiNodeSSA(const ssa::PhiNode &phi_node);
    PhiNodeSSA(const PhiNodeSSA &obj);

    virtual bool is_phinode() const;
};

class CallingConventionSSA : public BaseInstructionSSA {
public:
    CallingConventionSSA() = delete;
    CallingConventionSSA(const ssa::CallingConvention &calling_convention);
    CallingConventionSSA(const CallingConventionSSA &obj);

    virtual bool is_callingconvention() const;
};

#endif // SSA_INSTRUCTION_H
