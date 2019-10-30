#ifndef SSA_OPERAND_H
#define SSA_OPERAND_H

#include <ostream>
#include <algorithm>
#include "expression.h" // Needed for std::hash_combine()
#include "ssa_export.pb.h"
#include "amd64_ssa.h"

enum OperandAccessTypeSSA {
    SSAAccessTypeUnknown = 0,
    SSAAccessTypeRead = 1,
    SSAAccessTypeWirte = 2,
    SSAAccessTypeReadWrite = 3,
};

enum OperandTypeSSA {
    SSAOpTypeRegisterX64 = 0,
    SSAOpTypeConstantX64,
    SSAOpTypeAddressX64,
    SSAOpTypeMemoryX64,
};

class OperandSSA;

//! A shared pointer used to hold an `OperandSSA`.
typedef std::shared_ptr<const OperandSSA> OperandSSAPtr;

std::ostream &operator<<(std::ostream &stream, const OperandSSA &op);

/*!
 * \brief OperandSSA objects are meant to be immutable and therefore do not
 * do not offer an interface to change any values.
 */
class OperandSSA {

protected:
    OperandTypeSSA _type;
    OperandAccessTypeSSA _access_type;

    OperandSSA() = default;

public:
    OperandSSA(const OperandSSA&) = delete;
    virtual bool operator ==(const OperandSSA &other) const = 0;
    bool operator !=(const OperandSSA &other) const;
    virtual size_t hash() const = 0;

    /*!
     * \brief get_type
     * \return Returns the operand's type.
     */
    OperandTypeSSA get_type() const;

    /*!
     * \brief get_access_type
     * \return Returns the operand's access type.
     */
    OperandAccessTypeSSA get_access_type() const;

    /*!
     * \brief is_written
     * \return Returns `true` if the operand is written to.
     */
    bool is_written() const;

    /*!
     * \brief is_read
     * \return Returns `true` if the operand is read from.
     */
    bool is_read() const;

    /*!
     * \brief is_constant
     * \return Returns `true` if the operand is a constant object.
     */
    bool is_constant() const;

    /*!
     * \brief is_memory
     * \return Returns `true` if the operand is a memory object.
     */
    bool is_memory() const;

    /*!
     * \brief is_register
     * \return Returns if `true` the operand is a register object.
     */
    bool is_register() const;

    /*!
     * \brief is_arg_register
     * \return Returns `true` if the operand is an argument register.
     */
    virtual bool is_arg_register() const;

    /*!
     * \brief Checks if the other operand is contained inside this operand
     * without considering the phi index.
     * \return Returns `true` if the operand contains the other operand.
     */
    virtual bool contains_coarse(const OperandSSA &other) const = 0;

    /*!
     * \brief Checks if the other operand is contained inside this operand
     * by also considering the phi index. In cases like RegisterX64SSA or
     * ConstantX64SSA it does the same as the `==` operator.
     * \return Returns `true` if the operand contains the other operand.
     */
    virtual bool contains(const OperandSSA &other) const = 0;

};

struct SSAPtrDeref {
    /*!
     * \brief Type that specifies how `OperandSSAPtr` is hashed.
     */
    struct Hash {
        template <typename T>
        std::size_t operator() (const std::shared_ptr<T> &e) const {
            return e->hash();
        }
    };
    /*!
     * \brief Type that specifies how `OperandSSAPtr` is compared.
     */
    struct Compare {
        template <typename T>
        size_t operator() (std::shared_ptr<T> const &a,
                           std::shared_ptr<T> const &b) const {
            return *a == *b;
        }
    };
};


class RegisterX64SSA : public OperandSSA {

private:
    uint32_t _index;
    uint32_t _phi_index;

    // Constructor needed for MemoryX64SSA objects if no index is present.
    RegisterX64SSA();

public:
    RegisterX64SSA(const ssa::RegisterX64 &reg);
    RegisterX64SSA(const RegisterX64SSA &obj);
    virtual bool operator ==(const OperandSSA &other) const;
    virtual size_t hash() const;

    uint32_t get_index() const;
    uint32_t get_phi_index() const;
    virtual bool is_arg_register() const;

    /*!
     * \brief Checks if the other operand is contained inside this operand
     * without considering the phi index.
     * \return Returns `true` if the operand contains the other operand.
     */
    virtual bool contains_coarse(const OperandSSA &other) const;

    /*!
     * \brief Does the same as the `==` operator.
     * \return Returns `true` if the operand contains the other operand.
     */
    virtual bool contains(const OperandSSA &other) const;

    friend class MemoryX64SSA;
};

class ConstantX64SSA : public OperandSSA {

private:
    int64_t _value;

    // Constructor needed for MemoryX64SSA objects if no index_factor is present.
    ConstantX64SSA();

public:
    ConstantX64SSA(const ssa::ConstantX64 &constant);
    ConstantX64SSA(const ConstantX64SSA &obj);
    virtual bool operator ==(const OperandSSA &other) const;
    virtual size_t hash() const;

    int64_t get_value() const;

    /*!
     * \brief Does the same as the `==` operator.
     * \return Returns `true` if the operand contains the other operand.
     */
    virtual bool contains_coarse(const OperandSSA &other) const;

    /*!
     * \brief Does the same as the `==` operator.
     * \return Returns `true` if the operand contains the other operand.
     */
    virtual bool contains(const OperandSSA &other) const;

    friend class MemoryX64SSA;
};


class AddressX64SSA : public OperandSSA {

private:
    uint64_t _value;

public:
    AddressX64SSA() = delete;
    AddressX64SSA(const ssa::AddressX64 &address);
    AddressX64SSA(const AddressX64SSA &obj);
    virtual bool operator ==(const OperandSSA &other) const;
    virtual size_t hash() const;

    uint64_t get_value() const;

    /*!
     * \brief Does the same as the `==` operator.
     * \return Returns `true` if the operand contains the other operand.
     */
    virtual bool contains_coarse(const OperandSSA &other) const;

    /*!
     * \brief Does the same as the `==` operator.
     * \return Returns `true` if the operand contains the other operand.
     */
    virtual bool contains(const OperandSSA &other) const;
};


class MemoryX64SSA : public OperandSSA {

private:
    RegisterX64SSA _base;
    ConstantX64SSA _offset;
    RegisterX64SSA _index;
    ConstantX64SSA _index_factor;
    bool _has_index;
    bool _has_index_factor;

public:
    MemoryX64SSA() = delete;
    MemoryX64SSA(const ssa::MemoryX64 &memory);
    MemoryX64SSA(const MemoryX64SSA &obj);
    virtual bool operator ==(const OperandSSA &other) const;
    virtual size_t hash() const;

    const RegisterX64SSA &get_base() const;
    const ConstantX64SSA &get_offset() const;
    const RegisterX64SSA &get_index() const;
    const ConstantX64SSA &get_index_factor() const;
    bool has_index() const;
    bool has_index_factor() const;

    /*!
     * \brief Checks if the other operand is contained inside this operand
     * without considering the phi index.
     * \return Returns `true` if the operand contains the other operand.
     * If the other operand is the same operand it also returns `true`.
     */
    virtual bool contains_coarse(const OperandSSA &other) const;

    /*!
     * \brief Checks if the other operand is contained inside this operand
     * by also considering the phi index.
     * \return Returns `true` if the operand contains the other operand.
     * If the other operand is the same operand it also returns `true`.
     */
    virtual bool contains(const OperandSSA &other) const;
};

#endif // SSA_OPERAND_H
