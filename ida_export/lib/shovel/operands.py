
try:
    import idaapi
    import idc
except ImportError:
    IS_IDA = False
else:
    IS_IDA = True


from ctypes import c_uint32, c_int64

from arch import RegistersTricore, RegistersX64
import __builtin__


__all__ = [
    'Constant', 'Bit', 'Register', 'Memory', 'Address',
    'generate_name', 'AccessType', 'PhiEquality', 'CoarseEquality'
]


class AccessType(object):
    Unknown, Read, Write, ReadWrite = range(4)


def generate_name(variable, counters, stack):
    i = counters[variable]
    stack[variable].append(i)

    counters[variable] += 1
    return i


class Constant(object):
    def __init__(self, value):
        if isinstance(__builtin__.REGISTERS, RegistersTricore):
            self._value = c_uint32(value).value
        elif isinstance(__builtin__.REGISTERS, RegistersX64):
            self._value = c_int64(value).value
        else:
            raise NotImplementedError("Do not know how to handle "\
                "constants for architecture.")

    @property
    def value(self):
        return self._value

    def __str__(self):
        return '#%x' % self._value

    def __eq__(self, other):
        return isinstance(other, Constant) and self._value == other._value

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self._value)

    def rename_lhs(self, _counters, _stack):
        pass

    def rename_rhs(self, _counters, _stack):
        pass


# For direct memory accesses only.
# TODO: Extend to indirect memory access as well.
class Address(Constant):
    def __str__(self):
        if IS_IDA and idc.hasUserName(idaapi.getFlags(self._value)):
            return idc.Name(self._value)

        result = super(Address, self).__str__()
        return '%' + result[1:]


class Bit(object):
    def __init__(self, index):
        self._index = index

    @property
    def index(self):
        return self._index

    def __str__(self):
        return 'b_%d' % self._index

    def __eq__(self, other):
        return isinstance(other, Bit) and self._index == other._index

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self._index)

    def rename_lhs(self, _counters, _stack):
        pass

    def rename_rhs(self, _counters, _stack):
        pass


class Register(object):
    strict_equality = True

    def __init__(self, index):
        self._index = index
        self._phi_index = None

    @property
    def index(self):
        return self._index

    @property
    def phi_index(self):
        return self._phi_index

    def __str__(self):
        result = __builtin__.REGISTERS.to_str(self._index)

        if self._phi_index is not None:
            result += '_%d' % self._phi_index

        return result

    def __eq__(self, other):
        # Do not take phi_index into account or SSA will not properly look up
        # these objects. We need, however, strict equality when aiming to
        # distinguish SSA forms, so we can enable it using strict_equality.

        if not isinstance(other, Register):
            return False

        equal = True
        if Register.strict_equality:
            equal = self._phi_index == other._phi_index

        return self._index == other._index and equal

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        # Again, not taking phi_index into account unless requested.
        if Register.strict_equality:
            return hash((self._index, self._phi_index))

        return hash(self._index)

    def rename_lhs(self, counters, stack):
        self._phi_index = generate_name(self, counters, stack)

    def rename_rhs(self, _, stack):
        self._phi_index = stack[self][-1]


class Memory(object):
    def __init__(self, base, index=None, index_factor=None, offset=None, pre=False, post=False):
        self._base, self._index, self._index_factor, self._offset = base, index, index_factor, offset
        if offset is None:
            self._offset = Constant(0)

        self._pre_increment = pre
        self._post_increment = post

    @property
    def base(self):
        return self._base

    @property
    def index(self):
        return self._index

    @property
    def index_factor(self):
        return self._index_factor

    @property
    def offset(self):
        return self._offset

    def __str__(self):
        pre = '+' if self._pre_increment else ''
        post = '+' if self._post_increment else ''
        idx = '+%s' % str(self._index) if self._index else ''
        idx_factor = ('*%s' % str(self._index_factor)) if self._index_factor else ''
        return '[%s%s%s%s%s]%s' % \
               (pre, str(self._base), idx, idx_factor, post, self._offset)

    def __eq__(self, other):
        return isinstance(other, Memory) and self._base == other._base and \
               self._index == other._index and \
               self._offset == other._offset and \
               self._pre_increment == other._pre_increment and \
               self._post_increment == other._post_increment

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self._base, self._index, self._offset,
                     self._pre_increment, self._post_increment))

    def rename_lhs(self, counters, stack):
        # Inner expressions are implicitly on the right-hand side.
        self._base.rename_rhs(counters, stack)
        if self._index:
            self._index.rename_rhs(counters, stack)

    def rename_rhs(self, counters, stack):
        self._base.rename_rhs(counters, stack)
        if self._index:
            self._index.rename_rhs(counters, stack)


class PhiEquality(object):
    def __enter__(self):
        self._previous = Register.strict_equality
        Register.strict_equality = True

    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        Register.strict_equality = self._previous


class CoarseEquality(object):
    def __enter__(self):
        self._previous = Register.strict_equality
        Register.strict_equality = False

    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        Register.strict_equality = self._previous
