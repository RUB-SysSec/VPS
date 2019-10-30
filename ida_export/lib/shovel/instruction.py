
try:
    import idaapi
except ImportError:
    IS_IDA = False
else:
    IS_IDA = True

    def prevent_caching_for(modules):
        pass

    prevent_caching_for((
        'ida.ida_interface',
        'operands',
    ))

    from ida.ida_interface import *


from copy import deepcopy
from operands import AccessType

import operands


__all__ = [
    'Operand', 'Instruction', 'CallingConvention'
]


class Operand(object):
    def __init__(self, access_type, ida_operand=None, operand=None,
        ida_operand_str=None, address=None, op_num=None):
        self._ida_operand = ida_operand
        self._ida_operand_str = ida_operand_str
        self._access = access_type
        self._address = address
        self._op_num = op_num

        if operand:
            self._operand = operand
        else:
            self._operand = self._parse()

    def _parse(self):
        assert IS_IDA, 'IDA is required for operand parsing.'
        assert self._ida_operand, 'IDA operand required for parsing.'

        return parse_ida_operand(self._ida_operand,
                                 self._ida_operand_str,
                                 self._address,
                                 self._op_num)

    def __str__(self):
        return str(self._operand)

    def __eq__(self, other):
        return isinstance(other, Operand) and \
               self._access == other._access and self._operand == other._operand

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self._access, self._operand))

    def __deepcopy__(self, _):
        other = type(self)(self._access, self._ida_operand,
                           operand=self._operand)
        other._operand = deepcopy(self._operand)
        return other

    @property
    def operand(self):
        return self._operand

    @property
    def access(self):
        return self._access

    def is_read(self):
        return self._access in (AccessType.Read, AccessType.ReadWrite)

    def is_written(self):
        return self._access in (AccessType.Write, AccessType.ReadWrite)

    def rename_lhs(self, counters, stack):
        self._operand.rename_lhs(counters, stack)

    def rename_rhs(self, counters, stack):
        self._operand.rename_rhs(counters, stack)

    def __getstate__(self):
        return self._access, self._operand

    def __setstate__(self, state):
        self._access, self._operand = state
        self._ida_operand = None


class CallingConvention(object):
    def __init__(self, address, operands):
        self._address = address
        self._operands = operands

    def __str__(self):
        return '%08x cconv.w %s' % (self._address,
                                    ' '.join(str(o) for o in self._operands))

    def __eq__(self, other):
        return isinstance(other, CallingConvention) and \
            self._operands == other._operands

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self._address)

    @property
    def address(self):
        return self._address

    @property
    def definitions(self):
        return filter(lambda o: o.is_written(), self._operands)

    @property
    def uses(self):
        return filter(lambda o: o.is_read(), self._operands)

    @property
    def register_uses(self):
        return (u.operand for u in self.uses if isinstance(u.operand,
                                                           operands.Register))

    @property
    def is_control_flow(self):
        return False

    def rename_lhs(self, counters, stack):
        for o in filter(lambda o: o.is_written(), self._operands):
            o.rename_lhs(counters, stack)

    def rename_rhs(self, counters, stack):
        for o in filter(lambda o: o.is_read(), self._operands):
            o.rename_rhs(counters, stack)


class Instruction(object):
    def __init__(self, address, mnemonic, operands, is_control_flow=False,
                 comment=None):
        self._address = address
        self._mnemonic = mnemonic
        self._operands = operands
        self._comment = comment
        self._is_control_flow = is_control_flow

    def __str__(self):
        if self._comment:
            return '%08x %s %s (%s)' % (self._address, self._mnemonic,
                                        ' '.join(str(o) for o in self._operands),
                                        self._comment)
        else:
            return '%08x %s %s' % (self._address, self._mnemonic,
                                   ' '.join(str(o) for o in self._operands))

    def __eq__(self, other):
        return isinstance(other, Instruction) and \
               self._address == other._address and \
               self._mnemonic == other._mnemonic and \
               self._operands == other._operands

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self._address, self._mnemonic))

    @property
    def address(self):
        return self._address

    @property
    def operands(self):
        return self._operands

    @property
    def comment(self):
        return self._comment

    @comment.setter
    def comment(self, value):
        self._comment = value

    @property
    def mnemonic(self):
        return self._mnemonic

    @property
    def definitions(self):
        return filter(lambda o: o.is_written(), self._operands)

    @property
    def uses(self):
        # Does not take indirect uses on the LHS into account, e.g., [a12]#0.
        return filter(lambda o: o.is_read(), self._operands)

    @property
    def register_uses(self):
        return (u.operand for u in self.uses if isinstance(u.operand,
                                                           operands.Register))

    @property
    def is_control_flow(self):
        return self._is_control_flow

    @property
    def mnemonic(self):
        return self._mnemonic

    def rename_lhs(self, counters, stack):
        for o in filter(lambda o: o.is_written(), self._operands):
            o.rename_lhs(counters, stack)

    def rename_rhs(self, counters, stack):
        for o in filter(lambda o: o.is_read(), self._operands):
            o.rename_rhs(counters, stack)

    def contains_register(self, register):
        for op in self._operands:
            if op.operand == register:
                return True
        return False

    def contains_reg_addr_lhs(self, reg_addr):
        for op in self._operands:
            if op.is_written() and op.operand == reg_addr:
                return True
        return False

    def contains_register_rhs(self, register):
        for op in self._operands:
            if op.is_read() and op.operand == register:
                return True
        return False
