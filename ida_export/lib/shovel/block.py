
try:
    import idaapi
except ImportError:
    IS_IDA = False
else:
    IS_IDA = True

    from ida.ida_interface import *
    from idc import MakeComm, Comment


from copy import copy, deepcopy

# IDA uses module.reload, isinstance requires full type specification.
import operands
from operands import generate_name, PhiEquality


__all__ = [
    'PhiNode', 'Block'
]


class PhiNode(object):
    def __init__(self, address, definition, slot_count):
        self._address, self._definition = address, definition
        self._slots = [None] * slot_count

    @property
    def address(self):
        return self._address

    @property
    def definition(self):
        return self._definition

    @property
    def definitions(self):
        return (self._definition,)

    @property
    def slots(self):
        return self._slots

    @property
    def register_uses(self):
        return self._slots

    def rename_lhs(self, counters, stack):
        self._definition._phi_index = generate_name(self._definition,
                                                    counters, stack)

    def fill_slot(self, j, counters, stack):
        assert j < len(self._slots), 'Invalid slot index for phi function.'

        entry = deepcopy(self._definition)
        entry._phi_index = None

        entry.rename_rhs(counters, stack)
        self._slots[j] = entry

    def retrieve_slot(self, j):
        assert j < len(self._slots), 'Invalid slot index for phi function.'
        return self._slots[j]

    def __str__(self):
        incoming = ' '.join(str(i) if i else '_' for i in self._slots)
        return '%s phi %s [%s]' % (' ' * 8, str(self._definition), incoming)

    def __hash__(self):
        return hash(self._address)  # Maybe expand to Phi equality.

    def __eq__(self, other):
        return isinstance(other, PhiNode) and \
               self._address == other._address and \
               self._definition == other._definition and \
               self._slots == other._slots

    def __ne__(self, other):
        return not self == other


class Block(object):
    def __init__(self, address, end):
        self._address, self._end = address, end

        self._instructions = []
        self._predecessors, self._successors = set(), set()

        self._phi_nodes = {}
        self._in, self._out = set(), set()

        self._amoco_bb = None

    def add_instruction(self, i):
        self._instructions.append(i)

    def add_predecessor(self, p):
        self._predecessors.add(p)

    def add_successor(self, s):
        self._successors.add(s)

    def add_phi_node(self, definition):
        with operands.CoarseEquality():
            assert definition not in self._phi_nodes.keys(), \
                'Phi node already present for given definition.'

            key = deepcopy(definition)
            self._phi_nodes[key] = PhiNode(self._address, key,
                                           len(self._predecessors))

    def _predecessor_index(self, predecessor):
        return sorted(list(self._predecessors)).index(predecessor)

    def _get_phi_slot(self, phi, predecessor):
        j = self._predecessor_index(predecessor)
        return phi.retrieve_slot(j)

    def update_liveness(self, blocks):
        previous_in, previous_out = copy(self._in), copy(self._out)

        self._in.clear()
        self._out.clear()

        for successor in self._successors:
            successor = blocks[successor]

            for in_ in successor._in:
                for phi in successor._phi_nodes.values():
                    if phi.definition == in_:
                        slot = successor._get_phi_slot(phi, self._address)
                        self._out.add(slot)
                        break
                else:
                    self._out.add(in_)

        self._in = set(self.register_uses) | self._out
        self._in -= set(self.register_definitions)

        return self._in != previous_in or self._out != previous_out

    def _fill_phi_slot(self, predecessor, counters, stack):
        j = self._predecessor_index(predecessor)

        for phi in self._phi_nodes.values():
            phi.fill_slot(j, counters, stack)

    def rename(self, blocks, dominator_tree, counters, stack):
        with operands.CoarseEquality():
            for phi in self._phi_nodes.values():
                phi.rename_lhs(counters, stack)

            for i in self._instructions:
                i.rename_rhs(counters, stack)
                i.rename_lhs(counters, stack)

            for successor in self._successors:
                blocks[successor]._fill_phi_slot(self._address, counters, stack)

            for child in dominator_tree.successors(self._address):
                if child == self._address:
                    continue

                blocks[child].rename(blocks, dominator_tree, counters, stack)

            for phi in self._phi_nodes.values():
                stack[phi.definition].pop()

            for i in self._instructions:
                for d in i.definitions:
                    if isinstance(d.operand, operands.Register):
                        stack[d.operand].pop()

    def __str__(self):
        phi = '\n'.join(str(p) for p in self._phi_nodes.values())
        return phi + (phi and '\n') + '\n'.join(str(i) for i in
                                                self._instructions)

    def comment(self, annotate_liveness=False):
        assert IS_IDA, 'IDA is required for block commenting.'
        if not self._instructions:
            return

        i = self._instructions[0]

        if annotate_liveness:
            in_ = 'IN:  ' + ' '.join('%s' % str(x) for x in self._in) + '\n'
            out_ = 'OUT: ' + ' '.join('%s' % str(x) for x in self._out) + '\n'
            prefix = in_ + out_
        else:
            prefix = ''

        phi = '\n'.join(str(p) for p in self._phi_nodes.values())
        MakeComm(i.address, prefix + phi + (phi and '\n') + str(i))

        previous_address = i.address
        for i in self._instructions[1:]:
            if i.address == previous_address:
                MakeComm(i.address, '\n'.join((Comment(i.address), str(i))))
            else:
                MakeComm(i.address, str(i))
            previous_address = i.address

    @property
    def amoco_bb(self):
        return self._amoco_bb

    @amoco_bb.setter
    def amoco_bb(self, value):
        self._amoco_bb = value

    @property
    def address(self):
        return self._address

    @property
    def end(self):
        return self._end

    @property
    def register_definitions(self):
        result = set()
        for i in self._instructions:
            result.update(i.definitions)

        return (o.operand for o in result if isinstance(o.operand,
                                                        operands.Register))

    @property
    def reg_mem_definitions(self):
        result = set()
        for i in self._instructions:
            result.update(i.definitions)

        return (o.operand for o in result if isinstance(o.operand,
                                                        (operands.Register,
                                                         operands.Address)))

    @property
    def register_uses(self):
        result = set()

        for i in self._instructions:
            result.update(i.uses)

        uses = []
        for o in result:
            if isinstance(o.operand, operands.Register):
                uses.append(o.operand)

            # Uses in memory expressions (RHS).
            elif isinstance(o.operand, operands.Memory):
                uses.append(o.operand.base)

        # Uses in memory expressions (LHS).
        for i in self._instructions:
            for d in i.definitions:
                if isinstance(d.operand, operands.Memory):
                    uses.append(d.operand.base)

        return uses

    def is_incoming(self, definition):
        if definition in self._in:
            return True

        for phi in self._phi_nodes.values():
            if definition in phi.slots:
                return True

        return False

    def concrete_in(self):
        result = set()

        for definition in self._in:
            for phi in self._phi_nodes.values():
                if definition == phi.definition:
                    result.update(phi.slots)
                    break
            else:
                result.add(definition)

        return result

    def is_outgoing(self, definition):
        with PhiEquality():
            return definition in self._out

    @property
    def successors(self):
        return self._successors

    @property
    def predecessors(self):
        return self._predecessors

    @property
    def new_definitions(self):
        return set(self._out - self._in)

    def instructions(self, start_address=None, reverse=False):
        index = 0
        if start_address is not None:
            for i, instr in enumerate(self._instructions):
                if instr.address == start_address:
                    index = i
                    break
            else:
                index = None

        if index is not None:
            if reverse:
                if not start_address:
                    iterator = reversed(self._instructions)
                else:
                    iterator = reversed(self._instructions[:index + 1])
            else:
                iterator = self._instructions[index:]

            for instr in iterator:
                yield instr
