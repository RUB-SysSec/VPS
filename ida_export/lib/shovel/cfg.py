
try:
    import idaapi
except ImportError:
    IS_IDA = False
else:
    IS_IDA = True

    from ida.ida_interface import *
    from ida.decode import *

    from idc import GetFunctionAttr, FUNCATTR_START

import os
import struct

from ctypes import c_int16, c_uint32
from collections import defaultdict


import block
import operands
import instruction

from ida.ida_custom_imports import nx

__all__ = ['Function', 'Analysis']


def compute_address(memory, base=0, consider_post=False):
    result = base + c_int16(memory.offset.value).value + \
             memory._pre_increment + \
             (memory._post_increment if consider_post else 0)

    return result


class Function(object):
    ID_ENTRY_BLOCK = c_uint32(-1).value
    ID_EXIT_BLOCK = c_uint32(-2).value

    def __init__(self, address):
        assert IS_IDA, 'IDA is required for function construction.'

        self._address = GetFunctionAttr(address, FUNCATTR_START)
        self._entry = address

        self._graph = nx.DiGraph()
        self._blocks, self._successors = {}, defaultdict(set)

        self._unified_exit = block.Block(Function.ID_EXIT_BLOCK,
                                         Function.ID_EXIT_BLOCK)
        self._unified_entry = block.Block(Function.ID_ENTRY_BLOCK,
                                          Function.ID_ENTRY_BLOCK)

        self._build_cfg()

        self._stack, self._counters = defaultdict(lambda: [0]), \
                                      defaultdict(lambda: 1)
        self._definitions = {}
        self._uses, self._register_uses = defaultdict(set), defaultdict(set)

    def __getstate__(self):
        return self._address, self._graph, self._blocks, \
               self._unified_exit, self._unified_entry, self._entry, \
               self._successors

    def __setstate__(self, state):
        self._address, self._graph, self._blocks, self._unified_exit, \
            self._unified_entry, self._entry, _ = state

        self._stack, self._counters = defaultdict(lambda: [0]), \
                                      defaultdict(lambda: 1)

        self._definitions = {}
        self._successors = {}  # Only used for building graph.

        self._uses, self._register_uses = defaultdict(set), defaultdict(set)

        self._update_definitions_uses()

    @property
    def address(self):
        return self._address

    @property
    def graph(self):
        return self._graph

    @property
    def blocks(self):
        return self._blocks

    @property
    def uses(self):
        return self._uses

    @property
    def register_uses(self):
        return self._register_uses

    @property
    def definitions(self):
        return self._definitions

    def _build_cfg(self):
        decode_function(self)

        for b, successors in self._successors.iteritems():
            for s in successors:
                self._blocks[s].add_predecessor(b)
                self._blocks[b].add_successor(s)

                self._graph.add_edge(b, s)
        else:
            self._graph.add_node(self._address)

        for address, block in self._blocks.iteritems():
            if len(self._successors[address]) == 0:
                self._unified_exit.add_predecessor(address)
                block.add_successor(Function.ID_EXIT_BLOCK)

                self._graph.add_edge(address, Function.ID_EXIT_BLOCK)

            if len(block.predecessors) == 0 or address == self._address:
                self._unified_entry.add_successor(address)
                block.add_predecessor(Function.ID_ENTRY_BLOCK)

                self._graph.add_edge(Function.ID_ENTRY_BLOCK, address)

        self._blocks[Function.ID_ENTRY_BLOCK] = self._unified_entry
        self._blocks[Function.ID_EXIT_BLOCK] = self._unified_exit

        self._entry = Function.ID_ENTRY_BLOCK

    def __str__(self):
        header = '; function %08x\n\n' % self._address
        return header + '\n\n'.join(str(b) for b in
                                    sorted(self._blocks.values(),
                                           key=lambda b: b.address))

    def _collect_definitions(self):
        definitions = defaultdict(set)
        for b in self._blocks.values():
            for r in b.register_definitions:
                definitions[r].add(b.address)

        return definitions

    def calculate_control_dependence(self):
        h = nx.reverse(self._graph, copy=True)
        return nx.dominance_frontiers(h, Function.ID_EXIT_BLOCK)

    def _place_phi_nodes(self, definitions):
        frontiers = nx.dominance_frontiers(self._graph, self._entry)

        for definition, occurrences in definitions.iteritems():
            dom_fron_plus = set()
            seen = set()
            work = set()

            for o in occurrences:
                seen.add(o)
                work.add(o)

            while work:
                current = work.pop()
                for node in frontiers.get(current, []):
                    if node in dom_fron_plus:
                        continue

                    self._blocks[node].add_phi_node(definition)
                    dom_fron_plus.add(node)

                    if node not in seen:
                        seen.add(node)
                        work.add(node)

    def _rename_uses(self):
        dominators = nx.immediate_dominators(self._graph, self._entry)
        dominator_tree = nx.DiGraph()

        for node in dominators.keys():
            dominator_tree.add_edge(dominators[node], node)

        self._blocks[self._entry].rename(self._blocks, dominator_tree,
                                         self._counters, self._stack)

    def transform(self):
        with operands.CoarseEquality():
            definitions = self._collect_definitions()

            self._place_phi_nodes(definitions)
            self._rename_uses()

        self._prune()
        self._update_definitions_uses()

    def _update_definitions_uses(self):
        self._uses, self._definitions = defaultdict(set), defaultdict(set)

        # TODO using sets for definitions no longer necessary when memory SSA available

        for b in self._blocks.values():
            for i in b.instructions():
                for d in i.definitions:
                    if isinstance(d.operand, operands.Address):
                        self._definitions[d.operand].add(i)
                        continue
                    self._definitions[d.operand].add(i)
                    if isinstance(d.operand, operands.Memory):
                        self._uses[d.operand.base].add(i)

                for u in i.uses:
                    self._uses[u.operand].add(i)
                    if isinstance(u.operand, operands.Memory):
                        self._uses[u.operand.base].add(i)

                for u in i.register_uses:
                    self._register_uses[u].add(i)

            for phi in b._phi_nodes.values():
                self._definitions[phi.definition].add(phi)
                for u in phi.slots:
                    self._uses[u].add(phi)

    def _calculate_liveness(self):
        for block in self._blocks.values():
            block._in.clear()
            block._out.clear()

        while True:
            any_change = False

            for block in nx.dfs_postorder_nodes(self._graph, self._entry):
                if block in (Function.ID_EXIT_BLOCK,
                             Function.ID_ENTRY_BLOCK):
                    continue

                change = self._blocks[block].update_liveness(self._blocks)
                any_change = any_change or change

            if not any_change:
                break

    def _prune(self):
        self._calculate_liveness()

        with operands.CoarseEquality():
            prune_phi, prune_cconv = set(), defaultdict(set)

            # Prune phi backwards.
            for block in self._blocks.values():
                for definition in block._phi_nodes.keys():
                    with operands.PhiEquality():
                        if definition not in block._in:
                            prune_phi.add((block, definition))

            for block, definition in prune_phi:
                del block._phi_nodes[definition]

            # Prune cconv forwards.
            for block in self._blocks.values():
                for i, instr in enumerate(block._instructions):
                    if not isinstance(instr, instruction.CallingConvention):
                        continue

                    with operands.PhiEquality():
                        definition = instr.definitions[0].operand

                        if not any(self._blocks[s].is_incoming(definition)
                                   for s in block.successors) and \
                                definition not in block.register_uses:
                            prune_cconv[block].add(i)

            with operands.PhiEquality():
                for block, candidates in prune_cconv.iteritems():
                    block._instructions = [instr for i, instr in
                                           enumerate(block._instructions)
                                           if i not in candidates]

    def comment(self):
        assert IS_IDA, 'IDA is required for placing comments.'
        for b in self._blocks.values():
            b.comment()

    def get_containing_block(self, address):
        for block in self._blocks.values():
            if block.address <= address < block.end:
                return block

        return None

    def get_instruction_for_address(self, address):
        block = self.get_containing_block(address)
        if block is None:
            return None
        for instr in block.instructions(address):
            if instr.address == address:
                return instr
        return None

    def contains(self, address):
        return self.get_containing_block(address) is not None
