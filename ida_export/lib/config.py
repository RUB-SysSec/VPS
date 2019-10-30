# Import paths in order to work with pypy (i.e., networkx will not be found otherwise).
import os
import sys
_POTENTIAL_PATHS = [
    '/usr/lib/python2.7/dist-packages',
    '/usr/local/lib/python2.7/dist-packages',
    os.path.join(os.path.expanduser('~'),
                 '.local/lib/python2.7/site-packages'),
]

for p in _POTENTIAL_PATHS:
    sys.path.append(p)

import __builtin__
from collections import OrderedDict
from shovel.arch import RegistersX64


__builtin__.REGISTERS = RegistersX64()


# Argument registers for System-V ABI
_ARG_REGISTERS = [RegistersX64.rdi,
                 RegistersX64.rsi,
                 RegistersX64.rdx,
                 RegistersX64.rcx,
                 RegistersX64.r8,
                 RegistersX64.r9]

_CTOR_CALL_DEPTH = 3
_MAX_PROCESSING_ROUNDS = 150

DEBUG_GRAPHS_DUMP_ALL = False
DEBUG_GRAPH_DUMP_DIR = "/home/sqall/tmp/"
__builtin__.DEBUG_CURRENT_GRAPH_DUMP_DIR = None

_HIGHLIGHTING = OrderedDict()
_HIGHLIGHTING['(start_instr)'] = '#ffe4e1'
_HIGHLIGHTING['(vtable)'] = '#c6e2ff'
temp_key = "(using %s)" % __builtin__.REGISTERS.to_str(_ARG_REGISTERS[0])
_HIGHLIGHTING[temp_key] = '#a6f2ff'
_HIGHLIGHTING['Ctor_'] = '#e8f1d4'
_HIGHLIGHTING['(new operator)'] = '#d8f1c4'
_HIGHLIGHTING['(VTV)'] = '#f1c4ed'