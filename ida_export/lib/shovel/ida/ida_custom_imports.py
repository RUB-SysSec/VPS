
import os
import sys


'''
Prerequisites:
    - networkx (2.0.dev)
    - decorator (4.0.10)
    - pydot (1.2.2)

pip install requirements/networkx-2.0.dev*.tar.gz
'''


_POTENTIAL_PATHS = [
    '/usr/lib/python2.7/dist-packages',
    '/usr/local/lib/python2.7/dist-packages',
    os.path.join(os.path.expanduser('~'),
                 '.local/lib/python2.7/site-packages'),
]

for p in _POTENTIAL_PATHS:
    sys.path.append(p)


try:
    import networkx as nx
except ImportError:
    print('networkx may be missing.')
    raise


__all__ = [
    'nx'
]
