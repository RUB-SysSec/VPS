

class RegistersTricore(object):

    IMAGE_BASE = 0x80000000

    sp = 26

    d0 = 0
    d1 = d0 + 1
    d2 = d0 + 2
    d3 = d0 + 3
    d4 = d0 + 4
    d5 = d0 + 5
    d6 = d0 + 6
    d7 = d0 + 7
    d8 = d0 + 8
    d9 = d0 + 9
    d10 = d0 + 10
    d11 = d0 + 11
    d12 = d0 + 12
    d13 = d0 + 13
    d14 = d0 + 14
    d15 = d0 + 15

    a0 = 16
    a1 = a0 + 1
    a2 = a0 + 2
    a3 = a0 + 3
    a4 = a0 + 4
    a5 = a0 + 5
    a6 = a0 + 6
    a7 = a0 + 7
    a8 = a0 + 8
    a9 = a0 + 9
    a10 = a0 + 10
    a11 = a0 + 11
    a12 = a0 + 12
    a13 = a0 + 13
    a14 = a0 + 14
    a15 = a0 + 15

    e0 = 32
    e2 = e0 + 1
    e4 = e0 + 2
    e6 = e0 + 3
    e8 = e0 + 4
    e10 = e0 + 5
    e12 = e0 + 6
    e14 = e0 + 7

    retval = -1

    _to_str = {
        d0: "d0",
        d1: "d1",
        d2: "d2",
        d3: "d3",
        d4: "d4",
        d5: "d5",
        d6: "d6",
        d7: "d7",
        d8: "d8",
        d9: "d9",
        d10: "d10",
        d11: "d11",
        d12: "d12",
        d13: "d13",
        d14: "d14",
        d15: "d15",
        a0: "a0",
        a1: "a1",
        a2: "a2",
        a3: "a3",
        a4: "a4",
        a5: "a5",
        a6: "a6",
        a7: "a7",
        a8: "a8",
        a9: "a9",
        a10: "a10",
        a11: "a11",
        a12: "a12",
        a13: "a13",
        a14: "a14",
        a15: "a15",
        e0: "e0",
        e2: "e2",
        e4: "e4",
        e6: "e6",
        e8: "e8",
        e10: "e10",
        e12: "e12",
        e14: "e14",
        retval: "retval",
    }

    def __init__(self):
        pass

    def to_str(self, reg):
        if reg not in RegistersTricore._to_str:
            raise NotImplementedError('Unknown register index %d.' %
                                       reg)
        return RegistersTricore._to_str[reg]

    def to_idx(self, reg_str):
        raise NotImplementedError("Index lookup is not implemented.")