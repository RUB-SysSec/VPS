

class RegistersX64(object):

    rax = 0
    rcx = 1
    rdx = 2
    rbx = 3
    rsp = 4
    rbp = 5
    rsi = 6
    rdi = 7
    r8 = 8
    r9 = 9
    r10 = 10
    r11 = 11
    r12 = 12
    r13 = 13
    r14 = 14
    r15 = 15
    al = 16
    cl = 17
    dl = 18
    bl = 19
    ah = 20
    ch = 21
    dh = 22
    bh = 23
    spl = 24
    bpl = 25
    sil = 26
    dil = 27
    mm0 = 56
    mm1 = 57
    mm2 = 58
    mm3 = 59
    mm4 = 60
    mm5 = 61
    mm6 = 62
    mm7 = 63
    xmm0 = 64
    xmm1 = 65
    xmm2 = 66
    xmm3 = 67
    xmm4 = 68
    xmm5 = 69
    xmm6 = 70
    xmm7 = 71
    xmm8 = 72
    xmm9 = 73
    xmm10 = 74
    xmm11 = 75
    xmm12 = 76
    xmm13 = 77
    xmm14 = 78
    xmm15 = 79
    ymm0 = 81
    ymm1 = 82
    ymm2 = 83
    ymm3 = 84
    ymm4 = 85
    ymm5 = 86
    ymm6 = 87
    ymm7 = 88
    ymm8 = 89
    ymm9 = 90
    ymm10 = 91
    ymm11 = 92
    ymm12 = 93
    ymm13 = 94
    ymm14 = 95
    ymm15 = 96

    _to_str = {
        rax: "rax",
        rcx: "rcx",
        rdx: "rdx",
        rbx: "rbx",
        rsp: "rsp",
        rbp: "rbp",
        rsi: "rsi",
        rdi: "rdi",
        r8: "r8",
        r9: "r9",
        r10: "r10",
        r11: "r11",
        r12: "r12",
        r13: "r13",
        r14: "r14",
        r15: "r15",
        al: "al",
        cl: "cl",
        dl: "dl",
        bl: "bl",
        ah: "ah",
        ch: "ch",
        dh: "dh",
        bh: "bh",
        spl: "spl",
        bpl: "bpl",
        sil: "sil",
        dil: "dil",
        mm0: "mm0",
        mm1: "mm1",
        mm2: "mm2",
        mm3: "mm3",
        mm4: "mm4",
        mm5: "mm5",
        mm6: "mm6",
        mm7: "mm7",
        xmm0: "xmm0",
        xmm1: "xmm1",
        xmm2: "xmm2",
        xmm3: "xmm3",
        xmm4: "xmm4",
        xmm5: "xmm5",
        xmm6: "xmm6",
        xmm7: "xmm7",
        xmm8: "xmm8",
        xmm9: "xmm9",
        xmm10: "xmm10",
        xmm11: "xmm11",
        xmm12: "xmm12",
        xmm13: "xmm13",
        xmm14: "xmm14",
        xmm15: "xmm15",
        ymm0: "ymm0",
        ymm1: "ymm1",
        ymm2: "ymm2",
        ymm3: "ymm3",
        ymm4: "ymm4",
        ymm5: "ymm5",
        ymm6: "ymm6",
        ymm7: "ymm7",
        ymm8: "ymm8",
        ymm9: "ymm9",
        ymm10: "ymm10",
        ymm11: "ymm11",
        ymm12: "ymm12",
        ymm13: "ymm13",
        ymm14: "ymm14",
        ymm15: "ymm15",
    }

    _to_idx = {
        "eax": rax,
        "ecx": rcx,
        "edx": rdx,
        "ebx": rbx,
        "esp": rsp,
        "ebp": rbp,
        "esi": rsi,
        "edi": rdi,
        "rax": rax,
        "rcx": rcx,
        "rdx": rdx,
        "rbx": rbx,
        "rsp": rsp,
        "rbp": rbp,
        "rsi": rsi,
        "rdi": rdi,
        "r8d": r8,
        "r9d": r9,
        "r10d": r10,
        "r11d": r11,
        "r12d": r12,
        "r13d": r13,
        "r14d": r14,
        "r15d": r15,
        "r8": r8,
        "r9": r9,
        "r10": r10,
        "r11": r11,
        "r12": r12,
        "r13": r13,
        "r14": r14,
        "r15": r15,
        "al": al,
        "cl": cl,
        "dl": dl,
        "bl": bl,
        "ah": ah,
        "ch": ch,
        "dh": dh,
        "bh": bh,
        "spl": spl,
        "bpl": bpl,
        "sil": sil,
        "dil": dil,
        "xmm0": xmm0,
        "xmm1": xmm1,
        "xmm2": xmm2,
        "xmm3": xmm3,
        "xmm4": xmm4,
        "xmm5": xmm5,
        "xmm6": xmm6,
        "xmm7": xmm7,
        "xmm8": xmm8,
        "xmm9": xmm9,
        "xmm10": xmm10,
        "xmm11": xmm11,
        "xmm12": xmm12,
        "xmm13": xmm13,
        "xmm14": xmm14,
        "xmm15": xmm15,
        "ymm0": ymm0,
        "ymm1": ymm1,
        "ymm2": ymm2,
        "ymm3": ymm3,
        "ymm4": ymm4,
        "ymm5": ymm5,
        "ymm6": ymm6,
        "ymm7": ymm7,
        "ymm8": ymm8,
        "ymm9": ymm9,
        "ymm10": ymm10,
        "ymm11": ymm11,
        "ymm12": ymm12,
        "ymm13": ymm13,
        "ymm14": ymm14,
        "ymm15": ymm15,
    }

    def __init__(self):
        pass

    def to_str(self, reg):
        if reg not in RegistersX64._to_str:
            raise NotImplementedError('Unknown register index %d.' %
                                       reg)
        return RegistersX64._to_str[reg]

    def to_idx(self, reg_str):
        if reg_str not in RegistersX64._to_idx:
            raise NotImplementedError('Unknown register string %s.' %
                                       reg_str)
        return RegistersX64._to_idx[reg_str]