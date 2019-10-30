#ifndef AMD64_SSA_H
#define AMD64_SSA_H

#include <map>
#include <vector>
#include <string>
#include <sstream>
#include "amd64.h"

static std::map<uint32_t, std::string> AMD64_DISPLAY_REGISTERS_SSA = []{
    std::map<uint32_t, std::string> result;

    result[0] = "rax";
    result[1] = "rcx";
    result[2] = "rdx";
    result[3] = "rbx";
    result[4] = "rsp";
    result[5] = "rbp";
    result[6] = "rsi";
    result[7] = "rdi";
    result[8] = "r8";
    result[9] = "r9";
    result[10] = "r10";
    result[11] = "r11";
    result[12] = "r12";
    result[13] = "r13";
    result[14] = "r14";
    result[15] = "r15";
    result[16] = "al";
    result[17] = "cl";
    result[18] = "dl";
    result[19] = "bl";
    result[20] = "ah";
    result[21] = "ch";
    result[22] = "dh";
    result[23] = "bh";
    result[25] = "bpl";
    result[26] = "sil";
    result[27] = "dil";
    result[64] = "xmm0";
    result[65] = "xmm1";
    result[66] = "xmm2";
    result[67] = "xmm3";
    result[68] = "xmm4";
    result[69] = "xmm5";
    result[70] = "xmm6";
    result[71] = "xmm7";
    result[72] = "xmm8";
    result[73] = "xmm9";
    result[74] = "xmm10";
    result[75] = "xmm11";
    result[76] = "xmm12";
    result[77] = "xmm13";
    result[78] = "xmm14";
    result[79] = "xmm15";

    return result;
}();

static std::vector<uint32_t> AMD64_SYSTEM_V_ARG_REGS_SSA = []{
    std::vector<uint32_t> result;
    result.push_back(7); // rdi
    result.push_back(6); // rsi
    result.push_back(2); // rdx
    result.push_back(1); // rcx
    result.push_back(8); // r8
    result.push_back(9); // r9

    return result;
}();

const std::shared_ptr<Register> &convert_ssa_reg_to_vex_reg(uint32_t index);


#endif // AMD64_SSA_H
