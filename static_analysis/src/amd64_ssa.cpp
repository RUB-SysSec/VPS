#include "amd64_ssa.h"

using namespace std;

const shared_ptr<Register> &convert_ssa_reg_to_vex_reg(uint32_t index) {
    switch(index) {
        case 0:
            return register_rax;
        case 1:
            return register_rcx;
        case 2:
            return register_rdx;
        case 3:
            return register_rbx;
        case 4:
            return register_rsp;
        case 5:
            return register_rbp;
        case 6:
            return register_rsi;
        case 7:
            return register_rdi;
        case 8:
            return register_r8;
        case 9:
            return register_r9;
        case 10:
            return register_r10;
        case 11:
            return register_r11;
        case 12:
            return register_r12;
        case 13:
            return register_r13;
        case 14:
            return register_r14;
        case 15:
            return register_r15;
        default:
            stringstream err_msg;
            err_msg << "Do not know how to convert index "
                    << dec << index
                    << " into vex registers.";
            throw runtime_error(err_msg.str().c_str());
    }
}
