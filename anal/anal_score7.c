/* radare - LGPL - Copyright 2020 - LiraNuna */
#include <stdint.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#define BIT_RANGE(x, start, size) ((x >> start) & ((1 << size) - 1))

static int32_t sign_extend(uint32_t x, uint8_t b) {
    uint32_t m = 1UL << (b - 1);

    x = x & ((1UL << b) - 1);
    return (x ^ m) - m;
}

static void anal16(RAnal *anal, RAnalOp *aop, uint32_t addr, uint16_t insn) {
    switch (BIT_RANGE(insn, 12, 3)) {
        case 0x0: {
            uint32_t rA = BIT_RANGE(insn, 4, 4);
            uint32_t rD = BIT_RANGE(insn, 8, 4);
            switch (BIT_RANGE(insn, 0, 4)) {
                case 0x0: // nop
                    aop->type = R_ANAL_OP_TYPE_NOP;
                    return;
                case 0x1: // mlfh! rD, rA
                case 0x2: // mhfl! rD, rA
                case 0x3: // mv! rD, rA
                    aop->type = R_ANAL_OP_TYPE_MOV;
                    return;
                case 0x4: // br{cond}! rA
                    if (rD == 15) {
                        aop->type = R_ANAL_OP_TYPE_CJMP;
                        aop->fail = addr + 2;
                    } else {
                        aop->type = R_ANAL_OP_TYPE_JMP;
                    }
                    aop->eob = true;
                    return;
                case 0x5: // t{cond}!
                    aop->type = R_ANAL_OP_TYPE_CMP;
                    return;
                case 0xC: // br{cond}l! rA
                    if (rD == 15) {
                        aop->type = R_ANAL_OP_TYPE_CALL;
                        aop->fail = addr + 2;
                    } else {
                        aop->type = R_ANAL_OP_TYPE_CCALL;
                    }
                    return;
                default:
                    aop->type = R_ANAL_OP_TYPE_UNK;
                    return;
            }
        }
        case 0x1: {
            uint32_t rA = BIT_RANGE(insn, 4, 4);
            switch (BIT_RANGE(insn, 0, 4)) {
                case 0x0:
                    switch (BIT_RANGE(insn, 8, 4)) {
                        case 0x0: // mtcel! rA
                        case 0x1: // mtceh! rA
                            aop->type = R_ANAL_OP_TYPE_MOV;
                            return;
                        default:
                            aop->type = R_ANAL_OP_TYPE_UNK;
                            return;
                    }
                case 0x1:
                    switch (BIT_RANGE(insn, 8, 4)) {
                        case 0x0: // mfcel! rA
                        case 0x1: // mfceh! rA
                            aop->type = R_ANAL_OP_TYPE_MOV;
                            return;
                        default:
                            aop->type = R_ANAL_OP_TYPE_UNK;
                            return;
                    }
                default:
                    aop->type = R_ANAL_OP_TYPE_UNK;
                    return;
            }
        }
        case 0x2: {
            uint32_t rA = BIT_RANGE(insn, 4, 4);
            uint32_t rD = BIT_RANGE(insn, 8, 4);
            uint32_t rAh = BIT_RANGE(insn, 4, 3);
            uint32_t rH = BIT_RANGE(insn, 7, 1) << 4;
            switch (BIT_RANGE(insn, 0, 4)) {
                case 0x0: // add! rD, rA
                    aop->type = R_ANAL_OP_TYPE_ADD;
                    return;
                case 0x1: // sub rD, rA
                case 0x2: // neg! rD, rA
                    aop->type = R_ANAL_OP_TYPE_SUB;
                    return;
                case 0x3: // cmp! rD, rA;
                    aop->type = R_ANAL_OP_TYPE_CMP;
                    return;
                case 0x4: // and! rD, rA
                    aop->type = R_ANAL_OP_TYPE_AND;
                    return;
                case 0x5: // or! rD, rA
                    aop->type = R_ANAL_OP_TYPE_OR;
                    return;
                case 0x6: // not! rD, rA
                    aop->type = R_ANAL_OP_TYPE_NOT;
                    return;
                case 0x7: // xor! rD, rA
                    aop->type = R_ANAL_OP_TYPE_XOR;
                    return;
                case 0x8: // lw! rD, [rA]
                case 0x9: // lh! rD, [rA]
                case 0xB: // lbu! rD, [rA]
                    aop->type = R_ANAL_OP_TYPE_LOAD;
                    return;
                case 0xA: // pop!, rD + rH, [rAh]
                    aop->type = R_ANAL_OP_TYPE_POP;
                    return;
                case 0xC: // sw! rD, [rA]
                case 0xD: // sh! rD, [rA]
                case 0xF: // sb! rD, [rA]
                    aop->type = R_ANAL_OP_TYPE_STORE;
                    return;
                case 0xE: // push!, rD + rH, [rAh]
                    aop->type = R_ANAL_OP_TYPE_PUSH;
                    return;
            }
        }
        case 0x3: // j! imm12
            aop->type = R_ANAL_OP_TYPE_JMP;
            aop->jump = (addr & 0xFFFFF000) | (BIT_RANGE(insn, 1, 11) << 1);
            aop->eob = true;
            return;
        case 0x4: // b{cond}! imm8
            if (BIT_RANGE(insn, 8, 4) == 15) {
                aop->type = R_ANAL_OP_TYPE_JMP;
            } else {
                aop->type = R_ANAL_OP_TYPE_CJMP;
                aop->fail = addr + 2;
            }

            aop->jump = addr + (sign_extend(BIT_RANGE(insn, 0, 8), 8) << 1);
            return;
        case 0x5: // ldiu!, rD, imm8
            aop->type = R_ANAL_OP_TYPE_LOAD;
            return;
        case 0x6: {
            uint32_t rD = BIT_RANGE(insn, 8, 4);
            uint32_t imm5 = BIT_RANGE(insn, 3, 5);
            switch (BIT_RANGE(insn, 0, 3)) {
                case 0x0: // addei! rD, imm5
                    aop->type = R_ANAL_OP_TYPE_ADD;
                    return;
                case 0x1: // slli! rD, imm5
                    aop->type = R_ANAL_OP_TYPE_SHL;
                    return;
                case 0x2: // sdbbp, imm5
                    aop->type = R_ANAL_OP_TYPE_ILL;
                    return;
                case 0x3: // srli! rD, imm5
                    aop->type = R_ANAL_OP_TYPE_SHR;
                    return;
                case 0x4: // bitclr! rD, imm5);
                    aop->type = R_ANAL_OP_TYPE_AND;
                    return;
                case 0x5: // bitset! rD, imm5);
                    aop->type = R_ANAL_OP_TYPE_OR;
                    return;
                case 0x6: // bittst! rD, imm5);
                    aop->type = R_ANAL_OP_TYPE_CMP;
                    return;
                case 0x7:
                    aop->type = R_ANAL_OP_TYPE_UNK;
                    return;
            }
        }
        case 0x7: {
            uint32_t rD = BIT_RANGE(insn, 8, 4);
            uint32_t imm5 = BIT_RANGE(insn, 3, 5);
            switch (BIT_RANGE(insn, 0, 3)) {
                case 0x0: // lwp!, rD, imm5 << 2);
                case 0x1: // lhp!, rD, imm5 << 1);
                case 0x3: // lbup! rD, imm5);
                    aop->type = R_ANAL_OP_TYPE_LOAD;
                    return;
                case 0x4: // OP_RD(I16("swp"), rD, imm5 << 2);
                case 0x5: // OP_RD(I16("shp"), rD, imm5 << 1);
                case 0x6: // OP_RD(I16("sbp"), rD, imm5);
                    aop->type = R_ANAL_OP_TYPE_STORE;
                    return;
                default:
                    aop->type = R_ANAL_OP_TYPE_UNK;
                    return;
            }
        }
    }
}

static int score7_anop(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
    memset(op, '\0', sizeof(RAnalOp));
    if (len < 2) {
        return 0;
    }
    ut32 instruction = *(ut16 *) data;
    if (instruction & 0x8000) {
        if (len < 4) {
            return 0;
        }

        op->size = 4;
    } else {
        anal16(anal, op, addr, instruction);
        op->size = 2;
    }
    return op->size;
}

struct r_anal_plugin_t r_anal_plugin_score7 = {
    .name = "score7",
    .desc = "score7 analysis plugin",
    .license = "LGPL3",
    .arch = "score7",
    .bits = 32,
    .init = NULL,
    .fini = NULL,
    .op = &score7_anop,
    .set_reg_profile = NULL,
    .fingerprint_bb = NULL,
    .fingerprint_fcn = NULL,
    .diff_bb = NULL,
    .diff_fcn = NULL,
    .diff_eval = NULL
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ANAL,
    .data = &r_anal_plugin_score7,
    .version = R2_VERSION
};
#endif
