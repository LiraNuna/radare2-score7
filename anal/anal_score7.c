/* radare - LGPL - Copyright 2020 - LiraNuna */
#include <stdint.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#define BIT_RANGE(x, start, size) ((x >> start) & ((1 << size) - 1))

static const char *REGISTERS[] = {
    "r0", "r1", "r2", "r3",
    "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11",
    "r12", "r13", "r14", "r15",
    "r16", "r17", "r18", "r19",
    "r20", "r21", "r22", "r23",
    "r24", "r25", "r26", "r27",
    "r28", "r29", "r30", "r31",
};

static int32_t sign_extend(uint32_t x, uint8_t b) {
    uint32_t m = 1UL << (b - 1);

    x = x & ((1UL << b) - 1);
    return (x ^ m) - m;
}

static _RAnalCond CONDITIONALS[] = {
    R_ANAL_COND_HS, R_ANAL_COND_LO,
    R_ANAL_COND_HI, R_ANAL_COND_LS,
    R_ANAL_COND_EQ, R_ANAL_COND_NE,
    R_ANAL_COND_GT, R_ANAL_COND_LE,
    R_ANAL_COND_GE, R_ANAL_COND_LT,
    R_ANAL_COND_MI, R_ANAL_COND_PL,
    R_ANAL_COND_VS, R_ANAL_COND_VC,
    R_ANAL_COND_NV, R_ANAL_COND_AL,
};

static bool set_reg_profile(RAnal *anal) {
    const char *p = \
        "=PC    pc\n"
        "=SP    r0\n"
        "=LR    r3\n"
        "=BP    r2\n"
        "gpr    r0      .32 0   0\n"
        "gpr    r1      .32 4   0\n"
        "gpr    r2      .32 8   0\n"
        "gpr    r3      .32 12  0\n"
        "gpr    r4      .32 16  0\n"
        "gpr    r5      .32 20  0\n"
        "gpr    r6      .32 24  0\n"
        "gpr    r7      .32 28  0\n"
        "gpr    r8      .32 32  0\n"
        "gpr    r9      .32 36  0\n"
        "gpr    r10     .32 40  0\n"
        "gpr    r11     .32 44  0\n"
        "gpr    r12     .32 48  0\n"
        "gpr    r13     .32 52  0\n"
        "gpr    r14     .32 56  0\n"
        "gpr    r15     .32 60  0\n"
        "gpr    r16     .32 64  0\n"
        "gpr    r17     .32 68  0\n"
        "gpr    r18     .32 72  0\n"
        "gpr    r19     .32 76  0\n"
        "gpr    r20     .32 80  0\n"
        "gpr    r21     .32 84  0\n"
        "gpr    r22     .32 88  0\n"
        "gpr    r23     .32 92  0\n"
        "gpr    r24     .32 96  0\n"
        "gpr    r25     .32 100 0\n"
        "gpr    r27     .32 104 0\n"
        "gpr    r28     .32 108 0\n"
        "gpr    r29     .32 112 0\n"
        "gpr    r30     .32 116 0\n"
        "gpr    r31     .32 120 0\n";

    return r_reg_set_profile_string(anal->reg, p);
}


static void anal32(RAnal *anal, RAnalOp *aop, uint32_t addr, uint32_t insn) {
    switch(BIT_RANGE(insn, 25, 5)) {
        case 0x02: // j[l] imm24
            aop->eob = true;
            aop->type = BIT_RANGE(insn, 0, 1) ? R_ANAL_OP_TYPE_CALL : R_ANAL_OP_TYPE_JMP;
            aop->jump = (addr & 0xFC000000) | (BIT_RANGE(insn, 1, 24) << 1);
            return;
        case 0x04: //b{cond}[l] imm20
            aop->eob = true;
            aop->type = BIT_RANGE(insn, 0, 1) ? R_ANAL_OP_TYPE_CALL : R_ANAL_OP_TYPE_JMP;
            aop->cond = CONDITIONALS[BIT_RANGE(insn, 10, 5)];
            aop->type |= (aop->cond != R_ANAL_COND_AL) * R_ANAL_OP_TYPE_COND;
            aop->jump = addr + sign_extend(((BIT_RANGE(insn, 15, 10) << 9) | BIT_RANGE(insn, 1, 9)) << 1, 20);
            return;
    }
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
                    aop->eob = true;
                    aop->reg = REGISTERS[rA];
                    aop->cond = CONDITIONALS[rD];

                    if (rA == 3) { // r3 is a return
                        aop->type = R_ANAL_OP_TYPE_RET;
                    } else {
                        aop->type = R_ANAL_OP_TYPE_RJMP;
                    }

                    aop->type |= (aop->cond != R_ANAL_COND_AL) * R_ANAL_OP_TYPE_COND;
                    return;
                case 0x5: // t{cond}!
                    aop->type = R_ANAL_OP_TYPE_CMP;
                    return;
                case 0xC: // br{cond}l! rA
                    aop->eob = true;
                    aop->reg = REGISTERS[rA];
                    aop->cond = CONDITIONALS[rD];
                    aop->type = R_ANAL_OP_TYPE_RCALL;
                    aop->type |= (aop->cond != R_ANAL_COND_AL) * R_ANAL_OP_TYPE_COND;
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
        case 0x3: // j{l}! imm12
            aop->eob = true;
            aop->type = BIT_RANGE(insn, 0, 1) ? R_ANAL_OP_TYPE_CALL : R_ANAL_OP_TYPE_JMP;
            aop->jump = (addr & 0xFFFFF000) | (BIT_RANGE(insn, 1, 11) << 1);
            return;
        case 0x4: // b{cond}! imm8
            aop->eob = true;
            aop->cond = CONDITIONALS[BIT_RANGE(insn, 8, 4)];
            aop->type = R_ANAL_OP_TYPE_JMP;
            aop->type |= (aop->cond != R_ANAL_COND_AL) * R_ANAL_OP_TYPE_COND;
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
                case 0x0: // lwp!, rD, imm5 << 2;
                case 0x1: // lhp!, rD, imm5 << 1;
                case 0x3: // lbup! rD, imm5;
                    aop->type = R_ANAL_OP_TYPE_LOAD;
                    return;
                case 0x4: // swp rD, imm5
                case 0x5: // shp rD, imm5
                case 0x6: // sbp rD, imm5
                    aop->type = R_ANAL_OP_TYPE_STORE;
                    return;
                default:
                    aop->type = R_ANAL_OP_TYPE_UNK;
                    return;
            }
        }
    }
}

static int score7_anop(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buffer, int length, RAnalOpMask mask) {
    memset(op, '\0', sizeof(RAnalOp));
    if (length < 2) {
        return 0;
    }
    ut32 instruction = *(ut16 *) buffer;
    if (instruction & 0x8000) {
        if (length < 4) {
            return 0;
        }

        // Remove p0 and p1 bits before handling the instruction as 30bit
        instruction &= 0x00007FFF;
        instruction |= *(uint16_t *) (buffer + 2) << 15;
        instruction &= 0x3FFFFFFF;

        op->size = 4;
        anal32(anal, op, addr, instruction);
    } else {
        op->size = 2;
        anal16(anal, op, addr, instruction);
    }

    op->fail = addr + op->size;
    return op->size;
}

struct r_anal_plugin_t r_anal_plugin_score7 = {
    .name = "score7",
    .arch = "score7",
    .desc = "SunPlus S⁺core7 analysis plugin",
    .license = "LGPL3",
    .bits = 32,
    .init = NULL,
    .fini = NULL,
    .diff_bb = NULL,
    .diff_fcn = NULL,
    .diff_eval = NULL,
    .fingerprint_bb = NULL,
    .fingerprint_fcn = NULL,
    .op = &score7_anop,
    .set_reg_profile = &set_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ANAL,
    .data = &r_anal_plugin_score7,
    .version = R2_VERSION
};
#endif
