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
	return r_reg_set_profile_string (anal->reg, p);
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
                    aop->jump = rA;
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
        case 0x3: { // OP_W(IL16("j", BIT_RANGE(insn, 0, 1)),
            //   (uint32_t)(rasm->pc & 0xFFFFF000) | (BIT_RANGE(insn, 1, 11) << 1));
            aop->type = R_ANAL_OP_TYPE_JMP;
            aop->jump = (addr & 0xFFFFF000) | (BIT_RANGE(insn, 1, 11) << 1);
            aop->eob = true;
            return;
        }
        case 0x4: { //OP_W(IBL16("b", BIT_RANGE(insn, 8, 4), false),
            //  (uint32_t)rasm->pc + (sign_extend(BIT_RANGE(insn, 0, 8), 8) << 1));
            if (BIT_RANGE(insn, 8, 4) == 15) {
                aop->type = R_ANAL_OP_TYPE_JMP;
            } else {
                aop->type = R_ANAL_OP_TYPE_CJMP;
                aop->fail = addr + 2;
            }
            aop->jump = addr + (sign_extend(BIT_RANGE(insn, 0, 8), 8) << 1);
            return;
        }
        case 0x5: { //OP_RD(I16("ldiu"), BIT_RANGE(insn, 8, 4), BIT_RANGE(insn, 0, 8));
            aop->type = R_ANAL_OP_TYPE_LOAD;
            return;
        }
        case 0x6: {
            uint32_t rD = BIT_RANGE(insn, 8, 4);
            uint32_t imm5 = BIT_RANGE(insn, 3, 5);
            switch (BIT_RANGE(insn, 0, 3)) {
                case 0x0: { // OP_RD(I16("addei"), rD, sign_extend(imm5, 5));
                    aop->type = R_ANAL_OP_TYPE_ADD;
                    return;
                }
                case 0x1: { // OP_RD(I16("slli"), rD, imm5);
                    aop->type = R_ANAL_OP_TYPE_SHL;
                    return;
                }
                case 0x2: { // OP_D(I16("sdbbp"), imm5);
                    aop->type = R_ANAL_OP_TYPE_ILL;
                    return;
                }
                case 0x3: { // OP_RD(I16("srli"), rD, imm5);
                    aop->type = R_ANAL_OP_TYPE_SHR;
                    return;
                }
                case 0x4: { // OP_RD(I16("bitclr"), rD, imm5);
                    aop->type = R_ANAL_OP_TYPE_OR;
                    return;
                }
                case 0x5: { // OP_RD(I16("bitset"), rD, imm5);
                    aop->type = R_ANAL_OP_TYPE_AND;
                    return;
                }
                case 0x6: { // OP_RD(I16("bittst"), rD, imm5);
                    aop->type = R_ANAL_OP_TYPE_CMP;
                    return;
                }
                case 0x7: { // OP(I("invalid"));
                    aop->type = R_ANAL_OP_TYPE_UNK;
                    return;
                }
            }
        }
        case 0x7: {
            uint32_t rD = BIT_RANGE(insn, 8, 4);
            uint32_t imm5 = BIT_RANGE(insn, 3, 5);
            switch (BIT_RANGE(insn, 0, 3)) {
                case 0x0: { // OP_RD(I16("lwp"), rD, imm5 << 2);
                    aop->type = R_ANAL_OP_TYPE_LOAD;
                    return;
                }
                case 0x1: { // OP_RD(I16("lhp"), rD, imm5 << 1);
                    aop->type = R_ANAL_OP_TYPE_LOAD;
                    return;
                }
                case 0x3: { // OP_D(I16("lbup"), imm5);
                    aop->type = R_ANAL_OP_TYPE_LOAD;
                    return;
                }
                case 0x4: { // OP_RD(I16("swp"), rD, imm5 << 2);
                    aop->type = R_ANAL_OP_TYPE_STORE;
                    return;
                }
                case 0x5: { // OP_RD(I16("shp"), rD, imm5 << 1);
                    aop->type = R_ANAL_OP_TYPE_STORE;
                    return;
                }
                case 0x6: { // OP_RD(I16("sbp"), rD, imm5);
                    aop->type = R_ANAL_OP_TYPE_STORE;
                    return;
                }
                default: { // OP(I("invalid"));
                    aop->type = R_ANAL_OP_TYPE_UNK;
                    return;
                }
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
    .set_reg_profile = set_reg_profile,
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
