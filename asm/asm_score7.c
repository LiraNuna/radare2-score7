#include <r_asm.h>
#include <r_lib.h>
#include <r_types.h>

#define R_ASM_BUFSIZE 32
#define BIT_RANGE(x, start, size) ((x >> start) & ((1 << size) - 1))

// --- 32bit INSTRUCTIONS ---
#define I(name) make_insn(name, 15, 3, "")
#define IB(name, cond) make_insn(name, cond, 3, "")
#define IBL(name, cond, link) make_insn(name, cond, 3, link ? "l" : "")
#define IS(name, suffix) make_insn(name, 15, 3, suffix)
#define IL(name, link) IS(name, link ? "l" : "")
#define IC(name, c) IS(name, c ? ".c" : "")
#define ITC(name, t, c) make_insn(name, 15, t, c ? ".c" : "")

// --- 16bit INSTRUCTIONS ---
#define I16(name) make_insn(name, 15, 3, "!")
#define IL16(name, link) make_insn(name, 15, 3, link ? "l!" : "!")
#define IBL16(name, cond, link) make_insn(name, cond, 3, link ? "l!" : "!")

// --- OPCODES ---
#define OP_FMT_STR(op, fmt) "%s%s%s%s" fmt, op.name, CONDITIONALS[op.cond], TCS[op.t], op.suf
#define OP(op) snprintf(asm_op->buf_asm.buf, R_ASM_BUFSIZE, OP_FMT_STR(op, "")); return
#define FORMAT_OP(op, fmt, args...) snprintf(asm_op->buf_asm.buf, R_ASM_BUFSIZE, OP_FMT_STR(op, " " fmt), args); return

// --- OPCODE FORMATS ---
#define OP_R(op, reg1) FORMAT_OP(op, "%s", REGISTERS[reg1])
#define OP_RR(op, reg1, reg2) FORMAT_OP(op, "%s, %s", REGISTERS[reg1], REGISTERS[reg2])
#define OP_RPR(op, reg1, prefix, reg2) FORMAT_OP(op, "%s, %s%s", REGISTERS[reg1], prefix, REGISTERS[reg2])
#define OP_RRR(op, reg1, reg2, reg3) FORMAT_OP(op, "%s, %s, %s", REGISTERS[reg1], REGISTERS[reg2], REGISTERS[reg3])
#define OP_D(op, immd) FORMAT_OP(op, "%d", immd)
#define OP_RD(op, reg1, immd) FORMAT_OP(op, "%s, %d", REGISTERS[reg1], immd)
#define OP_RRD(op, reg1, reg2, immd) FORMAT_OP(op, "%s, %s, %d", REGISTERS[reg1], REGISTERS[reg2], immd)
#define OP_W(op, immx32) FORMAT_OP(op, "0x%08x", immx32)
#define OP_RH(op, reg1, immx16) FORMAT_OP(op, "%s, 0x%04x", REGISTERS[reg1], immx16)
#define OP_RRH(op, reg1, reg2, immx16) FORMAT_OP(op, "%s, %s, 0x%04x", REGISTERS[reg1], REGISTERS[reg2], immx16)
#define OP_RM(op, reg1, mem) FORMAT_OP(op, "%s, [%s]", REGISTERS[reg1], REGISTERS[mem])
#define OP_RMD(op, reg1, mem, immd) FORMAT_OP(op, "%s, [%s, %d]", REGISTERS[reg1], REGISTERS[mem], immd)
#define OP_RMDP(op, reg1, mem, immd) FORMAT_OP(op, "%s, [%s, %d]+", REGISTERS[reg1], REGISTERS[mem], immd)
#define OP_RMPD(op, reg1, mem, immd) FORMAT_OP(op, "%s, [%s]+, %d", REGISTERS[reg1], REGISTERS[mem], immd)
#define OP_MP(op, mem) FORMAT_OP(op, "[%s]+", REGISTERS[mem])
#define OP_RMP(op, reg1, mem) FORMAT_OP(op, "%s, [%s]+",  REGISTERS[reg1], REGISTERS[mem])

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

static const char *CONDITIONALS[] = {
    "cs", "cc",
    "gtu", "leu",
    "eq", "ne",
    "gt", "le",
    "ge", "lt",
    "mi", "pl",
    "vs", "vc",
    "cnz", "",
};

static const char *TCS[] = {
    "teq", "tmi",
    "", "",
};

typedef struct {
    const char *name;
    uint8_t cond;
    uint8_t t;
    const char *suf;
} instruction;

static int32_t sign_extend(uint32_t x, uint8_t b) {
    uint32_t m = 1UL << (b - 1);

    x = x & ((1UL << b) - 1);
    return (x ^ m) - m;
}

static instruction make_insn(const char *name, uint8_t cond, uint8_t t, const char *suf) {
    instruction op = {
        .name = name,
        .cond = cond,
        .t = t,
        .suf = suf,
    };

    return op;
}

static void disasm32(RAsm *rasm, RAsmOp *asm_op, uint32_t insn) {
    switch(BIT_RANGE(insn, 25, 5)) {
        case 0x00: {
            bool cu = BIT_RANGE(insn, 0, 1);
            uint32_t rD = BIT_RANGE(insn, 20, 5);
            uint32_t rA = BIT_RANGE(insn, 15, 5);
            uint32_t rB = BIT_RANGE(insn, 10, 5);

            switch(BIT_RANGE(insn, 1, 6)) {
                case 0x00: OP(I("nop"));
                case 0x01: OP_D(I("syscall"), BIT_RANGE(insn, 10, 15));
                case 0x02: OP_D(IB("trap", rB), rA);
                case 0x03: OP_D(I("sdbbp"), rA);
                case 0x04: OP_R(IBL("br", rB, cu), rA);
                case 0x05: OP(I("pflush"));
                case 0x06: OP_RM(I("alw"), rD, rA);
                case 0x07: OP_RM(I("asw"), rD, rA);
                case 0x08: OP_RRR(IC("add", cu), rD, rA, rB);
                case 0x09: OP_RRR(IC("addc", cu), rD, rA, rB);
                case 0x0A: OP_RRR(IC("sub", cu), rD, rA, rB);
                case 0x0C: OP_RR(ITC("cmp", rD, cu), rA, rB);
                case 0x0D: OP_RR(ITC("cmpz", rD, cu), rA, rB);
                case 0x0F: OP_RR(IC("neg", cu), rD, rA);
                case 0x10: OP_RRR(IC("and", cu), rD, rA, rB);
                case 0x11: OP_RRR(IC("or", cu), rD, rA, rB);
                case 0x12: OP_RRR(IC("not", cu), rD, rA, rB);
                case 0x13: OP_RRR(IC("xor", cu), rD, rA, rB);
                case 0x14: OP_RRD(IC("bitclr", cu), rD, rA, rB);
                case 0x15: OP_RRD(IC("bitset", cu), rD, rA, rB);
                case 0x16: OP_RD(IC("bittst", cu), rA, rB);
                case 0x17: OP_RRD(IC("bittgl", cu), rD, rA, rB);
                case 0x18: OP_RRR(IC("sll", cu), rD, rA, rB);
                case 0x19: OP(I("invalid"));
                case 0x1A: OP_RRR(IC("srl", cu), rD, rA, rB);
                case 0x1B: OP_RRR(IC("sra", cu), rD, rA, rB);
                case 0x1C: OP_RRR(IC("ror", cu), rD, rA, rB);
                case 0x1D: OP_RRR(IC("rorc", cu), rD, rA, rB);
                case 0x1E: OP_RRR(IC("rol", cu), rD, rA, rB);
                case 0x1F: OP_RRR(IC("rolc", cu), rD, rA, rB);
                case 0x20: OP_RR(IS("mul", cu ? ".f" : ""), rA, rB);
                case 0x21: OP_RR(I("mulu"), rA, rB);
                case 0x22: OP_RR(I("div"), rA, rB);
                case 0x23: OP_RR(I("divu"), rA, rB);
                case 0x24:
                    switch(rB) {
                        case 0x00: OP(I("invalid"));
                        case 0x01: OP_R(I("mfcel"), rD);
                        case 0x02: OP_R(I("mfceh"), rD);
                        case 0x03: OP_RR(I("mfcehl"), rD, rA);
                        default: OP(I("invalid"));
                    }
                case 0x25:
                    switch(rB) {
                        case 0x00: OP(I("invalid"));
                        case 0x01: OP_R(I("mtcel"), rD);
                        case 0x02: OP_R(I("mtceh"), rD);
                        case 0x03: OP_RR(I("mtcehl"), rD, rA);
                        default: OP(I("invalid"));
                    }
                case 0x28: OP_RPR(I("mfsr"), rA, "s", rB);
                case 0x29: OP_RPR(I("mtsr"), rA, "s", rB);
                case 0x2A: OP(IB("t", rB));
                case 0x2B: OP_RR(IB("mv", rB), rD, rA);
                case 0x2C: OP_RR(IC("extsb", cu), rD, rA);
                case 0x2D: OP_RR(IC("extsh", cu), rD, rA);
                case 0x2E: OP_RR(IC("extzb", cu), rD, rA);
                case 0x2F: OP_RR(IC("extzh", cu), rD, rA);
                case 0x30: OP_MP(I("lcb"), rA);
                case 0x31: OP_RMP(I("lcw"), rD, rA);
                case 0x33: OP_RMP(I("lce"), rD, rA);
                case 0x34: OP_RMP(I("scb"), rD, rA);
                case 0x35: OP_RMP(I("scw"), rD, rA);
                case 0x37: OP_MP(I("sce"), rA);
                case 0x38: OP_RRD(IC("slli", cu), rD, rA, rB);
                case 0x3A: OP_RRD(IC("srli", cu), rD, rA, rB);
                case 0x3B: OP_RRD(IC("srai", cu), rD, rA, rB);
                case 0x3C: OP_RRD(IC("rori", cu), rD, rA, rB);
                case 0x3D: OP_RRD(IC("roric", cu), rD, rA, rB);
                case 0x3E: OP_RRD(IC("roli", cu), rD, rA, rB);
                case 0x3F: OP_RRD(IC("rolic", cu), rD, rA, rB);
                default: OP(I("invalid"));
            }
        }
        case 0x01: {
            bool cu = BIT_RANGE(insn, 0, 1);
            uint16_t imm16 = BIT_RANGE(insn, 1, 16);
            uint32_t rD = BIT_RANGE(insn, 20, 5);

            switch (BIT_RANGE(insn, 17, 3)) {
                case 0x00: OP_RD(IC("addi", cu), rD, sign_extend(imm16, 16));
                case 0x02: OP_RD(IC("cmpi", cu), rD, sign_extend(imm16, 16));
                case 0x04: OP_RH(IC("andi", cu), rD, imm16);
                case 0x05: OP_RH(IC("ori", cu), rD, imm16);
                case 0x06: OP_RD(IC("ldi", cu), rD, imm16);
                default: OP(I("invalid"));
            }
        }
        case 0x02: OP_W(IL("j", BIT_RANGE(insn, 0, 1)), (uint32_t)(rasm->pc & 0xFC000000) | (BIT_RANGE(insn, 1, 24) << 1));
        case 0x03: {
            uint32_t rA = BIT_RANGE(insn, 15, 5);
            uint32_t rD = BIT_RANGE(insn, 20, 5);
            int16_t imm12 = sign_extend(BIT_RANGE(insn, 3, 12), 12);
            switch(BIT_RANGE(insn, 0, 3)) {
                case 0x00: OP_RMDP(I("lw"), rD, rA, imm12);
                case 0x01: OP_RMDP(I("lh"), rD, rA, imm12);
                case 0x02: OP_RMDP(I("lhu"), rD, rA, imm12);
                case 0x03: OP_RMDP(I("lb"), rD, rA, imm12);
                case 0x04: OP_RMDP(I("sw"), rD, rA, imm12);
                case 0x05: OP_RMDP(I("sh"), rD, rA, imm12);
                case 0x06: OP_RMDP(I("lbu"), rD, rA, imm12);
                case 0x07: OP_RMDP(I("sb"), rD, rA, imm12);
            }
        }
        case 0x04: {
            int32_t disp = sign_extend(((BIT_RANGE(insn, 15, 10) << 9) | BIT_RANGE(insn, 1, 9)) << 1, 20);
            OP_W(IBL("b", BIT_RANGE(insn, 10, 5), BIT_RANGE(insn, 0, 1)), (uint32_t) rasm->pc + disp);
        }
        case 0x05: {
            bool cu = BIT_RANGE(insn, 0, 1);
            uint16_t imm16 = BIT_RANGE(insn, 1, 16);
            uint32_t rD = BIT_RANGE(insn, 20, 5);

            switch (BIT_RANGE(insn, 17, 3)) {
                case 0x00: OP_RD(IC("addis", cu), rD, sign_extend(imm16, 16));
                case 0x02: OP_RD(IC("cmpis", cu), rD, sign_extend(imm16, 16));
                case 0x04: OP_RH(IC("andis", cu), rD, imm16);
                case 0x05: OP_RH(IC("oris", cu), rD, imm16);
                case 0x06: OP_RH(IC("ldis", cu), rD, imm16);
                default: OP(I("invalid"));
            }
        }
        case 0x07: {
            uint32_t rA = BIT_RANGE(insn, 15, 5);
            uint32_t rD = BIT_RANGE(insn, 20, 5);
            int16_t imm12 = sign_extend(BIT_RANGE(insn, 3, 12), 12);
            switch(BIT_RANGE(insn, 0, 3)) {
                case 0x00: OP_RMPD(I("lw"), rD, rA, imm12);
                case 0x01: OP_RMPD(I("lh"), rD, rA, imm12);
                case 0x02: OP_RMPD(I("lhu"), rD, rA, imm12);
                case 0x03: OP_RMPD(I("lb"), rD, rA, imm12);
                case 0x04: OP_RMPD(I("sw"), rD, rA, imm12);
                case 0x05: OP_RMPD(I("sh"), rD, rA, imm12);
                case 0x06: OP_RMPD(I("lbu"), rD, rA, imm12);
                case 0x07: OP_RMPD(I("sb"), rD, rA, imm12);
            }
        }
        case 0x08: OP_RRH(IC("addri", BIT_RANGE(insn, 0, 1)), BIT_RANGE(insn, 15, 5), BIT_RANGE(insn, 20, 5),
                          sign_extend(BIT_RANGE(insn, 1, 14), 14));
        case 0x0C: OP_RRH(IC("andri", BIT_RANGE(insn, 0, 1)), BIT_RANGE(insn, 15, 5), BIT_RANGE(insn, 20, 5),
                          sign_extend(BIT_RANGE(insn, 1, 14), 14));
        case 0x0D: OP_RRH(IC("orri", BIT_RANGE(insn, 0, 1)), BIT_RANGE(insn, 15, 5), BIT_RANGE(insn, 20, 5),
                          sign_extend(BIT_RANGE(insn, 1, 14), 14));
        case 0x10: OP_RMD(I("lw"), BIT_RANGE(insn, 20, 5), BIT_RANGE(insn, 15, 5),
                          sign_extend(BIT_RANGE(insn, 0, 15), 15));
        case 0x11: OP_RMD(I("lh"), BIT_RANGE(insn, 20, 5), BIT_RANGE(insn, 15, 5),
                          sign_extend(BIT_RANGE(insn, 0, 15), 15));
        case 0x12: OP_RMD(I("lhu"), BIT_RANGE(insn, 20, 5), BIT_RANGE(insn, 15, 5),
                          sign_extend(BIT_RANGE(insn, 0, 15), 15));
        case 0x13: OP_RMD(I("lb"), BIT_RANGE(insn, 20, 5), BIT_RANGE(insn, 15, 5),
                          sign_extend(BIT_RANGE(insn, 0, 15), 15));
        case 0x14: OP_RMD(I("sw"), BIT_RANGE(insn, 20, 5), BIT_RANGE(insn, 15, 5),
                          sign_extend(BIT_RANGE(insn, 0, 15), 15));
        case 0x15: OP_RMD(I("sh"), BIT_RANGE(insn, 20, 5), BIT_RANGE(insn, 15, 5),
                          sign_extend(BIT_RANGE(insn, 0, 15), 15));
        case 0x16: OP_RMD(I("lbu"), BIT_RANGE(insn, 20, 5), BIT_RANGE(insn, 15, 5),
                          sign_extend(BIT_RANGE(insn, 0, 15), 15));
        case 0x17: OP_RMD(I("sb"), BIT_RANGE(insn, 20, 5), BIT_RANGE(insn, 15, 5),
                          sign_extend(BIT_RANGE(insn, 0, 15), 15));
        default: OP(I("invalid"));
    }
}

static void disasm16(RAsm *rasm, RAsmOp *asm_op, uint16_t insn) {
    switch(BIT_RANGE(insn, 12, 3)) {
        case 0x0: {
            uint32_t rA = BIT_RANGE(insn, 4, 4);
            uint32_t rD = BIT_RANGE(insn, 8, 4);
            switch (BIT_RANGE(insn, 0, 4)) {
                case 0x0: OP(I16("nop"));
                case 0x1: OP_RR(I16("mlfh"), rD, rA + 16);
                case 0x2: OP_RR(I16("mhfl"), rD + 16, rA);
                case 0x3: OP_RR(I16("mv"), rD, rA);
                case 0x4: OP_R(IBL16("br", rD, false), rA);
                case 0x5: OP_R(IBL16("t", rD, false), rA);
                case 0xC: OP_R(IBL16("br", rD, true), rA);
                default: OP(I("invalid"));
            }
        }
        case 0x1: {
            uint32_t rA = BIT_RANGE(insn, 4, 4);
            switch(BIT_RANGE(insn, 0, 4)) {
                case 0x0:
                    switch(BIT_RANGE(insn, 8, 4)) {
                        case 0x0: OP_R(I16("mtcel"), rA);
                        case 0x1: OP_R(I16("mtceh"), rA);
                        default: OP(I("invalid"));
                    }
                case 0x1:
                    switch(BIT_RANGE(insn, 8, 4)) {
                        case 0x0: OP_R(I16("mfcel"), rA);
                        case 0x1: OP_R(I16("mfceh"), rA);
                        default: OP(I("invalid"));
                    }
                default: OP(I("invalid"));
            }
        }
        case 0x2: {
            uint32_t rA = BIT_RANGE(insn, 4, 4);
            uint32_t rD = BIT_RANGE(insn, 8, 4);
            uint32_t rAh = BIT_RANGE(insn, 4, 3);
            uint32_t rH = BIT_RANGE(insn, 7, 1) << 4;
            switch (BIT_RANGE(insn, 0, 4)) {
                case 0x0: OP_RR(I16("add"), rD, rA);
                case 0x1: OP_RR(I16("sub"), rD, rA);
                case 0x2: OP_RR(I16("neg"), rD, rA);
                case 0x3: OP_RR(I16("cmp"), rD, rA);
                case 0x4: OP_RR(I16("and"), rD, rA);
                case 0x5: OP_RR(I16("or"), rD, rA);
                case 0x6: OP_RR(I16("not"), rD, rA);
                case 0x7: OP_RR(I16("xor"), rD, rA);
                case 0x8: OP_RM(I16("lw"), rD, rA);
                case 0x9: OP_RM(I16("lh"), rD, rA);
                case 0xA: OP_RM(I16("pop"), rD + rH, rAh);
                case 0xB: OP_RM(I16("lbu"), rD, rA);
                case 0xC: OP_RM(I16("sw"), rD, rA);
                case 0xD: OP_RM(I16("sh"), rD, rA);
                case 0xE: OP_RM(I16("push"), rD + rH, rAh);
                case 0xF: OP_RM(I16("sb"), rD, rA);
            }
        }
        case 0x3: OP_W(IL16("j", BIT_RANGE(insn, 0, 1)),
                       (uint32_t)(rasm->pc & 0xFFFFF000) | (BIT_RANGE(insn, 1, 11) << 1));
        case 0x4: OP_W(IBL16("b", BIT_RANGE(insn, 8, 4), false),
                       (uint32_t)rasm->pc + (sign_extend(BIT_RANGE(insn, 0, 8), 8) << 1));
        case 0x5: OP_RD(I16("ldiu"), BIT_RANGE(insn, 8, 4), BIT_RANGE(insn, 0, 8));
        case 0x6: {
            uint32_t rD = BIT_RANGE(insn, 8, 4);
            uint32_t imm5 = BIT_RANGE(insn, 3, 5);
            switch (BIT_RANGE(insn, 0, 3)) {
                case 0x0: OP_RD(I16("addei"), rD, sign_extend(imm5, 5));
                case 0x1: OP_RD(I16("slli"), rD, imm5);
                case 0x2: OP_D(I16("sdbbp"), imm5);
                case 0x3: OP_RD(I16("srli"), rD, imm5);
                case 0x4: OP_RD(I16("bitclr"), rD, imm5);
                case 0x5: OP_RD(I16("bitset"), rD, imm5);
                case 0x6: OP_RD(I16("bittst"), rD, imm5);
                case 0x7: OP(I("invalid"));
            }
        }
        case 0x7: {
            uint32_t rD = BIT_RANGE(insn, 8, 4);
            uint32_t imm5 = BIT_RANGE(insn, 3, 5);
            switch (BIT_RANGE(insn, 0, 3)) {
                case 0x0: OP_RD(I16("lwp"), rD, imm5 << 2);
                case 0x1: OP_RD(I16("lhp"), rD, imm5 << 1);
                case 0x3: OP_RD(I16("lbup"), rD, imm5);
                case 0x4: OP_RD(I16("swp"), rD, imm5 << 2);
                case 0x5: OP_RD(I16("shp"), rD, imm5 << 1);
                case 0x6: OP_RD(I16("sbp"), rD, imm5);
                default: OP(I("invalid"));
            }
        }
    }
}

static int score7_disasm(RAsm *rasm, RAsmOp *asm_op, const uint8_t *buffer, int length) {
    memset(asm_op, 0, sizeof(RAsmOp));

    if (length < 2) {
        return 0;
    }

    uint32_t instruction = *(uint16_t *) buffer;
    if (instruction & 0x8000) {
        if (length < 4) {
            return 0;
        }

        // Remove p0 and p1 bits before handling the instruction as 30bit
        instruction &= 0x00007FFF;
        instruction |= *(uint16_t *) (buffer + 2) << 15;
        instruction &= 0x3FFFFFFF;

        disasm32(rasm, asm_op, instruction);
        return asm_op->size = 4;
    } else {
        disasm16(rasm, asm_op, instruction);
        return asm_op->size = 2;
    }
}

RAsmPlugin r_asm_plugin_score7 = {
    .name = "score7",
    .arch = "score7",
    .desc = "SunPlus S⁺core7 disassembly plugin",
    .license = "LGPL3",
    .bits = 32,
    .disassemble = &score7_disasm,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ASM,
    .data = &r_asm_plugin_score7,
};
#endif
