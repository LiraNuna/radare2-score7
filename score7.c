#include <r_asm.h>
#include <r_lib.h>
#include <r_types.h>

#define R_ASM_BUFSIZE 32

static int disassemble(RAsm *rasm, RAsmOp *asm_op, const uint8_t *buffer, int length) {
    snprintf(asm_op->buf_asm.buf, R_ASM_BUFSIZE, " ");

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

        return asm_op->size = 4;
    } else {
        return asm_op->size = 2;
    }
}

RAsmPlugin r_asm_plugin_score7 = {
    .name = "score7",
    .arch = "score7",
    .license = "LGPL3",
    .bits = 32,
    .desc = "SunPlus S⁺core7",
    .disassemble = &disassemble,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ASM,
    .data = &r_asm_plugin_score7,
};
#endif
