#include <r_asm.h>
#include <r_lib.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *b, int l) {
    return 4;
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
