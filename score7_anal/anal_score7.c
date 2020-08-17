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
	switch(BIT_RANGE(insn, 12, 3)) {
		case 0x0: {
					  uint32_t rA = BIT_RANGE(insn, 4, 4);
					  uint32_t rD = BIT_RANGE(insn, 8, 4);
					  switch (BIT_RANGE(insn, 0, 4)) {
						  case 0x0: {//OP(I16("nop"));
										aop->type = R_ANAL_OP_TYPE_NOP;
										return;
									}
						  case 0x1: { //OP_RR(I16("mlfh"), rD, rA + 16);
										aop->type = R_ANAL_OP_TYPE_MOV;
										return;
									}
						  case 0x2: { //OP_RR(I16("mhfl"), rD + 16, rA);
										aop->type = R_ANAL_OP_TYPE_MOV;
										return;
									}
						  case 0x3: { //OP_RR(I16("mv"), rD, rA);
										aop->type = R_ANAL_OP_TYPE_MOV;
										return;
									}
						  case 0x4: { //OP_R(IBL16("br", rD, false), rA);
										aop->type = R_ANAL_OP_TYPE_CJMP;
										aop->fail = addr + 2;
										aop->eob = true;
										return;
									}
						  case 0x5: { //OP_R(IBL16("t", rD, false), rA);
										aop->type = R_ANAL_OP_TYPE_CMP;
										return;
									}
						  case 0xC: { //OP_R(IBL16("br", rD, true), rA);
										aop->type = R_ANAL_OP_TYPE_CCALL;
										aop->fail = addr + 2;
										aop->eob = true;
										return;
									}
						  default: { // OP(I("invalid"));
									   aop->type = R_ANAL_OP_TYPE_UNK;
									   return;
								   }
					  }
				  }
		case 0x1: {
					  uint32_t rA = BIT_RANGE(insn, 4, 4);
					  switch(BIT_RANGE(insn, 0, 4)) {
						  case 0x0:
							  switch(BIT_RANGE(insn, 8, 4)) {
								  case 0x0: {// OP_R(I16("mtcel"), rA);
												aop->type = R_ANAL_OP_TYPE_MOV;
												return;
											}
								  case 0x1: { //OP_R(I16("mtceh"), rA);
												aop->type = R_ANAL_OP_TYPE_MOV;
												return;
											}
								  default: { //OP(I("invalid"));
											   aop->type = R_ANAL_OP_TYPE_UNK;
											   return;
										   }
							  }
						  case 0x1:
							  switch(BIT_RANGE(insn, 8, 4)) {
								  case 0x0: { //OP_R(I16("mfcel"), rA);
												aop->type = R_ANAL_OP_TYPE_MOV;
												return;
											}
								  case 0x1: { //OP_R(I16("mfceh"), rA);
												aop->type = R_ANAL_OP_TYPE_MOV;
												return;
											}
								  default: { //OP(I("invalid"));
											   aop->type = R_ANAL_OP_TYPE_UNK;
											   return;
										   }
							  }
						  default: { //OP(I("invalid"));
									   aop->type = R_ANAL_OP_TYPE_UNK;
									   return;
								   }
					  }
				  }

		case 0x2: {
					  uint32_t rA = BIT_RANGE(insn, 4, 4);
					  uint32_t rD = BIT_RANGE(insn, 8, 4);
					  uint32_t rAh = BIT_RANGE(insn, 4, 3);
					  uint32_t rH = BIT_RANGE(insn, 7, 1) << 4;
					  switch (BIT_RANGE(insn, 0, 4)) {
						  case 0x0: { // OP_RR(I16("add"), rD, rA);
										aop->type = R_ANAL_OP_TYPE_ADD;
										return;
									}
						  case 0x1: { // OP_RR(I16("sub"), rD, rA);
										aop->type = R_ANAL_OP_TYPE_SUB;
										return;
									}
						  case 0x2: { // OP_RR(I16("neg"), rD, rA);
										aop->type = R_ANAL_OP_TYPE_SUB;
										return;
									}
						  case 0x3: { // OP_RR(I16("cmp"), rD, rA);
										aop->type = R_ANAL_OP_TYPE_CMP;
										return;
									}
						  case 0x4: { // OP_RR(I16("and"), rD, rA);
										aop->type = R_ANAL_OP_TYPE_AND;
										return;
									}
						  case 0x5: { // OP_RR(I16("or"), rD, rA);
										aop->type = R_ANAL_OP_TYPE_OR;
										return;
									}
						  case 0x6: { // OP_RR(I16("not"), rD, rA);
										aop->type = R_ANAL_OP_TYPE_NOT;
										return;
									}
						  case 0x7: { // OP_RR(I16("xor"), rD, rA);
										aop->type = R_ANAL_OP_TYPE_XOR;
										return;
									}
						  case 0x8: { // OP_RM(I16("lw"), rD, rA);
										aop->type = R_ANAL_OP_TYPE_LOAD;
										return;
									}
						  case 0x9: { // OP_RM(I16("lh"), rD, rA);
										aop->type = R_ANAL_OP_TYPE_LOAD;
										return;
									}
						  case 0xA: { // OP_RM(I16("pop"), rD + rH, rAh);
										aop->type = R_ANAL_OP_TYPE_POP;
										return;
									}
						  case 0xB: { // OP_RM(I16("lbu"), rD, rA);
										aop->type = R_ANAL_OP_TYPE_LOAD;
										return;
									}
						  case 0xC: { // OP_RM(I16("sw"), rD, rA);
										aop->type = R_ANAL_OP_TYPE_STORE;
										return;
									}
						  case 0xD: { // OP_RM(I16("sh"), rD, rA);
										aop->type = R_ANAL_OP_TYPE_STORE;
										return;
									}
						  case 0xE: { // OP_RM(I16("push"), rD + rH, rAh);
										aop->type = R_ANAL_OP_TYPE_PUSH;
										return;
									}
						  case 0xF: { // OP_RM(I16("sb"), rD, rA);
										aop->type = R_ANAL_OP_TYPE_STORE;
										return;
									}
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
										aop->type= R_ANAL_OP_TYPE_STORE;
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
	memset (op, '\0', sizeof (RAnalOp));
	if (len < 2) {
		return 0;
	}
	ut32 instruction = *(ut16 *)data;
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
