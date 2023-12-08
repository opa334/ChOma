#ifndef ARM64_H
#define ARM64_H

#include "Util.h"

typedef struct s_arm64_register {
	bool isSet;
	bool is32;
	uint8_t number;
} arm64_register;
#define ARM64_REG(s_is32, x) (arm64_register){.isSet = true, .is32 = s_is32, .number = x}
#define ARM64_REG_X(x) ARM64_REG(false, x)
#define ARM64_REG_W(x) ARM64_REG(true, x)
#define ARM64_REG_ANY (arm64_register){.isSet = false, .is32 = false, .number = 0}
#define ARM64_REG_IS_32(x) (x.is32)
#define ARM64_REG_GET_NUM(x) (x.number & 0x1f)
#define ARM64_REG_IS_SET(x) (x.isSet)

int arm64_gen_b_l(optional_bool optIsBl, optional_uint64_t optOrigin, optional_uint64_t optTarget, uint32_t *bytesOut, uint32_t *maskOut);
int arm64_dec_b_l(uint32_t inst, uint64_t origin, uint64_t *targetOut, bool *isBlOut);
int arm64_gen_adr_p(optional_bool optIsAdrp, optional_uint64_t optOrigin, optional_uint64_t optTarget, arm64_register reg, uint32_t *bytesOut, uint32_t *maskOut);
int arm64_dec_adr_p(uint32_t inst, uint64_t origin, uint64_t *targetOut, arm64_register *registerOut, bool *isAdrpOut);
int arm64_gen_add_imm(arm64_register destinationReg, arm64_register sourceReg, optional_uint64_t optImm, uint32_t *bytesOut, uint32_t *maskOut);
int arm64_dec_add_imm(uint32_t inst, arm64_register *destinationRegOut, arm64_register *sourceRegOut, uint16_t *immOut);
int arm64_gen_ldr_imm(char type, arm64_register destinationReg, arm64_register sourceReg, optional_uint64_t optImm, uint32_t *bytesOut, uint32_t *maskOut);
int arm64_dec_ldr_imm(uint32_t inst, arm64_register *destinationReg, arm64_register *sourceReg, uint64_t *immOut, char *typeOut);
int arm64_gen_str_imm(char type, arm64_register destinationReg, arm64_register sourceReg, optional_uint64_t optImm, uint32_t *bytesOut, uint32_t *maskOut);
int arm64_dec_str_imm(uint32_t inst, arm64_register *destinationReg, arm64_register *sourceReg, uint64_t *immOut, char *typeOut);
#endif