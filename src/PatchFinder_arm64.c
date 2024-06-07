#include "PatchFinder_arm64.h"
#include "PatchFinder.h"
#include "arm64.h"
#include <sys/mman.h>

uint64_t pfsec_arm64_resolve_adrp_ldr_str_add_reference(PFSection *section, uint64_t adrpAddr, uint64_t ldrStrAddAddr)
{
	uint32_t ldrStrAddInst = pfsec_read32(section, ldrStrAddAddr);
	
	uint64_t imm = 0;
	if (arm64_dec_ldr_imm(ldrStrAddInst, NULL, NULL, &imm, NULL, NULL) != 0) {
		if (arm64_dec_ldrs_imm(ldrStrAddInst, NULL, NULL, &imm, NULL, NULL) != 0) {
			if (arm64_dec_str_imm(ldrStrAddInst, NULL, NULL, &imm, NULL, NULL) != 0) {
				uint16_t addImm = 0;
				if (arm64_dec_add_imm(ldrStrAddInst, NULL, NULL, &addImm) == 0) {
					imm = (uint64_t)addImm;
				}
				else {
					return 0;
				}
			}
		}
	}

	uint64_t adrpTarget = 0;
	arm64_dec_adr_p(pfsec_read32(section, adrpAddr), adrpAddr, &adrpTarget, NULL, NULL);

	return adrpTarget + imm;
}

uint64_t pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(PFSection *section, uint64_t ldrStrAddAddr)
{
	uint32_t inst = pfsec_read32(section, ldrStrAddAddr);

	arm64_register reg;
	if (arm64_dec_ldr_imm(inst, NULL, &reg, NULL, NULL, NULL) != 0) {
		if (arm64_dec_str_imm(inst, NULL, &reg, NULL, NULL, NULL) != 0) {
			if (arm64_dec_add_imm(inst, NULL, &reg, NULL) != 0) {
				return 0;
			}
		}
	}

	uint32_t adrpInst = 0, adrpInstMask = 0;
	arm64_gen_adr_p(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, reg, &adrpInst, &adrpInstMask);
	uint64_t adrpAddr = pfsec_find_prev_inst(section, ldrStrAddAddr, 100, adrpInst, adrpInstMask);
	if (!adrpAddr) return -1;
	return pfsec_arm64_resolve_adrp_ldr_str_add_reference(section, adrpAddr, ldrStrAddAddr);
}

uint64_t pfsec_arm64_resolve_stub(PFSection *section, uint64_t stubAddr)
{
	// A stub is usually:
	// adrp x16, ?
	// ldr x16, ?
	// br x16

	// First, check if what we have actually is a stub
	uint32_t inst[3];
	pfsec_read_at_address(section, stubAddr, inst, sizeof(inst));

	uint32_t stubInst[3], stubMask[3];
	arm64_gen_adr_p(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, ARM64_REG_X(16), &stubInst[0], &stubMask[0]);
	arm64_gen_ldr_imm(0, LDR_STR_TYPE_UNSIGNED, ARM64_REG_X(16), ARM64_REG_X(16), OPT_UINT64_NONE, &stubInst[1], &stubMask[1]);
	stubInst[2] = 0xd61f0200;
	stubMask[2] = 0xffffffff;

	if ((inst[0] & stubMask[0]) == stubInst[0] ||
		(inst[1] & stubMask[1]) == stubInst[1] ||
		(inst[2] & stubMask[2]) == stubInst[2]) {
		// This is a stub, resolve it
		uint64_t ptrAddr = pfsec_arm64_resolve_adrp_ldr_str_add_reference(section, stubAddr, stubAddr + 4);
		if (ptrAddr) {
			uint64_t targetAddr = 0;
			macho_read_at_vmaddr(section->macho, ptrAddr, sizeof(ptrAddr), &targetAddr);
			return targetAddr;
		}
	}

	// Not a stub, just return original address
	return stubAddr;
}

// Unified check for whether anything writes to a register between firstAddr and secondAddr
bool pfsec_arm64_scan_register_write(PFSection *section, arm64_register reg, uint64_t firstAddr, uint64_t secondAddr)
{
	uint64_t instrBetween = ((firstAddr - secondAddr) / 4);

	// check for ADD writing to it
	uint32_t addInst = 0, addMask = 0;
	arm64_gen_add_imm(reg, ARM64_REG_ANY, OPT_UINT64_NONE, &addInst, &addMask);
	if (pfsec_find_prev_inst(section, firstAddr - 4, instrBetween, addInst, addMask) != 0) {
		return true;
	}

	// TODO: other writes

	return false;
}

void pfsec_arm64_enumerate_xrefs(PFSection *section, Arm64XrefTypeMask types, void (^xrefBlock)(Arm64XrefType type, uint64_t source, uint64_t target, bool *stop))
{
	bool stop = false;
	if (section->initprot & PROT_EXEC) {
		for (uint64_t addr = section->vmaddr; addr < (section->vmaddr + section->size) && !stop; addr += sizeof(uint32_t)) {
			uint32_t inst = pfsec_read32(section, addr);
			if ((types & ARM64_XREF_TYPE_MASK_B) || (types & ARM64_XREF_TYPE_MASK_BL)) {
				uint64_t target = 0;
				bool isBl = 0;
				if (arm64_dec_b_l(inst, addr, &target, &isBl) == 0) {
					if (isBl && (types & ARM64_XREF_TYPE_MASK_BL)) {
						xrefBlock(ARM64_XREF_TYPE_BL, addr, target, &stop);
					}
					else if (!isBl && (types & ARM64_XREF_TYPE_MASK_B)) {
						xrefBlock(ARM64_XREF_TYPE_B, addr, target, &stop);
					}
					continue;
				}
			}
			if (types & ARM64_XREF_TYPE_MASK_ADR) {
				uint64_t target = 0;
				bool isAdrp = false;
				arm64_register reg;
				if (arm64_dec_adr_p(inst, addr, &target, &reg, &isAdrp) == 0) {
					if (!isAdrp) {
						xrefBlock(ARM64_XREF_TYPE_ADR, addr, target, &stop);
					}
					continue;
				}
			}
			if ((types & ARM64_XREF_TYPE_MASK_B_COND) || (types & ARM64_XREF_TYPE_MASK_BC_COND)) {
				uint64_t target = 0;
				bool isBc = false;
				if (arm64_dec_b_c_cond(inst, addr, &target, NULL, &isBc) == 0) {
					if (!isBc && (types & ARM64_XREF_TYPE_MASK_B_COND)) {
						xrefBlock(ARM64_XREF_TYPE_B_COND, addr, target, &stop);
					}
					if (isBc && (types & ARM64_XREF_TYPE_MASK_BC_COND)) {
						xrefBlock(ARM64_XREF_TYPE_BC_COND, addr, target, &stop);
					}
				}
			}
			if ((types & ARM64_XREF_TYPE_MASK_CBZ) || (types & ARM64_XREF_TYPE_MASK_CBNZ)) {
				uint64_t target = 0;
				bool isCbnz = false;
				if (arm64_dec_cb_n_z(inst, addr, &isCbnz, NULL, &target) == 0) {
					if (!isCbnz && (types & ARM64_XREF_TYPE_MASK_CBZ)) {
						xrefBlock(ARM64_XREF_TYPE_CBZ, addr, target, &stop);
					}
					if (isCbnz && (types & ARM64_XREF_TYPE_MASK_CBNZ)) {
						xrefBlock(ARM64_XREF_TYPE_CBNZ, addr, target, &stop);
					}
				}
			}
			if ((types & ARM64_XREF_TYPE_MASK_TBZ) || (types & ARM64_XREF_TYPE_MASK_TBNZ)) {
				uint64_t target = 0;
				bool isTbnz = false;
				if (arm64_dec_tb_n_z(inst, addr, &isTbnz, NULL, &target, NULL) == 0) {
					if (!isTbnz && (types & ARM64_XREF_TYPE_MASK_TBZ)) {
						xrefBlock(ARM64_XREF_TYPE_CBZ, addr, target, &stop);
					}
					if (isTbnz && (types & ARM64_XREF_TYPE_MASK_TBNZ)) {
						xrefBlock(ARM64_XREF_TYPE_CBNZ, addr, target, &stop);
					}
				}
			}
			#define ADRP_SEEK_BACK 8
			if (types & ARM64_XREF_TYPE_MASK_ADRP_ADD) {
				uint16_t addImm = 0;
				arm64_register addDestinationReg;
				arm64_register addSourceReg;
				if (arm64_dec_add_imm(inst, &addDestinationReg, &addSourceReg, &addImm) == 0) {
					uint32_t adrpInst = 0;
					uint32_t adrpMask = 0;
					if (arm64_gen_adr_p(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, addSourceReg, &adrpInst, &adrpMask) == 0) {
						uint64_t adrpAddr = pfsec_find_prev_inst(section, addr, ADRP_SEEK_BACK, adrpInst, adrpMask);
						if (adrpAddr != 0) {
							if (!pfsec_arm64_scan_register_write(section, addSourceReg, addr, adrpAddr)) {
								uint64_t adrpTarget = 0;
								arm64_dec_adr_p(pfsec_read32(section, adrpAddr), adrpAddr, &adrpTarget, NULL, NULL);
								xrefBlock(ARM64_XREF_TYPE_ADRP_ADD, addr, adrpTarget + addImm, &stop);
							}
						}
					}
				}
			}
			if (types & ARM64_XREF_TYPE_MASK_ADRP_LDR) {
				arm64_register ldrDestinationReg;
				arm64_register ldrSourceReg;
				uint64_t ldrImm = 0;
				char ldrType = -1;
				arm64_ldr_str_type instType = 0;
				if (arm64_dec_ldr_imm(inst, &ldrDestinationReg, &ldrSourceReg, &ldrImm, &ldrType, &instType) == 0) {
					uint32_t adrpInst = 0;
					uint32_t adrpMask = 0;
					if (arm64_gen_adr_p(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, ldrSourceReg, &adrpInst, &adrpMask) == 0) {
						uint64_t adrpAddr = pfsec_find_prev_inst(section, addr, ADRP_SEEK_BACK, adrpInst, adrpMask);
						if (adrpAddr != 0) {
							if (!pfsec_arm64_scan_register_write(section, ldrSourceReg, addr, adrpAddr)) {
								uint64_t adrpTarget = 0;
								arm64_dec_adr_p(pfsec_read32(section, adrpAddr), adrpAddr, &adrpTarget, NULL, NULL);
								xrefBlock(ARM64_XREF_TYPE_ADRP_LDR, addr, adrpTarget + ldrImm, &stop);
							}
						}
					}
				}
			}
			if (types & ARM64_XREF_TYPE_MASK_ADRP_STR) {
				arm64_register strDestinationReg;
				arm64_register strSourceReg;
				uint64_t strImm = 0;
				char strType = -1;
				arm64_ldr_str_type instType = 0;
				if (arm64_dec_str_imm(inst, &strDestinationReg, &strSourceReg, &strImm, &strType, &instType) == 0) {
					uint32_t adrpInst = 0;
					uint32_t adrpMask = 0;
					if (arm64_gen_adr_p(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, strSourceReg, &adrpInst, &adrpMask) == 0) {
						uint64_t adrpAddr = pfsec_find_prev_inst(section, addr, ADRP_SEEK_BACK, adrpInst, adrpMask);
						if (adrpAddr != 0) {
							if (!pfsec_arm64_scan_register_write(section, strSourceReg, addr, adrpAddr)) {
								uint64_t adrpTarget = 0;
								arm64_dec_adr_p(pfsec_read32(section, adrpAddr), adrpAddr, &adrpTarget, NULL, NULL);
								xrefBlock(ARM64_XREF_TYPE_ADRP_STR, addr, adrpTarget + strImm, &stop);
							}
						}
					}
				}
			}
		}
	}

	if ((types & ARM64_XREF_TYPE_MASK_POINTER)) {
		if (!strncmp(section->sectname, "__cfstring", sizeof(section->sectname) / sizeof(char))) {
			for (uint64_t addr = section->vmaddr; addr < (section->vmaddr + section->size) && !stop; addr += 0x20) {
				uint32_t fileoff = pfsec_read32(section, addr + 0x10);
				uint64_t vmaddr = 0;
				macho_translate_fileoff_to_vmaddr(section->macho, fileoff, &vmaddr, NULL);
				xrefBlock(ARM64_XREF_TYPE_POINTER, addr, vmaddr, &stop);
			}
		}
		else {
			for (uint64_t addr = section->vmaddr; addr < (section->vmaddr + section->size) && !stop; addr += sizeof(uint64_t)) {
				uint64_t ptr = pfsec_read_pointer(section, addr);
				xrefBlock(ARM64_XREF_TYPE_POINTER, addr, ptr, &stop);
			}
		}
	}
}