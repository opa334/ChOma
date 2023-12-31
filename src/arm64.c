#include "arm64.h"
#include "Util.h"
#include <stdio.h>

#define ADRP_PAGE_SIZE 0x1000
#define ADRP_PAGE_MASK 0x0fff

int arm64_gen_b_l(optional_bool optIsBl, optional_uint64_t optOrigin, optional_uint64_t optTarget, uint32_t *bytesOut, uint32_t *maskOut)
{
    bool isBl = false;
    if (OPT_BOOL_IS_SET(optIsBl)) {
        isBl = OPT_BOOL_GET_VAL(optIsBl);
    }

    uint64_t origin = 0;
    uint64_t target = 0;
    if (OPT_UINT64_IS_SET(optOrigin) && OPT_UINT64_IS_SET(optTarget)) {
        *maskOut = 0xffffffff;
        origin = OPT_UINT64_GET_VAL(optOrigin);
        target = OPT_UINT64_GET_VAL(optTarget);
    }
    else {
        if (!OPT_BOOL_IS_SET(optIsBl)) {
            *maskOut = 0x7c000000;
        }
        else {
            *maskOut = 0xfc000000;
        }
    }

    int64_t offset = ((int64_t)target - (int64_t)origin) / 4;
    *bytesOut = (isBl ? 0x94000000 : 0x14000000) | (uint32_t)(offset & 0x3ffffff);
    return 0;
}

int arm64_dec_b_l(uint32_t inst, uint64_t origin, uint64_t *targetOut, bool *isBlOut)
{
    if ((inst & 0xfc000000) == 0x14000000) {
        if (isBlOut) *isBlOut = false;
    }
    else if ((inst & 0xfc000000) == 0x94000000) {
        if (isBlOut) *isBlOut = true;
    }
    else {
        return -1;
    }

    int64_t offset = sxt64((inst & 0x3ffffff), 26);
    if (targetOut) *targetOut = origin + (offset * 4);
    return 0;
}

int arm64_gen_adr_p(optional_bool optIsAdrp, optional_uint64_t optOrigin, optional_uint64_t optTarget, arm64_register reg, uint32_t *bytesOut, uint32_t *maskOut)
{
    bool isAdrp = false;

    uint32_t inst = (1 << 28);
    uint32_t mask = 0x1f000000;

    if (OPT_BOOL_IS_SET(optIsAdrp)) {
        mask |= (1 << 31);
        isAdrp = OPT_BOOL_GET_VAL(optIsAdrp);
        if (isAdrp) {
            inst |= (1 << 31);
        }
    }

    if (OPT_UINT64_IS_SET(optOrigin) && OPT_UINT64_IS_SET(optTarget)) {
        mask |= 0x60FFFFE0;
        
        uint64_t origin = OPT_UINT64_GET_VAL(optOrigin);
        uint64_t target = OPT_UINT64_GET_VAL(optTarget);
        if (isAdrp) {
            origin &= ~ADRP_PAGE_MASK;
            target &= ~ADRP_PAGE_MASK;
        }
        int64_t offset = ((int64_t)target - (int64_t)origin);
        if (isAdrp) {
            offset = (offset >> 12);
        }

        if ((offset & ~0x7FFFF)) {
            // Offset too big
            return -1;
        }

        inst |= ((offset & 0x3) << 29);
        inst |= ((offset & 0x7FFFC) << 3);
    }

    if (ARM64_REG_IS_SET(reg)) {
        if (ARM64_REG_IS_32(reg)) return -1;
        inst |= ARM64_REG_GET_NUM(reg);;
        mask |= 0x1F;
    }

    if (bytesOut) *bytesOut = inst;
    if (maskOut) *maskOut = mask;
    return 0;
}

int arm64_dec_adr_p(uint32_t inst, uint64_t origin, uint64_t *targetOut, arm64_register *registerOut, bool *isAdrpOut)
{
    bool isAdrp = false;
    if ((inst & 0x9f000000) == 0x90000000) {
        isAdrp = true;
    }
    else if ((inst & 0x9f000000) == 0x10000000) {
        isAdrp = false;
    }
    else {
        return -1;
    }

    if (targetOut) {
        uint64_t offset = ((inst >> 29) & 0x3) | ((inst >> 3) & 0x1ffffc);
        if (isAdrp) {
            offset = (offset << 12);
            origin &= ~ADRP_PAGE_MASK;
        }
        int64_t signedOffset = sxt64(offset, 33);
        *targetOut = origin + signedOffset;
    }

    if (registerOut) *registerOut = ARM64_REG_X(inst & 0x1f);
    if (isAdrpOut) *isAdrpOut = isAdrp;
    return 0;
}

int arm64_gen_mov_imm(char type, arm64_register destinationReg, optional_uint64_t optImm, optional_uint64_t optShift, uint32_t *bytesOut, uint32_t *maskOut)
{
    uint32_t bytes = 0x12800000;
    uint32_t mask =  0x7f800000;

    switch (type) {
        case 'k': {
            bytes |= (1 << 30) | (1 << 29);
            break;
        }

        case 'n': {
            break;
        }

        case 'z': {
            bytes |= (1 << 30);
            break;
        }

        default: {
            return -1;
        }
    }

    if (ARM64_REG_IS_SET(destinationReg)) {
        mask |= (1 << 31);
        if (ARM64_REG_IS_32(destinationReg)) {
            if (OPT_UINT64_IS_SET(optShift)) {
                uint64_t shift = OPT_UINT64_GET_VAL(optShift);
                if (shift != 0 && shift != 16) return -1;
            }
        }
        else {
            bytes |= (1 << 31);
            if (OPT_UINT64_IS_SET(optShift)) {
                uint64_t shift = OPT_UINT64_GET_VAL(optShift);
                if (shift != 0 && shift != 16 && shift != 32 && shift != 48) return -1;
            }
        }

        mask |= 0x1f;
        bytes |= ARM64_REG_GET_NUM(destinationReg);
    }

    if (OPT_UINT64_IS_SET(optImm)) {
        uint64_t imm = OPT_UINT64_GET_VAL(optImm);
        if (imm > UINT16_MAX) return -1;
        mask |= 0x1fffe0;
        bytes |= ((uint32_t)imm << 5);
    }

    if (OPT_UINT64_IS_SET(optShift)) {
        uint64_t shift = OPT_UINT64_GET_VAL(optShift);
        bytes |= ((shift / 16) & 0b11) << 21;
        mask |= (0b11 << 21);
    }

    if (bytesOut) *bytesOut = bytes;
    if (maskOut) *maskOut = mask;
    return 0;
}

int arm64_dec_mov_imm(uint32_t inst, arm64_register *destinationRegOut, uint64_t *immOut, uint64_t *shiftOut, char *typeOut)
{
    if ((inst & 0x7f800000) != 0x11000000) return -1;

    char type = 0;
    uint8_t opc = ((inst >> 29) & 0b11);
    switch (opc) {
        case 0b11: {
            type = 'k';
        }
        case 0b00: {
            type = 'n';
        }
        case 0b10: {
            type = 'z';
        }
        default: {
            return -1;
        }
    } 

    if (destinationRegOut) {
        bool is64 = inst & (1 << 31);
        *destinationRegOut = ARM64_REG(!is64, inst & 0x1f);
    }
    if (immOut) {
        *immOut = (inst >> 5) & 0xffff;
    }
    if (shiftOut) {
        *shiftOut = ((inst >> 21) & 0b11) * 16;
    }
    if (typeOut) {
        *typeOut = type;
    }

    return 0;
}

int arm64_gen_add_imm(arm64_register destinationReg, arm64_register sourceReg, optional_uint64_t optImm, uint32_t *bytesOut, uint32_t *maskOut)
{
    if (ARM64_REG_IS_SET(destinationReg) && ARM64_REG_IS_SET(sourceReg)) {
        // if both regs are set and have a mismatching width, abort
        if (ARM64_REG_IS_32(destinationReg) != ARM64_REG_IS_32(sourceReg)) return -1;
    }

    uint32_t bytes = 0x11000000;
    uint32_t mask = 0x7f800000;

    // if one is set and 32 bit, include 32 bit in mask and set it in bytes
    if (ARM64_REG_IS_SET(destinationReg)) {
        mask |= (1 << 31);
        bytes |= ((uint32_t)(!ARM64_REG_IS_32(destinationReg)) << 31);
    }
    else if (ARM64_REG_IS_SET(sourceReg)) {
        mask |= (1 << 31);
        bytes |= ((uint32_t)(!ARM64_REG_IS_32(sourceReg)) << 31);
    }

    if (ARM64_REG_IS_SET(destinationReg)) {
        mask |= 0x1F;
        bytes |= (uint32_t)(ARM64_REG_GET_NUM(destinationReg));
    }
    if (ARM64_REG_IS_SET(sourceReg)) {
        mask |= (0x1F << 5);
        bytes |= ((uint32_t)(ARM64_REG_GET_NUM(destinationReg)) << 5);
    }

    if (OPT_UINT64_IS_SET(optImm)) {
        uint64_t imm = OPT_UINT64_GET_VAL(optImm);
        if (imm & ~0xFFF) return -1;
        mask |= (0xFFF << 10);
        bytes |= (imm << 10);
    }

    if (bytesOut) *bytesOut = bytes;
    if (maskOut) *maskOut = mask;
    return 0;
}

int arm64_dec_add_imm(uint32_t inst, arm64_register *destinationRegOut, arm64_register *sourceRegOut, uint16_t *immOut)
{
    if ((inst & 0x7f800000) != 0x11000000) return -1;
    bool is32 = !(inst & 0x80000000);
    bool shift = (inst & 0x400000);

    if (destinationRegOut) {
        *destinationRegOut = ARM64_REG(is32, inst & 0x1F);
    }
    if (sourceRegOut) {
        *sourceRegOut = ARM64_REG(is32, (inst >> 5) & 0x1F);
    }

    if (immOut) {
        uint16_t imm = ((inst >> 10) & 0xFFF);
        if (shift) {
            imm = (imm << 12);
        }
        *immOut = imm;
    }

    return 0;
}

static int _arm64_gen_str_ldr_imm(uint32_t inst, uint32_t mask, char type, arm64_register sourceDestinationReg, arm64_register addrReg, optional_uint64_t optImm, uint32_t *bytesOut, uint32_t *maskOut)
{
    uint8_t width = 0;

    if (type != -1 && type != 0) {
        mask |= (0b11 << 30); 
        if (type == 'b') {
            inst |= (0b00 << 30);
            width = 1;
        }
        else if (type == 'h') {
            inst |= (0b01 << 30);
            width = 2;
        }
    }
    else {
        if (type == 0) {
            mask |= (0b10 << 30); 
            inst |= (0b10 << 30);
        }
        if (ARM64_REG_IS_SET(sourceDestinationReg)) {
            mask |= (0b01 << 30); 
            if (ARM64_REG_IS_32(sourceDestinationReg)) {
                inst |= (0 << 30);
                width = 4;
            }
            else {
                inst |= (1 << 30);
                width = 8;
            }
        }
    }

    bool is64 = false;
    if (ARM64_REG_IS_SET(sourceDestinationReg)) {
        inst |= ARM64_REG_GET_NUM(sourceDestinationReg);
        mask |= 0x1f;

        is64 = !ARM64_REG_IS_32(sourceDestinationReg);
        inst |= (is64 << 30);
        mask |= (1 << 30);
    }

    if (ARM64_REG_IS_SET(addrReg)) {
        if (ARM64_REG_IS_32(addrReg)) return -1;
        inst |= ((uint32_t)(ARM64_REG_GET_NUM(addrReg)) << 5);
        mask |= (0x1f << 5);
    }

    if (OPT_UINT64_IS_SET(optImm)) {
        uint64_t imm = OPT_UINT64_GET_VAL(optImm) / width;
        if (imm & ~0xfff) return -1;
        inst |= (imm << 10);
        mask |= (0xfff << 10);
    }

    if (bytesOut) *bytesOut = inst;
    if (maskOut) *maskOut = mask;
    return 0;
}

static int _arm64_dec_str_ldr_imm(uint32_t inst, arm64_register *sourceDestinationReg, arm64_register *sourceReg, uint64_t *immOut, char *typeOut)
{
    uint8_t size = (inst >> 30);
    uint8_t targetWidth = 0;
    switch (size) {
        case 0b00:
        targetWidth = 1;
        break;
        case 0b01:
        targetWidth = 2;
        break;
        case 0b10:
        targetWidth = 4;
        break;
        case 0b11:
        targetWidth = 8;
        break;
    }

    if (typeOut) {
        switch (size) {
            case 0b00:
            *typeOut = 'b';
            break;
            case 0b01:
            *typeOut = 'h';
            break;
            default:
            *typeOut = 0;
            break;
        }
    }

    if (sourceDestinationReg) {
        *sourceDestinationReg = ARM64_REG((targetWidth != 8), inst & 0x1f);
    }

    if (sourceReg) {
        *sourceReg = ARM64_REG_X((inst >> 5) & 0x1f);
    }

    if (immOut) {
        uint64_t imm = ((inst >> 10) & 0xfff) * targetWidth;
        *immOut = imm;
    }

    return 0;
}

int arm64_gen_ldr_imm(char type, arm64_register destinationReg, arm64_register addrReg, optional_uint64_t optImm, uint32_t *bytesOut, uint32_t *maskOut)
{
    return _arm64_gen_str_ldr_imm(0x39400000, 0x3fc00000, type, destinationReg, addrReg, optImm, bytesOut, maskOut);
}

int arm64_dec_ldr_imm(uint32_t inst, arm64_register *destinationReg, arm64_register *addrReg, uint64_t *immOut, char *typeOut)
{
    if ((inst & 0x3fc00000) != 0x39400000) return -1;
    return _arm64_dec_str_ldr_imm(inst, destinationReg, addrReg, immOut, typeOut);
}

int arm64_gen_str_imm(char type, arm64_register sourceReg, arm64_register addrReg, optional_uint64_t optImm, uint32_t *bytesOut, uint32_t *maskOut)
{
    return _arm64_gen_str_ldr_imm(0x39000000, 0x3fc00000, type, sourceReg, addrReg, optImm, bytesOut, maskOut);
}

int arm64_dec_str_imm(uint32_t inst, arm64_register *sourceReg, arm64_register *addrReg, uint64_t *immOut, char *typeOut)
{
    if ((inst & 0x3fc00000) != 0x39000000) return -1;
    return _arm64_dec_str_ldr_imm(inst, sourceReg, addrReg, immOut, typeOut);
}

int arm64_gen_ldr_lit(arm64_register destinationReg, optional_uint64_t optImm, uint32_t *bytesOut, uint32_t *maskOut)
{
    uint32_t inst = 0x18000000;
    uint32_t mask = 0xbf000000;

    if (ARM64_REG_IS_SET(destinationReg)) {
        mask |= (1 << 30);
        inst |= (!ARM64_REG_IS_32(destinationReg) << 30);

        mask |= 0x1f;
        inst |= ARM64_REG_GET_NUM(destinationReg);
    }

    if (OPT_UINT64_IS_SET(optImm)) {
        uint64_t imm = OPT_UINT64_GET_VAL(optImm);
        mask |= 0xffffe0;
        inst |= ((imm / 4) & 0x7ffff) << 5;
    }

    if (bytesOut) *bytesOut = inst;
    if (maskOut) *maskOut = mask;

    return 0;
}

int arm64_dec_ldr_lit(uint32_t inst, arm64_register *destinationReg, int64_t *immOut)
{
    if ((inst & 0xbf000000) != 0x18000000) return -1;

    if (destinationReg) {
        *destinationReg = ARM64_REG(!(inst & (1 << 30)), inst & 0x1f);
    }

    if (immOut) {
        uint64_t imm = (inst >> 5) & 0x7ffff;
        *immOut = (sxt64(imm, 19) * 4);
    }

    return 0;
}

int arm64_gen_cb_n_z(optional_bool isCbnz, arm64_register reg, optional_uint64_t optTarget, uint32_t *bytesOut, uint32_t *maskOut)
{
    uint32_t inst = 0x34000000;
    uint32_t mask = 0x7e000000;

    if (OPT_BOOL_IS_SET(isCbnz)) {
        mask |= (1 << 24);
        if (OPT_BOOL_GET_VAL(isCbnz)) {
            inst |= (1 << 24);
        }
    }

    if (ARM64_REG_IS_SET(reg)) {
        mask |= 0x1f | (1 << 31);
        inst |= (!ARM64_REG_IS_32(reg) << 31);
        inst |= ARM64_REG_GET_NUM(reg);
    }

    if (OPT_UINT64_IS_SET(optTarget)) {
        uint64_t target = OPT_UINT64_GET_VAL(optTarget) / 4;
        if (target & ~0x7ffff) {
            return -1;
        }
        mask |= 0xffffe0;
        inst |= (target << 5);
    }

    if (bytesOut) *bytesOut = inst;
    if (maskOut) *maskOut = mask;
    return 0;
}

int arm64_dec_cb_n_z(uint32_t inst, uint64_t origin, bool *isCbnzOut, arm64_register *regOut, uint64_t *targetOut)
{
    if ((inst & 0x7e000000) != 0x34000000) return -1;

    if (isCbnzOut) {
        *isCbnzOut = ((inst >> 24) & 0x1);
    }
    if (regOut) {
        bool is64 = ((inst >> 31) & 0x1);
        uint16_t num = inst & 0x1f;
        *regOut = ARM64_REG(!is64, num);
    }
    if (targetOut) {
        *targetOut = origin + sxt64(((inst >> 5) & 0x7ffff) * 4, 19);
    }

    return 0;
}