#pragma once
#ifndef _ARM64GENERATOR_H_
#define _ARM64GENERATOR_H_

#include <string.h>
#include <stdint.h>
#include "util.h"
#include <vector>

static u32 generic_inst_b(u64 pc,u64 target){
    const uint32_t inst_b_head=0b000101 << 26;
    uint32_t offset=target-pc;
    offset/=4;

    u32 inst=inst_b_head | (offset & 0b00000011111111111111111111111111);

    return inst;
}
static u32 generic_inst_movz(u16 imm,u16 hw,u16 ridx){
    const u32 inst_template=0b11010010100000000000000000000000;

    u32 imm_or = static_cast<u32>(imm) << 5;
    u32 hw_or = static_cast<u32>(hw) << 21;

    return inst_template | imm_or | hw_or | static_cast<u32>(ridx);
}
static u32 generic_inst_movk(u16 imm,u16 hw,u16 ridx){
    const u32 inst_template=0b11110010100000000000000000000000;

    u32 imm_or = static_cast<u32>(imm) << 5;
    u32 hw_or = static_cast<u32>(hw) << 21;

    return inst_template | imm_or | hw_or | static_cast<u32>(ridx);
}
static u32 generic_inst_blr(u32 ridx){
    const u32 blr_template=0b11010110001111110000000000000000;
    return blr_template | (static_cast<u32>(ridx) << 5);
}
static u32 generic_inst_br(u32 ridx){
    const u32 br_template= 0b11010110000111110000000000000000;
    return br_template | (static_cast<u32>(ridx) << 5);
}

static void generic_inst_movabs(u32 ridx,u64 imm,u32* out){
    u16 subdata[4];
    *(u64*)subdata=imm;

    out[0]=generic_inst_movz(subdata[0],0,ridx);
    for(int i=1;i<4;i++){
        out[i]=generic_inst_movk(subdata[i],i,ridx);
    }
}
static void generic_inst_jmpabs(u64 target,u32 ridx,u32* out){
    u16 subdata[4];
    *(u64*)subdata=target;

    out[0]=generic_inst_movz(subdata[0],0,ridx);
    for(int i=1;i<4;i++){
        out[i]=generic_inst_movk(subdata[i],i,ridx);
    }

    const u32 br_template=0b11010110000111110000000000000000;
    out[4] = br_template | (ridx << 5);
}

static int generic_invoker(uintptr_t CB,uintptr_t JmpAddr,u32 oldinst,u32 *out){
    memcpy(
            &out[0],
           "\xfd\x7b\xbd\xa9\xff\x83\x04\xd1\xe0\x07\x00\xa9\xe2\x0f\x01\xa9\xe4\x17\x02\xa9\xe6\x1f\x03\xa9\xe8\x27\x04\xa9\xea\x2f\x05\xa9\xec\x37\x06\xa9\xee\x3f\x07\xa9\xf0\x47\x08\xa9\xf2\x4f\x09\xa9\xf4\x57\x0a\xa9\xf6\x5f\x0b\xa9\xf8\x67\x0c\xa9\xfa\x6f\x0d\xa9\xfc\x77\x0e\xa9\xfe\x7b\x00\xf9\xe0\x03\x00\x91",
            76
           );
    generic_inst_movabs(9,CB,&out[19]);
    out[23] = generic_inst_blr(9);

    memcpy(&out[24],
           "\xe0\x07\x40\xa9\xe2\x0f\x41\xa9\xe4\x17\x42\xa9\xe6\x1f\x43\xa9\xe8\x27\x44\xa9\xea\x2f\x45\xa9\xec\x37\x46\xa9\xee\x3f\x47\xa9\xf0\x47\x48\xa9\xf2\x4f\x49\xa9\xf4\x57\x4a\xa9\xf6\x5f\x4b\xa9\xf8\x67\x4c\xa9\xfa\x6f\x4d\xa9\xfc\x77\x4e\xa9\xfe\x7b\x40\xf9\xea\x7f\x40\xf9\xff\x83\x04\x91\xfd\x7b\xc3\xa8",
           76);
    /*
        CBZ X9,CONT
        RET
        CONT:
    */
    memcpy(&out[43],"\x49\x00\x00\xb4\xc0\x03\x5f\xd6",8);
    out[45] = oldinst;

    generic_inst_movabs(9,JmpAddr,&out[46]);

    out[50] = generic_inst_br(9);

    return 52;
}

#endif
