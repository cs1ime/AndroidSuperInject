//
// Created by www on 2023/4/21.
//

#ifndef MAPELF_CUSTOMDEF_H
#define MAPELF_CUSTOMDEF_H

#include <stdint.h>
#include <stdio.h>

#define pp1x(v)printf(""#v"\t=  %08llX\n",(uint64_t)v);fflush(stdout);
#define pp1d(v)printf(""#v"\t=  %08lld\n",(uint64_t)v);fflush(stdout);

#define p1x pp1x 
#define p1d pp1d

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef uint64_t bloom_el_t;
#define ELFCLASS_BITS 64

#endif //MAPELF_CUSTOMDEF_H
