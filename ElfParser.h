//
// Created by www on 4/27/2023.
//

#ifndef INJECTOR_ELF_PARSER_H
#define INJECTOR_ELF_PARSER_H

#include <stdint.h>
#include <elf.h>
#include "util.h"
#include "RemoteDlsym.h"

unsigned int
elf_hash (const char *name)
{
    const unsigned char *iname = (const unsigned char *) name;
    unsigned int hash = (unsigned int) *iname++;
    if (*iname != '\0')
    {
        hash = (hash << 4) + (unsigned int) *iname++;
        if (*iname != '\0')
        {
            hash = (hash << 4) + (unsigned int) *iname++;
            if (*iname != '\0')
            {
                hash = (hash << 4) + (unsigned int) *iname++;
                if (*iname != '\0')
                {
                    hash = (hash << 4) + (unsigned int) *iname++;
                    while (*iname != '\0')
                    {
                        unsigned int hi;
                        hash = (hash << 4) + (unsigned int) *iname++;
                        hi = hash & 0xf0000000;

                        /* The algorithm specified in the ELF ABI is as
                       follows:

                       if (hi != 0)
                       hash ^= hi >> 24;

                       hash &= ~hi;

                       But the following is equivalent and a lot
                       faster, especially on modern processors.  */

                        hash ^= hi;
                        hash ^= hi >> 24;
                    }
                }
            }
        }
    }
    return hash;
}
uint_fast32_t
gnu_hash (const char *s)
{
    uint_fast32_t h = 5381;
    for (unsigned char c = *s; c != '\0'; c = *++s)
        h = h * 33 + c;
    return h & 0xffffffff;
}


Elf64_Phdr *elf_get_phdr(u8*elf_file,Elf64_Word type){
    Elf64_Ehdr *ehdr=(Elf64_Ehdr *)elf_file;
    Elf64_Phdr *phdr=(Elf64_Phdr *)(elf_file+ehdr->e_phoff);
    for(int i=0;i<ehdr->e_phnum;i++){
        if(phdr->p_type==type){
            return phdr;
        }
        phdr++;
    }
    return nullptr;
}
uint64_t elf_virt_to_offs(u8*elf_file,uint64_t virt){
    Elf64_Ehdr *ehdr=(Elf64_Ehdr *)elf_file;
    Elf64_Phdr *phdr=(Elf64_Phdr *)(elf_file+ehdr->e_phoff);
    for(int i=0;i<ehdr->e_phnum;i++){
        if(phdr->p_type==PT_LOAD){
            if(virt>=phdr->p_vaddr && virt<(phdr->p_vaddr+phdr->p_filesz)){
                return virt-phdr->p_vaddr+phdr->p_offset;
            }
        }
        phdr++;
    }
    return 0;
}

size_t elf_get_image_sz(u8* elf_file){
    Elf64_Ehdr *ehdr=(Elf64_Ehdr *)elf_file;
    Elf64_Phdr *phdr=(Elf64_Phdr *)(elf_file+ehdr->e_phoff);
    uintptr_t maxaddr=0;
    uintptr_t minaddr=0xffffffffffffffff;
    uintptr_t minaddr_init=false;
    for(int i=0;i<ehdr->e_phnum;i++){
        if(phdr->p_vaddr+phdr->p_memsz>maxaddr){
            maxaddr=phdr->p_vaddr+phdr->p_memsz;
        }
        if(minaddr_init==false){
            minaddr=phdr->p_vaddr;
            minaddr_init=true;
        }
        if(phdr->p_vaddr < minaddr){
            minaddr=phdr->p_vaddr;
        }
        phdr++;
    }
    return maxaddr;
}
Elf64_Dyn *elf_get_dynseg(u8*elf_file,Elf64_Sxword tag){
    Elf64_Phdr *phdr=elf_get_phdr(elf_file,PT_DYNAMIC);
    Elf64_Dyn *dyn=(Elf64_Dyn *)(phdr->p_offset+elf_file);
    while(dyn->d_tag!=DT_NULL){
        if(dyn->d_tag==tag){
            return dyn;
        }
        dyn++;
    }
    return nullptr;
}
u8* elf_get_dynseg_addr(u8*elf_file,Elf64_Sxword tag){
    Elf64_Dyn *dynseg=elf_get_dynseg(elf_file,tag);
    if(dynseg != nullptr)
    {
        uint64_t offs=elf_virt_to_offs(elf_file,dynseg->d_un.d_ptr);
        //p1x(offs);
        return elf_file+offs;
    }
    return nullptr;
}
uint64_t elf_get_dynseg_vaddr(u8*elf_file,Elf64_Sxword tag){
    Elf64_Dyn *dynseg=elf_get_dynseg(elf_file,tag);
    if(dynseg != nullptr)
    {
        uint64_t vaddr=dynseg->d_un.d_ptr;
        //p1x(offs);
        return vaddr;
    }
    return 0;
}
Elf64_Xword elf_get_dynseg_val(u8*elf_file,Elf64_Sxword tag){
    Elf64_Dyn *dynseg=elf_get_dynseg(elf_file,tag);
    if(dynseg != nullptr){
        return dynseg->d_un.d_val;
    }
    return 0;
}

Elf64_Shdr *elf_get_shdr(u8*elf_file,Elf64_Word type){
    Elf64_Ehdr *ehdr=(Elf64_Ehdr *)elf_file;
    Elf64_Shdr *shdr=(Elf64_Shdr *)((u8*)elf_file+ehdr->e_shoff);

    for(int i=0;i<ehdr->e_shnum;i++){
        if(shdr->sh_type==type){
            return shdr;
        }
        shdr++;
    }
    return nullptr;
}
u8* elf_get_shdr_addr(u8*elf_file,Elf64_Word type){
    Elf64_Shdr *shdr=elf_get_shdr(elf_file,type);
    if(shdr!= nullptr){
        return shdr->sh_offset+elf_file;
    }
    return nullptr;
}
Elf64_Xword elf_get_shdr_sz(u8*elf_file,Elf64_Word type){
    Elf64_Shdr *shdr=elf_get_shdr(elf_file,type);
    if(shdr!= nullptr){
        return shdr->sh_size;
    }
    return 0;
}

const char *elf_get_require_ver(u8*elf_file,Elf64_Xword symidx){
    const char* strtab=(decltype(strtab))elf_get_dynseg_addr(elf_file,DT_STRTAB);
    Elf64_Sym *symtab=(Elf64_Sym *)elf_get_dynseg_addr(elf_file,DT_SYMTAB);
    Elf64_Versym *versymtab=(Elf64_Versym *)elf_get_dynseg_addr(elf_file,DT_VERSYM);
    Elf64_Verneed *verneedtab=(Elf64_Verneed *)elf_get_dynseg_addr(elf_file,DT_VERNEED);
    if(symtab == nullptr || versymtab == nullptr || verneedtab == nullptr || strtab== nullptr)
        return nullptr;
    Elf64_Versym versym=versymtab[symidx];
    if(versym==0 || versym==1)
        return nullptr;
    while(1){
        Elf64_Vernaux *vernaux=(Elf64_Vernaux *)(verneedtab->vn_aux+(u8*)verneedtab);
        while(1){
            Elf64_Half other=vernaux->vna_other;
            //p1x(other);
            if((other & 0x8000)==0){
                if(other==(versym & 0x7FFF)){
                    return strtab+vernaux->vna_name;
                }
            }
            if(vernaux->vna_next==0)
                break;
            vernaux=(decltype(vernaux))((u8*)vernaux+vernaux->vna_next);
        }
        if(verneedtab->vn_next==0)
            break;
        verneedtab=(decltype(verneedtab))((u8*)verneedtab+verneedtab->vn_next);
    }
    return nullptr;
}
const char *elf_get_require_file(u8*elf_file,Elf64_Xword symidx){
    const char* strtab=(decltype(strtab))elf_get_dynseg_addr(elf_file,DT_STRTAB);
    Elf64_Sym *symtab=(Elf64_Sym *)elf_get_dynseg_addr(elf_file,DT_SYMTAB);
    Elf64_Versym *versymtab=(Elf64_Versym *)elf_get_dynseg_addr(elf_file,DT_VERSYM);
    Elf64_Verneed *verneedtab=(Elf64_Verneed *)elf_get_dynseg_addr(elf_file,DT_VERNEED);
    if(symtab == nullptr || versymtab == nullptr || verneedtab == nullptr || strtab== nullptr)
        return nullptr;
    Elf64_Versym versym=versymtab[symidx];
    if(versym==0 || versym==1)
        return nullptr;
    while(1){
        Elf64_Vernaux *vernaux=(Elf64_Vernaux *)(verneedtab->vn_aux+(u8*)verneedtab);
        while(1){
            Elf64_Half other=vernaux->vna_other;
            //p1x(other);
            if((other & 0x8000)==0){
                if(other==(versym & 0x7FFF)){
                    return strtab+verneedtab->vn_file;
                }
            }
            if(vernaux->vna_next==0)
                break;
            vernaux=(decltype(vernaux))((u8*)vernaux+vernaux->vna_next);
        }
        if(verneedtab->vn_next==0)
            break;
        verneedtab=(decltype(verneedtab))((u8*)verneedtab+verneedtab->vn_next);
    }
    return nullptr;
}
int elf_lookup_symidx(u8*elf_file,const char* name){
    uint_fast32_t namehash=gnu_hash(name);

    uint32_t *hashtab=(decltype(hashtab))elf_get_dynseg_addr(elf_file,DT_GNU_HASH);
    const char *strtab=(decltype(strtab))elf_get_dynseg_addr(elf_file,DT_STRTAB);
    Elf64_Sym *symtab=(decltype(symtab)) elf_get_dynseg_addr(elf_file,DT_SYMTAB);

    const uint32_t nbuckets = hashtab[0];   // 哈希桶的数量
    const uint32_t symndx = hashtab[1];     // 符号表中第一个全局符号的索引
    const uint32_t bloom_size = hashtab[2]; // Bloom 过滤器的掩码数
    const uint32_t bloom_shift = hashtab[3];

    bloom_el_t *blooms=(decltype(blooms))&hashtab[4];
    const uint32_t* buckets = (decltype(buckets))&blooms[bloom_size];
    const uint32_t* chain = &buckets[nbuckets];

    bloom_el_t word = blooms[(namehash / ELFCLASS_BITS) % bloom_size];
    bloom_el_t mask = 0
                      | (bloom_el_t)1 << (namehash % ELFCLASS_BITS)
                      | (bloom_el_t)1 << ((namehash >> bloom_shift) % ELFCLASS_BITS);
    if ((word & mask) != mask) {
        return 0;
    }
    uint32_t symix = buckets[namehash % nbuckets];
    if (symix < symndx) {
        return 0;
    }
    while (true) {
        const char* symname = strtab + symtab[symix].st_name;
        const uint32_t hash = chain[symix - symndx];

        if ((namehash|1) == (hash|1) && strcmp(name, symname) == 0) {
            return symix;
        }

        /* Chain ends with an element with the lowest bit set to 1. */
        if (hash & 1) {
            break;
        }

        symix++;
    }

    return 0;
}

Elf64_Addr elf_dlvsym_vaddr(u8*elf_file,const char * __name,const char * __version)
{
    const char* strtab=(decltype(strtab))elf_get_dynseg_addr(elf_file,DT_STRTAB);
    Elf64_Sym *symtab=(Elf64_Sym *)elf_get_dynseg_addr(elf_file,DT_SYMTAB);
    Elf64_Versym *versymtab=(Elf64_Versym *)elf_get_dynseg_addr(elf_file,DT_VERSYM);
    Elf64_Verdef *verdeftab=(Elf64_Verdef *)elf_get_dynseg_addr(elf_file,DT_VERDEF);
    int symidx=elf_lookup_symidx(elf_file,__name);
    if(symtab == nullptr || versymtab == nullptr || verdeftab == nullptr || strtab== nullptr)
        return 0;
    Elf64_Versym versym=versymtab[symidx];
    if(versym==0 || versym==1)
        return 0;
    while(1){
        Elf64_Verdaux *verdaux=(Elf64_Verdaux *)(verdeftab->vd_aux+(u8*)verdeftab);
        while(1){
            const char *vername=strtab+verdaux->vda_name;
            puts(vername);
            if(!strcmp(vername,__version)){
                return symtab[symidx].st_value;
            }
            if(verdaux->vda_next ==0)
                break;
            verdaux=(decltype(verdaux))((u8*)verdaux+verdaux->vda_next);
        }
        if(verdeftab->vd_next == 0)
            break;
        verdeftab=(decltype(verdeftab))((u8*)verdeftab+verdeftab->vd_next);
    }
    return 0;
}
Elf64_Addr elf_dlsym_vaddr(u8*elf_file,const char * __name)
{
    const char* strtab=(decltype(strtab))elf_get_dynseg_addr(elf_file,DT_STRTAB);
    Elf64_Sym *symtab=(Elf64_Sym *)elf_get_dynseg_addr(elf_file,DT_SYMTAB);
    int symidx=elf_lookup_symidx(elf_file,__name);
    if(symtab == nullptr || strtab== nullptr || symidx==0)
        return 0;

    return symtab[symidx].st_value;
}

void mapelf(pid_t pid,uintptr_t remoteaddr,u8*elf_file,u8*rwx_buff){
    //Elf64_Addr ssym= elf_dlsym_vaddr(elf_file,"main");
    //p1x(ssym);
    //exit(1);

    Elf64_Ehdr *ehdr=(Elf64_Ehdr *)elf_file;
    Elf64_Phdr *phdr=(Elf64_Phdr *)(elf_file+ehdr->e_phoff);
    for(int i=0;i<ehdr->e_phnum;i++){
        memcpy(rwx_buff+phdr->p_vaddr,elf_file+phdr->p_offset,phdr->p_filesz);
        phdr++;
    }

    Elf64_Rela *rela_array=(Elf64_Rela *)elf_get_dynseg_addr(elf_file,DT_RELA);
    const char *strtab=(decltype(strtab))(elf_get_dynseg_addr(elf_file,DT_STRTAB));
    Elf64_Sym *syms= (decltype(syms))(elf_get_dynseg_addr(elf_file,DT_SYMTAB));
    int num_rela=elf_get_dynseg_val(elf_file,DT_RELASZ)/sizeof(Elf64_Rela);
    if(rela_array== nullptr || strtab== nullptr || syms== nullptr){
        p1x(rela_array);
        p1x(strtab);
        p1x(syms);
        return;
    }
    for(int i=0;i<num_rela;i++){
        Elf64_Rela *rela=&rela_array[i];
        Elf64_Xword symidx = ELF64_R_SYM(rela->r_info);
        Elf64_Xword type = ELF64_R_TYPE(rela->r_info);
        //p1x(type);
        //p1x(symidx);
        if(type == R_AARCH64_GLOB_DAT){
            if(syms[symidx].st_shndx!=0 && syms[symidx].st_value!=0)
            {
                uintptr_t sym_addr=(uint64_t)syms[symidx].st_value+remoteaddr;
                *(uint64_t*)(rwx_buff+rela->r_offset)=sym_addr;
                printf("[+] fixing R_X86_64_GLOB_DAT symidx:%d rva:%llX\n",symidx,syms[symidx].st_value);
            }
            else
            {
                const char *sym_name=strtab+syms[symidx].st_name;
                const char *ver_name= elf_get_require_ver(elf_file,symidx);
                const char *ver_file= elf_get_require_file(elf_file,symidx);

                if(ver_name && ver_file){
                    //void* soinfo= dlopen(ver_name,RTLD_NOW);
                    uintptr_t sym_addr=process_dlvsym(pid,ver_file,sym_name,ver_name);
                    //p1x(sym_addr);
                    if(sym_addr != 0){
                        *(uint64_t*)(rwx_buff+rela->r_offset)=(uint64_t)sym_addr;
                        printf("[+] fixing R_X86_64_GLOB_DAT sym:%s ver:%s file:%s remote:%llX\n",sym_name,ver_name,ver_file,sym_addr);
                    }
                }
            }

        }
        if(type == R_AARCH64_RELATIVE){
            printf("[+] fixing R_X86_64_RELATIVE r_offset: %llX r_addend: %llX\n",rela->r_offset,rela->r_addend);
            *(uint64_t*)(rwx_buff+rela->r_offset)=(uint64_t)rela->r_addend + (uint64_t)rwx_buff;
        }
        if(type == R_AARCH64_ABS64){
            const char *sym_name=strtab+syms[symidx].st_name;
            Elf64_Addr sym_addr=remoteaddr+syms[symidx].st_value;
            //p1x(sym_addr);
            if(sym_addr != 0){
                *(Elf64_Addr *)(rwx_buff+rela->r_offset)=(uint64_t)sym_addr;
                printf("[+] fixing R_AARCH64_ABS64 sym:%s addr:%llX\n",sym_name,sym_addr);
            }
        }
    }

    Elf64_Rela *jmprel_array=(Elf64_Rela *)elf_get_dynseg_addr(elf_file,DT_JMPREL);
    Elf64_Xword jmprel_sz= elf_get_dynseg_val(elf_file,DT_PLTRELSZ);
    if(jmprel_array==nullptr)
        return;
    int numjmprel=jmprel_sz/sizeof(Elf64_Rela);
    for(int i=0;i<numjmprel;i++){
        Elf64_Rela*rela=&jmprel_array[i];
        Elf64_Xword symidx = ELF64_R_SYM(rela->r_info);
        Elf64_Xword type = ELF64_R_TYPE(rela->r_info);
        const char *sym_name=strtab+syms[symidx].st_name;
        if(type==R_AARCH64_JUMP_SLOT){
            if(syms[symidx].st_value !=0 )
            {
                uintptr_t sym_addr=remoteaddr + syms[symidx].st_value;
                if(sym_addr != 0){
                    *(uint64_t*)(rwx_buff+rela->r_offset)=(uint64_t)sym_addr;
                    printf("[+] fixing R_AARCH64_JUMP_SLOT offset:%04X remote:%llX\n",rela->r_offset,sym_addr);
                }
            }
            else
            {
                const char *ver_name=elf_get_require_ver(elf_file,symidx);
                const char *ver_file= elf_get_require_file(elf_file,symidx);
                p1x(ver_name);
                if(ver_name)
                {
                    if(ver_file)
                    {
                        uintptr_t sym_addr=process_dlvsym(pid,ver_file,sym_name,ver_name);
                        if(sym_addr != 0){
                            *(uint64_t*)(rwx_buff+rela->r_offset)=(uint64_t)sym_addr;
                            printf("[+] fixing R_AARCH64_JUMP_SLOT offset:%04X sym:%s ver:%s file:%s remote:%llX\n",rela->r_offset,sym_name,ver_name,ver_file,sym_addr);
                        }
                        else
                        {
                            printf("[-] unknown2\r\n");
                        }
                    }
                }
                else
                {
                    p1x(rela->r_offset);
                }
            }
            
        }
    }

    //void(*Entry)() =decltype(Entry)(0x1189+rwx_buff);
    //Entry();

}

#endif //INJECTOR_ELF_PARSER_H
