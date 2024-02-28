//
// Created by www on 4/27/2023.
//

#ifndef _TOUCHLAB_PROCESS_CONTROL_H
#define _TOUCHLAB_PROCESS_CONTROL_H
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <iostream>
#include <string>
#include <sys/mman.h>
#include <string.h>
#include <dlfcn.h>
#include <stdio.h>
#include <elf.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <map>
#include <dlfcn.h>
#include "KDrv.h"

static const char *pathsuffix(const char *path){
    const char *final= path;
    while(*path++){
        if(*path=='/'){
            final=path+1;
        }
    }
    return final;
}

static void process_enumlibs(pid_t pid,int (*EnumCB)(const char *name,uintptr_t addr,uintptr_t execaddr,uintptr_t imgsz,void *context),void *context){
    char path_proc_pid_maps[1024]={0};
    snprintf(path_proc_pid_maps,1024,"/proc/%d/maps",pid);
    FILE*fp=fopen(path_proc_pid_maps,"r");

    char line[1024];
    struct {
        int inode=0;
        uintptr_t baseaddr=0;
        uintptr_t endaddr=0;
        uintptr_t execaddr=0;
        char path[1024]={0};
    } lookinginode;
    bool looked= false;
    //int lookinginode=0;
    while(fgets(line,1024,fp)!=0){
        uint64_t addr_begin=0,addr_end=0;
        uint32_t offset=0;
        uint32_t dev_major=0,dev_minor=0;
        int inode=0;
        char pathname[1024]={0};

        char prot[5]={0};
        sscanf(line,"%llx-%llx %4s %x %x:%x %d %1024s",
               &addr_begin,&addr_end,prot,&offset,&dev_major,&dev_minor,&inode,&pathname);

        if(lookinginode.inode!=inode)
        {
            //如果已经遍历到了可执行的内存块,则开始记录
            if(looked==true){
                if(EnumCB != nullptr && EnumCB(lookinginode.path,lookinginode.baseaddr,lookinginode.execaddr,lookinginode.endaddr-lookinginode.baseaddr,context)==1)
                    return;
            }
            //如果inode存在,则视为一个新模块的开始,并重新初始化变量
            if(inode!=0){
                lookinginode.inode=inode;
                lookinginode.baseaddr=addr_begin;
                lookinginode.endaddr=addr_end;
                strncpy(lookinginode.path,pathname,1024);
            }

            looked=false;
        }

        //判断是否是连续文件映射内存块
        if(lookinginode.inode==inode && inode!=0 ){
            //如果保护属性里面有可执行属性,则标记
            if(prot[2]=='x' && looked==false){
                lookinginode.execaddr=addr_begin;
                looked=true;
            }
            lookinginode.endaddr=addr_end;
        }
    }
    if(looked==true){
        if(EnumCB != nullptr && EnumCB(lookinginode.path,lookinginode.baseaddr,lookinginode.execaddr,lookinginode.endaddr-lookinginode.baseaddr,context)==1)
            return;
    }
}
static uintptr_t process_symaddr_to_libaddr(pid_t pid,uintptr_t symaddr){
    struct {
        uintptr_t symaddr=symaddr;
        uintptr_t retval=0;
    }local_ctx={symaddr,0};
    process_enumlibs(pid,[](const char* path,uintptr_t addr,uintptr_t execaddr,uintptr_t imgsz,void*context)->int{
        auto ctx=(decltype(local_ctx)*)context;
        if(ctx->symaddr>=addr && (ctx->symaddr)<(addr+imgsz)){
            ctx->retval=addr;
            return 1;
        }
        return 0;
    }, &local_ctx);
    return local_ctx.retval;
}
static std::string process_libaddr_to_libpath(pid_t pid,uintptr_t libaddr){
    struct {
        uintptr_t libaddr=libaddr;
        std::string retval="";
    }local_ctx={libaddr,""};
    process_enumlibs(pid,[](const char* path,uintptr_t addr,uintptr_t execaddr,uintptr_t imgsz,void*context)->int{
        auto ctx=(decltype(local_ctx)*)context;
        if(ctx->libaddr==addr){
            ctx->retval=path;
            return 1;
        }
        return 0;
    }, &local_ctx);
    return local_ctx.retval;
}
static uintptr_t process_get_libaddr(pid_t pid,const char* libpath){
    struct {
        const char* libpath=libpath;
        uintptr_t retval=0;
    }local_ctx={libpath,0};
    process_enumlibs(pid,[](const char* path,uintptr_t addr,uintptr_t execaddr,uintptr_t imgsz,void*context)->int{
        auto ctx=(decltype(local_ctx)*)context;
        if(!strcmp(ctx->libpath,path)){
            ctx->retval=addr;
            return 1;
        }
        return 0;
    }, &local_ctx);
    return local_ctx.retval;
}
static uintptr_t process_get_simplelibaddr(pid_t pid,const char* libpath){
    struct {
        const char* libpath=pathsuffix(libpath);
        uintptr_t retval=0;
    }local_ctx={libpath,0};
    process_enumlibs(pid,[](const char* path,uintptr_t addr,uintptr_t execaddr,uintptr_t imgsz,void*context)->int{
        auto ctx=(decltype(local_ctx)*)context;
        if(!strcmp(ctx->libpath,pathsuffix(path))){
            ctx->retval=addr;
            return 1;
        }
        return 0;
    }, &local_ctx);
    return local_ctx.retval;
}
static uintptr_t process_get_simplelibexecaddr(pid_t pid,const char* libpath){
    struct {
        const char* libpath=pathsuffix(libpath);
        uintptr_t retval=0;
    }local_ctx={libpath,0};
    process_enumlibs(pid,[](const char* path,uintptr_t addr,uintptr_t execaddr,uintptr_t imgsz,void*context)->int{
        auto ctx=(decltype(local_ctx)*)context;
        if(!strcmp(ctx->libpath,pathsuffix(path))){
            ctx->retval=execaddr;
            return 1;
        }
        return 0;
    }, &local_ctx);
    return local_ctx.retval;
}

static void process_print_libs(pid_t pid){
    struct {
        const char* libpath=libpath;
        uintptr_t retval=0;
    }local_ctx={0,0};
    process_enumlibs(pid,[](const char* path,uintptr_t addr,uintptr_t execaddr,uintptr_t imgsz,void*context)->int{
        printf("%p %p %s\n",addr,imgsz,path);
        return 0;
    }, &local_ctx);
    return;
}

static uintptr_t process_dlvsym(pid_t pid,const char *lib,const char * __name,const char * __version){
    void* soinfo=dlopen(lib,RTLD_NOW);
    if(soinfo)
    {
        uintptr_t local_sym = (uintptr_t)dlvsym(soinfo,__name,__version);
        uintptr_t local_lib = process_symaddr_to_libaddr(getpid(),local_sym);
        uintptr_t sym_offset=local_sym-local_lib;
        std::string local_lib_path= process_libaddr_to_libpath(getpid(),local_lib);

        // std::cout << local_lib_path << std::endl;
        // auto suffix = pathsuffix(local_lib_path.c_str());

        uintptr_t remote_lib=process_get_libaddr(pid,local_lib_path.c_str());
        // auto kdrv = CreateKDrvObject();
        // kdrv->setPid(pid);
        // uintptr_t remote_lib=kdrv->getModuleAddress(suffix);
        if(remote_lib)
        {
            return remote_lib+sym_offset;
        }
    }
    return 0;
}
static uintptr_t process_dlsym(pid_t pid,const char *lib,const char * __name){
    void* soinfo=dlopen(lib,RTLD_NOW);
    if(soinfo)
    {
        uintptr_t local_sym = (uintptr_t)dlsym(soinfo,__name);
        uintptr_t local_lib = process_symaddr_to_libaddr(getpid(),local_sym);
        uintptr_t sym_offset=local_sym-local_lib;
        std::string local_lib_path= process_libaddr_to_libpath(getpid(),local_lib);

        uintptr_t remote_lib=process_get_libaddr(pid,local_lib_path.c_str());
        return  remote_lib+sym_offset;
    }
    return 0;
}

#endif //_TOUCHLAB_PROCESS_CONTROL_H
