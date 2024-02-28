//
// Created by www on 4/27/2023.
//

#ifndef _PROCESS_CONTROL_H_
#define _PROCESS_CONTROL_H_
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
#include "util.h"
#include "RemoteDlsym.h"

uintptr_t process_remotecall(pid_t pid,uintptr_t calladdr,
                             uint64_t a1,uint64_t a2,uint64_t a3,uint64_t a4,uint64_t a5,uint64_t a6){
    if(ptrace(PTRACE_ATTACH,pid,0,0)){
        fprintf(stderr,"%s\n","process attach failed!");
        return 0;
    }
    waitpid(pid,0,0 );

    int regset=NT_PRSTATUS;
    user_pt_regs ori_regs;
    iovec iov;
    iov.iov_base=&ori_regs;
    iov.iov_len=sizeof(ori_regs);
    if(ptrace(PTRACE_GETREGSET,pid,(void *)regset,&iov)){
        fputs("getreg failed!\n",stderr);
        fflush(stdout);
        ptrace(PTRACE_DETACH,pid,0,0);
        return 0;
    }
    //show_reg(&ori_regs);
    user_pt_regs modify_regs;
    memcpy(&modify_regs,&ori_regs,sizeof(modify_regs));

    modify_regs.regs[0]=a1;
    modify_regs.regs[1]=a2;
    modify_regs.regs[2]=a3;//PROT_EXEC | PROT_READ | PROT_WRITE;
    modify_regs.regs[3]=a4;//MAP_ANONYMOUS | MAP_PRIVATE;
    modify_regs.regs[4]=a5;
    modify_regs.regs[5]=a6;

    //uintptr_t addr_mmap= process_dlsym(pid,"libc.so","mmap");
    //uintptr_t addr_libc= process_symaddr_to_libaddr(pid,addr_mmap);
    //p1x(addr_libc);
    modify_regs.regs[30]=0;
    modify_regs.pc=calladdr;

    iov.iov_base=&modify_regs;
    iov.iov_len=sizeof(modify_regs);
    ptrace(PTRACE_SETREGSET,pid,(void *)regset,&iov);
    ptrace(PTRACE_CONT,pid,0,0);

    uintptr_t return_value=0;
    while (1){
        waitpid(pid,0,0);
        user_pt_regs regs;
        memset(&regs,0,sizeof(regs));
        iov.iov_base=&regs;
        iov.iov_len=sizeof(regs);
        ptrace(PTRACE_GETREGSET,pid,(void *)regset,&iov);
        if(regs.pc==0 && regs.regs[30]==0) {
            return_value=regs.regs[0];
            break;
        }
    }


    iov.iov_base=&ori_regs;
    iov.iov_len=sizeof(ori_regs);
    ptrace(PTRACE_SETREGSET,pid,(void *)regset,&iov);

    ptrace(PTRACE_DETACH,pid,0,0);

    //p1x(return_value);
    return return_value;
}
void process_remotecall_nonret(pid_t pid,uintptr_t calladdr,
                               uint64_t a1,uint64_t a2,uint64_t a3,uint64_t a4,uint64_t a5,uint64_t a6){
    if(ptrace(PTRACE_ATTACH,pid,0,0)){
        fprintf(stderr,"%s\n","process attach failed!");
        return;
    }
    waitpid(pid,0,0 );

    int regset=NT_PRSTATUS;
    user_pt_regs ori_regs;
    iovec iov;
    iov.iov_base=&ori_regs;
    iov.iov_len=sizeof(ori_regs);
    if(ptrace(PTRACE_GETREGSET,pid,(void *)regset,&iov)){
        fputs("getreg failed!\n",stderr);
        fflush(stdout);
        ptrace(PTRACE_DETACH,pid,0,0);
        return;
    }
    //show_reg(&ori_regs);
    user_pt_regs modify_regs;
    memcpy(&modify_regs,&ori_regs,sizeof(modify_regs));

    modify_regs.regs[0]=a1;
    modify_regs.regs[1]=a2;
    modify_regs.regs[2]=a3;//PROT_EXEC | PROT_READ | PROT_WRITE;
    modify_regs.regs[3]=a4;//MAP_ANONYMOUS | MAP_PRIVATE;
    modify_regs.regs[4]=a5;
    modify_regs.regs[5]=a6;

    uintptr_t addr_mmap= process_dlsym(pid,"libc.so","mmap");
    uintptr_t addr_libc= process_symaddr_to_libaddr(pid,addr_mmap);
    p1x(addr_libc);
    modify_regs.regs[30]=0;
    modify_regs.pc=calladdr;

    iov.iov_base=&modify_regs;
    iov.iov_len=sizeof(modify_regs);
    ptrace(PTRACE_SETREGSET,pid,(void *)regset,&iov);
    ptrace(PTRACE_CONT,pid,0,0);

    uintptr_t return_value=0;
    while (1){
        waitpid(pid,0,0);
        user_pt_regs regs;
        memset(&regs,0,sizeof(regs));
        iov.iov_base=&regs;
        iov.iov_len=sizeof(regs);
        ptrace(PTRACE_GETREGSET,pid,(void *)regset,&iov);
        if(regs.pc==addr_libc && regs.regs[30]==addr_libc) {
            return_value=regs.regs[0];
            break;
        }
    }


    iov.iov_base=&ori_regs;
    iov.iov_len=sizeof(ori_regs);
    ptrace(PTRACE_SETREGSET,pid,(void *)regset,&iov);

    ptrace(PTRACE_DETACH,pid,0,0);

    //p1x(return_value);
    return ;
}


uintptr_t process_mmap(pid_t pid,size_t length,int prot){
    uintptr_t remote_mmap=process_dlsym(pid,"libc.so","mmap");
    p1x(remote_mmap);
    if(remote_mmap!=0){
        return process_remotecall(pid,
                                  remote_mmap,
                                  0,
                                  (uintptr_t)length,
                                  prot,
                                  MAP_ANONYMOUS | MAP_PRIVATE,
                                  0,0);
    }
    return 0;
}
uintptr_t process_mprotect(pid_t pid,uintptr_t addr,size_t length,int prot){
    uintptr_t remote_mmap=process_dlsym(pid,"libc.so","mprotect");
    p1x(remote_mmap);
    if(remote_mmap!=0){
        return process_remotecall(pid,
                                  remote_mmap,
                                  addr,
                                  (uintptr_t)length,
                                  prot,
                                  0,
                                  0,0);
    }
    return 0;
}


#endif //INJECTSURFACEFLINGER_PROCESS_CONTROL_H
