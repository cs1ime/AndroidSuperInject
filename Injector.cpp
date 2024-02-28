#include <iostream>
#include "KDrv.h"
#include "util.h"
#include "RemoteDlsym.h"
#include "binso.hpp"
#include "ElfParser.h"
#include "Arm64Generator.h"
#include "ProcessControl.h"
#include <dirent.h>
#include <linux/uinput.h>
#include <android/input.h>
#include <android/keycodes.h>

using namespace std;

#define BITS_PER_LONG (sizeof(long) * 8)
#define test_bit(array, bit)    ((array[bit / BITS_PER_LONG] >> bit % BITS_PER_LONG) & 1)
#define NBITS(x)             ((((x)-1)/BITS_PER_LONG)+1)

#define rpm _KDrv->readMemory
#define wpm _KDrv->writeMemoryPtrace

shared_ptr<KDrv> _KDrv = nullptr;

int64_t findSystemServer()
{
    auto r = _KDrv->traverseProcesses();
    for(auto& [pid,name] : r)
    {
        if(name == "system_server")
        {
            return pid;
        }
    }
    return -1;
}

int enumFD(int pid,int(*enumCB)(int fd,const char *filePath,void* ctx),void* ctx)
{
    DIR *d;
    struct dirent *dir;
    char fd_path[PATH_MAX];
    char proc_fd_path[1024];
    snprintf(proc_fd_path,1024,"/proc/%d/fd",pid);

    // 打开 /proc/self/fd 目录
    d = opendir(proc_fd_path);
    if (d == NULL) {
        return -1;
    }

    // 遍历 /proc/self/fd 下的每个条目
    while ((dir = readdir(d)) != NULL) {
        // 跳过 "." 和 ".." 目录
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) {
            continue;
        }

        // 构建 fd 的路径
        snprintf(fd_path, sizeof(fd_path), "%s/%s", proc_fd_path, dir->d_name);
        
        char link_target[PATH_MAX];
        ssize_t len;

        // 读取符号链接，获取文件描述符对应的文件路径
        if ((len = readlink(fd_path, link_target, sizeof(link_target) - 1)) != -1) {
            link_target[len] = '\0'; // 确保字符串 null 终止
            // printf("文件描述符 %s -> %s\n", dir->d_name, link_target);
            int fd = atoi(dir->d_name);
            if(enumCB(fd,link_target,ctx)!=0)
            {
                closedir(d);
                return fd;
            }
        }
    }

    // 关闭目录
    closedir(d);
    return -1;
}
int getFDCB(int fd,const char *filePath,void* ctx)
{
    const char * findpath = (const char *)ctx;
    if(!strcmp(filePath,findpath))
    {
        return 1;
    }
    return 0;
}
int getFD(int pid,const char *path)
{
    return enumFD(pid,getFDCB,(void*)path);
}
int isa_event_device(const struct dirent *dir) {
    return strncmp("event", dir->d_name, 5) == 0;
}
std::string getTouchScreenDevice() {
    struct dirent **namelist;
    int i, ndev;
    ndev = scandir("/dev/input", &namelist, isa_event_device, alphasort);
    if (ndev <= 0) {
        return "";
    }
    for (i = 0; i < ndev; i++) {
        char fname[64];
        int fd = -1;
        unsigned long keybit[NBITS(KEY_CNT)];
        unsigned long propbit[INPUT_PROP_MAX];
        snprintf(fname, sizeof(fname), "%s/%s", "/dev/input", namelist[i]->d_name);
        fd = open(fname, O_RDONLY);
        if (fd < 0) {
            continue;
        }
        memset(keybit, 0, sizeof(keybit));
        memset(propbit, 0, sizeof(propbit));
        ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(keybit)), keybit);
        ioctl(fd, EVIOCGPROP(INPUT_PROP_MAX), propbit);
        close(fd);
        free(namelist[i]);
        if (test_bit(propbit, INPUT_PROP_DIRECT) &&
            (test_bit(keybit, BTN_TOUCH) || test_bit(keybit, BTN_TOOL_FINGER))) {
            return {fname};
        } else if (test_bit(keybit, BTN_TOUCH) || test_bit(keybit, BTN_TOOL_FINGER)) {
            return {fname};
        }
    }
    return "";
}

int main()
{
    _KDrv = CreateKDrvObject();
    auto pid = findSystemServer();
    int touchFD = -1;
    auto dev = getTouchScreenDevice();
    if(!dev.empty())
    {
        touchFD = getFD(pid,dev.c_str());
    }
    if(touchFD < 0)
    {
        puts("cannot find touch device!");
        exit(1);
    }
    p1d(touchFD);

    p1d(pid);
    _KDrv->setPid(pid);
    _KDrv->enableReadCache();

    auto libc = _KDrv->getModuleAddress("libc.so");

    p1x(libc);

    auto exitaddr = process_dlsym(pid,"libc.so","abort");
    p1x(exitaddr);
    auto readaddr = process_dlsym(pid,"libc.so","read");
    p1x(readaddr);
    auto mallocaddr = process_dlsym(pid,"libc.so","malloc");
    p1x(mallocaddr);
    auto readoldinst = rpm<u32>(readaddr).value_or(0);
    p1x(readoldinst)

    auto nestaddr = process_get_simplelibexecaddr(pid,"libbacktrace.so");
    p1x(nestaddr);

    auto elf = binso::binary_data;

    auto imgsz = elf_get_image_sz(elf);
    auto imgdat = (u8*)malloc(imgsz);
    p1x(imgsz)
    memset(imgdat,0,imgsz);
    mapelf(pid,nestaddr,elf,imgdat);
    auto readCallback = elf_dlsym_vaddr(elf,"readCallback") + nestaddr;
    auto IsInjectorOk = elf_dlsym_vaddr(elf,"g_IsInjectorOk") + nestaddr;
    auto contextptr = elf_dlsym_vaddr(elf,"g_contextPtr") + nestaddr;
    auto touchDeviceFD = elf_dlsym_vaddr(elf,"g_TouchDeviceFD") + nestaddr;
    p1x(readCallback);
    p1x(IsInjectorOk);
    p1x(contextptr);
    p1x(touchDeviceFD);

    auto wrsz = wpm(nestaddr,imgdat,imgsz);
    p1x(wrsz);

    uint32_t inst_jmp2exit;
    inst_jmp2exit = generic_inst_b(readaddr,exitaddr);
    p1x(inst_jmp2exit)
    uint32_t inst_invokecallback[52]={0};
    generic_invoker(readCallback,readaddr+4,readoldinst,inst_invokecallback);
    
    wpm(exitaddr,&inst_invokecallback,sizeof(inst_invokecallback));

    auto contextmallocaddr = process_remotecall(pid,mallocaddr,0x1000,0,0,0,0,0);
    p1x(contextmallocaddr);
    auto vecZerp = vector<u8>(0x1000,0);
    wpm(contextmallocaddr,vecZerp);

    wpm<uintptr_t>(contextptr,contextmallocaddr);
    wpm<int>(touchDeviceFD,touchFD);
    wpm<int>(readaddr,inst_jmp2exit);
    wpm<int>(IsInjectorOk,1);

    return 0;
}
