#include "KDrv.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/uio.h>
#include <fcntl.h>
#include "RemoteDlsym.h"

using namespace std;

class KDrvRootImpl : public KDrvImplement
{
    private:
    uint64_t mPid = 0;

    public:
    KDrvRootImpl()
    {

    }
    size_t readMemory(uint64_t address,void* data,size_t size) override
    {
        struct iovec local[1];
        struct iovec remote[1];

        local[0].iov_base = data;
        local[0].iov_len = size;
        remote[0].iov_base = (void *)address;
        remote[0].iov_len = size;

        ssize_t n_read = process_vm_readv(mPid, local, 1, remote, 1, 0);
        return n_read;
    }
    size_t writeMemory(uint64_t address,const void* data,size_t size) override
    {
        auto len = size;
        auto buf = (uint8_t*)data;
        auto addr = address;
        auto pid = mPid;
        
        long word;
        size_t bytes_written = 0;
        size_t bytes = len;

        if(ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
            return bytes_written;
        }
        waitpid(pid, NULL, 0);

        // 逐字(word)写入数据
        while (bytes >= sizeof(long)) {
            memcpy(&word, buf + bytes_written, sizeof(long));
            if (ptrace(PTRACE_POKEDATA, pid, addr + bytes_written, word) == -1) {
                fprintf(stderr, "PTRACE_POKEDATA failed: %s\n", strerror(errno));
                return bytes_written;
            }
            bytes -= sizeof(long);
            bytes_written += sizeof(long);
        }

        if (bytes > 0) {
            // 只剩下不足一个字的字节
            uint8_t last_word_data[sizeof(long)];
            memcpy(last_word_data,buf+bytes_written,bytes);
            readMemory(address+bytes_written+bytes,last_word_data+bytes,sizeof(long) - bytes);
            long last_word = *(long*)last_word_data;
            if (ptrace(PTRACE_PEEKDATA, pid, addr + bytes_written, &last_word) == -1) {
                fprintf(stderr, "PTRACE_PEEKDATA failed: %s\n", strerror(errno));
                return bytes_written;
            }
            
            // 使用缓冲区稍后写入的字节覆盖最后一个字中的前几个字节
            memcpy(&last_word, buf + bytes_written, bytes);
            if (ptrace(PTRACE_POKEDATA, pid, addr + bytes_written, last_word) == -1) {
                fprintf(stderr, "PTRACE_POKEDATA failed: %s\n", strerror(errno));
                return bytes_written;
            }
        }

        ptrace(PTRACE_DETACH, pid, 0, 0);
        return bytes_written;
    }
    size_t writeMemoryPtrace(uint64_t address,const void* data,size_t size) override
    {
        return writeMemory(address,data,size);
    }
    uint64_t getModuleAddress(std::string moduleName) override
    {
        if(!moduleName.empty())
        {
            return process_get_simplelibaddr(mPid,moduleName.c_str());
        }
        return 0;
    }
    std::vector<std::pair<uint64_t,std::string>> traverseProcesses() override
    {
        std::vector<std::pair<uint64_t,std::string>> ret;
        DIR* dir = opendir("/proc");
        if (!dir) {
            return ret;
        }
        struct dirent* entry;
        while ((entry = readdir(dir))) {
            if (entry->d_type != DT_DIR) {
                continue;
            }
            const char* name = entry->d_name;
            if (*name < '0' || *name > '9') {
                continue;
            }
            int pid = atoi(name);
            char cmdline_path[256];
            snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
            FILE* cmdline_file = fopen(cmdline_path, "r");
            if (!cmdline_file) {
                continue;
            }
            char cmdline[256];
            int len = fread(cmdline, 1, sizeof(cmdline), cmdline_file);
            fclose(cmdline_file);
            if (len <= 0) {
                continue;
            }
            cmdline[len] = '\0';
            ret.push_back(make_pair(pid,string(cmdline)));
        }
        closedir(dir);
        return ret;
    }
    uint64_t remoteMmap(uint64_t size, uint64_t prot, uint64_t flags)
    {
        return 0;
    }
    void setPid(uint64_t pid) override
    {
        mPid = pid;
    }
};

std::unique_ptr<KDrvImplement> CreateKDrvimplementObject()
{
    return make_unique<KDrvRootImpl>();
}

