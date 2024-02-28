#pragma once

#ifndef _KDRV_H_
#define _KDRV_H_

#include <optional>
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <array>
#include <tuple>

class KDrvImplement
{
    public:
    virtual size_t readMemory(uint64_t address,void* data,size_t size) = 0;
    virtual size_t writeMemory(uint64_t address,const void* data,size_t size) = 0;
    virtual size_t writeMemoryPtrace(uint64_t address,const void* data,size_t size) = 0;
    virtual uint64_t getModuleAddress(std::string moduleName) = 0;
    virtual std::vector<std::pair<uint64_t,std::string>> traverseProcesses() = 0;
    virtual uint64_t remoteMmap(uint64_t size, uint64_t prot, uint64_t flags) = 0;
    virtual void setPid(uint64_t pid) = 0;
};

enum class KDrvReadCacheStatus : int
{
    UNUSED = 0,
    BADPAGE,
    GOOD,
};

class KDrvReadCache {
    private:
    
    std::unordered_map<uint64_t,std::array<uint8_t,0x1000>> mCache;
    std::unordered_map<uint64_t,KDrvReadCacheStatus> mCacheStatus;
    int cacheClock = 0;

    protected:
    std::shared_ptr<KDrvImplement> _impl;
    bool updatePage(uint64_t PFN,std::array<uint8_t,0x1000>& outData)
    {
        auto &Status = mCacheStatus[PFN];
        switch (Status)
        {
        case KDrvReadCacheStatus::UNUSED:
        {
            std::array<uint8_t,0x1000> data;
            if(_impl->readMemory(PFN*0x1000,(void*)&data[0],0x1000) == 0x1000)
            {
                mCacheStatus[PFN] = KDrvReadCacheStatus::GOOD;
                mCache[PFN] = data;
                outData = mCache[PFN];
                return true;
            }
            else
            {
                mCacheStatus[PFN] = KDrvReadCacheStatus::BADPAGE;
                return false;
            }
            break;
        }
        case KDrvReadCacheStatus::BADPAGE:
        {
            return false;
            break;
        }
        case KDrvReadCacheStatus::GOOD:
        {
            auto &cData =  mCache[PFN];
            outData = cData;
            return true;
        }
        default:
            break;
        }
        
        
        return false;
    }
    
    
    public:
    KDrvReadCache(std::shared_ptr<KDrvImplement> impl)
    {
        _impl = impl;
    }
    size_t readMemoryWithCache(uint64_t address,void* data,size_t size) 
    {
        uint64_t StartAddress = (uint64_t)address;
        uint64_t EndAddress = StartAddress + size - 1;
        uint64_t StartAddressPage = StartAddress & 0xFFFFFFFFFFFFF000;
        uint64_t EndAddressPage = EndAddress & 0xFFFFFFFFFFFFF000;
        uint64_t StartAddressReadOffset = StartAddress - StartAddressPage;
        uint64_t StartAddressReadSize = 0x1000 - StartAddressReadOffset;
        uint64_t EndAddressReadSize = EndAddress - EndAddressPage;
        uint64_t StartPFN = StartAddress / 0x1000;
        uint64_t EndPFN = EndAddress / 0x1000;
        uint64_t successDataCount = 0;

        uint8_t *uData = (uint8_t *)data;

        std::array<uint8_t,0x1000> pageData;
        
        if(!updatePage(StartPFN , pageData))
        {
            return 0;
        }

        if(EndPFN > StartPFN)
        {
            memcpy(uData,&(pageData)[StartAddressReadOffset],StartAddressReadSize);
            successDataCount += StartAddressReadSize;
            uData += StartAddressReadSize;
            uint64_t ThroughPages = EndPFN - StartPFN - 1;
            for(uint64_t i=0;i<ThroughPages;i++)
            {
                uint64_t currentPFN = StartPFN + 1 + i;
                if(!updatePage(currentPFN , pageData))
                {
                    return successDataCount;
                }
                memcpy(uData,&(pageData)[0],0x1000);
                successDataCount += 0x1000;
                uData += 0x1000;
            }
            if(!updatePage(EndPFN , pageData))
            {
                return successDataCount;
            }
            memcpy(uData,&(pageData)[0],EndAddressReadSize);
            successDataCount += EndAddressReadSize;
            uData += EndAddressReadSize;
        }
        else
        {
            memcpy(uData,&(pageData)[StartAddressReadOffset],size);
            successDataCount+=size;
        }
        return successDataCount;
    }
    std::string readStringWithCache(uint64_t address, size_t cb) 
    {
        std::vector<char> s;
        
        char c;
        int i=0;
        while(readMemoryWithCache(address+i,(void*)&c,1) && c && ++i < cb)
        {
            s.push_back(c);
        }
        s.push_back(0);
        return std::string(&s[0]);
    }

    void invalidateReadCache() {
        mCache.clear();
        mCacheStatus.clear();
    }
};

class KDrv
{
    private:
    bool mEnableReadCache = false;
    std::shared_ptr<KDrvImplement> _impl = nullptr;
    std::shared_ptr<KDrvReadCache> mReadCache = nullptr;

    public:
    KDrv(std::shared_ptr<KDrvImplement> impl)
    {
        _impl = impl;
        mReadCache = std::make_shared<KDrvReadCache>(_impl);
    }

    uint64_t getModuleAddress(std::string moduleName)
    {
        if(moduleName.length() > 0)
        {
            auto addr = _impl->getModuleAddress(moduleName);
            if(addr != -1)
            {
                return addr;
            }
        }
        return 0;
    }
    uint64_t remoteMmap(uint64_t size, uint64_t prot, uint64_t flags)
    {
        return _impl->remoteMmap(size,prot,flags);
    }

    std::vector<std::pair<uint64_t,std::string>> traverseProcesses()
    {
        return _impl->traverseProcesses();
    }
    void setPid(uint64_t pid)
    {
        _impl->setPid(pid);
    }
    
    void invalidateReadCache()
    {
        mReadCache->invalidateReadCache();
    }
    void enableReadCache()
    {
        mEnableReadCache = true;
        invalidateReadCache();
    }
    void disableReadCache()
    {
        mEnableReadCache = false;
        invalidateReadCache();
    }

    template<typename T>
    std::optional<T> readMemory(uint64_t address)
    {
        T data={};
        if(mEnableReadCache)
        {
            if(mReadCache->readMemoryWithCache(address,&data,sizeof(T)) == sizeof(T))
            {
                return data;
            }
        }
        else
        {
            if(_impl->readMemory(address,&data,sizeof(T)) == sizeof(T))
            {
                return data;
            }
        }
        
        return {};
    }
    std::optional<std::vector<uint8_t>> readMemory(uint64_t address,size_t size)
    {
        std::vector<uint8_t> data;
        data.resize(size);
        if(mEnableReadCache)
        {
            if(mReadCache->readMemoryWithCache(address,(void*)&data[0],size) == size)
            {
                return data;
            }
        }
        else
        {
            if(_impl->readMemory(address,(void*)&data[0],size) == size)
            {
                return data;
            }
        }
        
        return {};
    }

    template<typename T>
    T readMemorySimplely(uint64_t address)
    {
        auto rr = readMemory<T>(address);
        if(rr)
        {
            return *rr;
        }
        T rval={};
        return rval;
    }

    template<typename T>
    size_t writeMemory(uint64_t address,const T& data)
    {
        auto size = _impl->writeMemory(address,&data,sizeof(T));
        if(size > 0)
        {
            return size;
        }
        return 0;
    }
    size_t writeMemory(uint64_t address,const std::vector<uint8_t> &data)
    {
        auto size = _impl->writeMemory(address,(void*)&data[0],data.size());
        if(size > 0)
        {
            return size;
        }
        return 0;
    }
    size_t writeMemory(uint64_t address,void* data,size_t size)
    {
        return _impl->writeMemory(address,data,size);
    }

    template<typename T>
    size_t writeMemoryPtrace(uint64_t address,const T& data)
    {
        auto size = _impl->writeMemoryPtrace(address,(void*)&data,sizeof(T));
        if(size > 0)
        {
            return size;
        }
        return 0;
    }
    size_t writeMemoryPtrace(uint64_t address,const std::vector<uint8_t> &data)
    {
        auto size = _impl->writeMemoryPtrace(address,(void*)&data[0],data.size());
        if(size > 0)
        {
            return size;
        }
        return 0;
    }
    size_t writeMemoryPtrace(uint64_t address,const void* data,size_t size)
    {
        return _impl->writeMemoryPtrace(address,data,size);
    }

    std::string readString(uint64_t address,size_t cb = 1024)
    {
        if(mEnableReadCache)
        {
            return mReadCache->readStringWithCache(address,cb);
        }
        else
        {
            auto tempCache = std::make_shared<KDrvReadCache>(_impl);
            return tempCache->readStringWithCache(address,cb);
        }
    }

};


std::shared_ptr<KDrv> CreateKDrvObject();

#endif