#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <dirent.h>
#include <linux/uinput.h>
#include <android/input.h>
#include <android/keycodes.h>
#include <sys/syscall.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <android/log.h>
#include "TouchLabStructs.hpp"

#define TAG ("TOUCHLAB")

#define p1x(v){char __strbuf__[64];memset(__strbuf__,0,sizeof(__strbuf__));snprintf(__strbuf__,64,"[++] "#v"=%llX",(uint64_t)v);__android_log_print(100,TAG,__strbuf__);};
#define p1d(v){char __strbuf__[64];memset(__strbuf__,0,sizeof(__strbuf__));snprintf(__strbuf__,64,"[++] "#v"=%lld",(uint64_t)v);__android_log_print(100,TAG,__strbuf__);};
#define p1s(v){char __strbuf__[64];memset(__strbuf__,0,sizeof(__strbuf__));snprintf(__strbuf__,64,"[++] "#v"=%s",(uint64_t)v);__android_log_print(100,TAG,__strbuf__);};

#define p1x
#define p1d
#define p1s

#define InterlockedCompareExchange16(target,new_value,expected) (__sync_val_compare_and_swap(target, expected, new_value))

typedef struct {
    short InitLockOnce;
    int IsInitOk;
    int logfd;
    int touchScreenDeviceFd;
    struct universal_events_queue simEventsQueue;
    pthread_rwlock_t simEventsQueueLock;
    pthread_t eventsThread;
} ContextStruct;
typedef struct {
    int hasEvent;
    struct TouchEvent event;
} TouchEventStruct;



__attribute__((visibility("default"))) 
int g_IsInjectorOk = 0;
__attribute__((visibility("default"))) 
ContextStruct* g_contextPtr = NULL;
__attribute__((visibility("default"))) 
TouchEventStruct* g_touchEventPtr = NULL;
__attribute__((visibility("default"))) 
int g_TouchDeviceFD = 0;

void EventsThread();
void Initialize()
{
    g_contextPtr->touchScreenDeviceFd = g_TouchDeviceFD;
    {
        universal_events_queue_initialize(&g_contextPtr->simEventsQueue);
        pthread_rwlockattr_t attr;
        pthread_rwlockattr_init(&attr);
        pthread_rwlock_init(&g_contextPtr->simEventsQueueLock, &attr);
    }

    int ThreadResult = pthread_create(&g_contextPtr->eventsThread,NULL,EventsThread,NULL);
    p1d(ThreadResult);
    
    g_contextPtr->IsInitOk = 1;
}

void EventsThread()
{
    p1s("EventsThread!");
    // 从外部接受按键模拟请求，该部分尚未完成
    while(1)
    {
        // if(g_touchEventPtr->hasEvent)
        // {


        //     g_touchEventPtr->hasEvent = 0;
        // }

        msleep(1000);
    }
}

ssize_t myRead(int fd,void *buf,size_t sz)
{
    // return -1; // 这行是屏蔽对于touchScreenDeviceFd的所有read

    // 如果原先FD能读到事件，则返回
    ssize_t r = syscall(SYS_read,g_contextPtr->touchScreenDeviceFd,buf,sz);
    if(errno != EAGAIN && errno != EINTR)
    {
        return r;
    }
    // 下面是模拟触摸事件的实现

    int numBlocks = sz / sizeof(struct input_event);
    struct input_event *outBuf = (struct input_event *)buf;

    struct input_event_block block;
    pthread_rwlock_wrlock(&g_contextPtr->simEventsQueueLock);
    int numQueue = universal_events_queue_length(&g_contextPtr->simEventsQueue);
    int readCount = numQueue;
    if(readCount > numBlocks)
    {
        readCount = numBlocks;
    }
    if(readCount > 0)
    {
        for(int i=0;i<readCount;i++)
        {
            universal_events_queue_dequeue(&g_contextPtr->simEventsQueue,&block);
            outBuf[i] = block.event;
        }
        pthread_rwlock_unlock(&g_contextPtr->simEventsQueueLock);
        errno = 0;
        return readCount * sizeof(struct input_event);
    }
    pthread_rwlock_unlock(&g_contextPtr->simEventsQueueLock);

    return r;
}

typedef struct {
    uint64_t x0,x1,x2,x3,x4,x5,x6,x7,x8,x9;
    uint64_t x10,x11,x12,x13,x14,x15,x16,x17,x18,x19;
    uint64_t x20,x21,x22,x23,x24,x25,x26,x27,x28,x29;
    uint64_t x30,x31;
} Arm64Context;

int readCallbackInner(Arm64Context *context) 
{
    int fd = context->x0;
    if(!g_contextPtr->IsInitOk)
    {
        if(InterlockedCompareExchange16(&g_contextPtr->InitLockOnce,1,0) == 0)
        {
            Initialize();
        }        
    }
    
    if(g_contextPtr->IsInitOk)
    {
        if(fd == g_contextPtr->touchScreenDeviceFd)
        {
            p1s("touch2!");
            context->x0 = myRead(fd,(void*)context->x1,(size_t)context->x2);
            return 1;
        }
    }
    return 0;
}

__attribute__((visibility("default"))) 
void readCallback(uint64_t sp)
{
    Arm64Context *context = (Arm64Context *)sp;
    if(readCallbackInner(context))
    {
        // context->x0 = -1;
        context->x9 = 1;
    }
    else
    {
        context->x9 = 0;
    }
}



