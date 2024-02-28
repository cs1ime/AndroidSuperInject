## 注入被SELinux保护的系统服务进程

1. 手工映射要注入的SO，以对方的进程模块信息来修补SO的重定位

2. 以对方进程libbacktrace.so的.text段作为nest，写入映射后的SO

3. Hook对方进程的某个j经常被调用的函数作为执行时机初始化代码（比如 libc.so.read）

4. 编写要注入的SO文件时需保证不写全局变量（你在一个权限为r-x的内存范围内运行这个SO）

仓库里的代码是一个hook system_server的read函数从而劫持eventhub实现模拟触摸的半成品
