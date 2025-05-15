#include "hook.h"

// 仅前四个参数有参考价值，因为当依赖栈传参 + 原函数第一条指令为栈操作指令时，栈错误；但是不影响原函数执行。
INT64 __stdcall Hook0x00001(PREGContext pushedAqs) {
    // 做自定义的行为
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "NT  Hook0x00001 ,rcx:%llx,rdx:%llx,r8:%llx,r9:%llx\n",pushedAqs->rcx,pushedAqs->rdx,pushedAqs->r8,pushedAqs->r9);
    // 由于此处没有足够的参数信息，因此无法完成原函数调用；可以通过调整 PREGContext 结构体尝试获取完整所需参数。

    return 0; // 表示调用原始函数
}

INT64 __stdcall Hook0x00002(PREGContext pushedAqs) {
    // 做自定义的行为
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ZW  Hook0x00002 ,rcx:%llx,rdx:%llx,r8:%llx,r9:%llx\n", pushedAqs->rcx, pushedAqs->rdx, pushedAqs->r8, pushedAqs->r9);
    // 由于此处没有足够的参数信息，因此无法完成原函数调用；可以通过调整 PREGContext 结构体尝试获取完整所需参数。

    return 0; // 表示调用原始函数
}