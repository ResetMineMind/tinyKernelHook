#include "trapHook.h"

// 外部一定要包裹自旋锁
BOOLEAN IsRecordHook(UINT64 func) {
    BOOLEAN get = FALSE;
    if (!(pModHeadNode->list.Flink == NULL || IsListEmpty(&pModHeadNode->list))) {
        for (PLIST_ENTRY pEntry = pHookTable->list.Flink; pEntry != &pHookTable->list; pEntry = pEntry->Flink) {
            PHOOKDESC node = CONTAINING_RECORD(pEntry, HOOKDESC, list);
            // 说明Hook已经注册过了
            if (func == (ULONG64)node->moduleBase + (ULONG64)node->funcOffset) {
                get = TRUE;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "该处已经注册过Hook了： %llx\n", func);
                break;
            }
        }
    }
    return get;
}

// 外部一定要包裹自旋锁
BOOLEAN IsRecordModule(PCHAR moduleName) {
    BOOLEAN get = FALSE;
    if (!(pModHeadNode->list.Flink == NULL || IsListEmpty(&pModHeadNode->list))) {
        for (PLIST_ENTRY pEntry = pModHeadNode->list.Flink; pEntry != &pModHeadNode->list; pEntry = pEntry->Flink) {
            PHOOKMODULENODE node = CONTAINING_RECORD(pEntry, HOOKMODULENODE, list);
            // DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "正在查找 pModHeadNode 链表，当前：%s, %p\n", node->name, node->base);
            if (!_stricmp(moduleName, node->name)) {
                get = TRUE;
                break;
            }
        }
    }
    return get;
}

BOOLEAN FindModuleBase(PCHAR moduleName, PULONG64 moduleBase) {
    // DbgBreakPoint();
    BOOLEAN get = FALSE;
    UINT32 buffSize = 0;
    PRTL_PROCESS_MODULES modules = NULL;
    do {
        if (!ZwQuerySystemInformation) {
            UNICODE_STRING name = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
            ZwQuerySystemInformation = (PZwQuerySystemInformation)MmGetSystemRoutineAddress(&name);
        }

        if (!ZwQuerySystemInformation) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "MmGetSystemRoutineAddress 获取函数ZwQuerySystemInformation地址失败\n");
            break;
        }

        NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, buffSize, &buffSize);
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ZwQuerySystemInformation 获取缓冲区大小失败\n");
            break;
        }

        modules = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffSize, 'MODI');
        if (!modules) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ExAllocatePool2 获取非分页缓冲区失败\n");
            break;
        }

        status = ZwQuerySystemInformation(SystemModuleInformation, modules, buffSize, &buffSize);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ZwQuerySystemInformation 获取模块信息失败\n");
            ExFreePoolWithTag(modules, 'MODI');
            break;
        }

        PRTL_PROCESS_MODULE_INFORMATION moduleInfo = modules->Modules;
        for (UINT32 i = 0; i < modules->NumberOfModules; i++) {
            PCHAR shortName = strrchr(moduleInfo[i].FullPathName, '\\');
            if (!shortName) {
                /*DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "模块名称：%s，模块基址：%p，模块大小：%lx\n",
                    moduleInfo[i].FullPathName, moduleInfo[i].ImageBase, moduleInfo[i].ImageSize);*/
                continue;
            }
            shortName += 1;
            /*DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "模块名称：%s，模块基址：%p，模块大小：%lx\n",
                shortName, moduleInfo[i].ImageBase, moduleInfo[i].ImageSize);*/
            if (!_stricmp(moduleName, shortName)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "模块名称：%s，模块基址：%p，模块大小：%lx\n",
                    shortName, moduleInfo[i].ImageBase, moduleInfo[i].ImageSize);
                *moduleBase = moduleInfo[i].ImageBase;
                get = TRUE;
                break;
            }
        }
    } while (0);

    // 释放资源
    if (modules) {
        ExFreePoolWithTag(modules, 'MODI');
    }

    return get;
}

// 此函数，可重入
BOOLEAN FindModuleBaseByChain(PCHAR moduleName,PULONG64 moduleBase) {
    BOOLEAN get = FALSE;
    if (!(pModHeadNode->list.Flink == NULL || IsListEmpty(&pModHeadNode->list))) {
        KIRQL oldIRQL;
        // 获取自旋锁
        KeAcquireSpinLock(&pModHeadNode->spLock, &oldIRQL);
        for (PLIST_ENTRY pEntry = pModHeadNode->list.Flink; pEntry != &pModHeadNode->list; pEntry = pEntry->Flink) {
            PHOOKMODULENODE node = CONTAINING_RECORD(pEntry, HOOKMODULENODE, list);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "正在查找 pModHeadNode 链表，当前：%s, %p\n", node->name, node->base);
            if (!_stricmp(moduleName, node->name)) {
                *moduleBase = node->base;
                get = TRUE;
                break;
            }
        }
        // 释放自旋锁
        KeReleaseSpinLock(&pModHeadNode->spLock, oldIRQL);
        if (get) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "查找 pModHeadNode 链表，查找成功，目标：%s, %llx\n", moduleName, *moduleBase);
            return get;
        }
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "查找 pModHeadNode 链表，查找失败，目标：%s\n", moduleName);
    // 没找到

    return get;
}

PVOID FindIDT() {
    // 每个核都要做的操作
    IDTR idtr;
    //GetIDTAddr(&idtr);
    __sidt(&idtr);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "IDTR base: 0x%08llx, limit: %04hx, this pointer: %p\n", idtr.base, idtr.limit, &idtr);
    GetIDTEntryFuncAddr((PVOID)idtr.base);
    return (PVOID)idtr.base;
}

/* 可删除 */
PVOID GetIDTEntryFuncAddr(PVOID idt) {
    KidtEntry idte;
    RtlCopyMemory(&idte, idt, sizeof(idte));
    UINT64 offset_high = idte.offset_high;
    UINT64 offset_middle = idte.idtEntry.fields.offset_middle;
    UINT64 offset_low = idte.idtEntry.fields.offset_low;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "idt func: 0x%08llx\n", (offset_high << 32 | offset_middle << 16 | offset_low));
    return NULL;
}

/* 待做 */
INT16 FindProperIDTE(PVOID idt) {
    INT16 retIndex = 0x2e;
    KidtEntry idte;
    RtlCopyMemory(&idte, idt, sizeof(idte));
    UINT64 offset_high = idte.offset_high;
    UINT64 offset_middle = idte.idtEntry.fields.offset_middle;
    UINT64 offset_low = idte.idtEntry.fields.offset_low;
    // 去找，找不到就用0x2e，即老版本系统调用

    return retIndex;
}

VOID  ModfiyIDTEntry(PVOID idt, BOOLEAN doHook) {
    KidtEntry idte;
    if (doHook) {
        // 真实修改IDT指定表项
        gVec = FindProperIDTE(idt);
        hookBytes[1] = gVec;

        idte.reserved = 0;
        idte.offset_high = (ULONG32)((ULONG64)CommonHookEntry >> 32);
        idte.idtEntry.fields.offset_middle = (UINT16)((ULONG64)CommonHookEntry >> 16);
        idte.idtEntry.fields.offset_low = (UINT16)((ULONG64)CommonHookEntry);
        idte.idtEntry.fields.dpl = 0;
        idte.idtEntry.fields.selector = 0x10;
        idte.idtEntry.fields.ist_index = 0; // 不使用独立的ist1-ist7中断栈
        idte.idtEntry.fields.reserved = 0;
        idte.idtEntry.fields.reserved2 = 0;
        idte.idtEntry.fields.present = 1;
        idte.idtEntry.fields.type = 0xe;

        BOOLEAN isNonPaged = MmIsNonPagedSystemAddressValid(DoHookDispatchPre);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "DoHookDispatchPre  非分页内存： %d\n", isNonPaged);
        isNonPaged = MmIsNonPagedSystemAddressValid(CommonHookEntry);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CommonHookEntry  非分页内存： %d\n", isNonPaged);
        isNonPaged = MmIsNonPagedSystemAddressValid(ModfiyIDTEntry);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ModfiyIDTEntry  非分页内存： %d\n", isNonPaged);

        RtlCopyMemory(&orgIDTEntryX, (ULONG64)idt + gVec * 16, sizeof(KidtEntry));
        MdlChangeBytes(idt, gVec * 16, &idte, sizeof(idte));
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "TestHook : %p\n", &TestHook);
    }else {
        MdlChangeBytes(idt, gVec * 16, &orgIDTEntryX, sizeof(KidtEntry));
    }
}

VOID MdlChangeBytes(PVOID orgAddrBase, UINT32 offset, PVOID payload, UINT32 length) {
    /**
    ULONG64 orgAddr = (ULONG64)orgAddrBase + offset;
    PMDL orgAddrMdl = IoAllocateMdl((PVOID)orgAddr, length, FALSE, FALSE, NULL);
    if (!orgAddrMdl)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "IoAllocateMdl Error\n");
        return;
    }
    BOOLEAN locked = FALSE;
    // mdl映射
    __try {
        MmProbeAndLockPages(orgAddrMdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "MmProbeAndLockPages Error\n");
        if (locked) {
            MmUnlockPages(orgAddrMdl);
        }
        return;
    }
    PVOID opAddr = MmMapLockedPagesSpecifyCache(orgAddrMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!opAddr) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "MmMapLockedPagesSpecifyCache Error\n");
        IoFreeMdl(orgAddrMdl);
        return;
    }
    NTSTATUS status = MmProtectMdlSystemAddress(orgAddrMdl, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        MmUnmapLockedPages(opAddr, orgAddrMdl);
        MmUnlockPages(orgAddrMdl);
        IoFreeMdl(orgAddrMdl);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "MmProtectMdlSystemAddress Error\n");
        return;
    }
    // 完成修改
    RtlCopyMemory((PUCHAR)opAddr, (PUCHAR)payload, length);

    // 清理资源
    MmUnmapLockedPages(opAddr, orgAddrMdl);
    MmUnlockPages(orgAddrMdl);
    IoFreeMdl(orgAddrMdl);
    */
    // 检查是否为非分页内存
    BOOLEAN isNonPaged = MmIsNonPagedSystemAddressValid(orgAddrBase);
    if (isNonPaged) {
        ULONG64 orgAddr = (ULONG64)orgAddrBase + offset;
        PMDL orgAddrMdl = IoAllocateMdl((PVOID)orgAddr, length, FALSE, FALSE, NULL);
        if (!orgAddrMdl)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "IoAllocateMdl Error\n");
            return;
        }
        // mdl映射
        __try {
            MmBuildMdlForNonPagedPool(orgAddrMdl);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "MmBuildMdlForNonPagedPool Error\n");
        }
        PVOID opAddr = MmMapLockedPagesSpecifyCache(orgAddrMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
        if (!opAddr) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "MmMapLockedPagesSpecifyCache Error\n");
            IoFreeMdl(orgAddrMdl);
            return;
        }

        // 完成修改
        RtlCopyMemory((PUCHAR)opAddr, (PUCHAR)payload, length);

        // 清理资源
        MmUnmapLockedPages(opAddr, orgAddrMdl);
        IoFreeMdl(orgAddrMdl);
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "分页内存尚未处理\n");
    }
}

// 此函数，可重入
PHOOKMODULENODE AddHookModuleNode(PCHAR moduleName, PVOID moduleBase) {
    PHOOKMODULENODE node = NULL;
    // 获取自旋锁
    KIRQL oldIRQL;
    KeAcquireSpinLock(&pModHeadNode->spLock, &oldIRQL);
    BOOLEAN is = IsRecordModule(moduleName);
    // 未记录才记录
    if (!is) {
        node = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HOOKMODULENODE), 'NODE');
        if (!node)
        {
            // 释放自旋锁
            KeReleaseSpinLock(&pModHeadNode->spLock, oldIRQL);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ExAllocatePool2 HOOKMODULENODE 节点创建失败\n");
            return NULL;
        }
        node->base = moduleBase;
        RtlCopyMemory(node->name, moduleName, strnlen_s(moduleName, 256));
        InsertTailList(&pModHeadNode->list, &node->list);
    }
    // 释放自旋锁
    KeReleaseSpinLock(&pModHeadNode->spLock, oldIRQL);
    return node;
}

// 此函数，可重入
VOID DelAllHookModuleNode() {
    // 获取自旋锁
    KIRQL oldIRQL;
    KeAcquireSpinLock(&pModHeadNode->spLock, &oldIRQL);
    while (!IsListEmpty(&pModHeadNode->list)) {
        // 释放节点
        PLIST_ENTRY listEntry = RemoveHeadList(&pModHeadNode->list);
        PHOOKMODULENODE node = CONTAINING_RECORD(listEntry, HOOKMODULENODE, list);
        ExFreePoolWithTag(node, 'NODE');
    }
    // 释放自旋锁
    KeReleaseSpinLock(&pModHeadNode->spLock, oldIRQL);
}

PHOOKDESC CreateHookNode(PVOID moduleBase,UINT32 insLen, PVOID func, PVOID hookFunc) {
    PHOOKDESC node = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HOOKDESC), 'HOOK');
    if (!node)
    {
        return NULL;
    }
    node->moduleBase = moduleBase;
    node->funcOffset = (ULONG64)func - (ULONG64)moduleBase;
    node->insLen = insLen;
    node->hookPtr = hookFunc;
    RtlCopyMemory(node->orgIns, func, insLen);
    RtlCopyMemory(node->orgIns + insLen, "\xff\x25\x00\x00\x00\x00", 6);
    ULONG64 addr = (ULONG64)func + insLen;
    RtlCopyMemory(node->orgIns + insLen + 6, &addr, 8);
    // 修正Hook函数的跳板
    MdlChangeBytes(hookFunc, 0x30, node->orgIns, insLen + 14);
    return node;
}

// 此函数，可重入
VOID DelAllHookNode() {
    // 获取自旋锁
    KIRQL oldIRQL;
    KeAcquireSpinLock(&pHookTable->spLock, &oldIRQL);
    while (!IsListEmpty(&pHookTable->list)) {
        // 释放节点
        PLIST_ENTRY listEntry = RemoveHeadList(&pHookTable->list);
        PHOOKDESC node = CONTAINING_RECORD(listEntry, HOOKDESC, list);
        // 恢复函数
        MdlChangeBytes(node->moduleBase, node->funcOffset, node->orgIns, node->insLen);
        // 释放节点
        ExFreePoolWithTag(node, 'HOOK');
    }
    // 释放自旋锁
    KeReleaseSpinLock(&pHookTable->spLock, oldIRQL);
}

//获取>=2个字节的指令长度
ULONG_PTR GetWriteCodeLen(PVOID buffer)
{
    const char* const buffer_end = (char*)buffer + 45;

    nmd_x86_instruction instruction;
    char formatted_instruction[128];

    for (size_t i = 0; i < 45; i += instruction.length)
    {
        if (!nmd_decode_x86((char*)buffer + i, buffer_end - ((char*)buffer + i), &instruction, NMD_X86_MODE_64, NMD_X86_DECODER_FLAGS_MINIMAL))
            break;
#pragma warning(push)
#pragma warning(disable:4245)
        nmd_format_x86(&instruction, formatted_instruction, NMD_X86_INVALID_RUNTIME_ADDRESS, NMD_X86_FORMAT_FLAGS_DEFAULT);
#pragma warning(pop)
        if (i >= 2) return i;
    }

    return 0;
}

/* ===> 后续考虑使用红黑树来关联所有hook节点，保证异常分发速度 */
/* ===> 引入反汇编引擎，实现函数指令长度的在线计算 */
// 此函数，可重入
PVOID InstallHook(PCHAR moduleName, PVOID func, PVOID hookFunc, BOOLEAN call) {
    ULONG64 moduleBase = 0;
    BOOLEAN get = FindModuleBaseByChain(moduleName, &moduleBase);
    if (!get) {
        return NULL;
    }
    // DbgBreakPoint();
    if (!func || !moduleBase) {
        // 未指定函数或者 未指定模块，则默认hook ntoskernel.exe模块的所有导出函数
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "尝试hook ntoskernel.exe 所有导出函数\n");
        // 待做
    }
    else {
        // 计算函数的指令长度信息
        UINT32 insLen = GetWriteCodeLen(func);
        
        if (pHookTable->remainHook <= 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Hook 已达最大数量\n");
            return NULL;
        }
        //// 获取自旋锁
        KIRQL oldIRQL;
        KeAcquireSpinLock(&pHookTable->spLock, &oldIRQL);
        BOOLEAN is = IsRecordHook(func);
        // 没有记录
        if (!is) {
            PHOOKDESC node = CreateHookNode(moduleBase, insLen, func, hookFunc);
            if (!node) {
                // 释放自旋锁
                KeReleaseSpinLock(&pHookTable->spLock, oldIRQL);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CreateHookNode HOOKDESC 节点创建失败\n");
                return NULL;
            }
            // 计数减少
            pHookTable->remainHook -= 1;
            // 登记Hook信息
            InsertTailList(&pHookTable->list, &node->list);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "InsertTailList 节点成功：%p\n", node);
        }
        else {
            // 释放自旋锁
            KeReleaseSpinLock(&pHookTable->spLock, oldIRQL);
            // 此处存在Hook了，则不再次Hook
            return NULL;
        }
        // 释放自旋锁
        KeReleaseSpinLock(&pHookTable->spLock, oldIRQL);

        // 理论上在HOOK时需要原子操作，此处暂时不考虑;小于8字节hook可以使用原子操作交换内存
        MdlChangeBytes(func, 0, hookBytes, insLen);
    }
    return (ULONG64)hookFunc + 0x30;
}

/* ===> 后续考虑使用红黑树来关联所有hook节点，保证异常分发速度 */
NTSTATUS UnInstallHook() {
    
    // 先读写锁互斥登记Hook信息
    KIRQL irql = KeGetCurrentIrql();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "UnInstallHook irql:%d, pHookTable:%p\n", irql, pHookTable);

    DelAllHookNode();
    return STATUS_SUCCESS;
}
INT64 __stdcall TestHook(ULONG t1, ULONG t2, ULONG t3, ULONG t4, UINT32 t5, ULONG64 t6) {
    KIRQL irql = KeGetCurrentIrql();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "原始 TestHook 执行,t1:%lx,t2:%lx,t3:%lx,t4:%lx,t5:%x,t6:%llx, IRQL: %d\n", t1, t2, t3, t4, t5, t6, irql);
}

// 根据栈上的rip，动态计算出 对应的hook函数。 // 中断上下文，尽量少做事情
VOID __stdcall DoHookDispatchPre(PIntStackFrame thisFrame) {
    // 将异常返回的栈顶指针 生长。
    thisFrame->rsp -= 8;
    // 将中断帧向栈顶移动一格
    thisFrame->ripBak = thisFrame->rip;
    thisFrame->rip = thisFrame->cs;
    thisFrame->cs = thisFrame->eflags;
    thisFrame->eflags = thisFrame->rsp;
    thisFrame->rsp = thisFrame->ss;
    thisFrame->ss = thisFrame->errorCode;
    // 保存调用者信息到栈中
    thisFrame->errorCode = thisFrame->ripBak;

    // 中断返回后跳回 DoHookDispatch
    thisFrame->ripBak = DoHookDispatch;
}


/* ===> 此处pHookTable是上了写锁的，但是使用临界区加读锁会导致蓝屏，后续调整 */
/* ===> 后续考虑使用红黑树来关联所有hook节点，保证异常分发速度 */
// 如果动态增加hook，会出现，锁住pHookTable时，此分发函数仍然工作，但是理论上没有问题，因为肯定不会用到新项目
PVOID __stdcall DoHookDispatchStub(PIntTriggerAddr intTriggerAddr) {
    // KIRQL irql = KeGetCurrentIrql();
    PVOID retAddr = NULL;
    // DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "DoHookDispatchStub irql:%d, pHookTable:%p\n", irql, pHookTable);
    //KIRQL oldIRQL;
    //// 获取自旋锁
    //KeAcquireSpinLock(&pHookTable->spLock, &oldIRQL);
    for (PLIST_ENTRY pEntry = pHookTable->list.Flink; pEntry != &pHookTable->list; pEntry = pEntry->Flink) {
        PHOOKDESC node = CONTAINING_RECORD(pEntry, HOOKDESC, list);
        if (intTriggerAddr->triggerAddr == (ULONG64)node->moduleBase + (ULONG64)node->funcOffset + 2) {
            retAddr = &node->moduleBase;
            break;
        }
    }
    //// 释放自旋锁
    //KeReleaseSpinLock(&pHookTable->spLock, oldIRQL);
    if (!retAddr) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "查找HOOK链表失败\n");
        DbgBreakPoint();
    }
    return retAddr;
}

VOID UnInstallAndRecoverHook(
    _In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    //获取当前CPU核心的号数
    ULONG index = KeGetCurrentProcessorIndex();
    // 都是可重入的函数
    // 删除所有的模块基址信息
    DelAllHookModuleNode();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CPU %d DelAllHookModuleNode Ok!\n", index);
    // 删除所有Hook
    UnInstallHook();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CPU %d UnInstallHook Ok!\n", index);
    if (SystemArgument2 != 0 && SystemArgument1 != 0) {
        KeSignalCallDpcSynchronize(SystemArgument2);
        KeSignalCallDpcDone(SystemArgument1);
    }
}
VOID RecoverHookIDT(
    _In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    //获取当前CPU核心的号数
    ULONG index = KeGetCurrentProcessorIndex();
    // 修改 idt 表项，并正式卸载hook
    PVOID idt = FindIDT();
    ModfiyIDTEntry(idt, FALSE);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CPU %d Recover IDT Ok!\n", index);

    if (SystemArgument2 != 0 && SystemArgument1 != 0) {
        KeSignalCallDpcSynchronize(SystemArgument2);
        KeSignalCallDpcDone(SystemArgument1);
    }
}

VOID InitHookIDT(
    _In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    // DbgBreakPoint();

    //获取当前CPU核心的号数
    ULONG index = KeGetCurrentProcessorIndex();
    // 修改 idt 表项
    PVOID idt = FindIDT();  // 后期可能需要保证每个CPU选择的 vec 相同
    ModfiyIDTEntry(idt, TRUE);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CPU %d Init IDT Ok!\n", index);

    if (SystemArgument2 != 0 && SystemArgument1 != 0) {
        KeSignalCallDpcSynchronize(SystemArgument2);
        KeSignalCallDpcDone(SystemArgument1);
    }
}

VOID InitAndInstallHook(
    _In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    //获取当前CPU核心的号数
    ULONG index = KeGetCurrentProcessorIndex();

    // 都是可重入的函数
    // InstallHook("tinykernelhook.sys", &TestHook, &ExecuteHook0x00001, TRUE);
    // TestHook(1, 2, 3, 4, 5, 6);
    InstallHook("ntoskrnl.exe", &NtCreateFile, &ExecuteHook0x00001, TRUE);
    InstallHook("ntoskrnl.exe", &ZwCreateFile, &ExecuteHook0x00002, TRUE);
    InstallHook("ntoskrnl.exe", &NtCreateFile, &ExecuteHook0x00001, TRUE);
    InstallHook("ntoskrnl.exe", &ZwCreateFile, &ExecuteHook0x00002, TRUE);
    InstallHook("ntoskrnl.exe", &NtCreateFile, &ExecuteHook0x00001, TRUE);
    InstallHook("ntoskrnl.exe", &ZwCreateFile, &ExecuteHook0x00002, TRUE);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CPU %d InitAndInstallHook Ok!\n", index);

    if (SystemArgument2 != 0 && SystemArgument1 != 0) {
        KeSignalCallDpcSynchronize(SystemArgument2);
        KeSignalCallDpcDone(SystemArgument1);
    }
}

NTSTATUS InitBasicResource() {
    // 分配非分页内存构建HookTable
    pHookTable = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HOOKTABLE), 'TINY');
    if (!pHookTable) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "HookTable 构建失败\n");
        return STATUS_ACCESS_DENIED;
    }
    // 初始化链表头
    InitializeListHead(&pHookTable->list);
    // 初始化自旋锁
    KeInitializeSpinLock(&pHookTable->spLock);

    pHookTable->remainHook = MAX_HOOK_NUM;

    // 分配module base存储链表的头节点
    pModHeadNode = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HOOKMODULEHEADNODE), 'HEAD'); // 64位默认16字节对齐
    if (!pModHeadNode) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "pModHeadNode 构建失败\n");
        return STATUS_ACCESS_DENIED;
    }
    // 初始化链表头
    InitializeListHead(&pModHeadNode->list);
    // 初始化自旋锁
    KeInitializeSpinLock(&pModHeadNode->spLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "pModHeadNode: %p, pHookTable: %p\n", pModHeadNode, pHookTable);

    return STATUS_SUCCESS;
}
VOID RecycleResource() {
    if (pHookTable) {
        ExFreePoolWithTag(pHookTable, 'TINY');
        pHookTable = NULL;
    }

    if (pModHeadNode) {
        ExFreePoolWithTag(pModHeadNode, 'HEAD');
        pModHeadNode = NULL;
    }
}

NTSTATUS AddAHookModule(PCHAR moduleName) {
    ULONG64 moduleBase = 0;
    BOOLEAN get = FindModuleBase(moduleName, &moduleBase);
    // 增加链表项目
    if (!get) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "FindModuleBase 模块: %s 查找失败！\n", moduleName);
        return STATUS_ACCESS_DENIED;
    }
    AddHookModuleNode(moduleName, moduleBase);
    return STATUS_SUCCESS;
}
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    if (DriverObject != NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Driver Unload...Driver Object Address: %p\n", DriverObject);
    }
    // 取消Hook
    /* ===> 多核时，应当DPC同步 */
    KeGenericCallDpc(UnInstallAndRecoverHook, NULL);
    KeGenericCallDpc(RecoverHookIDT, NULL);

    // 回收资源
    RecycleResource();

    return;
}

#ifdef __cplusplus
extern "C" {
#endif
    NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
    {
        if (RegistryPath != NULL)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Driver RegistryPath: %wZ\n", RegistryPath);
        }

        if (DriverObject != NULL)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Driver Object Address: %p\n", DriverObject);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "BASE:%p, SIZE: %x \n", DriverObject->DriverStart, DriverObject->DriverSize);
            DriverObject->DriverUnload = DriverUnload;
            tmpModuleBase = (ULONG64)(DriverObject->DriverStart);
        }
        NTSTATUS status = STATUS_ACCESS_DENIED;
        do {
            status = InitBasicResource();
            if (!NT_SUCCESS(status)) {
                break;
            }
            status = AddAHookModule("ntoskrnl.exe");
            if (!NT_SUCCESS(status)) {
                break;
            }
            status = AddAHookModule("tinykernelhook.sys");
            if (!NT_SUCCESS(status)) {
                break;
            }

            /* ===> 多核时，应当DPC同步 */
            KeGenericCallDpc(InitHookIDT, NULL);
            KeGenericCallDpc(InitAndInstallHook, NULL);
        } while (0);
        if (!NT_SUCCESS(status)) {
            RecycleResource();
        }

        return status;
    }
#ifdef __cplusplus
}
#endif
