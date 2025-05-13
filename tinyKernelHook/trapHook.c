#include "trapHook.h"

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

/* ===> 后续考虑使用红黑树来关联所有hook节点，保证异常分发速度 */
/* ===> 引入反汇编引擎，实现函数指令长度的在线计算 */
PVOID InstallHook(PVOID moudleBase, PVOID func, PVOID hookFunc, BOOLEAN call) {
    if (!func || !moudleBase) {
        // 未指定函数或者 未指定模块，则默认hook ntoskernel.exe模块的所有导出函数
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "尝试hook ntoskernel.exe 所有导出函数\n");
        // 待做
    }
    else {
        // 计算函数的指令长度信息
        UINT32 insLen = 4;
        insLen = 7;
        //insLen = 3;
        // 先读写锁互斥登记Hook信息
        KIRQL irql = KeGetCurrentIrql();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "InstallHook irql:%d, pHookTable:%p\n", irql, pHookTable);
        
        if(irql > APC_LEVEL) KeLowerIrql(APC_LEVEL);
        KeEnterCriticalRegion();
        if (ExAcquireResourceExclusiveLite(&pHookTable->lock, TRUE)) {
            if (pHookTable->remainHook <= 0) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Hook 已达最大数量\n");
                return NULL;
            }
            // 计数减少
            pHookTable->remainHook -= 1;
            // 登记Hook信息
            // 计算空闲hook位
            UINT32 index = 0;
            pHookTable->tableBase[index].moduleBase = moudleBase;
            pHookTable->tableBase[index].funcOffset = (ULONG64)func - (ULONG64)moudleBase;
            pHookTable->tableBase[index].insLen = insLen;
            pHookTable->tableBase[index].hookPtr = hookFunc;
            RtlCopyMemory(pHookTable->tableBase[index].orgIns, func, insLen);
            RtlCopyMemory(pHookTable->tableBase[index].orgIns + insLen, "\xff\x25\x00\x00\x00\x00", 6);
            ULONG64 addr = (ULONG64)func + insLen;
            RtlCopyMemory(pHookTable->tableBase[index].orgIns + insLen + 6, &addr, 8);
            // 修正Hook函数的跳板
            MdlChangeBytes(hookFunc, 0x30, pHookTable->tableBase[index].orgIns, insLen + 14);
            // 释放资源
            ExReleaseResourceLite(&pHookTable->lock);
        }
        KeLeaveCriticalRegion();
        if (irql > APC_LEVEL) KeRaiseIrql(irql, &irql);

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

    KeEnterCriticalRegion();
    // DbgBreakPoint();
    if (ExAcquireResourceSharedLite(&pHookTable->lock, TRUE)) {
        for (int i = 0; i < MAX_HOOK_NUM - pHookTable->remainHook; i++) {
            // 恢复
            MdlChangeBytes(pHookTable->tableBase[0].moduleBase, pHookTable->tableBase[0].funcOffset, 
                pHookTable->tableBase[0].orgIns, pHookTable->tableBase[0].insLen);
        }
        // 释放资源
        ExReleaseResourceLite(&pHookTable->lock);
    }
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}
INT64 __stdcall TestHook(ULONG t1, ULONG t2, ULONG t3, ULONG t4, UINT32 t5, ULONG64 t6) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "原始 TestHook 执行,t1:%lx,t2:%lx,t3:%lx,t4:%lx,t5:%x,t6:%llx\n", t1, t2, t3, t4, t5, t6);
}

// 根据栈上的rip，动态计算出 对应的hook函数。 // 中断上下文，尽量少做事情
VOID __stdcall DoHookDispatchPre(PIntStackFrame thisFrame) {
    thisFrame->rip = DoHookDispatch;
}


/* ===> 此处pHookTable是上了写锁的，但是使用临界区加读锁会导致蓝屏，后续调整 */
/* ===> 后续考虑使用红黑树来关联所有hook节点，保证异常分发速度 */
PVOID __stdcall DoHookDispatchStub() {
    // KIRQL irql = KeGetCurrentIrql();
    PVOID retAddr = NULL;
    // DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "DoHookDispatchStub irql:%d, pHookTable:%p\n", irql, pHookTable);
    retAddr = &pHookTable->tableBase[0];
    return retAddr;
}

/**
PVOID __stdcall DoHookDispatchStub() {
    PVOID retAddr = NULL;
    // 首先，查到被hook函数的hook指令长度、找到对应的hook函数，设置到堆栈中。// 成功改变执行流！！！ //必须要使用红黑树做分发才行
    KIRQL irql = KeGetCurrentIrql();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "DoHookDispatchStub irql:%d, pHookTable:%p\n", irql, pHookTable);

    if (irql > APC_LEVEL) KeLowerIrql(APC_LEVEL);
    KeEnterCriticalRegion();
    if (ExAcquireResourceSharedLite(&pHookTable->lock, TRUE)) {
        retAddr = &pHookTable->tableBase[0];
        // 释放资源
        ExReleaseResourceLite(&pHookTable->lock);
    }
    KeLeaveCriticalRegion();
    if (irql > APC_LEVEL) KeRaiseIrql(irql, &irql);

    if (!retAddr) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "离谱至极，就该 Panic\n");
    }

    return retAddr;
}
*/

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    if (DriverObject != NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Driver Unload...Driver Object Address: %p\n", DriverObject);
    }
    // 取消Hook
    /* ===> 多核时，应当DPC同步 */
    UnInstallHook();
    // 修改 idt 表项，并正式卸载hook
    /* ===> 多核时，应当DPC同步 */
    PVOID idt = FindIDT();
    ModfiyIDTEntry(idt, FALSE);


    // 回收资源
    if (pHookTable) {
        ExDeleteResourceLite(&pHookTable->lock);
        if (pHookTable->tableBase) {
            ExFreePoolWithTag(pHookTable->tableBase, 'TAB');
            pHookTable->tableBase = NULL;
        }
        ExFreePoolWithTag(pHookTable, 'TINY');
        pHookTable = NULL;
    }

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
        // 分配非分页内存构建HookTable
        pHookTable = ExAllocatePoolWithTag(NonPagedPool, sizeof(HOOKTABLE), 'TINY');
        if (!pHookTable) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "HookTable 构建失败\n");
            return STATUS_ACCESS_DENIED;
        }
        // 初始化读写锁
        NTSTATUS init = ExInitializeResourceLite(&pHookTable->lock);
        if (!NT_SUCCESS(init)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "HookTable 读写锁 构建失败\n");
            ExFreePoolWithTag(pHookTable, 'TINY');
            pHookTable = NULL;
            return STATUS_ACCESS_DENIED;
        }

        // 分配非分页内存构建HookTable tableBase
        pHookTable->tableBase = ExAllocatePoolWithTag(NonPagedPool, sizeof(HOOKDESC) * MAX_HOOK_NUM, 'TAB');
        if (!pHookTable->tableBase) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "HookTable tableBase 构建失败\n");
            ExFreePoolWithTag(pHookTable, 'TINY');
            pHookTable = NULL;
            return STATUS_ACCESS_DENIED;
        }
        pHookTable->remainHook = MAX_HOOK_NUM;

        /* ===> 多核时，应当DPC同步 */
        // 修改 idt 表项，并正式安装hook
        PVOID idt = FindIDT();
        ModfiyIDTEntry(idt, TRUE);
        // InstallHook(tmpModuleBase, &TestHook, &ExecuteHook0x00001, TRUE);
        /* ===> 实现内核模块的基址动态查询 */
        ULONG64 tmp = 0xfffff80218200000;
        /* ===> 多核时，应当DPC同步 */
        PVOID orgZwCreateFile = InstallHook(tmp, &NtCreateFile, &ExecuteHook0x00001, TRUE);
        // TestHook(0x100,0x200,0x300,0x1,0x2,0xffffffff88888888);

        return STATUS_SUCCESS;
    }
#ifdef __cplusplus
}
#endif
