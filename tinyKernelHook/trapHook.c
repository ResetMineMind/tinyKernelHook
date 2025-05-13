#include "trapHook.h"

PVOID FindIDT() {
    // ÿ���˶�Ҫ���Ĳ���
    IDTR idtr;
    //GetIDTAddr(&idtr);
    __sidt(&idtr);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "IDTR base: 0x%08llx, limit: %04hx, this pointer: %p\n", idtr.base, idtr.limit, &idtr);
    GetIDTEntryFuncAddr((PVOID)idtr.base);
    return (PVOID)idtr.base;
}

/* ��ɾ�� */
PVOID GetIDTEntryFuncAddr(PVOID idt) {
    KidtEntry idte;
    RtlCopyMemory(&idte, idt, sizeof(idte));
    UINT64 offset_high = idte.offset_high;
    UINT64 offset_middle = idte.idtEntry.fields.offset_middle;
    UINT64 offset_low = idte.idtEntry.fields.offset_low;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "idt func: 0x%08llx\n", (offset_high << 32 | offset_middle << 16 | offset_low));
    return NULL;
}

/* ���� */
INT16 FindProperIDTE(PVOID idt) {
    INT16 retIndex = 0x2e;
    KidtEntry idte;
    RtlCopyMemory(&idte, idt, sizeof(idte));
    UINT64 offset_high = idte.offset_high;
    UINT64 offset_middle = idte.idtEntry.fields.offset_middle;
    UINT64 offset_low = idte.idtEntry.fields.offset_low;
    // ȥ�ң��Ҳ�������0x2e�����ϰ汾ϵͳ����

    return retIndex;
}

VOID  ModfiyIDTEntry(PVOID idt, BOOLEAN doHook) {
    KidtEntry idte;
    if (doHook) {
        // ��ʵ�޸�IDTָ������
        gVec = FindProperIDTE(idt);
        hookBytes[1] = gVec;

        idte.reserved = 0;
        idte.offset_high = (ULONG32)((ULONG64)CommonHookEntry >> 32);
        idte.idtEntry.fields.offset_middle = (UINT16)((ULONG64)CommonHookEntry >> 16);
        idte.idtEntry.fields.offset_low = (UINT16)((ULONG64)CommonHookEntry);
        idte.idtEntry.fields.dpl = 0;
        idte.idtEntry.fields.selector = 0x10;
        idte.idtEntry.fields.ist_index = 0; // ��ʹ�ö�����ist1-ist7�ж�ջ
        idte.idtEntry.fields.reserved = 0;
        idte.idtEntry.fields.reserved2 = 0;
        idte.idtEntry.fields.present = 1;
        idte.idtEntry.fields.type = 0xe;

        BOOLEAN isNonPaged = MmIsNonPagedSystemAddressValid(DoHookDispatchPre);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "DoHookDispatchPre  �Ƿ�ҳ�ڴ棺 %d\n", isNonPaged);
        isNonPaged = MmIsNonPagedSystemAddressValid(CommonHookEntry);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CommonHookEntry  �Ƿ�ҳ�ڴ棺 %d\n", isNonPaged);
        isNonPaged = MmIsNonPagedSystemAddressValid(ModfiyIDTEntry);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ModfiyIDTEntry  �Ƿ�ҳ�ڴ棺 %d\n", isNonPaged);

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
    // mdlӳ��
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
    // ����޸�
    RtlCopyMemory((PUCHAR)opAddr, (PUCHAR)payload, length);

    // ������Դ
    MmUnmapLockedPages(opAddr, orgAddrMdl);
    MmUnlockPages(orgAddrMdl);
    IoFreeMdl(orgAddrMdl);
    */
    // ����Ƿ�Ϊ�Ƿ�ҳ�ڴ�
    BOOLEAN isNonPaged = MmIsNonPagedSystemAddressValid(orgAddrBase);
    if (isNonPaged) {
        ULONG64 orgAddr = (ULONG64)orgAddrBase + offset;
        PMDL orgAddrMdl = IoAllocateMdl((PVOID)orgAddr, length, FALSE, FALSE, NULL);
        if (!orgAddrMdl)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "IoAllocateMdl Error\n");
            return;
        }
        // mdlӳ��
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

        // ����޸�
        RtlCopyMemory((PUCHAR)opAddr, (PUCHAR)payload, length);

        // ������Դ
        MmUnmapLockedPages(opAddr, orgAddrMdl);
        IoFreeMdl(orgAddrMdl);
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "��ҳ�ڴ���δ����\n");
    }
}

/* ===> ��������ʹ�ú��������������hook�ڵ㣬��֤�쳣�ַ��ٶ� */
/* ===> ���뷴������棬ʵ�ֺ���ָ��ȵ����߼��� */
PVOID InstallHook(PVOID moudleBase, PVOID func, PVOID hookFunc, BOOLEAN call) {
    if (!func || !moudleBase) {
        // δָ���������� δָ��ģ�飬��Ĭ��hook ntoskernel.exeģ������е�������
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "����hook ntoskernel.exe ���е�������\n");
        // ����
    }
    else {
        // ���㺯����ָ�����Ϣ
        UINT32 insLen = 4;
        insLen = 7;
        //insLen = 3;
        // �ȶ�д������Ǽ�Hook��Ϣ
        KIRQL irql = KeGetCurrentIrql();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "InstallHook irql:%d, pHookTable:%p\n", irql, pHookTable);
        
        if(irql > APC_LEVEL) KeLowerIrql(APC_LEVEL);
        KeEnterCriticalRegion();
        if (ExAcquireResourceExclusiveLite(&pHookTable->lock, TRUE)) {
            if (pHookTable->remainHook <= 0) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Hook �Ѵ��������\n");
                return NULL;
            }
            // ��������
            pHookTable->remainHook -= 1;
            // �Ǽ�Hook��Ϣ
            // �������hookλ
            UINT32 index = 0;
            pHookTable->tableBase[index].moduleBase = moudleBase;
            pHookTable->tableBase[index].funcOffset = (ULONG64)func - (ULONG64)moudleBase;
            pHookTable->tableBase[index].insLen = insLen;
            pHookTable->tableBase[index].hookPtr = hookFunc;
            RtlCopyMemory(pHookTable->tableBase[index].orgIns, func, insLen);
            RtlCopyMemory(pHookTable->tableBase[index].orgIns + insLen, "\xff\x25\x00\x00\x00\x00", 6);
            ULONG64 addr = (ULONG64)func + insLen;
            RtlCopyMemory(pHookTable->tableBase[index].orgIns + insLen + 6, &addr, 8);
            // ����Hook����������
            MdlChangeBytes(hookFunc, 0x30, pHookTable->tableBase[index].orgIns, insLen + 14);
            // �ͷ���Դ
            ExReleaseResourceLite(&pHookTable->lock);
        }
        KeLeaveCriticalRegion();
        if (irql > APC_LEVEL) KeRaiseIrql(irql, &irql);

        // ��������HOOKʱ��Ҫԭ�Ӳ������˴���ʱ������;С��8�ֽ�hook����ʹ��ԭ�Ӳ��������ڴ�
        MdlChangeBytes(func, 0, hookBytes, insLen);
    }
    return (ULONG64)hookFunc + 0x30;
}

/* ===> ��������ʹ�ú��������������hook�ڵ㣬��֤�쳣�ַ��ٶ� */
NTSTATUS UnInstallHook() {
    
    // �ȶ�д������Ǽ�Hook��Ϣ
    KIRQL irql = KeGetCurrentIrql();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "UnInstallHook irql:%d, pHookTable:%p\n", irql, pHookTable);

    KeEnterCriticalRegion();
    // DbgBreakPoint();
    if (ExAcquireResourceSharedLite(&pHookTable->lock, TRUE)) {
        for (int i = 0; i < MAX_HOOK_NUM - pHookTable->remainHook; i++) {
            // �ָ�
            MdlChangeBytes(pHookTable->tableBase[0].moduleBase, pHookTable->tableBase[0].funcOffset, 
                pHookTable->tableBase[0].orgIns, pHookTable->tableBase[0].insLen);
        }
        // �ͷ���Դ
        ExReleaseResourceLite(&pHookTable->lock);
    }
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}
INT64 __stdcall TestHook(ULONG t1, ULONG t2, ULONG t3, ULONG t4, UINT32 t5, ULONG64 t6) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ԭʼ TestHook ִ��,t1:%lx,t2:%lx,t3:%lx,t4:%lx,t5:%x,t6:%llx\n", t1, t2, t3, t4, t5, t6);
}

// ����ջ�ϵ�rip����̬����� ��Ӧ��hook������ // �ж������ģ�������������
VOID __stdcall DoHookDispatchPre(PIntStackFrame thisFrame) {
    thisFrame->rip = DoHookDispatch;
}


/* ===> �˴�pHookTable������д���ģ�����ʹ���ٽ����Ӷ����ᵼ���������������� */
/* ===> ��������ʹ�ú��������������hook�ڵ㣬��֤�쳣�ַ��ٶ� */
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
    // ���ȣ��鵽��hook������hookָ��ȡ��ҵ���Ӧ��hook���������õ���ջ�С�// �ɹ��ı�ִ���������� //����Ҫʹ�ú�������ַ�����
    KIRQL irql = KeGetCurrentIrql();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "DoHookDispatchStub irql:%d, pHookTable:%p\n", irql, pHookTable);

    if (irql > APC_LEVEL) KeLowerIrql(APC_LEVEL);
    KeEnterCriticalRegion();
    if (ExAcquireResourceSharedLite(&pHookTable->lock, TRUE)) {
        retAddr = &pHookTable->tableBase[0];
        // �ͷ���Դ
        ExReleaseResourceLite(&pHookTable->lock);
    }
    KeLeaveCriticalRegion();
    if (irql > APC_LEVEL) KeRaiseIrql(irql, &irql);

    if (!retAddr) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "�����������͸� Panic\n");
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
    // ȡ��Hook
    /* ===> ���ʱ��Ӧ��DPCͬ�� */
    UnInstallHook();
    // �޸� idt �������ʽж��hook
    /* ===> ���ʱ��Ӧ��DPCͬ�� */
    PVOID idt = FindIDT();
    ModfiyIDTEntry(idt, FALSE);


    // ������Դ
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
        // ����Ƿ�ҳ�ڴ湹��HookTable
        pHookTable = ExAllocatePoolWithTag(NonPagedPool, sizeof(HOOKTABLE), 'TINY');
        if (!pHookTable) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "HookTable ����ʧ��\n");
            return STATUS_ACCESS_DENIED;
        }
        // ��ʼ����д��
        NTSTATUS init = ExInitializeResourceLite(&pHookTable->lock);
        if (!NT_SUCCESS(init)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "HookTable ��д�� ����ʧ��\n");
            ExFreePoolWithTag(pHookTable, 'TINY');
            pHookTable = NULL;
            return STATUS_ACCESS_DENIED;
        }

        // ����Ƿ�ҳ�ڴ湹��HookTable tableBase
        pHookTable->tableBase = ExAllocatePoolWithTag(NonPagedPool, sizeof(HOOKDESC) * MAX_HOOK_NUM, 'TAB');
        if (!pHookTable->tableBase) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "HookTable tableBase ����ʧ��\n");
            ExFreePoolWithTag(pHookTable, 'TINY');
            pHookTable = NULL;
            return STATUS_ACCESS_DENIED;
        }
        pHookTable->remainHook = MAX_HOOK_NUM;

        /* ===> ���ʱ��Ӧ��DPCͬ�� */
        // �޸� idt �������ʽ��װhook
        PVOID idt = FindIDT();
        ModfiyIDTEntry(idt, TRUE);
        // InstallHook(tmpModuleBase, &TestHook, &ExecuteHook0x00001, TRUE);
        /* ===> ʵ���ں�ģ��Ļ�ַ��̬��ѯ */
        ULONG64 tmp = 0xfffff80218200000;
        /* ===> ���ʱ��Ӧ��DPCͬ�� */
        PVOID orgZwCreateFile = InstallHook(tmp, &NtCreateFile, &ExecuteHook0x00001, TRUE);
        // TestHook(0x100,0x200,0x300,0x1,0x2,0xffffffff88888888);

        return STATUS_SUCCESS;
    }
#ifdef __cplusplus
}
#endif
