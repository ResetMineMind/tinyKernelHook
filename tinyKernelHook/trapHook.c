#include "trapHook.h"

// �ⲿһ��Ҫ����������
BOOLEAN IsRecordHook(UINT64 func) {
    BOOLEAN get = FALSE;
    if (!(pModHeadNode->list.Flink == NULL || IsListEmpty(&pModHeadNode->list))) {
        for (PLIST_ENTRY pEntry = pHookTable->list.Flink; pEntry != &pHookTable->list; pEntry = pEntry->Flink) {
            PHOOKDESC node = CONTAINING_RECORD(pEntry, HOOKDESC, list);
            // ˵��Hook�Ѿ�ע�����
            if (func == (ULONG64)node->moduleBase + (ULONG64)node->funcOffset) {
                get = TRUE;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "�ô��Ѿ�ע���Hook�ˣ� %llx\n", func);
                break;
            }
        }
    }
    return get;
}

// �ⲿһ��Ҫ����������
BOOLEAN IsRecordModule(PCHAR moduleName) {
    BOOLEAN get = FALSE;
    if (!(pModHeadNode->list.Flink == NULL || IsListEmpty(&pModHeadNode->list))) {
        for (PLIST_ENTRY pEntry = pModHeadNode->list.Flink; pEntry != &pModHeadNode->list; pEntry = pEntry->Flink) {
            PHOOKMODULENODE node = CONTAINING_RECORD(pEntry, HOOKMODULENODE, list);
            // DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "���ڲ��� pModHeadNode ������ǰ��%s, %p\n", node->name, node->base);
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
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "MmGetSystemRoutineAddress ��ȡ����ZwQuerySystemInformation��ַʧ��\n");
            break;
        }

        NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, buffSize, &buffSize);
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ZwQuerySystemInformation ��ȡ��������Сʧ��\n");
            break;
        }

        modules = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffSize, 'MODI');
        if (!modules) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ExAllocatePool2 ��ȡ�Ƿ�ҳ������ʧ��\n");
            break;
        }

        status = ZwQuerySystemInformation(SystemModuleInformation, modules, buffSize, &buffSize);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ZwQuerySystemInformation ��ȡģ����Ϣʧ��\n");
            ExFreePoolWithTag(modules, 'MODI');
            break;
        }

        PRTL_PROCESS_MODULE_INFORMATION moduleInfo = modules->Modules;
        for (UINT32 i = 0; i < modules->NumberOfModules; i++) {
            PCHAR shortName = strrchr(moduleInfo[i].FullPathName, '\\');
            if (!shortName) {
                /*DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ģ�����ƣ�%s��ģ���ַ��%p��ģ���С��%lx\n",
                    moduleInfo[i].FullPathName, moduleInfo[i].ImageBase, moduleInfo[i].ImageSize);*/
                continue;
            }
            shortName += 1;
            /*DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ģ�����ƣ�%s��ģ���ַ��%p��ģ���С��%lx\n",
                shortName, moduleInfo[i].ImageBase, moduleInfo[i].ImageSize);*/
            if (!_stricmp(moduleName, shortName)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ģ�����ƣ�%s��ģ���ַ��%p��ģ���С��%lx\n",
                    shortName, moduleInfo[i].ImageBase, moduleInfo[i].ImageSize);
                *moduleBase = moduleInfo[i].ImageBase;
                get = TRUE;
                break;
            }
        }
    } while (0);

    // �ͷ���Դ
    if (modules) {
        ExFreePoolWithTag(modules, 'MODI');
    }

    return get;
}

// �˺�����������
BOOLEAN FindModuleBaseByChain(PCHAR moduleName,PULONG64 moduleBase) {
    BOOLEAN get = FALSE;
    if (!(pModHeadNode->list.Flink == NULL || IsListEmpty(&pModHeadNode->list))) {
        KIRQL oldIRQL;
        // ��ȡ������
        KeAcquireSpinLock(&pModHeadNode->spLock, &oldIRQL);
        for (PLIST_ENTRY pEntry = pModHeadNode->list.Flink; pEntry != &pModHeadNode->list; pEntry = pEntry->Flink) {
            PHOOKMODULENODE node = CONTAINING_RECORD(pEntry, HOOKMODULENODE, list);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "���ڲ��� pModHeadNode ������ǰ��%s, %p\n", node->name, node->base);
            if (!_stricmp(moduleName, node->name)) {
                *moduleBase = node->base;
                get = TRUE;
                break;
            }
        }
        // �ͷ�������
        KeReleaseSpinLock(&pModHeadNode->spLock, oldIRQL);
        if (get) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "���� pModHeadNode �������ҳɹ���Ŀ�꣺%s, %llx\n", moduleName, *moduleBase);
            return get;
        }
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "���� pModHeadNode ��������ʧ�ܣ�Ŀ�꣺%s\n", moduleName);
    // û�ҵ�

    return get;
}

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

// �˺�����������
PHOOKMODULENODE AddHookModuleNode(PCHAR moduleName, PVOID moduleBase) {
    PHOOKMODULENODE node = NULL;
    // ��ȡ������
    KIRQL oldIRQL;
    KeAcquireSpinLock(&pModHeadNode->spLock, &oldIRQL);
    BOOLEAN is = IsRecordModule(moduleName);
    // δ��¼�ż�¼
    if (!is) {
        node = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HOOKMODULENODE), 'NODE');
        if (!node)
        {
            // �ͷ�������
            KeReleaseSpinLock(&pModHeadNode->spLock, oldIRQL);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ExAllocatePool2 HOOKMODULENODE �ڵ㴴��ʧ��\n");
            return NULL;
        }
        node->base = moduleBase;
        RtlCopyMemory(node->name, moduleName, strnlen_s(moduleName, 256));
        InsertTailList(&pModHeadNode->list, &node->list);
    }
    // �ͷ�������
    KeReleaseSpinLock(&pModHeadNode->spLock, oldIRQL);
    return node;
}

// �˺�����������
VOID DelAllHookModuleNode() {
    // ��ȡ������
    KIRQL oldIRQL;
    KeAcquireSpinLock(&pModHeadNode->spLock, &oldIRQL);
    while (!IsListEmpty(&pModHeadNode->list)) {
        // �ͷŽڵ�
        PLIST_ENTRY listEntry = RemoveHeadList(&pModHeadNode->list);
        PHOOKMODULENODE node = CONTAINING_RECORD(listEntry, HOOKMODULENODE, list);
        ExFreePoolWithTag(node, 'NODE');
    }
    // �ͷ�������
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
    // ����Hook����������
    MdlChangeBytes(hookFunc, 0x30, node->orgIns, insLen + 14);
    return node;
}

// �˺�����������
VOID DelAllHookNode() {
    // ��ȡ������
    KIRQL oldIRQL;
    KeAcquireSpinLock(&pHookTable->spLock, &oldIRQL);
    while (!IsListEmpty(&pHookTable->list)) {
        // �ͷŽڵ�
        PLIST_ENTRY listEntry = RemoveHeadList(&pHookTable->list);
        PHOOKDESC node = CONTAINING_RECORD(listEntry, HOOKDESC, list);
        // �ָ�����
        MdlChangeBytes(node->moduleBase, node->funcOffset, node->orgIns, node->insLen);
        // �ͷŽڵ�
        ExFreePoolWithTag(node, 'HOOK');
    }
    // �ͷ�������
    KeReleaseSpinLock(&pHookTable->spLock, oldIRQL);
}

//��ȡ>=2���ֽڵ�ָ���
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

/* ===> ��������ʹ�ú��������������hook�ڵ㣬��֤�쳣�ַ��ٶ� */
/* ===> ���뷴������棬ʵ�ֺ���ָ��ȵ����߼��� */
// �˺�����������
PVOID InstallHook(PCHAR moduleName, PVOID func, PVOID hookFunc, BOOLEAN call) {
    ULONG64 moduleBase = 0;
    BOOLEAN get = FindModuleBaseByChain(moduleName, &moduleBase);
    if (!get) {
        return NULL;
    }
    // DbgBreakPoint();
    if (!func || !moduleBase) {
        // δָ���������� δָ��ģ�飬��Ĭ��hook ntoskernel.exeģ������е�������
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "����hook ntoskernel.exe ���е�������\n");
        // ����
    }
    else {
        // ���㺯����ָ�����Ϣ
        UINT32 insLen = GetWriteCodeLen(func);
        
        if (pHookTable->remainHook <= 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Hook �Ѵ��������\n");
            return NULL;
        }
        //// ��ȡ������
        KIRQL oldIRQL;
        KeAcquireSpinLock(&pHookTable->spLock, &oldIRQL);
        BOOLEAN is = IsRecordHook(func);
        // û�м�¼
        if (!is) {
            PHOOKDESC node = CreateHookNode(moduleBase, insLen, func, hookFunc);
            if (!node) {
                // �ͷ�������
                KeReleaseSpinLock(&pHookTable->spLock, oldIRQL);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CreateHookNode HOOKDESC �ڵ㴴��ʧ��\n");
                return NULL;
            }
            // ��������
            pHookTable->remainHook -= 1;
            // �Ǽ�Hook��Ϣ
            InsertTailList(&pHookTable->list, &node->list);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "InsertTailList �ڵ�ɹ���%p\n", node);
        }
        else {
            // �ͷ�������
            KeReleaseSpinLock(&pHookTable->spLock, oldIRQL);
            // �˴�����Hook�ˣ����ٴ�Hook
            return NULL;
        }
        // �ͷ�������
        KeReleaseSpinLock(&pHookTable->spLock, oldIRQL);

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

    DelAllHookNode();
    return STATUS_SUCCESS;
}
INT64 __stdcall TestHook(ULONG t1, ULONG t2, ULONG t3, ULONG t4, UINT32 t5, ULONG64 t6) {
    KIRQL irql = KeGetCurrentIrql();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ԭʼ TestHook ִ��,t1:%lx,t2:%lx,t3:%lx,t4:%lx,t5:%x,t6:%llx, IRQL: %d\n", t1, t2, t3, t4, t5, t6, irql);
}

// ����ջ�ϵ�rip����̬����� ��Ӧ��hook������ // �ж������ģ�������������
VOID __stdcall DoHookDispatchPre(PIntStackFrame thisFrame) {
    // ���쳣���ص�ջ��ָ�� ������
    thisFrame->rsp -= 8;
    // ���ж�֡��ջ���ƶ�һ��
    thisFrame->ripBak = thisFrame->rip;
    thisFrame->rip = thisFrame->cs;
    thisFrame->cs = thisFrame->eflags;
    thisFrame->eflags = thisFrame->rsp;
    thisFrame->rsp = thisFrame->ss;
    thisFrame->ss = thisFrame->errorCode;
    // �����������Ϣ��ջ��
    thisFrame->errorCode = thisFrame->ripBak;

    // �жϷ��غ����� DoHookDispatch
    thisFrame->ripBak = DoHookDispatch;
}


/* ===> �˴�pHookTable������д���ģ�����ʹ���ٽ����Ӷ����ᵼ���������������� */
/* ===> ��������ʹ�ú��������������hook�ڵ㣬��֤�쳣�ַ��ٶ� */
// �����̬����hook������֣���סpHookTableʱ���˷ַ�������Ȼ����������������û�����⣬��Ϊ�϶������õ�����Ŀ
PVOID __stdcall DoHookDispatchStub(PIntTriggerAddr intTriggerAddr) {
    // KIRQL irql = KeGetCurrentIrql();
    PVOID retAddr = NULL;
    // DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "DoHookDispatchStub irql:%d, pHookTable:%p\n", irql, pHookTable);
    //KIRQL oldIRQL;
    //// ��ȡ������
    //KeAcquireSpinLock(&pHookTable->spLock, &oldIRQL);
    for (PLIST_ENTRY pEntry = pHookTable->list.Flink; pEntry != &pHookTable->list; pEntry = pEntry->Flink) {
        PHOOKDESC node = CONTAINING_RECORD(pEntry, HOOKDESC, list);
        if (intTriggerAddr->triggerAddr == (ULONG64)node->moduleBase + (ULONG64)node->funcOffset + 2) {
            retAddr = &node->moduleBase;
            break;
        }
    }
    //// �ͷ�������
    //KeReleaseSpinLock(&pHookTable->spLock, oldIRQL);
    if (!retAddr) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "����HOOK����ʧ��\n");
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

    //��ȡ��ǰCPU���ĵĺ���
    ULONG index = KeGetCurrentProcessorIndex();
    // ���ǿ�����ĺ���
    // ɾ�����е�ģ���ַ��Ϣ
    DelAllHookModuleNode();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CPU %d DelAllHookModuleNode Ok!\n", index);
    // ɾ������Hook
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

    //��ȡ��ǰCPU���ĵĺ���
    ULONG index = KeGetCurrentProcessorIndex();
    // �޸� idt �������ʽж��hook
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

    //��ȡ��ǰCPU���ĵĺ���
    ULONG index = KeGetCurrentProcessorIndex();
    // �޸� idt ����
    PVOID idt = FindIDT();  // ���ڿ�����Ҫ��֤ÿ��CPUѡ��� vec ��ͬ
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

    //��ȡ��ǰCPU���ĵĺ���
    ULONG index = KeGetCurrentProcessorIndex();

    // ���ǿ�����ĺ���
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
    // ����Ƿ�ҳ�ڴ湹��HookTable
    pHookTable = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HOOKTABLE), 'TINY');
    if (!pHookTable) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "HookTable ����ʧ��\n");
        return STATUS_ACCESS_DENIED;
    }
    // ��ʼ������ͷ
    InitializeListHead(&pHookTable->list);
    // ��ʼ��������
    KeInitializeSpinLock(&pHookTable->spLock);

    pHookTable->remainHook = MAX_HOOK_NUM;

    // ����module base�洢�����ͷ�ڵ�
    pModHeadNode = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HOOKMODULEHEADNODE), 'HEAD'); // 64λĬ��16�ֽڶ���
    if (!pModHeadNode) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "pModHeadNode ����ʧ��\n");
        return STATUS_ACCESS_DENIED;
    }
    // ��ʼ������ͷ
    InitializeListHead(&pModHeadNode->list);
    // ��ʼ��������
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
    // ����������Ŀ
    if (!get) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "FindModuleBase ģ��: %s ����ʧ�ܣ�\n", moduleName);
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
    // ȡ��Hook
    /* ===> ���ʱ��Ӧ��DPCͬ�� */
    KeGenericCallDpc(UnInstallAndRecoverHook, NULL);
    KeGenericCallDpc(RecoverHookIDT, NULL);

    // ������Դ
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

            /* ===> ���ʱ��Ӧ��DPCͬ�� */
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
