#pragma once
#include <intrin.h>
#include <ntifs.h>
#include "nmd_assembly.h"

/**
* ��������������
*		���Խ��int nָ�ʵ�����ֽ��޸ĵ������ں˺���hook�� 
* 
* ������Ŀ��
*	"===>" ��ʶ��Ϊ������Ŀ���˴������������� 10��
*/


#include <pshpack1.h>  // 1�ֽڶ���
typedef struct _IDTR {
	UINT16 limit;
	UINT64 base;
}IDTR,*PIDTR;

typedef struct _KidtEntry {
	union {
		ULONG64 all;
		struct {
			unsigned short offset_low;
			unsigned short selector;
			unsigned char ist_index : 3;  //!< [0:2]
			unsigned char reserved : 5;   //!< [3:7]
			unsigned char type : 4;       //!< [8:12]
			unsigned char reserved2 : 1;
			unsigned char dpl : 2;        //!< [13:14]
			unsigned char present : 1;    //!< [15]
			unsigned short offset_middle;
		} fields;
	}idtEntry;
	ULONG32 offset_high;
	ULONG32 reserved;
}KidtEntry;

// ȫ�ֵ�Hook��Ϣ��
typedef struct _HOOKDESC {
    LIST_ENTRY list;
	UINT64 moduleBase;
	UINT32 funcOffset;
	UINT32 insLen;
	PVOID  hookPtr;
	UCHAR  orgIns[32];
}HOOKDESC, * PHOOKDESC;
#include <poppack.h>

typedef struct _IntStackFrame{
    ULONG64 ripBak;
	ULONG64 rip;
	ULONG64 cs;
	ULONG64 eflags;
	ULONG64 rsp;
	ULONG64 ss;
    ULONG64   errorCode;
}IntStackFrame, *PIntStackFrame;

typedef struct _IntTriggerAddr {
    ULONG64 triggerAddr;
}IntTriggerAddr,*PIntTriggerAddr;

// �����ҵ�IDT��ַ
PVOID FindIDT();
// �޸�IDT�к��ʵĿ�����Ŀ
VOID  ModfiyIDTEntry(PVOID idt, BOOLEAN doHook);
// �ҵ����ʵ�IDT�еĿ�����Ŀ
INT16 FindProperIDTE(PVOID idt);
// ��ɾ��
PVOID GetIDTEntryFuncAddr(PVOID idt);
// MDL�޸��ڴ�
VOID MdlChangeBytes(PVOID orgAddrBase, UINT32 offset, PVOID payload, UINT32 length);
// ��װһ��Hook����¼hook��Ϣ
PVOID InstallHook(PVOID moudleBase, PVOID func, PVOID hookFunc, BOOLEAN call);
// ж������Hook
NTSTATUS UnInstallHook();

// �жϴ���hook�ַ�ϵ�к���
VOID CommonHookEntry(); 
VOID __stdcall DoHookDispatchPre(PIntStackFrame thisFrame);
VOID __stdcall DoHookDispatch();
PVOID __stdcall DoHookDispatchStub(PIntTriggerAddr intTriggerAddr);

// ȫ�ֻ�ַ��������ʱ����ʹ��
ULONG64 tmpModuleBase = NULL;
INT64 __stdcall TestHook(ULONG t1, ULONG t2, ULONG t3, ULONG t4, UINT32 t5, ULONG64 t6);

#pragma alloc_text("NONPAGED", CommonHookEntry)
#pragma alloc_text("NONPAGED", DoHookDispatchPre)


// ���ݴ��� 2��ָ�������м���HookBytes
// ���ú�������func_offset �� hook_ins_len
// ����ջ�ϵ�rip����̬����� ��Ӧ��hook������
typedef struct _HOOKTABLE {
    KSPIN_LOCK spLock;
    LIST_ENTRY list;
	ULONG64	  remainHook;
}HOOKTABLE,*PHOOKTABLE;
#define MAX_HOOK_NUM 1024
static PHOOKTABLE pHookTable = NULL;
// ���ݳ��ȴ��� 2��ָ�������м���HookBytes => ���ڽ���Ҫ���ֽڼ���ʵ��HOOK���������滻����ָ�16�ֽڿ��Ը��ǡ�
static UCHAR gVec = 0x2e;
static UCHAR hookBytes[16] = { 0xCD, 0x2E, 0xcc, 0xcc,
							   0xcc, 0xcc, 0xcc, 0xcc,
							   0xcc, 0xcc, 0xcc, 0xcc,
							   0xcc, 0xcc, 0xcc, 0xcc };

// IDT���������
static KidtEntry orgIDTEntryX = {
	.idtEntry.all = 0,
	.offset_high = 0,
	.reserved = 0
};

// ��ʼ����Դ
NTSTATUS InitBasicResource();
VOID RecycleResource();

// hook �ַ���Ӧ�ĺ���������ÿһ��hook������Ӧ�ö�Ӧʵ��һ�� ExecuteHook0x00001 �� Hook0x00001��ǰ�����ڴ����ջ��ִ��ԭ����������������ʱ��¼��Ϣ��
extern VOID ExecuteHook0x00001();
extern VOID ExecuteHook0x00002();




typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemNextEventIdInformation,
    SystemEventIdsInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemPlugPlayBusInformation,
    SystemDockInformation,
#if !defined PO_CB_SYSTEM_POWER_POLICY
    SystemPowerInformation,
#else
    _SystemPowerInformation,
#endif
    SystemProcessorSpeedInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    ULONG Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

// PZwQuerySystemInformation ����ָ��
typedef NTSYSAPI NTSTATUS(NTAPI* PZwQuerySystemInformation)(
    IN SYSTEM_INFORMATION_CLASS SystemInfoClass,
    OUT PVOID SystemInfoBuffer,
    IN ULONG SystemInfoBufferSize,
    OUT PULONG BytesReturned OPTIONAL
    );

PZwQuerySystemInformation ZwQuerySystemInformation = NULL;

typedef struct _HOOKMODULENODE {
    LIST_ENTRY list;
	CHAR name[256];
	PVOID base;
}HOOKMODULENODE, *PHOOKMODULENODE;
typedef struct _HOOKMODULEHEADNODE {
    LIST_ENTRY list;
    KSPIN_LOCK spLock;
}HOOKMODULEHEADNODE, * PHOOKMODULEHEADNODE;

static PHOOKMODULEHEADNODE pModHeadNode = NULL;
BOOLEAN FindModuleBase(PCHAR moduleName, PULONG64 moduleBase);
BOOLEAN FindModuleBaseByChain(PCHAR moduleName, PULONG64 moduleBase);
PHOOKMODULENODE AddHookModuleNode(PCHAR moduleName, PVOID moduleBase);
VOID DelAllHookModuleNode();
NTSTATUS AddAHookModule(PCHAR moduleName);

PHOOKDESC CreateHookNode(PVOID moduleBase, UINT32 insLen, PVOID func, PVOID hookFunc);



extern VOID NTAPI KeGenericCallDpc(IN PKDEFERRED_ROUTINE Routine, IN PVOID Context);
extern BOOLEAN NTAPI KeSignalCallDpcSynchronize(IN PVOID SystemArgument2);
extern VOID NTAPI KeSignalCallDpcDone(IN PVOID SystemArgument1);
VOID InitAndInstallHook(
    _In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);
VOID InitHookIDT(
    _In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);

VOID UnInstallAndRecoverHook(
    _In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);
VOID RecoverHookIDT(
    _In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);