#pragma once
#include <intrin.h>
#include <ntifs.h>
#include "nmd_assembly.h"

/**
* 最终任务描述：
*		尝试结合int n指令，实现两字节修改的任意内核函数hook。 
* 
* 待做项目：
*	"===>" 标识即为待做项目，此处余留待做数量 10。
*/


#include <pshpack1.h>  // 1字节对齐
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

// 全局的Hook信息表
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

// 快速找到IDT基址
PVOID FindIDT();
// 修改IDT中合适的空闲项目
VOID  ModfiyIDTEntry(PVOID idt, BOOLEAN doHook);
// 找到合适的IDT中的空闲项目
INT16 FindProperIDTE(PVOID idt);
// 可删除
PVOID GetIDTEntryFuncAddr(PVOID idt);
// MDL修改内存
VOID MdlChangeBytes(PVOID orgAddrBase, UINT32 offset, PVOID payload, UINT32 length);
// 安装一个Hook，记录hook信息
PVOID InstallHook(PVOID moudleBase, PVOID func, PVOID hookFunc, BOOLEAN call);
// 卸载所有Hook
NTSTATUS UnInstallHook();

// 中断触发hook分发系列函数
VOID CommonHookEntry(); 
VOID __stdcall DoHookDispatchPre(PIntStackFrame thisFrame);
VOID __stdcall DoHookDispatch();
PVOID __stdcall DoHookDispatchStub(PIntTriggerAddr intTriggerAddr);

// 全局基址变量，临时测试使用
ULONG64 tmpModuleBase = NULL;
INT64 __stdcall TestHook(ULONG t1, ULONG t2, ULONG t3, ULONG t4, UINT32 t5, ULONG64 t6);

#pragma alloc_text("NONPAGED", CommonHookEntry)
#pragma alloc_text("NONPAGED", DoHookDispatchPre)


// 根据大于 2的指令来自行计算HookBytes
// 调用函数查找func_offset 和 hook_ins_len
// 根据栈上的rip，动态计算出 对应的hook函数。
typedef struct _HOOKTABLE {
    KSPIN_LOCK spLock;
    LIST_ENTRY list;
	ULONG64	  remainHook;
}HOOKTABLE,*PHOOKTABLE;
#define MAX_HOOK_NUM 1024
static PHOOKTABLE pHookTable = NULL;
// 根据长度大于 2的指令来自行计算HookBytes => 由于仅需要两字节即可实现HOOK，因此最多替换两条指令，16字节可以覆盖。
static UCHAR gVec = 0x2e;
static UCHAR hookBytes[16] = { 0xCD, 0x2E, 0xcc, 0xcc,
							   0xcc, 0xcc, 0xcc, 0xcc,
							   0xcc, 0xcc, 0xcc, 0xcc,
							   0xcc, 0xcc, 0xcc, 0xcc };

// IDT表项留存地
static KidtEntry orgIDTEntryX = {
	.idtEntry.all = 0,
	.offset_high = 0,
	.reserved = 0
};

// 初始化资源
NTSTATUS InitBasicResource();
VOID RecycleResource();

// hook 分发对应的函数，后续每一个hook函数都应该对应实现一个 ExecuteHook0x00001 和 Hook0x00001；前者用于处理堆栈、执行原函数，后者用于临时记录信息。
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

// PZwQuerySystemInformation 函数指针
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