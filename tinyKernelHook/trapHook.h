#pragma once
// #include <ntddk.h>
// #include <wdf.h>
#include <intrin.h>
#include <ntifs.h>

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
	UINT64 moduleBase;
	UINT32 funcOffset;
	UINT32 insLen;
	PVOID  hookPtr;
	UCHAR  orgIns[32];
}HOOKDESC, * PHOOKDESC;
#include <poppack.h>

typedef struct _IntStackFrame{
	ULONG64 rip;
	ULONG64 cs;
	ULONG64 eflags;
	ULONG64 rsp;
	ULONG64 ss;
}IntStackFrame, *PIntStackFrame;

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
PVOID __stdcall DoHookDispatchStub();

// ȫ�ֻ�ַ��������ʱ����ʹ��
ULONG64 tmpModuleBase = NULL;
INT64 __stdcall TestHook(ULONG t1, ULONG t2, ULONG t3, ULONG t4, UINT32 t5, ULONG64 t6);

#pragma alloc_text("NONPAGED", CommonHookEntry)
#pragma alloc_text("NONPAGED", DoHookDispatchPre)


// ���ݴ��� 2��ָ�������м���HookBytes
// ���ú�������func_offset �� hook_ins_len
// ����ջ�ϵ�rip����̬����� ��Ӧ��hook������
typedef struct _HOOKTABLE {
	ERESOURCE lock;
	ULONG64	  remainHook;
	PHOOKDESC tableBase;
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

// hook �ַ���Ӧ�ĺ���������ÿһ��hook������Ӧ�ö�Ӧʵ��һ�� ExecuteHook0x00001 �� Hook0x00001��ǰ�����ڴ����ջ��ִ��ԭ����������������ʱ��¼��Ϣ��
extern VOID ExecuteHook0x00001();