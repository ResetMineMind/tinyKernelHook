#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <intrin.h>

typedef struct _REGContext { // ½öÍ¨ÓÃ¼Ä´æÆ÷
	ULONG64 r15;
	ULONG64 r14;
	ULONG64 r13;
	ULONG64 r12;
	ULONG64 r11;
	ULONG64 r10;
	ULONG64 r9;
	ULONG64 r8;
	ULONG64 rdi;
	ULONG64 rsi;
	ULONG64 rbp;
	ULONG64 reserved1;
	ULONG64 rbx;
	ULONG64 rdx;
	ULONG64 rcx;
	ULONG64 rax;
}REGContext, * PREGContext;

INT64 __stdcall Hook0x00001(PREGContext pushedAqs);