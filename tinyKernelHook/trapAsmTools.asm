PUBLIC GetIDTAddr

EXTERNDEF DbgBreakPoint       : proc
EXTERN    DoHookDispatchPre   : proc
EXTERN	  DoHookDispatchStub  : proc
EXTERN	  ExecuteHook0x00001  : proc

PUSHAQ MACRO
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    -1      ; �൱��push rsp
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
ENDM

POPAQ MACRO
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    add     rsp, 8    ; �൱�� pop rsp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
ENDM

.CODE

GetIDTAddr PROC
	sub		rsp, 28h

	; do something
	push	rbx
	mov		rbx,rcx
	sidt	[rbx]
	pop		rbx

	add		rsp, 28h
	ret
GetIDTAddr ENDP


CommonHookEntry PROC
    ; int   3
	; �Զ����жϴ���ʵ�������ڷַ�hook
	swapgs
    push    0                           ; Ǩ���ж�֡
	push	rcx
	lea		rcx,[rsp+8]
	PUSHAQ
	sub		rsp, 28h
	call	DoHookDispatchPre ; 
	add		rsp, 28h
	POPAQ
	pop		rcx

	swapgs
	iretq								; ���������ģ���ת�� DoHookDispatch
CommonHookEntry ENDP

DoHookDispatch PROC
    push rcx
    lea		rcx,[rsp+8]                 ; DoHookDispatchPre�н����Ϊ�����жϵĵ�ַ��
	; ��ַ�����
	PUSHAQ
	call	DoHookDispatchStub

	mov		rcx,qword ptr [rax + 10h]		; �ַ�����ֻ��Ҫ�ܲ�ѯ�� hookPtr ��˭������

	; ִ�зַ�����
	jmp		rcx
	
DoHookDispatch ENDP

END
