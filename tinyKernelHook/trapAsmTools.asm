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
    push    -1      ; 相当于push rsp
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
    add     rsp, 8    ; 相当于 pop rsp
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
	; 自定义中断处理，实际上用于分发hook
	swapgs
    push    0                           ; 迁移中断帧
	push	rcx
	lea		rcx,[rsp+8]
	PUSHAQ
	sub		rsp, 28h
	call	DoHookDispatchPre ; 
	add		rsp, 28h
	POPAQ
	pop		rcx

	swapgs
	iretq								; 进程上下文，跳转到 DoHookDispatch
CommonHookEntry ENDP

DoHookDispatch PROC
    push rcx
    lea		rcx,[rsp+8]                 ; DoHookDispatchPre中将其改为触发中断的地址了
	; 查分发函数
	PUSHAQ
	call	DoHookDispatchStub

	mov		rcx,qword ptr [rax + 10h]		; 分发函数只需要能查询到 hookPtr 是谁就行了

	; 执行分发函数
	jmp		rcx
	
DoHookDispatch ENDP

END
