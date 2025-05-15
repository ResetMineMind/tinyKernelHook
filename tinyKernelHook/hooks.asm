EXTERN    tmpModuleBase          : QWORD 


EXTERN    Hook0x00001  : proc
EXTERN    Hook0x00002  : proc

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

ExecuteHook0x00001 PROC
ALIGN 16
    mov     rcx,rsp
	call	Hook0x00001                 ; 执行自定义函数
    ; POPAQ                             ; 会影响后续 0x30 总偏移的计算
    ; ret                               ; 但是如果就此返回，理论上堆栈是不平衡的（因为原始函数调用可能有参数压栈，此时被调用者没有平栈？思考调用约定）
ALIGN 16
    POPAQ                               ; 恢复原始的 函数调用信息 => 占据空间 0x20
    pop     rcx                         ; DoHookDispatchStub 参数使用rcx
    add     rsp, 8                      ; 在中断触发时，用来保存触发地址了
    
                                        ; 打算后续的内容都在注册hook时主动进行修改。
ALIGN 16                                ; 这里的偏移一定是：0x20 + 0x10 => 0x30
back:
	REPEAT 020h
        int     3
    ENDM
ExecuteHook0x00001 ENDP

ExecuteHook0x00002 PROC
ALIGN 16
    mov     rcx,rsp
	call	Hook0x00002                 ; 执行自定义函数
    ; POPAQ                             ; 会影响后续 0x30 总偏移的计算
    ; ret                               ; 但是如果就此返回，理论上堆栈是不平衡的（因为原始函数调用可能有参数压栈，此时被调用者没有平栈？思考调用约定）
ALIGN 16
    POPAQ                               ; 恢复原始的 函数调用信息 => 占据空间 0x20
    pop     rcx                         ; DoHookDispatchStub 参数使用rcx
    add     rsp, 8                      ; 在中断触发时，用来保存触发地址了
    
                                        ; 打算后续的内容都在注册hook时主动进行修改。
ALIGN 16                                ; 这里的偏移一定是：0x20 + 0x10 => 0x30
back:
	REPEAT 020h
        int     3
    ENDM
ExecuteHook0x00002 ENDP

END