EXTERN    tmpModuleBase          : QWORD 


EXTERN    Hook0x00001  : proc
EXTERN    Hook0x00002  : proc

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

ExecuteHook0x00001 PROC
ALIGN 16
    mov     rcx,rsp
	call	Hook0x00001                 ; ִ���Զ��庯��
    ; POPAQ                             ; ��Ӱ����� 0x30 ��ƫ�Ƶļ���
    ; ret                               ; ��������ʹ˷��أ������϶�ջ�ǲ�ƽ��ģ���Ϊԭʼ�������ÿ����в���ѹջ����ʱ��������û��ƽջ��˼������Լ����
ALIGN 16
    POPAQ                               ; �ָ�ԭʼ�� ����������Ϣ => ռ�ݿռ� 0x20
    pop     rcx                         ; DoHookDispatchStub ����ʹ��rcx
    add     rsp, 8                      ; ���жϴ���ʱ���������津����ַ��
    
                                        ; ������������ݶ���ע��hookʱ���������޸ġ�
ALIGN 16                                ; �����ƫ��һ���ǣ�0x20 + 0x10 => 0x30
back:
	REPEAT 020h
        int     3
    ENDM
ExecuteHook0x00001 ENDP

ExecuteHook0x00002 PROC
ALIGN 16
    mov     rcx,rsp
	call	Hook0x00002                 ; ִ���Զ��庯��
    ; POPAQ                             ; ��Ӱ����� 0x30 ��ƫ�Ƶļ���
    ; ret                               ; ��������ʹ˷��أ������϶�ջ�ǲ�ƽ��ģ���Ϊԭʼ�������ÿ����в���ѹջ����ʱ��������û��ƽջ��˼������Լ����
ALIGN 16
    POPAQ                               ; �ָ�ԭʼ�� ����������Ϣ => ռ�ݿռ� 0x20
    pop     rcx                         ; DoHookDispatchStub ����ʹ��rcx
    add     rsp, 8                      ; ���жϴ���ʱ���������津����ַ��
    
                                        ; ������������ݶ���ע��hookʱ���������޸ġ�
ALIGN 16                                ; �����ƫ��һ���ǣ�0x20 + 0x10 => 0x30
back:
	REPEAT 020h
        int     3
    ENDM
ExecuteHook0x00002 ENDP

END