#include "hook.h"

// ��ǰ�ĸ������вο���ֵ����Ϊ������ջ���� + ԭ������һ��ָ��Ϊջ����ָ��ʱ��ջ���󣻵��ǲ�Ӱ��ԭ����ִ�С�
INT64 __stdcall Hook0x00001(PREGContext pushedAqs) {
    // ���Զ������Ϊ
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "NT  Hook0x00001 ,rcx:%llx,rdx:%llx,r8:%llx,r9:%llx\n",pushedAqs->rcx,pushedAqs->rdx,pushedAqs->r8,pushedAqs->r9);
    // ���ڴ˴�û���㹻�Ĳ�����Ϣ������޷����ԭ�������ã�����ͨ������ PREGContext �ṹ�峢�Ի�ȡ�������������

    return 0; // ��ʾ����ԭʼ����
}

INT64 __stdcall Hook0x00002(PREGContext pushedAqs) {
    // ���Զ������Ϊ
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ZW  Hook0x00002 ,rcx:%llx,rdx:%llx,r8:%llx,r9:%llx\n", pushedAqs->rcx, pushedAqs->rdx, pushedAqs->r8, pushedAqs->r9);
    // ���ڴ˴�û���㹻�Ĳ�����Ϣ������޷����ԭ�������ã�����ͨ������ PREGContext �ṹ�峢�Ի�ȡ�������������

    return 0; // ��ʾ����ԭʼ����
}