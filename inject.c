#include "windbg.h"

BOOLEAN WindbgValidateProcess(HANDLE ProcessHandle, ULONG ProcessId)
{
    UNREFERENCED_PARAMETER(ProcessHandle);
    UNREFERENCED_PARAMETER(ProcessId);
    return TRUE;
}

NTSTATUS WindbgInjectProcess(ULONG ProcessId, PVOID Payload, ULONG PayloadSize)
{
    NTSTATUS Status;
    PEPROCESS Process = NULL;
    HANDLE ProcessHandle = NULL;
    KAPC_STATE ApcState;
    PVOID RemoteMemory = NULL;
    SIZE_T MemSize;

    if (!Payload || PayloadSize == 0 || PayloadSize > 0x1000) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = ObOpenObjectByPointer(
        Process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_ALL_ACCESS,
        *PsProcessType,
        KernelMode,
        &ProcessHandle
    );

    if (!NT_SUCCESS(Status)) {
        ObDereferenceObject(Process);
        return Status;
    }

    MemSize = PayloadSize;
    KeStackAttachProcess((PKPROCESS)Process, &ApcState);

    Status = ZwAllocateVirtualMemory(
        ProcessHandle,
        &RemoteMemory,
        0,
        &MemSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (NT_SUCCESS(Status) && RemoteMemory) {
        RtlCopyMemory(RemoteMemory, Payload, PayloadSize);
    }

    KeUnstackDetachProcess(&ApcState);
    ZwClose(ProcessHandle);
    ObDereferenceObject(Process);

    return Status;
}
