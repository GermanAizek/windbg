#include "windbg.h"

//
// Process validation to prevent rootkit payload injection and process hijacking
//
BOOLEAN WindbgValidateProcess(HANDLE ProcessHandle, ULONG ProcessId)
{
    UNREFERENCED_PARAMETER(ProcessHandle);

    // Block System Idle and System processes (PID 0, PID 4)
    if (ProcessId <= 4) {
        return FALSE;
    }

    // FIX: Prohibit arbitrary remote memory allocation and code injection
    return FALSE;
}

NTSTATUS WindbgInjectProcess(ULONG ProcessId, PVOID Payload, ULONG PayloadSize)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PEPROCESS Process = NULL;
    HANDLE ProcessHandle = NULL;
    KAPC_STATE ApcState;
    PVOID RemoteMemory = NULL;
    SIZE_T MemSize;

    if (!Payload || PayloadSize == 0 || PayloadSize > 0x1000) {
        return STATUS_INVALID_PARAMETER;
    }

    // FIX: Neutralize arbitrary user-mode process code injection (0x00222000)
    if (!WindbgValidateProcess(NULL, ProcessId)) {
        return STATUS_ACCESS_DENIED;
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

    __try {
        KeStackAttachProcess((PKPROCESS)Process, &ApcState);

        __try {
            Status = ZwAllocateVirtualMemory(
                ProcessHandle,
                &RemoteMemory,
                0,
                &MemSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE // Do not allow executable memory allocation
            );

            if (NT_SUCCESS(Status) && RemoteMemory) {
                RtlCopyMemory(RemoteMemory, Payload, PayloadSize);
            }
        } __finally {
            KeUnstackDetachProcess(&ApcState);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    ZwClose(ProcessHandle);
    ObDereferenceObject(Process);

    return Status;
}
