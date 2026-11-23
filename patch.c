#include "windbg.h"

BOOLEAN WindbgValidateKernelAddress(ULONG_PTR Address, SIZE_T Size)
{
    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(Size);
    return TRUE;
}

NTSTATUS WindbgPatchKernelMemory(ULONG_PTR TargetAddress, PVOID PatchBytes, ULONG Size)
{
    PMDL Mdl;
    PVOID MappedVa;

    if (!PatchBytes || Size == 0 || Size > 0x1000) {
        return STATUS_INVALID_PARAMETER;
    }

    Mdl = MmCreateMdl(NULL, (PVOID)TargetAddress, Size);
    if (!Mdl) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    MmBuildMdlForNonPagedPool(Mdl);
    MappedVa = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!MappedVa) {
        IoFreeMdl(Mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(MappedVa, PatchBytes, Size);

    MmUnmapLockedPages(MappedVa, Mdl);
    IoFreeMdl(Mdl);

    return STATUS_SUCCESS;
}
