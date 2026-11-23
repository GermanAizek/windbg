#pragma once

#include <ntifs.h>
#include <wdmsec.h>
#include <ntstrsafe.h>

#define WINDBG_DEVICE_TYPE           0x22

#define IOCTL_WINDBG_INJECT_PROCESS  0x00222000
#define IOCTL_WINDBG_PATCH_KERNEL    0x00222004
#define IOCTL_WINDBG_BLOCK_PROCESS   0x00222008
#define IOCTL_WINDBG_GET_STATUS      0x0022200C

#define WINDBG_DEVICE_NAME           L"\\Device\\windbg"
#define WINDBG_DOS_DEVICE_NAME       L"\\DosDevices\\windbg"
#define WINDBG_POOL_TAG              'GDBW'

#pragma pack(push, 1)
typedef struct _WINDBG_INJECT_REQ {
    ULONG ProcessId;
    ULONG CodeSize;
    UCHAR Payload[256];
} WINDBG_INJECT_REQ, *PWINDBG_INJECT_REQ;

typedef struct _WINDBG_PATCH_REQ {
    ULONG_PTR TargetAddress;
    ULONG Size;
    UCHAR PatchBytes[64];
} WINDBG_PATCH_REQ, *PWINDBG_PATCH_REQ;

typedef struct _WINDBG_STATUS_REQ {
    ULONG ActiveFilters;
    ULONG InjectedProcesses;
    ULONG BlockedAttempts;
} WINDBG_STATUS_REQ, *PWINDBG_STATUS_REQ;
#pragma pack(pop)

typedef struct _WINDBG_FILTER_EXTENSION {
    PDEVICE_OBJECT AttachedDeviceObject;
    PDEVICE_OBJECT TargetDeviceObject;
    ULONG DeviceType;
    BOOLEAN IsAttached;
} WINDBG_FILTER_EXTENSION, *PWINDBG_FILTER_EXTENSION;

// Driver Dispatch Prototypes
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD WindbgUnload;

NTSTATUS WindbgCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS WindbgDispatchDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS WindbgPassThrough(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

// Process Code Injection (inject.c)
NTSTATUS WindbgInjectProcess(ULONG ProcessId, PVOID Payload, ULONG PayloadSize);
BOOLEAN WindbgValidateProcess(HANDLE ProcessHandle, ULONG ProcessId);

// Kernel Memory Patching (patch.c)
NTSTATUS WindbgPatchKernelMemory(ULONG_PTR TargetAddress, PVOID PatchBytes, ULONG Size);
BOOLEAN WindbgValidateKernelAddress(ULONG_PTR Address, SIZE_T Size);

// File System Filter (fsfilter.c)
VOID WindbgFsRegistrationChange(PDEVICE_OBJECT DeviceObject, BOOLEAN FsActive);
NTSTATUS WindbgAttachToFileSystem(PDEVICE_OBJECT DeviceObject);
VOID WindbgDetachFromFileSystem(PDEVICE_OBJECT DeviceObject);
VOID WindbgCleanupAllFilters(PDRIVER_OBJECT DriverObject);
ULONG WindbgGetActiveFilterCount(VOID);
