#include "windbg.h"

PDEVICE_OBJECT g_ControlDevice = NULL;

NTSTATUS WindbgCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS WindbgPassThrough(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PWINDBG_FILTER_EXTENSION DevExt = (PWINDBG_FILTER_EXTENSION)DeviceObject->DeviceExtension;

    if (DeviceObject == g_ControlDevice || !DevExt || !DevExt->AttachedDeviceObject) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(DevExt->AttachedDeviceObject, Irp);
}

VOID WindbgUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING SymlinkName;

    IoUnregisterFsRegistrationChange(DriverObject, WindbgFsRegistrationChange);
    WindbgCleanupAllFilters(DriverObject);

    RtlInitUnicodeString(&SymlinkName, WINDBG_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&SymlinkName);

    if (g_ControlDevice) {
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = NULL;
    }
}

NTSTATUS WindbgDispatchDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID Buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Information = 0;

    if (DeviceObject != g_ControlDevice) {
        return WindbgPassThrough(DeviceObject, Irp);
    }

    switch (IoControlCode) {
    case IOCTL_WINDBG_INJECT_PROCESS:
        if (Buffer && InputBufferLength >= sizeof(WINDBG_INJECT_REQ)) {
            PWINDBG_INJECT_REQ Req = (PWINDBG_INJECT_REQ)Buffer;
            Status = WindbgInjectProcess(Req->ProcessId, Req->Payload, Req->CodeSize);
            if (NT_SUCCESS(Status)) {
                Information = sizeof(WINDBG_INJECT_REQ);
            }
        } else {
            Status = STATUS_INVALID_BUFFER_SIZE;
        }
        break;

    case IOCTL_WINDBG_PATCH_KERNEL:
        if (Buffer && InputBufferLength >= sizeof(WINDBG_PATCH_REQ)) {
            PWINDBG_PATCH_REQ Req = (PWINDBG_PATCH_REQ)Buffer;
            Status = WindbgPatchKernelMemory(Req->TargetAddress, Req->PatchBytes, Req->Size);
            if (NT_SUCCESS(Status)) {
                Information = sizeof(WINDBG_PATCH_REQ);
            }
        } else {
            Status = STATUS_INVALID_BUFFER_SIZE;
        }
        break;

    case IOCTL_WINDBG_BLOCK_PROCESS:
        if (Buffer && InputBufferLength >= sizeof(ULONG)) {
            Information = sizeof(ULONG);
            Status = STATUS_SUCCESS;
        } else {
            Status = STATUS_INVALID_BUFFER_SIZE;
        }
        break;

    case IOCTL_WINDBG_GET_STATUS:
        if (Buffer && OutputBufferLength >= sizeof(WINDBG_STATUS_REQ)) {
            PWINDBG_STATUS_REQ Req = (PWINDBG_STATUS_REQ)Buffer;
            Req->ActiveFilters = WindbgGetActiveFilterCount();
            Req->InjectedProcesses = 0;
            Req->BlockedAttempts = 0;
            Information = sizeof(WINDBG_STATUS_REQ);
        } else {
            Status = STATUS_INVALID_BUFFER_SIZE;
        }
        break;

    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;
    UNICODE_STRING DeviceName;
    UNICODE_STRING SymlinkName;
    ULONG i;

    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = WindbgUnload;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = WindbgPassThrough;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = WindbgCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = WindbgCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = WindbgDispatchDeviceControl;

    RtlInitUnicodeString(&DeviceName, WINDBG_DEVICE_NAME);
    Status = IoCreateDevice(
        DriverObject,
        0,
        &DeviceName,
        WINDBG_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_ControlDevice
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    RtlInitUnicodeString(&SymlinkName, WINDBG_DOS_DEVICE_NAME);
    Status = IoCreateSymbolicLink(&SymlinkName, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = NULL;
        return Status;
    }

    g_ControlDevice->Flags |= DO_BUFFERED_IO;
    g_ControlDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    IoRegisterFsRegistrationChange(DriverObject, WindbgFsRegistrationChange);

    return STATUS_SUCCESS;
}
