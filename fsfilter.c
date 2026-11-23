#include "windbg.h"

static PDRIVER_OBJECT g_DriverObject = NULL;
static ULONG g_ActiveFilterCount = 0;

ULONG WindbgGetActiveFilterCount(VOID)
{
    return g_ActiveFilterCount;
}

NTSTATUS WindbgAttachToFileSystem(PDEVICE_OBJECT TargetDeviceObject)
{
    NTSTATUS Status;
    PDEVICE_OBJECT FilterDeviceObject = NULL;
    PWINDBG_FILTER_EXTENSION DevExt;

    if (!TargetDeviceObject || !g_DriverObject) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = IoCreateDevice(
        g_DriverObject,
        sizeof(WINDBG_FILTER_EXTENSION),
        NULL,
        TargetDeviceObject->DeviceType,
        0,
        FALSE,
        &FilterDeviceObject
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    DevExt = (PWINDBG_FILTER_EXTENSION)FilterDeviceObject->DeviceExtension;
    RtlZeroMemory(DevExt, sizeof(WINDBG_FILTER_EXTENSION));

    DevExt->TargetDeviceObject = TargetDeviceObject;
    DevExt->DeviceType = TargetDeviceObject->DeviceType;

    Status = IoAttachDeviceToDeviceStackSafe(
        FilterDeviceObject,
        TargetDeviceObject,
        &DevExt->AttachedDeviceObject
    );

    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(FilterDeviceObject);
        return Status;
    }

    DevExt->IsAttached = TRUE;
    FilterDeviceObject->Flags |= TargetDeviceObject->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO);
    FilterDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    InterlockedIncrement((LONG *)&g_ActiveFilterCount);
    return STATUS_SUCCESS;
}

VOID WindbgDetachFromFileSystem(PDEVICE_OBJECT FilterDeviceObject)
{
    PWINDBG_FILTER_EXTENSION DevExt;

    if (!FilterDeviceObject) {
        return;
    }

    DevExt = (PWINDBG_FILTER_EXTENSION)FilterDeviceObject->DeviceExtension;
    if (DevExt && DevExt->IsAttached && DevExt->AttachedDeviceObject) {
        IoDetachDevice(DevExt->AttachedDeviceObject);
        DevExt->AttachedDeviceObject = NULL;
        DevExt->IsAttached = FALSE;
        InterlockedDecrement((LONG *)&g_ActiveFilterCount);
    }

    IoDeleteDevice(FilterDeviceObject);
}

VOID WindbgFsRegistrationChange(PDEVICE_OBJECT DeviceObject, BOOLEAN FsActive)
{
    if (FsActive) {
        WindbgAttachToFileSystem(DeviceObject);
    }
}

VOID WindbgCleanupAllFilters(PDRIVER_OBJECT DriverObject)
{
    PDEVICE_OBJECT CurrentDevice;
    PDEVICE_OBJECT NextDevice;

    if (!DriverObject) {
        return;
    }

    g_DriverObject = DriverObject;
    CurrentDevice = DriverObject->DeviceObject;

    while (CurrentDevice) {
        NextDevice = CurrentDevice->NextDevice;
        if (CurrentDevice->DeviceType != WINDBG_DEVICE_TYPE) {
            WindbgDetachFromFileSystem(CurrentDevice);
        }
        CurrentDevice = NextDevice;
    }
}
