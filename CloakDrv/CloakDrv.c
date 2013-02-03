/*++

Module Name:

    CloakDrv.c

Abstract:

    This is the main module of the CloakDrv miniFilter driver.

Author:
    Cameron Gutman

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


//
// CloakDrv <-> CloakUtil interface header
//
#include "cloakiface.h"

//
// Pool tags for allocation tracking
//
#define FILE_NAME_TAG 'nFlC'

PFLT_FILTER gFilterHandle;
PDEVICE_OBJECT gDeviceObject;

PUNICODE_STRING gHideFileName; //Files with this file name will be hidden from directory enumerations
PUNICODE_STRING gInaccessibleFileName; //Files with this file name will not be allowed to be opened or created
PUNICODE_STRING gReadOnlyFileName; //Files with this file name will not be writable

//
// Writes on files with this file name will be spoofed onto gWriteSpoofTargetFileName in the same directory
//
PUNICODE_STRING gWriteSpoofSourceFileName; 
PUNICODE_STRING gWriteSpoofTargetFileName;

/*************************************************************************
    Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
CloakDrvUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
CloakDrvQueryTeardown (
    _In_  PCFLT_RELATED_OBJECTS FltObjects,
    _In_  FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
CloakDrvPreCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
CloakDrvPreWrite (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
CloakDrvPreDirectoryControl (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
CloakDrvPostDirectoryControl (
  _Inout_   PFLT_CALLBACK_DATA Data,
  _In_      PCFLT_RELATED_OBJECTS FltObjects,
  _In_opt_  PVOID CompletionContext,
  _In_      FLT_POST_OPERATION_FLAGS Flags
    );

NTSTATUS
CloakDrvIoctl (
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    );

NTSTATUS
CloakDrvCreateClose (
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    );
//
//  Operation registration
//
CONST FLT_OPERATION_REGISTRATION Callbacks[] =
{
    { IRP_MJ_CREATE,
      0,
      CloakDrvPreCreate,
      NULL },

    { IRP_MJ_WRITE,
      0,
      CloakDrvPreWrite,
      NULL },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      CloakDrvPreDirectoryControl,
      CloakDrvPostDirectoryControl },

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//
CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks
    CloakDrvUnload,                     //  MiniFilterUnload
    NULL,                               //  InstanceSetup
    CloakDrvQueryTeardown,              //  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent
};

/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    DbgPrint("DriverEntry() of CloakDrv has been called\n");

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status ))
    {
        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status ))
        {
            FltUnregisterFilter( gFilterHandle );
        }
    }

    DbgPrint("Filter registration status: 0x%x\n", status);

    if (!NT_SUCCESS(status))
    {
        //
        // Fail driver load if we couldn't start the filter
        //
        return status;
    }

    //
    // Everything is disabled at load-time
    //
    gHideFileName = NULL;
    gInaccessibleFileName = NULL;
    gReadOnlyFileName = NULL;
    gWriteSpoofSourceFileName = NULL;
    gWriteSpoofTargetFileName = NULL;

    //
    // Create the device object used to configure the filter
    //
    status = IoCreateDevice(
        DriverObject,
        0,
        &gDeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &gDeviceObject);
    if (!NT_SUCCESS(status))
    {
        //
        // If this doesn't work, unregister the filter and fail driver load
        //
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    //
    // Install our dispatch handler for IOCTL requests
    //
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CloakDrvIoctl;

    //
    // Install our dispatch handler for creates and closes
    //
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CloakDrvCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CloakDrvCreateClose;

    return STATUS_SUCCESS;
}

NTSTATUS
CloakDrvUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    DbgPrint("CloakDrvUnload called with flags 0x%x\n", Flags);

    FltUnregisterFilter(gFilterHandle);

    IoDeleteDevice(gDeviceObject);

    //
    // We need to cleanup our file name allocations or we'll leak memory.
    // Remember kids, leaks in kernel-mode stay around until system reboot, so free your memory!
    //

    if (gHideFileName != NULL)
    {
        ExFreePoolWithTag(gHideFileName, FILE_NAME_TAG);
    }

    if (gInaccessibleFileName != NULL)
    {
        ExFreePoolWithTag(gInaccessibleFileName, FILE_NAME_TAG);
    }

    if (gReadOnlyFileName != NULL)
    {
        ExFreePoolWithTag(gReadOnlyFileName, FILE_NAME_TAG);
    }

    if (gWriteSpoofSourceFileName != NULL)
    {
        ExFreePoolWithTag(gWriteSpoofSourceFileName, FILE_NAME_TAG);
    }

    if (gWriteSpoofTargetFileName != NULL)
    {
        ExFreePoolWithTag(gWriteSpoofTargetFileName, FILE_NAME_TAG);
    }

    return STATUS_SUCCESS;
}
/*************************************************************************
    IRP dispatch  routines.
*************************************************************************/
NTSTATUS
CloakDrvCreateClose (
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    // We don't maintain any handle-specific state here so it's a nop
    //
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
CloakDrvIoctl (
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    BOOLEAN unset;
    PUNICODE_STRING *target, *target2;
    UNICODE_STRING source;
    ULONG allocationSize;

    DBG_UNREFERENCED_PARAMETER(DeviceObject);
    NT_ASSERT(DeviceObject == gDeviceObject);
    NT_ASSERT(IrpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL);

    //
    // Handle each operation using lots of shared code
    //
    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_CLOAKDRV_SET_HIDE:
        unset = FALSE;
        target = &gHideFileName;
        target2 = NULL;
        break;

    case IOCTL_CLOAKDRV_UNSET_HIDE:
        unset = TRUE;
        target = &gHideFileName;
        target2 = NULL;
        break;

    case IOCTL_CLOAKDRV_SET_INACCESSIBLE:
        unset = FALSE;
        target = &gInaccessibleFileName;
        target2 = NULL;
        break;

    case IOCTL_CLOAKDRV_UNSET_INACCESSIBLE:
        unset = TRUE;
        target = &gInaccessibleFileName;
        target2 = NULL;
        break;

    case IOCTL_CLOAKDRV_SET_READONLY:
        unset = FALSE;
        target = &gReadOnlyFileName;
        target2 = NULL;
        break;

    case IOCTL_CLOAKDRV_UNSET_READONLY:
        unset = TRUE;
        target = &gReadOnlyFileName;
        target2 = NULL;
        break;

    case IOCTL_CLOAKDRV_SET_WRITESPOOF_SOURCE:
        unset = FALSE;
        target = &gWriteSpoofSourceFileName;
        target2 = NULL;
        break;

    case IOCTL_CLOAKDRV_SET_WRITESPOOF_TARGET:
        unset = FALSE;
        target = &gWriteSpoofTargetFileName;
        target2 = NULL;
        break;

    case IOCTL_CLOAKDRV_UNSET_WRITESPOOF:
        unset = TRUE;
        target = &gWriteSpoofSourceFileName;
        target2 = &gWriteSpoofTargetFileName;
        break;

    default:
        //
        // Anything else is not supported
        //
        Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_NOT_SUPPORTED;
    }

    //
    // Always "unset" the target(s)
    //
    if ((target != NULL) && (*target != NULL))
    {
        ExFreePoolWithTag(*target, FILE_NAME_TAG);
        *target = NULL;
    }
    if ((target2 != NULL) && (*target2 != NULL))
    {
        ExFreePoolWithTag(*target2, FILE_NAME_TAG);
        *target2 = NULL;
    }

    //
    // If we're doing a set also, copy the string from the input buffer
    //
    if (unset == FALSE)
    {
        //
        // Setup the source string from the input buffer
        //
        source.Buffer = (PWCHAR)Irp->AssociatedIrp.SystemBuffer;
        source.Length = (USHORT)IrpSp->Parameters.DeviceIoControl.InputBufferLength;
        source.MaximumLength = source.Length;

        //
        // We'll use one allocation for both the string header and the string data
        //
        allocationSize = sizeof(UNICODE_STRING) + source.MaximumLength;
        *target = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, allocationSize, FILE_NAME_TAG);
        if (*target == NULL)
        {
            Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        //
        // Put the header first, then the string data after
        //
        (*target)->Buffer = (PWCHAR)((PUCHAR)(*target) + sizeof(UNICODE_STRING));
        (*target)->MaximumLength = source.MaximumLength;
        (*target)->Length = 0;

        //
        // Copy their data into our string and upcase it so the FsRtl API we use works as expected
        //
        NT_VERIFY(NT_SUCCESS(RtlUpcaseUnicodeString(*target, &source, FALSE)));
    }

    //
    // Success!
    //
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*************************************************************************
    Callback  helper routines.
*************************************************************************/
VOID
CloakDrvGetFileName (
    _In_ PUNICODE_STRING FilePath,
    _Out_ PUNICODE_STRING FileName
    )
{
    ULONG i;

    //
    // We can't touch FilePath because it likely belongs to filter manager, so we have to copy this
    //
    *FileName = *FilePath;

    //
    // Start at the end
    //
    i = FileName->Length / sizeof(WCHAR);
    if ((i == 0) || (FileName->Buffer[i - 1] == L'\\'))
    {
        //
        // Empty file name
        //
        FileName->Length = 0;
        return;
    }

    //
    // Walk the characters in reverse order
    //
    for (;;)
    {
        i--;

        //
        // When we hit a backslash, we're done
        //
        if (FileName->Buffer[i] == L'\\')
        {
            //
            // Adjust the string 
            //
            FileName->Buffer += i + 1;
            FileName->Length -= (USHORT)((i + 1) * sizeof(WCHAR));
            return;
        }

        //
        // If we reach 0, the whole thing is a file name
        //
        if (i == 0)
        {
            //
            // No need to touch anything in this case
            //
            return;
        }
    }
}

NTSTATUS
CloakDrvGetFileNameInformation (
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PFLT_FILE_NAME_INFORMATION *FileNameInfo
    )
{
    //
    // Query the filter manager for the file information
    //
    return FltGetFileNameInformation(Data,
                                     FLT_FILE_NAME_NORMALIZED | // We want the system-normalized file name with resolved symbolic links, etc.
                                     FLT_FILE_NAME_QUERY_DEFAULT, // If it's not safe to query, we want this call to fail.
                                     FileNameInfo);
}

BOOLEAN
CloakDrvCheckForNameMatch (
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PUNICODE_STRING PotentialMatch
    )
{
    NTSTATUS status;
    UNICODE_STRING fileName;
    PFLT_FILE_NAME_INFORMATION fileNameInformation;
    BOOLEAN nameMatch;

    //
    // This can fail in some circumstances. In those cases, we return false.
    //
    status = CloakDrvGetFileNameInformation(Data, &fileNameInformation);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    //
    // The file name information we got is actually a fully qualified file path, but we just want the last component of that - the real file name
    //
    CloakDrvGetFileName(&fileNameInformation->Name, &fileName);

    //
    // Since we have a file name now, let's check if it matches the one that we're currently configured to check for using
    // the awesome FsRtlIsNameInExpression function that handles regex for us :)
    //
    if (fileName.Length != 0)
    {
        nameMatch = FsRtlIsNameInExpression(PotentialMatch, &fileName, TRUE, NULL);
    }
    else
    {
        //
        // An empty file name is never a match
        //
        nameMatch = FALSE;
    }

    //
    // Release the file name information back to filter manager before returning the match status
    //
    FltReleaseFileNameInformation(fileNameInformation);

    return nameMatch;
}

/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
NTSTATUS
CloakDrvQueryTeardown (
    _In_  PCFLT_RELATED_OBJECTS FltObjects,
    _In_  FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
CloakDrvPreCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation IRP_MJ_CREATE dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    //
    // Check if we have a file name configured to make inaccessible
    //
    if (gInaccessibleFileName == NULL)
    {
        //
        // Nothing to hide, so just let them through
        //
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Call our helper to see if this matches the hide file name
    //
    if (CloakDrvCheckForNameMatch(Data, gInaccessibleFileName))
    {
        //
        // Fail this guy!
        //
        Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
        return FLT_PREOP_COMPLETE;
    }
    else
    {
        //
        // Otherwise, it's not a match
        //
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
}

FLT_PREOP_CALLBACK_STATUS
CloakDrvPreWrite (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation IRP_MJ_WRITE dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    NTSTATUS status;
    PVOID writeSourceBuffer;
    ULONG writeLength;
    LARGE_INTEGER writeFileOffset;
    PFLT_FILE_NAME_INFORMATION fileNameInformation;
    UNICODE_STRING filePath, fileName;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE parentDirectoryHandle, targetFileHandle;
    PFILE_OBJECT targetFileObject;
    IO_STATUS_BLOCK ioStatusBlock;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    //
    // Check if we have a file name configured to make read-only
    //
    if (gReadOnlyFileName != NULL)
    {
        //
        // Read-only takes precedence over write-spoofing here so handle it first
        //
        if (CloakDrvCheckForNameMatch(Data, gReadOnlyFileName))
        {
            //
            // Fail the operation with STATUS_ACCESS_DENIED
            //
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            return FLT_PREOP_COMPLETE;
        }
    }

    //
    // Check if we have a file name configured to write-spoof
    //
    if (gWriteSpoofSourceFileName != NULL)
    {
        //
        // Make sure it matches first
        //
        if (CloakDrvCheckForNameMatch(Data, gWriteSpoofSourceFileName) == FALSE)
        {
            //
            // No match
            //
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        //
        // Grab the write parameters
        //
        writeSourceBuffer = Data->Iopb->Parameters.Write.WriteBuffer;
        writeFileOffset = Data->Iopb->Parameters.Write.ByteOffset;
        writeLength = Data->Iopb->Parameters.Write.Length;

        //
        // Get the file name information. This should never fail because CloakDrvCheckForNameMatch
        // would have already returned false.
        //
        status = CloakDrvGetFileNameInformation(Data, &fileNameInformation);
        NT_ASSERT(NT_SUCCESS(status));

        //
        // We have to capture this because it's read-only
        //
        filePath = fileNameInformation->Name;

        //
        // We're going to get the path by subtracting the length of the file name
        //
        CloakDrvGetFileName(&filePath, &fileName);
        filePath.Length -= fileName.Length;

        //
        // If removing the file name left filePath ending in a path separator (\) then we chop that off,
        // because the kernel and FS stack don't like it being there.
        //
        if (filePath.Buffer[filePath.Length / sizeof(WCHAR) - 1] == L'\\')
        {
            filePath.Length -= sizeof(WCHAR);
        }

        //
        // Define the object attributes of the parent directory handle
        //
        InitializeObjectAttributes(&objectAttributes, &filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        //
        // First open a handle to the parent directory
        //
        status = FltCreateFile(
            gFilterHandle,
            FltObjects->Instance,
            &parentDirectoryHandle,
            GENERIC_READ | GENERIC_WRITE,
            &objectAttributes,
            &ioStatusBlock,
            NULL,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE, //Allow others to read and write while we have a handle open
            FILE_OPEN, //Only open if it exists
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0,
            0);
        if (!NT_SUCCESS(status))
        {
            //
            // Failed to open a handle to the parent directory
            //
            FltReleaseFileNameInformation(fileNameInformation);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        //
        // Define the object attributes of the target file using the parent directory handle
        //
        InitializeObjectAttributes(&objectAttributes, gWriteSpoofTargetFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, parentDirectoryHandle, NULL);

        //
        // Now open the target file
        //
        status = FltCreateFileEx(
            gFilterHandle,
            FltObjects->Instance,
            &targetFileHandle,
            &targetFileObject,
            FILE_ALL_ACCESS,
            &objectAttributes,
            &ioStatusBlock,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ, // Allow other guys to read this file while we have a handle open to it
            FILE_OPEN_IF, //If it exists, open it; else, create it.
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0,
            0);

        //
        // We're done with the parent and file name information now
        //
        FltClose(parentDirectoryHandle);
        FltReleaseFileNameInformation(fileNameInformation);

        if (!NT_SUCCESS(status))
        {
            //
            // Failed to open the spoof target
            //
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        //
        // Finally, the write itself
        //
        status = FltWriteFile(
            FltObjects->Instance,
            targetFileObject,
            &writeFileOffset,
            writeLength,
            writeSourceBuffer,
            0,
            NULL,
            NULL,
            NULL);

        //
        // Dereference the file object and close the handle
        //
        ObDereferenceObject(targetFileObject);
        FltClose(targetFileHandle);

        if (!NT_SUCCESS(status))
        {
            //
            // Failed to spoof the write
            //
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        //
        // Write the final status
        //
        Data->IoStatus.Status = STATUS_SUCCESS;
        return FLT_PREOP_COMPLETE;
    }

    //
    // Neither file names were configured
    //
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
CloakDrvPreDirectoryControl (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation IRP_MJ_DIRECTORY_CONTROL dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    //
    // Check if we have a file name configured to hide
    //
    if (gHideFileName == NULL)
    {
        //
        // Nothing to hide, so just let them through
        //
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Check if it's a query directory request
    //
    if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
    {
        //
        // Not a query directory request, so let it through
        //
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Check for a directory enumeration
    //
    switch (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass)
    {
    case FileIdFullDirectoryInformation:
    case FileIdBothDirectoryInformation:
    case FileBothDirectoryInformation:
    case FileDirectoryInformation:
    case FileFullDirectoryInformation:
    case FileNamesInformation:
        //
        // These are all enumerations we want to intercept
        //
        break;

    default:
        //
        // Anything else is not
        //
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // For this one, we do want a post-operation callback so we can examine what
    // the directory enumeration is returning and make modifications if required.
    //
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
CloakDrvPostDirectoryControl (
    _Inout_   PFLT_CALLBACK_DATA Data,
    _In_      PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_  PVOID CompletionContext,
    _In_      FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is a post-operation IRP_MJ_DIRECTORY_CONTROL dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

    Flags - Indicates whether the miniport is being cleaned up.

Return Value:

    The return value is the status of the operation.

--*/
{
    PFILE_DIRECTORY_INFORMATION fileDirInfo, lastFileDirInfo, nextFileDirInfo;
    PFILE_FULL_DIR_INFORMATION fileFullDirInfo, lastFileFullDirInfo, nextFileFullDirInfo;
    PFILE_NAMES_INFORMATION fileNamesInfo, lastFileNamesInfo, nextFileNamesInfo;
    PFILE_BOTH_DIR_INFORMATION fileBothDirInfo, lastFileBothDirInfo, nextFileBothDirInfo;
    PFILE_ID_BOTH_DIR_INFORMATION fileIdBothDirInfo, lastFileIdBothDirInfo, nextFileIdBothDirInfo;
    PFILE_ID_FULL_DIR_INFORMATION fileIdFullDirInfo, lastFileIdFullDirInfo, nextFileIdFullDirInfo;
    UNICODE_STRING fileName;
    ULONG moveLength;

    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    //
    // There's a chance that this was removed after the pre-callback
    //
    if (gHideFileName == NULL)
    {
        //
        // It's gone now.
        //
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // If the operation didn't succeed, we don't care
    //
    if (!NT_SUCCESS(Data->IoStatus.Status))
    {
        //
        // Nothing to fixup but it failed
        //
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    switch (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass)
    {
    case FileDirectoryInformation:
        lastFileDirInfo = NULL;
        fileDirInfo = (PFILE_DIRECTORY_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
        for (;;)
        {
            //
            // Create a unicode string from file name so we can use FsRtl
            //
            fileName.Buffer = fileDirInfo->FileName;
            fileName.Length = (USHORT)fileDirInfo->FileNameLength;
            fileName.MaximumLength = fileName.Length;

            //
            // Check if this is a match on our hide file name
            //
            if (FsRtlIsNameInExpression(gHideFileName, &fileName, TRUE, NULL))
            {
                //
                // Skip this entry
                //
                if (lastFileDirInfo != NULL)
                {
                    //
                    // This is not the first entry
                    //
                    if (fileDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Just point the last info's offset to the next info
                        //
                        lastFileDirInfo->NextEntryOffset += fileDirInfo->NextEntryOffset;
                    }
                    else
                    {
                        //
                        // This is the last entry
                        //
                        lastFileDirInfo->NextEntryOffset = 0;
                    }
                }
                else
                {
                    //
                    // This is the first entry
                    //
                    if (fileDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Calculate the length of the whole list
                        //
                        nextFileDirInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)fileDirInfo + fileDirInfo->NextEntryOffset);
                        moveLength = 0;
                        while (nextFileDirInfo->NextEntryOffset != 0)
                        {
                            //
                            // We use the FIELD_OFFSET macro because FileName is declared as FileName[1] which means that
                            // we can't just do sizeof(FILE_DIRECTORY_INFORMATION) + nextFileDirInfo->FileNameLength.
                            //
                            moveLength += FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName) + nextFileDirInfo->FileNameLength;
                            nextFileDirInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)nextFileDirInfo + nextFileDirInfo->NextEntryOffset);
                        }

                        //
                        // Add the final entry
                        //
                        moveLength += FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName) + nextFileDirInfo->FileNameLength;

                        //
                        // We need to move everything forward.
                        // NOTE: RtlMoveMemory (memove) is required for overlapping ranges like this one.
                        //
                        RtlMoveMemory(
                            fileDirInfo,
                            (PUCHAR)fileDirInfo + fileDirInfo->NextEntryOffset,
                            moveLength);
                    }
                    else
                    {
                        //
                        // This is the first and last entry, so there's nothing to return
                        //
                        Data->IoStatus.Status = STATUS_NO_MORE_ENTRIES;
                        return FLT_POSTOP_FINISHED_PROCESSING;
                    }
                }
            }

            //
            // Advance to the next directory info
            //
            lastFileDirInfo = fileDirInfo;
            fileDirInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)fileDirInfo + fileDirInfo->NextEntryOffset);
            if (lastFileDirInfo == fileDirInfo)
            {
                break;
            }
        }
        break;

    case FileFullDirectoryInformation:
        lastFileFullDirInfo = NULL;
        fileFullDirInfo = (PFILE_FULL_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
        for (;;)
        {
            //
            // Create a unicode string from file name so we can use FsRtl
            //
            fileName.Buffer = fileFullDirInfo->FileName;
            fileName.Length = (USHORT)fileFullDirInfo->FileNameLength;
            fileName.MaximumLength = fileName.Length;

            //
            // Check if this is a match on our hide file name
            //
            if (FsRtlIsNameInExpression(gHideFileName, &fileName, TRUE, NULL))
            {
                //
                // Skip this entry
                //
                if (lastFileFullDirInfo != NULL)
                {
                    //
                    // This is not the first entry
                    //
                    if (fileFullDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Just point the last info's offset to the next info
                        //
                        lastFileFullDirInfo->NextEntryOffset += fileFullDirInfo->NextEntryOffset;
                    }
                    else
                    {
                        //
                        // This is the last entry
                        //
                        lastFileFullDirInfo->NextEntryOffset = 0;
                    }
                }
                else
                {
                    //
                    // This is the first entry
                    //
                    if (fileFullDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Calculate the length of the whole list
                        //
                        nextFileFullDirInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)fileFullDirInfo + fileFullDirInfo->NextEntryOffset);
                        moveLength = 0;
                        while (nextFileFullDirInfo->NextEntryOffset != 0)
                        {
                            //
                            // We use the FIELD_OFFSET macro because FileName is declared as FileName[1] which means that
                            // we can't just do sizeof(FILE_DIRECTORY_INFORMATION) + nextFileDirInfo->FileNameLength.
                            //
                            moveLength += FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName) + nextFileFullDirInfo->FileNameLength;
                            nextFileFullDirInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)nextFileFullDirInfo + nextFileFullDirInfo->NextEntryOffset);
                        }

                        //
                        // Add the final entry
                        //
                        moveLength += FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName) + nextFileFullDirInfo->FileNameLength;

                        //
                        // We need to move everything forward.
                        // NOTE: RtlMoveMemory (memove) is required for overlapping ranges like this one.
                        //
                        RtlMoveMemory(
                            fileFullDirInfo,
                            (PUCHAR)fileFullDirInfo + fileFullDirInfo->NextEntryOffset,
                            moveLength);
                    }
                    else
                    {
                        //
                        // This is the first and last entry, so there's nothing to return
                        //
                        Data->IoStatus.Status = STATUS_NO_MORE_ENTRIES;
                        return FLT_POSTOP_FINISHED_PROCESSING;
                    }
                }
            }

            //
            // Advance to the next directory info
            //
            lastFileFullDirInfo = fileFullDirInfo;
            fileFullDirInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)fileFullDirInfo + fileFullDirInfo->NextEntryOffset);
            if (lastFileFullDirInfo == fileFullDirInfo)
            {
                break;
            }
        }
        break;

    case FileNamesInformation:
        lastFileNamesInfo = NULL;
        fileNamesInfo = (PFILE_NAMES_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
        for (;;)
        {
            //
            // Create a unicode string from file name so we can use FsRtl
            //
            fileName.Buffer = fileNamesInfo->FileName;
            fileName.Length = (USHORT)fileNamesInfo->FileNameLength;
            fileName.MaximumLength = fileName.Length;

            //
            // Check if this is a match on our hide file name
            //
            if (FsRtlIsNameInExpression(gHideFileName, &fileName, TRUE, NULL))
            {
                //
                // Skip this entry
                //
                if (lastFileNamesInfo != NULL)
                {
                    //
                    // This is not the first entry
                    //
                    if (fileNamesInfo->NextEntryOffset != 0)
                    {
                        //
                        // Just point the last info's offset to the next info
                        //
                        lastFileNamesInfo->NextEntryOffset += fileNamesInfo->NextEntryOffset;
                    }
                    else
                    {
                        //
                        // This is the last entry
                        //
                        lastFileNamesInfo->NextEntryOffset = 0;
                    }
                }
                else
                {
                    //
                    // This is the first entry
                    //
                    if (fileNamesInfo->NextEntryOffset != 0)
                    {
                        //
                        // Calculate the length of the whole list
                        //
                        nextFileNamesInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)fileNamesInfo + fileNamesInfo->NextEntryOffset);
                        moveLength = 0;
                        while (nextFileNamesInfo->NextEntryOffset != 0)
                        {
                            //
                            // We use the FIELD_OFFSET macro because FileName is declared as FileName[1] which means that
                            // we can't just do sizeof(FILE_DIRECTORY_INFORMATION) + nextFileDirInfo->FileNameLength.
                            //
                            moveLength += FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName) + nextFileNamesInfo->FileNameLength;
                            nextFileNamesInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)nextFileNamesInfo + nextFileNamesInfo->NextEntryOffset);
                        }

                        //
                        // Add the final entry
                        //
                        moveLength += FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName) + nextFileNamesInfo->FileNameLength;

                        //
                        // We need to move everything forward.
                        // NOTE: RtlMoveMemory (memove) is required for overlapping ranges like this one.
                        //
                        RtlMoveMemory(
                            fileNamesInfo,
                            (PUCHAR)fileNamesInfo + fileNamesInfo->NextEntryOffset,
                            moveLength);
                    }
                    else
                    {
                        //
                        // This is the first and last entry, so there's nothing to return
                        //
                        Data->IoStatus.Status = STATUS_NO_MORE_ENTRIES;
                        return FLT_POSTOP_FINISHED_PROCESSING;
                    }
                }
            }

            //
            // Advance to the next directory info
            //
            lastFileNamesInfo = fileNamesInfo;
            fileNamesInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)fileNamesInfo + fileNamesInfo->NextEntryOffset);
            if (lastFileNamesInfo == fileNamesInfo)
            {
                break;
            }
        }
        break;

        case FileBothDirectoryInformation:
        lastFileBothDirInfo = NULL;
        fileBothDirInfo = (PFILE_BOTH_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
        for (;;)
        {
            //
            // Create a unicode string from file name so we can use FsRtl
            //
            fileName.Buffer = fileBothDirInfo->FileName;
            fileName.Length = (USHORT)fileBothDirInfo->FileNameLength;
            fileName.MaximumLength = fileName.Length;

            //
            // Check if this is a match on our hide file name
            //
            if (FsRtlIsNameInExpression(gHideFileName, &fileName, TRUE, NULL))
            {
                //
                // Skip this entry
                //
                if (lastFileBothDirInfo != NULL)
                {
                    //
                    // This is not the first entry
                    //
                    if (fileBothDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Just point the last info's offset to the next info
                        //
                        lastFileBothDirInfo->NextEntryOffset += fileBothDirInfo->NextEntryOffset;
                    }
                    else
                    {
                        //
                        // This is the last entry
                        //
                        lastFileBothDirInfo->NextEntryOffset = 0;
                    }
                }
                else
                {
                    //
                    // This is the first entry
                    //
                    if (fileBothDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Calculate the length of the whole list
                        //
                        nextFileBothDirInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)fileBothDirInfo + fileBothDirInfo->NextEntryOffset);
                        moveLength = 0;
                        while (nextFileBothDirInfo->NextEntryOffset != 0)
                        {
                            //
                            // We use the FIELD_OFFSET macro because FileName is declared as FileName[1] which means that
                            // we can't just do sizeof(FILE_DIRECTORY_INFORMATION) + nextFileDirInfo->FileNameLength.
                            //
                            moveLength += FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + nextFileBothDirInfo->FileNameLength;
                            nextFileBothDirInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)nextFileBothDirInfo + nextFileBothDirInfo->NextEntryOffset);
                        }

                        //
                        // Add the final entry
                        //
                        moveLength += FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + nextFileBothDirInfo->FileNameLength;

                        //
                        // We need to move everything forward.
                        // NOTE: RtlMoveMemory (memove) is required for overlapping ranges like this one.
                        //
                        RtlMoveMemory(
                            fileBothDirInfo,
                            (PUCHAR)fileBothDirInfo + fileBothDirInfo->NextEntryOffset,
                            moveLength);
                    }
                    else
                    {
                        //
                        // This is the first and last entry, so there's nothing to return
                        //
                        Data->IoStatus.Status = STATUS_NO_MORE_ENTRIES;
                        return FLT_POSTOP_FINISHED_PROCESSING;
                    }
                }
            }

            //
            // Advance to the next directory info
            //
            lastFileBothDirInfo = fileBothDirInfo;
            fileBothDirInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)fileBothDirInfo + fileBothDirInfo->NextEntryOffset);
            if (lastFileBothDirInfo == fileBothDirInfo)
            {
                break;
            }
        }
        break;

        case FileIdBothDirectoryInformation:
        lastFileIdBothDirInfo = NULL;
        fileIdBothDirInfo = (PFILE_ID_BOTH_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
        for (;;)
        {
            //
            // Create a unicode string from file name so we can use FsRtl
            //
            fileName.Buffer = fileIdBothDirInfo->FileName;
            fileName.Length = (USHORT)fileIdBothDirInfo->FileNameLength;
            fileName.MaximumLength = fileName.Length;

            //
            // Check if this is a match on our hide file name
            //
            if (FsRtlIsNameInExpression(gHideFileName, &fileName, TRUE, NULL))
            {
                //
                // Skip this entry
                //
                if (lastFileIdBothDirInfo != NULL)
                {
                    //
                    // This is not the first entry
                    //
                    if (fileIdBothDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Just point the last info's offset to the next info
                        //
                        lastFileIdBothDirInfo->NextEntryOffset += fileIdBothDirInfo->NextEntryOffset;
                    }
                    else
                    {
                        //
                        // This is the last entry
                        //
                        lastFileIdBothDirInfo->NextEntryOffset = 0;
                    }
                }
                else
                {
                    //
                    // This is the first entry
                    //
                    if (fileIdBothDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Calculate the length of the whole list
                        //
                        nextFileIdBothDirInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)fileIdBothDirInfo + fileIdBothDirInfo->NextEntryOffset);
                        moveLength = 0;
                        while (nextFileIdBothDirInfo->NextEntryOffset != 0)
                        {
                            //
                            // We use the FIELD_OFFSET macro because FileName is declared as FileName[1] which means that
                            // we can't just do sizeof(FILE_DIRECTORY_INFORMATION) + nextFileDirInfo->FileNameLength.
                            //
                            moveLength += FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + nextFileIdBothDirInfo->FileNameLength;
                            nextFileIdBothDirInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)nextFileIdBothDirInfo + nextFileIdBothDirInfo->NextEntryOffset);
                        }

                        //
                        // Add the final entry
                        //
                        moveLength += FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + nextFileIdBothDirInfo->FileNameLength;

                        //
                        // We need to move everything forward.
                        // NOTE: RtlMoveMemory (memove) is required for overlapping ranges like this one.
                        //
                        RtlMoveMemory(
                            fileIdBothDirInfo,
                            (PUCHAR)fileIdBothDirInfo + fileIdBothDirInfo->NextEntryOffset,
                            moveLength);
                    }
                    else
                    {
                        //
                        // This is the first and last entry, so there's nothing to return
                        //
                        Data->IoStatus.Status = STATUS_NO_MORE_ENTRIES;
                        return FLT_POSTOP_FINISHED_PROCESSING;
                    }
                }
            }

            //
            // Advance to the next directory info
            //
            lastFileIdBothDirInfo = fileIdBothDirInfo;
            fileIdBothDirInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)fileIdBothDirInfo + fileIdBothDirInfo->NextEntryOffset);
            if (lastFileIdBothDirInfo == fileIdBothDirInfo)
            {
                break;
            }
        }
        break;

        case FileIdFullDirectoryInformation:
        lastFileIdFullDirInfo = NULL;
        fileIdFullDirInfo = (PFILE_ID_FULL_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
        for (;;)
        {
            //
            // Create a unicode string from file name so we can use FsRtl
            //
            fileName.Buffer = fileIdFullDirInfo->FileName;
            fileName.Length = (USHORT)fileIdFullDirInfo->FileNameLength;
            fileName.MaximumLength = fileName.Length;

            //
            // Check if this is a match on our hide file name
            //
            if (FsRtlIsNameInExpression(gHideFileName, &fileName, TRUE, NULL))
            {
                //
                // Skip this entry
                //
                if (lastFileIdFullDirInfo != NULL)
                {
                    //
                    // This is not the first entry
                    //
                    if (fileIdFullDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Just point the last info's offset to the next info
                        //
                        lastFileIdFullDirInfo->NextEntryOffset += fileIdFullDirInfo->NextEntryOffset;
                    }
                    else
                    {
                        //
                        // This is the last entry
                        //
                        lastFileIdFullDirInfo->NextEntryOffset = 0;
                    }
                }
                else
                {
                    //
                    // This is the first entry
                    //
                    if (fileIdFullDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Calculate the length of the whole list
                        //
                        nextFileIdFullDirInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)fileIdFullDirInfo + fileIdFullDirInfo->NextEntryOffset);
                        moveLength = 0;
                        while (nextFileIdFullDirInfo->NextEntryOffset != 0)
                        {
                            //
                            // We use the FIELD_OFFSET macro because FileName is declared as FileName[1] which means that
                            // we can't just do sizeof(FILE_DIRECTORY_INFORMATION) + nextFileDirInfo->FileNameLength.
                            //
                            moveLength += FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName) + nextFileIdFullDirInfo->FileNameLength;
                            nextFileIdFullDirInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)nextFileIdFullDirInfo + nextFileIdFullDirInfo->NextEntryOffset);
                        }

                        //
                        // Add the final entry
                        //
                        moveLength += FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName) + nextFileIdFullDirInfo->FileNameLength;

                        //
                        // We need to move everything forward.
                        // NOTE: RtlMoveMemory (memove) is required for overlapping ranges like this one.
                        //
                        RtlMoveMemory(
                            fileIdFullDirInfo,
                            (PUCHAR)fileIdFullDirInfo + fileIdFullDirInfo->NextEntryOffset,
                            moveLength);
                    }
                    else
                    {
                        //
                        // This is the first and last entry, so there's nothing to return
                        //
                        Data->IoStatus.Status = STATUS_NO_MORE_ENTRIES;
                        return FLT_POSTOP_FINISHED_PROCESSING;
                    }
                }
            }

            //
            // Advance to the next directory info
            //
            lastFileIdFullDirInfo = fileIdFullDirInfo;
            fileIdFullDirInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)fileIdFullDirInfo + fileIdFullDirInfo->NextEntryOffset);
            if (lastFileIdFullDirInfo == fileIdFullDirInfo)
            {
                break;
            }
        }
        break;

    default:
        //
        // We shouldn't get a post call for anything else
        //
        NT_ASSERT(FALSE);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // Processing is done
    //
    return FLT_POSTOP_FINISHED_PROCESSING;
}