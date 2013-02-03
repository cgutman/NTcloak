// CloakCfg.cpp : Defines the entry point for the console application.
//
// Cameron Gutman
//

#include "stdafx.h"

#define CLOAKDRV_UM
#include "../CloakDrv/cloakiface.h"

int SendIoctl(ULONG IoctlCode, PWCHAR String)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE configHandle;
    IO_STATUS_BLOCK ioStatusBlock;
    UNICODE_STRING deviceName;

    RtlInitUnicodeString(&deviceName, CLOAKDRV_DEVICE_NAME);

    InitializeObjectAttributes(
        &objectAttributes,
        &deviceName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    status = NtOpenFile(
        &configHandle,
        FILE_ALL_ACCESS,
        &objectAttributes,
        &ioStatusBlock,
        0,
        FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"Failed to open config handle: 0x%x\n", status);
        return -1;
    }

    status = NtDeviceIoControlFile(
        configHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        IoctlCode,
        String,
        String != NULL ? wcslen(String) * sizeof(WCHAR) : 0,
        NULL,
        0);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"IOCTL failed: 0x%x\n", status);
        return -1;
    }

    return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
    int i;

    for (i = 1; i < argc; i++)
    {
        /* We use +/- prefixes here to make things simple */
        if (argv[i][0] == _T('+'))
        {
            if (i + 1 >= argc)
            {
                wprintf(L"Not enough arguments for %ls\n", argv[i]);
                return -2;
            }

            if (argv[i][1] == _T('h'))
            {
                if (SendIoctl(IOCTL_CLOAKDRV_SET_HIDE, argv[++i]) != 0)
                    return -1;
            }
            else if (argv[i][1] == _T('i'))
            {
                if (SendIoctl(IOCTL_CLOAKDRV_SET_INACCESSIBLE, argv[++i]) != 0)
                    return -1;
            }
            else if (argv[i][1] == _T('r'))
            {
                if (SendIoctl(IOCTL_CLOAKDRV_SET_READONLY, argv[++i]) != 0)
                    return -1;
            }
            else if (argv[i][1] == _T('w'))
            {
                if (i + 2 >= argc)
                {
                    wprintf(L"Not enough arguments for %ls\n", argv[i]);
                    return -2;
                }

                if (SendIoctl(IOCTL_CLOAKDRV_SET_WRITESPOOF_SOURCE, argv[++i]) != 0)
                    return -1;

                if (SendIoctl(IOCTL_CLOAKDRV_SET_WRITESPOOF_TARGET, argv[++i]) != 0)
                    return -1;
            }
            else
            {
                wprintf(L"Unrecognized option: %ls\n", argv[i]);
                return -2;
            }
        }
        else if (argv[i][0] == _T('-'))
        {
            if (argv[i][1] == _T('h'))
            {
                if (SendIoctl(IOCTL_CLOAKDRV_UNSET_HIDE, NULL) != 0)
                    return -1;
            }
            else if (argv[i][1] == _T('i'))
            {
                if (SendIoctl(IOCTL_CLOAKDRV_UNSET_INACCESSIBLE, NULL) != 0)
                    return -1;
            }
            else if (argv[i][1] == _T('r'))
            {
                if (SendIoctl(IOCTL_CLOAKDRV_UNSET_READONLY, NULL) != 0)
                    return -1;
            }
            else if (argv[i][1] == _T('w'))
            {
                if (SendIoctl(IOCTL_CLOAKDRV_UNSET_WRITESPOOF, NULL) != 0)
                    return -1;
            }
            else
            {
                wprintf(L"Unrecognized option: %ls\n", argv[i]);
                return -2;
            }
        }
        else
        {
            wprintf(L"Unrecognized option: %ls\n", argv[i]);
            return -2;
        }
    }
}

