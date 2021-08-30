/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <efi.h>
#include <efilib.h>

#include "common.h"
#include "signature_list.h"

typedef UINT32 EFI_IMAGE_EXECUTION_ACTION;

typedef struct {
    EFI_IMAGE_EXECUTION_ACTION Action;
    UINT32 InfoSize;
    /* CHAR16 Name[]; */
    /* EFI_DEVICE_PATH_PROTOCOL DevicePath; */
    /* EFI_SIGNATURE_LIST Signature; */
} EFI_IMAGE_EXECUTION_INFO;

typedef struct {
    EFI_IMAGE_EXECUTION_INFO *Entry;

    EFI_IMAGE_EXECUTION_ACTION *Action;
    UINT32 *InfoSize;
    CHAR16 *Name;
    EFI_DEVICE_PATH_PROTOCOL *DevicePath;
    EFI_SIGNATURE_LIST *Signature;
    
    EFI_IMAGE_EXECUTION_INFO *Next;
} EFI_IMAGE_EXECUTION_INFO_PROXY;

typedef struct {
    UINTN NumberOfImages;
    UINT8 InformationInfo[];
} EFI_IMAGE_EXECUTION_INFO_TABLE;

static inline void
EfiImageExecutionInfoToProxy ( IN EFI_IMAGE_EXECUTION_INFO *Info, 
                              OUT EFI_IMAGE_EXECUTION_INFO_PROXY *Proxy)
{
    Proxy->Entry      =  Info;
    Proxy->Action     = &Info->Action; 
    Proxy->InfoSize   = &Info->InfoSize; 

    Proxy->Name       =                   (CHAR16 *) ((UINT8 *) Info + sizeof (*Info));
    Proxy->DevicePath = (EFI_DEVICE_PATH_PROTOCOL *) ((UINT8 *) Proxy->Name + StrSize(Proxy->Name));
    Proxy->Signature  =       (EFI_SIGNATURE_LIST *) ((UINT8 *) Proxy->DevicePath + DevicePathSize(Proxy->DevicePath));
    
    Proxy->Next       = (EFI_IMAGE_EXECUTION_INFO *) ((UINT8 *) Info + Info->InfoSize);

    if ((UINT8 *) Proxy->Signature == (UINT8 *) Proxy->Next)
        Proxy->Signature = NULL;
}

static const CHAR16 *AUTH_STR[] = {
    L"Untested",
    L"Signature Verification Failed",
    L"Signature Verification Passed",
    L"Signature Not Found",
    L"Signature Found",
    L"Policy Failed",
    L"Unknown verification state",
    L"Unknown verification state"
};

static EFI_IMAGE_EXECUTION_INFO_TABLE *
GetImageExecInfoTable (VOID)
{
    EFI_CONFIGURATION_TABLE *CT, *Last;

    for (CT = ST->ConfigurationTable, Last = CT + ST->NumberOfTableEntries; CT < Last; CT++)
        if (!CompareGuid(&CT->VendorGuid, &IMAGE_SECURITY_DATABASE_GUID))
            return (EFI_IMAGE_EXECUTION_INFO_TABLE *) CT->VendorTable;
    
    return NULL;
}

static UINTN
ListImageExecInfoTable (IN EFI_IMAGE_EXECUTION_INFO_TABLE *Table)
{
    UINTN Index = 0;
    CHAR16 *DevicePathStr;

    EFI_IMAGE_EXECUTION_INFO_PROXY Proxy = {
        .Next = (EFI_IMAGE_EXECUTION_INFO *) Table->InformationInfo
    };

    if (!Table)
        return Index;

    for (; Index < Table->NumberOfImages; Index++) 
    {
        if (Index)
            Print(L"\r\n");

        /* XXX: what are the alignment constraints of EFI_IMAGE_EXECUTION_INFO */
        EfiImageExecutionInfoToProxy(Proxy.Next, &Proxy);

        DevicePathStr = DevicePathToStr(Proxy.DevicePath);
        Print(L"%EImage %u:%N\r\n"
               "  Device: %D\r\n"
               "    Name: %s\r\n"
               "   State: %s%s\r\n",
              Index, 
              DevicePathStr,
              Proxy.Name,
              AUTH_STR[*Proxy.Action & 0x7], *Proxy.Action & 0x8 ? L", Initialized" : L"");
        FreePool(DevicePathStr);

        if (Proxy.Signature)
        {
            Print(L"\r\n");
            /* FIXME: possible unaligned access */
            ListSignatures(Proxy.Signature, (UINTN) ((UINT8 *) Proxy.Next - (UINT8 *) Proxy.Signature));
        }
    }

    return Index;
}

EFI_STATUS EFIAPI
efi_main ()
{    
    if (ListImageExecInfoTable(GetImageExecInfoTable()))
        return EFI_SUCCESS;

    Print(L"No entries.\r\n");
    return EFI_NOT_FOUND;
}
