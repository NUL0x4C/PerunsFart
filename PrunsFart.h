#pragma once
#include <Windows.h>


// replace GetModuleHandle
PVOID GetDll(PWSTR FindName);

// does the actual patching 
void ReplaceNtdll(PVOID pLocalNtdll, PVOID pRemoteNdll, PIMAGE_SECTION_HEADER TxtSextion);