#include "IATHook.h"
#include <string>

IATHook::IATHook(const char* sz_IAT_Module, const char* szModuleName, const char* szFunctionName, void* pHkFunction)
{
    this->sz_IAT_Module     = sz_IAT_Module;
    this->szModuleName      = szModuleName;
    this->szFunctionName    = szFunctionName;
    this->pHkFunction       = reinterpret_cast<DWORD>(pHkFunction);
    this->pOriginalFunction = 0;
    this->pHookLocation     = 0;
}

bool IATHook::ApplyHook()
{
    BYTE* hModule = reinterpret_cast<BYTE*>(GetModuleHandleA(this->sz_IAT_Module));
    if (!hModule)
        return false;
    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (!pDosHeader)
        return false;
    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(hModule + pDosHeader->e_lfanew);
    if (!pNtHeaders)
        return false;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeaders->OptionalHeader;
    if (!pOptHeader)
        return false;
    IMAGE_DATA_DIRECTORY dataDirectory = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
    PIMAGE_THUNK_DATA pThunkDataFirst;
    UINT_PTR* pThunkDataOriginal;
    PIMAGE_IMPORT_BY_NAME pImportByName;

    char* szModName, * szImportName;
 
    DWORD oldProtection;
    if (dataDirectory.Size > 0)
    {
        pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(hModule + dataDirectory.VirtualAddress);
        do
        {
            szModName = reinterpret_cast<char*>(hModule + pImportDescriptor->Name);
            if (!_stricmp(szModName, this->szModuleName))
            {
                pThunkDataFirst = reinterpret_cast<PIMAGE_THUNK_DATA>(hModule + pImportDescriptor->FirstThunk);
                pThunkDataOriginal = reinterpret_cast<UINT_PTR*>(hModule + pImportDescriptor->OriginalFirstThunk);
                do
                {
                    pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<BYTE*>(hModule) + *pThunkDataOriginal);
                    szImportName = reinterpret_cast<char*>(pImportByName->Name);
                    if (!_stricmp(szImportName, this->szFunctionName))
                    {
                        VirtualProtect(&pThunkDataFirst->u1.Function, sizeof(UINT_PTR), PAGE_EXECUTE_READWRITE, &oldProtection);
                        if(this->pOriginalFunction == 0)
                            this->pOriginalFunction = pThunkDataFirst->u1.Function;
                        pThunkDataFirst->u1.Function = this->pHkFunction;
                        if(this->pHookLocation == 0)
                            this->pHookLocation = reinterpret_cast<UINT_PTR*>(&pThunkDataFirst->u1.Function);
                        VirtualProtect(&pThunkDataFirst->u1.Function, sizeof(UINT_PTR), oldProtection, &oldProtection);
                        return true;
                    }
                    pThunkDataFirst++;
                    pThunkDataOriginal++;
                } while (*pThunkDataOriginal);
            }
            pImportDescriptor++;
        } while (pImportDescriptor->Name);
    }
    return false;
}

void IATHook::Unhook()
{
    DWORD oldProtection;
    VirtualProtect(this->pHookLocation, sizeof(UINT_PTR), PAGE_EXECUTE_READWRITE, &oldProtection);
    *this->pHookLocation = this->pOriginalFunction;
    VirtualProtect(this->pHookLocation, sizeof(UINT_PTR), oldProtection, &oldProtection);
}