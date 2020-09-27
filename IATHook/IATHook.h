#pragma once
#include <windows.h>

class IATHook
{
    DWORD       pOriginalFunction;
    DWORD       pHkFunction;
    DWORD       *pHookLocation;
    const char  *sz_IAT_Module;
    const char  *szModuleName;
    const char  *szFunctionName;
public:
    IATHook(const char* sz_IAT_Module, const char* szModuleName, const char* szFunctionName, void* pHkFunction);
    bool ApplyHook();
    void Unhook();
};