#pragma once
#include <windows.h>

class IATHook
{
    UINT_PTR    pOriginalFunction;
    UINT_PTR    pHkFunction;
    UINT_PTR    *pHookLocation;
    const char  *sz_IAT_Module;
    const char  *szModuleName;
    const char  *szFunctionName;
public:
    IATHook(const char* sz_IAT_Module, const char* szModuleName, const char* szFunctionName, void* pHkFunction);
    bool ApplyHook();
    void Unhook();
};