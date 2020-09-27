#include <windows.h>
#include <stdio.h>
#include "IATHook.h"

FARPROC __stdcall hkGetProcAddress(HMODULE hModule, LPCSTR lpProcName);

void Example()
{
    IATHook test = IATHook(0, "KERNEL32.dll", "GetProcAddress", &hkGetProcAddress);
    if (!test.ApplyHook())
    {
        return;
    }
    while (!GetAsyncKeyState(VK_F7))
    {
        Sleep(500);
    }
    test.Unhook();
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(Example), 0, 0, 0);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

FARPROC __stdcall hkGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    printf("GetProcAddress called: %s\n", lpProcName);
    FARPROC original = GetProcAddress(hModule, lpProcName);
    return original;
}