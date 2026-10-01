#pragma once

#include <Windows.h>

extern "C"
{
    __declspec(dllexport) volatile LONG ObservedStartupCallback = 0;

    __declspec(dllexport) void NTAPI CommandLineStartup(PVOID, DWORD reason, PVOID)
    {
        if(reason == DLL_PROCESS_ATTACH)
            InterlockedExchange(&ObservedStartupCallback, 1);
    }

#pragma section(".CRT$XLB", long, read)
    __declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK CommandLineStartupCallback = CommandLineStartup;
}
