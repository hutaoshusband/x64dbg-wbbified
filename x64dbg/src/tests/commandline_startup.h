#pragma once

#include <Windows.h>
#include <cstdio>

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

inline void WriteCommandLineWideValue(const char* key, const wchar_t* value)
{
    std::printf("%s=", key);
    for(size_t index = 0; value[index]; ++index)
    {
        const auto codeUnit = static_cast<unsigned int>(value[index]);
        std::printf("%02x%02x", codeUnit & 0xff, codeUnit >> 8);
    }
    std::putchar('\n');
}

inline bool WriteNormalCommandLineObservation(LONG ready, int crtArgc, int winArgc, const wchar_t* commandLine,
        const wchar_t* crtArgv1, const wchar_t* crtArgv2, const wchar_t* winArgv1, const wchar_t* winArgv2)
{
    wchar_t normalMode[2] = {};
    if(GetEnvironmentVariableW(L"WININSPECT_TEST_NORMAL", normalMode, 2) != 1 || normalMode[0] != L'1')
        return false;
    std::printf("ready=%ld\nstartupCallback=%ld\ncrtArgc=%d\nwinArgc=%d\n", ready, ObservedStartupCallback, crtArgc, winArgc);
    WriteCommandLineWideValue("commandLine", commandLine);
    WriteCommandLineWideValue("crtArgv1", crtArgv1);
    WriteCommandLineWideValue("crtArgv2", crtArgv2);
    WriteCommandLineWideValue("winArgv1", winArgv1);
    WriteCommandLineWideValue("winArgv2", winArgv2);
    return std::fflush(stdout) == 0;
}
