#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <cstdint>

namespace NativeBreakIn
{
    struct Result
    {
        bool created = false;
        LONG status = 0;
        DWORD error = 0;
    };

    bool BeginTarget(HANDLE process);
    void EndTarget();
    Result Create(std::uintptr_t ntdllBase);
    void BindThread(DWORD processId, DWORD threadId, const CREATE_THREAD_DEBUG_INFO& information);
    bool Consume(DWORD processId, DWORD threadId, const EXCEPTION_DEBUG_INFO& information);
    void Shutdown();
}
