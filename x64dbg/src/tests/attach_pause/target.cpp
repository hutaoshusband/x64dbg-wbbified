#include <windows.h>

#include <cstdio>
#include <cstring>
#include "../../dbg/handle.h"

static HANDLE gParkSignal;

static DWORD WINAPI ParkedThread(LPVOID)
{
    // Block forever on a private event.
    HANDLE hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    WaitForSingleObject(hEvent, INFINITE);
    return 0;
}

static volatile LONG gWakeCount = 0;

static DWORD WINAPI MarkedParkedThread(LPVOID)
{
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    FILETIME creation{}, exit{}, kernel{}, user{};
    if(!event || !GetThreadTimes(GetCurrentThread(), &creation, &exit, &kernel, &user))
        return 21;
    const auto time = (static_cast<unsigned long long>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
    std::printf("parked %lu %lu %llu %ld\n", GetCurrentProcessId(), GetCurrentThreadId(), time, InterlockedCompareExchange(&gWakeCount, 0, 0));
    std::fflush(stdout);
    const auto result = WaitForSingleObject(event, INFINITE);
    return result == WAIT_OBJECT_0 ? 0 : 22;
}

static DWORD WINAPI SignaledParkedThread(LPVOID)
{
    // After the driver signals (post-attach), produce a debug event so this
    // thread becomes the debugger's active thread, then block forever.
    WaitForSingleObject(gParkSignal, INFINITE);
    OutputDebugStringA("attach_pause: parking");
    return MarkedParkedThread(nullptr);
}

int main(int argc, char** argv)
{
    // In block mode every thread (including the main thread) blocks forever,
    // so a pause is only possible with a break-in thread.
    bool blockMode = argc > 1 && std::strcmp(argv[1], "block") == 0;

    // Create the message queue before signaling readiness.
    MSG msg;
    PeekMessageW(&msg, nullptr, 0, 0, PM_NOREMOVE);

    gParkSignal = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    CloseHandle(CreateThread(nullptr, 0, SignaledParkedThread, nullptr, 0, nullptr));
    for(int i = 0; i < 4; i++)
        CloseHandle(CreateThread(nullptr, 0, ParkedThread, nullptr, 0, nullptr));

    FILETIME mainCreation{}, mainExit{}, mainKernel{}, mainUser{};
    if(!GetThreadTimes(GetCurrentThread(), &mainCreation, &mainExit, &mainKernel, &mainUser))
        return 25;
    const auto mainTime = (static_cast<unsigned long long>(mainCreation.dwHighDateTime) << 32) | mainCreation.dwLowDateTime;
    std::printf("ready %lu %lu %llu\n", GetCurrentProcessId(), GetCurrentThreadId(), mainTime);
    std::fflush(stdout);

    if(blockMode)
        return (int)ParkedThread(nullptr); // the driver terminates the process

    // Pump messages like the main thread of a GUI application. The pause
    // command wakes this loop up with WM_NULL; the driver stops it with WM_QUIT
    // and triggers the signaled thread with WM_APP.
    while(GetMessageW(&msg, nullptr, 0, 0) > 0)
    {
        if(msg.message == WM_APP)
            SetEvent(gParkSignal);
        if(msg.message == WM_APP + 1)
        {
            Handle worker(CreateThread(nullptr, 0, MarkedParkedThread, nullptr, 0, nullptr));
            if(!worker)
                return 23;
        }
        if(msg.message == WM_NULL)
            InterlockedIncrement(&gWakeCount);
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    BOOL debugPort = TRUE;
    const auto queried = CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugPort);
    std::printf("completed %lu %ld %u %u\n", GetCurrentProcessId(), InterlockedCompareExchange(&gWakeCount, 0, 0), unsigned(queried), unsigned(debugPort));
    std::fflush(stdout);
    return queried && !debugPort && gWakeCount > 0 ? 0 : 24;
}
