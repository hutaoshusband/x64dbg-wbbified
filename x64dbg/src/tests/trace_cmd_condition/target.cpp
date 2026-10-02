#include <windows.h>
#include <cstdio>

extern "C"
{
    __declspec(dllexport) volatile unsigned gTraceMode = 0;
    __declspec(dllexport) volatile unsigned gTracePhase = 0;
    __declspec(dllexport) DWORD gTracePid = 0;
    __declspec(dllexport) DWORD gTraceThread = 0;
    __declspec(dllexport) volatile DWORD gTraceSeed = 7;
    __declspec(dllexport) DWORD gTraceValues[4]{};
    __declspec(dllexport) DWORD gTraceSum = 0;
    __declspec(dllexport) DWORD gTraceCalls = 0;
    __declspec(dllexport) DWORD gTraceEven = 0;
    __declspec(dllexport) DWORD gTraceOdd = 0;
    __declspec(dllexport) DWORD gTraceCompleted = 0;
    __declspec(dllexport) DWORD gTraceReturned = 0;
    __declspec(dllexport) DWORD gTraceVerified = 0;
    __declspec(dllexport) uintptr_t gTraceImageBase = 0;
    DWORD TraceRun();
}
extern "C" __declspec(dllexport) __declspec(noinline) void TraceReady()
{
    InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&gTracePhase), 1, 1);
}
extern "C" __declspec(dllexport) __declspec(noinline) void TraceFinish()
{
    InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&gTracePhase), 3, 3);
}
static int RunTraceReference(bool normal)
{
    gTracePid = GetCurrentProcessId();
    gTraceThread = GetCurrentThreadId();
    gTraceImageBase = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    gTracePhase = 1;
    TraceReady();
    gTracePhase = 2;
    gTraceReturned = TraceRun();
    gTracePhase = 3;
    gTraceVerified = gTraceSeed == 7 && gTraceValues[0] == 9 && gTraceValues[1] == 12 && gTraceValues[2] == 14 && gTraceValues[3] == 17
                     && gTraceSum == 52 && gTraceReturned == 17 && gTraceCalls == 4 && gTraceEven == 2 && gTraceOdd == 2 && gTraceCompleted == 1;
    if(normal)
    {
        printf("mode=%u\nphase=%u\npid=%lu\nthread=%lu\nimageBase=%llx\nseed=%lu\ncalls=%lu\neven=%lu\nodd=%lu\ncompleted=%lu\nsum=%lu\nreturned=%lu\nverified=%lu\n",
               gTraceMode, gTracePhase, gTracePid, gTraceThread, static_cast<unsigned long long>(gTraceImageBase), gTraceSeed,
               gTraceCalls, gTraceEven, gTraceOdd, gTraceCompleted, gTraceSum, gTraceReturned, gTraceVerified);
        for(unsigned index = 0; index < 4; ++index)
            printf("value%u=%lu\n", index, gTraceValues[index]);
        fflush(stdout);
    }
    TraceFinish();
    return gTraceVerified ? 52 : 108;
}
static int RunOriginalTrace()
{
    Sleep(10);
    return 0;
}

int main()
{
    wchar_t selected[4]{};
    const bool normal = GetEnvironmentVariableW(L"WININSPECT_TEST_NORMAL", selected, 4) == 1 && selected[0] == L'1';
    if(normal)
    {
        if(GetEnvironmentVariableW(L"WININSPECT_TEST_TRACE_MODE", selected, 4) != 1 || selected[0] != L'1')
            return 238;
        gTraceMode = 1;
    }
    if(gTraceMode == 1)
        return RunTraceReference(normal);
    if(gTraceMode != 0)
        return 239;
    return RunOriginalTrace();
}
