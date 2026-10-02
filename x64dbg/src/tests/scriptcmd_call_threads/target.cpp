#include <windows.h>
#include <cstdio>
#include <cstdint>

static HANDLE gGoEvent = nullptr;
static volatile LONG gMainCounter = 0;
static volatile LONG gWorkerCounter = 0;

extern "C" __declspec(dllexport) __declspec(noinline) void MainThreadOuterHit()
{
    InterlockedIncrement(&gMainCounter);
}

extern "C" __declspec(dllexport) __declspec(noinline) void WorkerThreadInnerHit()
{
    InterlockedExchangeAdd(&gWorkerCounter, 2);
}

static DWORD WINAPI WorkerThreadProc(void*)
{
    WaitForSingleObject(gGoEvent, INFINITE);
    WorkerThreadInnerHit();
    return 0;
}

static int RunOriginalThreads()
{
    gGoEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if(gGoEvent == nullptr)
        return 1;

    auto thread = CreateThread(nullptr, 0, WorkerThreadProc, nullptr, 0, nullptr);
    if(thread == nullptr)
    {
        CloseHandle(gGoEvent);
        return 1;
    }

    MainThreadOuterHit();
    SetEvent(gGoEvent);

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    CloseHandle(gGoEvent);
    return 0;
}

extern "C"
{
    __declspec(dllexport) volatile unsigned gThreadMode = 0;
    __declspec(dllexport) volatile unsigned gThreadMutation = 0;
    __declspec(dllexport) volatile LONG gThreadPhase = 0;
    __declspec(dllexport) DWORD gThreadPid = 0;
    __declspec(dllexport) DWORD gThreadMainId = 0;
    __declspec(dllexport) unsigned long long gThreadMainCreation = 0;
    __declspec(dllexport) DWORD gThreadIds[2]{};
    __declspec(dllexport) unsigned long long gThreadCreations[2]{};
    __declspec(dllexport) volatile LONG gThreadEntered[2]{};
    __declspec(dllexport) volatile LONG gThreadCounters[2]{};
    __declspec(dllexport) DWORD gThreadValues[2]{};
    __declspec(dllexport) DWORD gThreadExitCodes[2]{};
    __declspec(dllexport) DWORD gThreadDone[2]{};
    __declspec(dllexport) DWORD gThreadRetired[2]{};
    __declspec(dllexport) DWORD gThreadExtraSuspend = ~0UL;
    __declspec(dllexport) DWORD gThreadInitialReleases[2]{~0UL, ~0UL};
    __declspec(dllexport) DWORD gThreadHeldQuery = ~0UL;
    __declspec(dllexport) DWORD gThreadHeldQueryRelease = ~0UL;
    __declspec(dllexport) DWORD gThreadStillHeld = 0;
    __declspec(dllexport) DWORD gThreadFinalRelease = ~0UL;
    __declspec(dllexport) DWORD gThreadReleaseEffect = 0;
    __declspec(dllexport) DWORD gThreadVerified = 0;
    void ThreadProbe0();
    void ThreadProbe1();
}

namespace
{
    class OwnedHandle
    {
    public:
        ~OwnedHandle() { if(value) CloseHandle(value); }
        OwnedHandle() = default;
        OwnedHandle(const OwnedHandle&) = delete;
        OwnedHandle& operator=(const OwnedHandle&) = delete;
        HANDLE value = nullptr;
    };
    HANDLE gThreadStart[2]{};
    HANDLE gThreadPrepared[2]{};
    HANDLE gThreadCompleted[2]{};

    bool ReadCreation(HANDLE thread, unsigned long long& creation)
    {
        FILETIME created{}, exited{}, kernel{}, user{};
        if(!GetThreadTimes(thread, &created, &exited, &kernel, &user))
            return false;
        creation = (static_cast<unsigned long long>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        return creation != 0;
    }
}

extern "C" __declspec(dllexport) __declspec(noinline) void ThreadReady()
{
    InterlockedCompareExchange(&gThreadPhase, 1, 1);
}
extern "C" __declspec(dllexport) __declspec(noinline) void ThreadHeld()
{
    InterlockedCompareExchange(&gThreadPhase, 3, 3);
}
extern "C" __declspec(dllexport) __declspec(noinline) void ThreadFinish()
{
    InterlockedCompareExchange(&gThreadPhase, 4, 4);
}
extern "C" __declspec(dllexport) DWORD WINAPI ThreadReferenceWorker(void* argument)
{
    const auto index = reinterpret_cast<uintptr_t>(argument);
    if(index > 1 || !SetEvent(gThreadPrepared[index]) || WaitForSingleObject(gThreadStart[index], 15000) != WAIT_OBJECT_0)
        return 110;
    InterlockedIncrement(&gThreadEntered[index]);
    if(index == 0)
        ThreadProbe0();
    else
        ThreadProbe1();
    InterlockedExchangeAdd(&gThreadCounters[index], index == 0 ? 11 : 22);
    if(!SetEvent(gThreadCompleted[index]))
        return 111;
    return 81 + static_cast<DWORD>(index);
}

bool ThreadValuesMatch()
{
    return gThreadPhase == 4 && gThreadMutation <= 1 && gThreadPid != 0 && gThreadMainId != 0 && gThreadMainCreation != 0
           && gThreadIds[0] != 0 && gThreadIds[1] != 0 && gThreadIds[0] != gThreadIds[1]
           && gThreadIds[0] != gThreadMainId && gThreadIds[1] != gThreadMainId && gThreadCreations[0] != 0 && gThreadCreations[1] != 0
           && gThreadExtraSuspend == 0 && gThreadInitialReleases[0] == 1 && gThreadInitialReleases[1] == 1
           && gThreadHeldQuery == 1 && gThreadHeldQueryRelease == 2 && gThreadStillHeld == 1 && gThreadFinalRelease == 1 && gThreadReleaseEffect == 1
           && gThreadEntered[0] == 1 && gThreadEntered[1] == 1 && gThreadCounters[0] == 11 && gThreadCounters[1] == 22
           && gThreadValues[0] == 0x10203040 && gThreadValues[1] == (gThreadMutation ? 0x2468ACE0 : 0x50607080)
           && gThreadExitCodes[0] == 81 && gThreadExitCodes[1] == 82 && gThreadDone[0] == 1 && gThreadDone[1] == 1
           && gThreadRetired[0] == 1 && gThreadRetired[1] == 1;
}

static int RunThreadReference(bool normal)
{
    OwnedHandle starts[2], prepared[2], completed[2], workers[2];
    gThreadPid = GetCurrentProcessId();
    gThreadMainId = GetCurrentThreadId();
    if(!ReadCreation(GetCurrentThread(), gThreadMainCreation))
        return 101;
    for(unsigned index = 0; index < 2; ++index)
    {
        starts[index].value = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        prepared[index].value = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        completed[index].value = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if(!starts[index].value || !prepared[index].value || !completed[index].value)
            return 102;
        gThreadStart[index] = starts[index].value;
        gThreadPrepared[index] = prepared[index].value;
        gThreadCompleted[index] = completed[index].value;
        workers[index].value = CreateThread(nullptr, 0, ThreadReferenceWorker, reinterpret_cast<void*>(static_cast<uintptr_t>(index)), CREATE_SUSPENDED, &gThreadIds[index]);
        if(!workers[index].value || !ReadCreation(workers[index].value, gThreadCreations[index]))
            return 103;
    }
    gThreadInitialReleases[0] = ResumeThread(workers[0].value);
    gThreadInitialReleases[1] = ResumeThread(workers[1].value);
    if(gThreadInitialReleases[0] != 1 || gThreadInitialReleases[1] != 1
            || WaitForSingleObject(prepared[0].value, 15000) != WAIT_OBJECT_0 || WaitForSingleObject(prepared[1].value, 15000) != WAIT_OBJECT_0)
        return 104;
    gThreadExtraSuspend = SuspendThread(workers[0].value);
    if(gThreadExtraSuspend != 0)
        return 104;
    gThreadPhase = 1;
    ThreadReady();
    gThreadPhase = 2;
    if(!SetEvent(starts[0].value) || !SetEvent(starts[1].value))
        return 105;
    gThreadDone[1] = WaitForSingleObject(completed[1].value, 15000) == WAIT_OBJECT_0;
    gThreadRetired[1] = WaitForSingleObject(workers[1].value, 15000) == WAIT_OBJECT_0;
    if(!gThreadDone[1] || !gThreadRetired[1] || !GetExitCodeThread(workers[1].value, &gThreadExitCodes[1]))
        return 106;
    gThreadHeldQuery = SuspendThread(workers[0].value);
    gThreadHeldQueryRelease = ResumeThread(workers[0].value);
    gThreadStillHeld = WaitForSingleObject(completed[0].value, 0) == WAIT_TIMEOUT && gThreadEntered[0] == 0 && gThreadCounters[0] == 0 && gThreadValues[0] == 0;
    gThreadPhase = 3;
    ThreadHeld();
    gThreadFinalRelease = ResumeThread(workers[0].value);
    gThreadDone[0] = WaitForSingleObject(completed[0].value, 15000) == WAIT_OBJECT_0;
    gThreadReleaseEffect = gThreadDone[0];
    gThreadRetired[0] = WaitForSingleObject(workers[0].value, 15000) == WAIT_OBJECT_0;
    if(!gThreadDone[0] || !gThreadRetired[0] || !GetExitCodeThread(workers[0].value, &gThreadExitCodes[0]))
        return 107;
    gThreadPhase = 4;
    gThreadVerified = ThreadValuesMatch();
    if(normal)
    {
        printf("mutation=%u\nphase=%ld\npid=%lu\nmainTid=%lu\nmainCreation=%llu\n", gThreadMutation, gThreadPhase, gThreadPid, gThreadMainId, gThreadMainCreation);
        for(unsigned index = 0; index < 2; ++index)
            printf("tid%u=%lu\ncreation%u=%llu\nentered%u=%ld\ncounter%u=%ld\nvalue%u=%lx\nexit%u=%lu\ndone%u=%lu\nretired%u=%lu\ninitialRelease%u=%lu\n",
                   index, gThreadIds[index], index, gThreadCreations[index], index, gThreadEntered[index], index, gThreadCounters[index], index, gThreadValues[index],
                   index, gThreadExitCodes[index], index, gThreadDone[index], index, gThreadRetired[index], index, gThreadInitialReleases[index]);
        printf("extraSuspend=%lu\nheldQuery=%lu\nheldQueryRelease=%lu\nstillHeld=%lu\nfinalRelease=%lu\nreleaseEffect=%lu\nverified=%lu\n",
               gThreadExtraSuspend, gThreadHeldQuery, gThreadHeldQueryRelease, gThreadStillHeld, gThreadFinalRelease, gThreadReleaseEffect, gThreadVerified);
        fflush(stdout);
    }
    ThreadFinish();
    return gThreadVerified ? (gThreadMutation ? 88 : 87) : 108;
}

int main()
{
    wchar_t selected[4]{};
    const bool normal = GetEnvironmentVariableW(L"WININSPECT_TEST_NORMAL", selected, 4) == 1 && selected[0] == L'1';
    if(normal)
    {
        if(GetEnvironmentVariableW(L"WININSPECT_TEST_THREAD_MODE", selected, 4) != 1 || selected[0] != L'1')
            return 238;
        gThreadMode = 1;
    }
    if(gThreadMode == 1)
        return RunThreadReference(normal);
    return gThreadMode == 0 ? RunOriginalThreads() : 239;
}
