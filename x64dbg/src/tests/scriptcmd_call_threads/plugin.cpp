#include <windows.h>
#include <array>
#include <atomic>
#include <charconv>
#include <cstring>
#include <string>
#include "_plugins.h"
#include "bridgemain.h"

namespace
{
    int gPluginHandle = 0;
    struct ThreadEvent
    {
        DWORD kind, pid, tid, code;
        duint start, teb;
    };
    struct ThreadContext
    {
        duint ip, ax, sp;
    };
    std::array<ThreadEvent, 32> gEvents{};
    std::atomic<unsigned> gEventCount{0};
    std::atomic<bool> gEventOverflow{false};
    std::atomic<DWORD> gExitCode{0};
    std::atomic<bool> gExitObserved{false};
    std::array<DWORD, 3> gIds{};
    std::array<unsigned long long, 3> gCreations{};
    std::array<ThreadContext, 3> gContexts{};
    DWORD gPid = 0;
    unsigned gMutation = 0, gStep = 0, gCountStep = 0, gPausedCountOffset = 0;
    duint gWorkerStart = 0;

    void cbThreadEvent(CBTYPE type, void* callbackInfo)
    {
        if(type == CB_INITDEBUG)
        {
            gEventCount = 0;
            gEventOverflow = false;
            gExitCode = 0;
            gExitObserved = false;
            gIds = {};
            gCreations = {};
            gContexts = {};
            gPid = 0;
            gMutation = 0;
            gStep = 0;
            gCountStep = 0;
            gPausedCountOffset = 0;
            gWorkerStart = 0;
        }
        else if(type == CB_DEBUGEVENT)
        {
            const auto info = static_cast<PLUG_CB_DEBUGEVENT*>(callbackInfo);
            if(!info || !info->DebugEvent)
                return;
            const auto& event = *info->DebugEvent;
            if(event.dwDebugEventCode != CREATE_THREAD_DEBUG_EVENT && event.dwDebugEventCode != EXIT_THREAD_DEBUG_EVENT)
                return;
            const auto count = gEventCount.load(std::memory_order_relaxed);
            if(count >= gEvents.size())
            {
                gEventOverflow.store(true, std::memory_order_release);
                return;
            }
            const bool created = event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT;
            gEvents[count] = {event.dwDebugEventCode, event.dwProcessId, event.dwThreadId, created ? 0 : event.u.ExitThread.dwExitCode,
                              created ? reinterpret_cast<duint>(event.u.CreateThread.lpStartAddress) : 0,
                              created ? reinterpret_cast<duint>(event.u.CreateThread.lpThreadLocalBase) : 0};
            gEventCount.store(count + 1, std::memory_order_release);
        }
        else if(type == CB_EXITPROCESS)
        {
            const auto info = static_cast<PLUG_CB_EXITPROCESS*>(callbackInfo);
            if(info && info->ExitProcess)
            {
                gExitCode.store(info->ExitProcess->dwExitCode, std::memory_order_relaxed);
                gExitObserved.store(true, std::memory_order_release);
            }
        }
    }
    template<typename Value> bool ReadTarget(const char* name, Value& value)
    {
        const auto expression = std::string("scriptcmd_call_threads:") + name;
        const auto address = DbgValFromString(expression.c_str());
        return _plugin_testassert(address != 0 && DbgMemRead(address, &value, sizeof(value)), "read thread reference field %s", name);
    }
    bool ParseIndex(int argc, char** argv, unsigned& value, unsigned maximum)
    {
        if(!_plugin_testassert(argc == 2, "thread command requires one literal index"))
            return false;
        const auto end = argv[1] + strlen(argv[1]);
        const auto parsed = std::from_chars(argv[1], end, value);
        return _plugin_testassert(parsed.ec == std::errc{} && parsed.ptr == end && value <= maximum, "thread command index is decimal and bounded");
    }
    class ThreadList
    {
    public:
        ThreadList() { DbgGetThreadList(&value); }
        ~ThreadList() { if(value.list) BridgeFree(value.list); }
        ThreadList(const ThreadList&) = delete;
        ThreadList& operator=(const ThreadList&) = delete;
        const THREADALLINFO* Find(DWORD id) const
        {
            if(value.count < 1 || value.count > 32 || !value.list)
                return nullptr;
            const THREADALLINFO* found = nullptr;
            for(int index = 0; index < value.count; ++index)
                if(value.list[index].BasicInfo.ThreadId == id)
                {
                    if(found)
                        return nullptr;
                    found = &value.list[index];
                }
            return found;
        }
        THREADLIST value{};
    };
    unsigned long long FileTimeValue(const FILETIME& value)
    {
        return (static_cast<unsigned long long>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
    }
    bool ReadContext(const ThreadList& threads, unsigned index, ThreadContext& result)
    {
        const auto thread = threads.Find(gIds[index]);
        FILETIME creation{}, exit{}, kernel{}, user{};
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if(!_plugin_testassert(thread && GetThreadId(thread->BasicInfo.Handle) == gIds[index] && GetProcessIdOfThread(thread->BasicInfo.Handle) == gPid
                              && GetThreadTimes(thread->BasicInfo.Handle, &creation, &exit, &kernel, &user) && FileTimeValue(creation) == gCreations[index]
                              && FileTimeValue(thread->CreationTime) == gCreations[index] && thread->BasicInfo.ThreadLocalBase != 0
                              && GetThreadContext(thread->BasicInfo.Handle, &context), "native thread list and OS context retain exact PID/TID/creation identity %u", index))
            return false;
#ifdef _WIN64
        result = {context.Rip, context.Rax, context.Rsp};
#else
        result = {context.Eip, context.Eax, context.Esp};
#endif
        return _plugin_testassert(result.ip != 0 && result.sp != 0 && thread->ThreadCip == result.ip, "native thread list instruction pointer matches the OS context %u", index);
    }
    bool CheckIdentity()
    {
        DWORD pid = 0, mainId = 0;
        std::array<DWORD, 2> ids{};
        std::array<unsigned long long, 2> creations{};
        unsigned long long mainCreation = 0;
        return ReadTarget("gThreadPid", pid) && ReadTarget("gThreadMainId", mainId) && ReadTarget("gThreadIds", ids)
               && ReadTarget("gThreadCreations", creations) && ReadTarget("gThreadMainCreation", mainCreation)
               && _plugin_testassert(pid == gPid && DbgGetProcessId() == pid && mainId == gIds[2] && mainCreation == gCreations[2]
                                     && ids[0] == gIds[0] && ids[1] == gIds[1] && creations[0] == gCreations[0] && creations[1] == gCreations[1], "target thread identities remain unchanged");
    }
    bool CheckSuspend(const ThreadList& threads, unsigned index, DWORD expected)
    {
        const auto thread = threads.Find(gIds[index]);
        if(!_plugin_testassert(thread != nullptr, "suspend reference requires its exact live worker"))
            return false;
        const auto previous = SuspendThread(thread->BasicInfo.Handle);
        if(!_plugin_testassert(previous != ~0UL, "bounded paused OS suspend query succeeds"))
            return false;
        const auto released = ResumeThread(thread->BasicInfo.Handle);
        return _plugin_testassert(released == previous + 1 && previous == expected && thread->SuspendCount == expected + gPausedCountOffset,
                                  "balanced paused OS query and native list preserve the known worker suspension count %u", index);
    }
    bool CheckEvents(unsigned index, bool exited)
    {
        const auto count = gEventCount.load(std::memory_order_acquire);
        unsigned creates = 0, exits = 0;
        if(!_plugin_testassert(!gEventOverflow.load(std::memory_order_acquire) && count <= gEvents.size(), "thread lifecycle observation is bounded without gaps"))
            return false;
        for(unsigned slot = 0; slot < count; ++slot)
        {
            const auto& event = gEvents[slot];
            if(event.tid != gIds[index])
                continue;
            if(!_plugin_testassert(event.pid == gPid, "worker lifecycle belongs to the actual target process"))
                return false;
            if(event.kind == CREATE_THREAD_DEBUG_EVENT)
            {
                ++creates;
                if(!_plugin_testassert(exits == 0 && event.start == gWorkerStart && event.teb != 0, "worker creation has its exact source entry and precedes exit"))
                    return false;
            }
            else
            {
                ++exits;
                if(!_plugin_testassert(creates == 1 && event.code == 81 + index, "actual worker exit callback carries its known return value"))
                    return false;
            }
        }
        return _plugin_testassert(creates == 1 && exits == (exited ? 1U : 0U), "worker lifecycle has exactly one creation and its expected exit state %u", index);
    }
    bool cbPrepare(int argc, char** argv)
    {
        unsigned mutation = 0, actualMutation = 0;
        LONG phase = 0;
        std::array<DWORD, 2> ids{};
        std::array<unsigned long long, 2> creations{};
        if(!ParseIndex(argc, argv, mutation, 1) || !ReadTarget("gThreadMutation", actualMutation) || !ReadTarget("gThreadPhase", phase)
                || !ReadTarget("gThreadPid", gPid) || !ReadTarget("gThreadMainId", gIds[2]) || !ReadTarget("gThreadMainCreation", gCreations[2])
                || !ReadTarget("gThreadIds", ids) || !ReadTarget("gThreadCreations", creations))
            return false;
        gIds[0] = ids[0]; gIds[1] = ids[1]; gCreations[0] = creations[0]; gCreations[1] = creations[1];
        if(!_plugin_testassert(gStep == 0 && phase == 1 && actualMutation == mutation && gPid != 0 && DbgGetProcessId() == gPid
                              && gIds[0] != 0 && gIds[1] != 0 && gIds[2] != 0 && gIds[0] != gIds[1] && gIds[0] != gIds[2] && gIds[1] != gIds[2]
                              && gCreations[0] != 0 && gCreations[1] != 0 && gCreations[2] != 0, "thread reference starts at its known barrier with three distinct live identities"))
            return false;
        gWorkerStart = DbgValFromString("scriptcmd_call_threads:ThreadReferenceWorker");
        gMutation = mutation;
        ThreadList threads;
        for(unsigned index = 0; index < 3; ++index)
            if(!ReadContext(threads, index, gContexts[index]))
                return false;
        const auto held = threads.Find(gIds[0]);
        const auto other = threads.Find(gIds[1]);
        if(!_plugin_testassert(held && other && held->SuspendCount >= 1 && held->SuspendCount <= 2 && other->SuspendCount == held->SuspendCount - 1,
                              "paused native counts retain a common observed stop offset and the fixture's extra count"))
            return false;
        gPausedCountOffset = held->SuspendCount - 1;
        if(!CheckSuspend(threads, 0, 1) || !CheckSuspend(threads, 1, 0))
            return false;
        if(!CheckEvents(0, false) || !CheckEvents(1, false))
            return false;
        gStep = 1;
        return true;
    }
    bool cbContext(int argc, char** argv)
    {
        unsigned index = 0;
        if(!ParseIndex(argc, argv, index, 2) || !CheckIdentity())
            return false;
        ThreadList threads;
        ThreadContext context{};
        REGDUMP dump{};
        if(!ReadContext(threads, index, context))
            return false;
        const auto& previous = gContexts[index];
        const duint expectedAx = gStep == 3 && index == 1 ? (gMutation ? 0x2468ACE0 : 0x50607080) : previous.ax;
        return _plugin_testassert(gStep >= 1 && gStep <= 3 && threads.value.CurrentThread >= 0
                                 && threads.value.CurrentThread < threads.value.count && threads.value.list[threads.value.CurrentThread].BasicInfo.ThreadId == gIds[index]
                                 && DbgGetRegDumpEx(reinterpret_cast<REGDUMP_AVX512*>(&dump), sizeof(dump))
                                 && dump.regcontext.cip == context.ip && dump.regcontext.cax == context.ax && dump.regcontext.csp == context.sp
                                 && context.ip == previous.ip && context.sp == previous.sp && context.ax == expectedAx,
                                 "selected debugger thread, native list and actual OS registers agree without changing another context %u", index);
    }
    bool cbCount(int argc, char** argv)
    {
        unsigned step = 0;
        LONG phase = 0;
        std::array<LONG, 2> entered{}, counters{};
        std::array<DWORD, 2> values{};
        if(!ParseIndex(argc, argv, step, 2) || !CheckIdentity() || !ReadTarget("gThreadPhase", phase) || !ReadTarget("gThreadEntered", entered)
                || !ReadTarget("gThreadCounters", counters) || !ReadTarget("gThreadValues", values))
            return false;
        ThreadList threads;
        const auto held = threads.Find(gIds[0]);
        const auto other = threads.Find(gIds[1]);
        if(!_plugin_testassert(gStep == 1 && step == gCountStep && phase == 1 && held && other
                              && entered == std::array<LONG, 2>{0, 0} && counters == std::array<LONG, 2>{0, 0}
                              && values == std::array<DWORD, 2>{0, 0}, "one native suspend/resume pair retains the fixture's earlier suspension and unchanged workers"))
            return false;
        if(!CheckSuspend(threads, 0, step == 1 ? 2 : 1) || !CheckSuspend(threads, 1, 0))
            return false;
        ++gCountStep;
        if(gCountStep == 3)
            gStep = 2;
        return true;
    }
    bool cbStop(int argc, char** argv)
    {
        unsigned index = 0;
        LONG phase = 0;
        std::array<LONG, 2> entered{}, counters{};
        std::array<DWORD, 2> values{};
        if(!ParseIndex(argc, argv, index, 1) || !CheckIdentity() || !ReadTarget("gThreadPhase", phase) || !ReadTarget("gThreadEntered", entered)
                || !ReadTarget("gThreadCounters", counters) || !ReadTarget("gThreadValues", values))
            return false;
        ThreadList threads;
        ThreadContext context{};
        if(!ReadContext(threads, index, context))
            return false;
        const auto stop = DbgValFromString(index == 0 ? "scriptcmd_call_threads:ThreadStop0" : "scriptcmd_call_threads:ThreadStop1");
        const auto held = threads.Find(gIds[0]);
        if(!_plugin_testassert(gStep == (index == 1 ? 2U : 4U) && phase == (index == 1 ? 2 : 3) && DbgGetThreadId() == gIds[index]
                              && context.ip == stop && context.ax == (index == 0 ? 0x10203040 : 0x50607080) && entered[index] == 1
                              && counters[index] == 0 && values[index] == 0 && held
                              && (index == 1 ? entered[0] == 0 && counters[0] == 0 && values[0] == 0
                                            : counters[1] == 22 && values[1] == (gMutation ? 0x2468ACE0 : 0x50607080) && !threads.Find(gIds[1])),
                              "actual worker reaches its distinct seeded instruction before its own counter/store while the other worker retains the required state"))
            return false;
        if(!CheckSuspend(threads, 0, index == 1 ? 1 : 0))
            return false;
        if(index == 1)
            for(unsigned slot = 0; slot < 3; ++slot)
                if(!ReadContext(threads, slot, gContexts[slot]))
                    return false;
        if(!CheckEvents(0, false) || !CheckEvents(1, index == 0))
            return false;
        gStep = index == 1 ? 3 : 5;
        return true;
    }
    bool cbHeld(int, char**)
    {
        LONG phase = 0;
        DWORD heldQuery = 0, queryRelease = 0, stillHeld = 0;
        std::array<LONG, 2> counters{}, entered{};
        std::array<DWORD, 2> values{}, exits{}, done{}, retired{};
        if(!CheckIdentity() || !ReadTarget("gThreadPhase", phase) || !ReadTarget("gThreadHeldQuery", heldQuery) || !ReadTarget("gThreadHeldQueryRelease", queryRelease)
                || !ReadTarget("gThreadStillHeld", stillHeld) || !ReadTarget("gThreadCounters", counters) || !ReadTarget("gThreadEntered", entered)
                || !ReadTarget("gThreadValues", values) || !ReadTarget("gThreadExitCodes", exits) || !ReadTarget("gThreadDone", done) || !ReadTarget("gThreadRetired", retired))
            return false;
        ThreadList threads;
        const auto held = threads.Find(gIds[0]);
        if(!_plugin_testassert(gStep == 3 && phase == 3 && DbgGetThreadId() == gIds[2] && held && !threads.Find(gIds[1])
                              && heldQuery == 1 && queryRelease == 2 && stillHeld == 1 && counters == std::array<LONG, 2>{0, 22} && entered == std::array<LONG, 2>{0, 1}
                              && values[0] == 0 && values[1] == (gMutation ? 0x2468ACE0 : 0x50607080) && exits[1] == 82 && done[1] == 1 && retired[1] == 1,
                              "the fixture's suspended worker remains held after the other worker executes its actual register store, counter and exit"))
            return false;
        if(!CheckSuspend(threads, 0, 1))
            return false;
        if(!CheckEvents(0, false) || !CheckEvents(1, true))
            return false;
        gStep = 4;
        return true;
    }
    bool cbResult(int, char**)
    {
        LONG phase = 0;
        unsigned mutation = 0;
        DWORD verified = 0, extra = 0, held = 0, queryRelease = 0, stillHeld = 0, finalRelease = 0, effect = 0;
        std::array<LONG, 2> counters{}, entered{};
        std::array<DWORD, 2> values{}, exits{}, done{}, retired{}, initial{};
        if(!CheckIdentity() || !ReadTarget("gThreadPhase", phase) || !ReadTarget("gThreadMutation", mutation) || !ReadTarget("gThreadVerified", verified)
                || !ReadTarget("gThreadExtraSuspend", extra) || !ReadTarget("gThreadHeldQuery", held) || !ReadTarget("gThreadHeldQueryRelease", queryRelease)
                || !ReadTarget("gThreadStillHeld", stillHeld) || !ReadTarget("gThreadFinalRelease", finalRelease) || !ReadTarget("gThreadReleaseEffect", effect)
                || !ReadTarget("gThreadCounters", counters) || !ReadTarget("gThreadEntered", entered) || !ReadTarget("gThreadValues", values)
                || !ReadTarget("gThreadExitCodes", exits) || !ReadTarget("gThreadDone", done) || !ReadTarget("gThreadRetired", retired) || !ReadTarget("gThreadInitialReleases", initial))
            return false;
        ThreadList threads;
        if(!_plugin_testassert(gStep == 5 && phase == 4 && DbgGetThreadId() == gIds[2] && !threads.Find(gIds[0]) && !threads.Find(gIds[1])
                              && mutation == gMutation && verified == 1 && extra == 0 && initial == std::array<DWORD, 2>{1, 1} && held == 1 && queryRelease == 2
                              && stillHeld == 1 && finalRelease == 1 && effect == 1 && counters == std::array<LONG, 2>{11, 22} && entered == std::array<LONG, 2>{1, 1}
                              && values[0] == 0x10203040 && values[1] == (gMutation ? 0x2468ACE0 : 0x50607080) && exits == std::array<DWORD, 2>{81, 82}
                              && done == std::array<DWORD, 2>{1, 1} && retired == std::array<DWORD, 2>{1, 1}, "both workers execute exactly once and retire only after each suspension owner releases its own count"))
            return false;
        if(!CheckEvents(0, true) || !CheckEvents(1, true))
            return false;
        _plugin_logprintf("THREAD_REFERENCE pid=%lu main=%lu/%llu worker0=%lu/%llu worker1=%lu/%llu mutation=%u stopCountOffset=%u values=%lx/%lx counters=%ld/%ld exits=%lu/%lu\n",
                          gPid, gIds[2], gCreations[2], gIds[0], gCreations[0], gIds[1], gCreations[1], gMutation, gPausedCountOffset, values[0], values[1], counters[0], counters[1], exits[0], exits[1]);
        gStep = 6;
        return true;
    }
    bool cbExit(int argc, char** argv)
    {
        unsigned code = 0;
        return ParseIndex(argc, argv, code, 88) && _plugin_testassert(gStep == 6 && code == (gMutation ? 88U : 87U)
               && gExitObserved.load(std::memory_order_acquire) && gExitCode.load(std::memory_order_acquire) == code && !DbgIsDebugging(), "actual target exit matches its completed thread and register effects");
    }
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* init)
{
    init->pluginVersion = 1;
    init->sdkVersion = PLUG_SDKVERSION;
    strcpy_s(init->pluginName, "thread-reference");
    gPluginHandle = init->pluginHandle;
    for(const auto type : {CB_INITDEBUG, CB_DEBUGEVENT, CB_EXITPROCESS})
        _plugin_registercallback(gPluginHandle, type, cbThreadEvent);
    return _plugin_registercommand(gPluginHandle, "threadprepare", cbPrepare, true)
           && _plugin_registercommand(gPluginHandle, "threadcontext", cbContext, true)
           && _plugin_registercommand(gPluginHandle, "threadcount", cbCount, true)
           && _plugin_registercommand(gPluginHandle, "threadstop", cbStop, true)
           && _plugin_registercommand(gPluginHandle, "threadheld", cbHeld, true)
           && _plugin_registercommand(gPluginHandle, "threadresult", cbResult, true)
           && _plugin_registercommand(gPluginHandle, "threadexit", cbExit, false);
}
extern "C" __declspec(dllexport) bool plugstop() { return true; }
