#include <Windows.h>
#include <atomic>
#include <charconv>
#include <cstring>
#include <initializer_list>
#include "_plugins.h"
#include "bridgemain.h"

namespace
{
    std::atomic<unsigned int> systemStops{0};
    std::atomic<unsigned int> escapedExceptions{0};
    std::atomic<DWORD> exitCode{0};
    std::atomic<bool> exitObserved{false};
    std::atomic<duint> breakpointAddress{0};
    std::atomic<unsigned int> dynamicEvents{0};

    void CaptureEvent(CBTYPE type, void* callback)
    {
        if(type == CB_INITDEBUG)
        {
            systemStops = 0;
            escapedExceptions = 0;
            exitCode = 0;
            exitObserved = false;
            breakpointAddress = 0;
            dynamicEvents = 0;
        }
        else if(type == CB_SYSTEMBREAKPOINT)
            systemStops.fetch_add(1);
        else if(type == CB_EXCEPTION)
        {
            const auto info = static_cast<PLUG_CB_EXCEPTION*>(callback);
            if(info->Exception->ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
                escapedExceptions.fetch_add(1);
        }
        else if(type == CB_EXITPROCESS)
        {
            const auto info = static_cast<PLUG_CB_EXITPROCESS*>(callback);
            exitCode.store(info->ExitProcess->dwExitCode, std::memory_order_relaxed);
            exitObserved.store(true, std::memory_order_release);
        }
        else if(type == CB_DEBUGEVENT)
        {
            const auto event = static_cast<PLUG_CB_DEBUGEVENT*>(callback)->DebugEvent;
            if(event->dwDebugEventCode == EXCEPTION_DEBUG_EVENT && event->u.Exception.dwFirstChance &&
                    event->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT &&
                    reinterpret_cast<duint>(event->u.Exception.ExceptionRecord.ExceptionAddress) == breakpointAddress.load())
                dynamicEvents.fetch_add(1);
        }
    }

    bool AssertSystemStop(int, char**)
    {
        if(!_plugin_testassert(systemStops.load() == 1, "exactly one actual initial system breakpoint was observed"))
            return false;
        return _plugin_testassert(escapedExceptions.load() == 0, "no managed breakpoint became a generic breakpoint exception");
    }

    bool AssertExit(int argc, char** argv)
    {
        if(!_plugin_testassert(argc == 2, "staleexit requires one decimal exit code"))
            return false;
        DWORD expected = 0;
        const auto end = argv[1] + strlen(argv[1]);
        const auto parsed = std::from_chars(argv[1], end, expected);
        if(!_plugin_testassert(parsed.ec == std::errc{} && parsed.ptr == end, "staleexit requires a valid 32-bit decimal exit code"))
            return false;
        if(!_plugin_testassert(exitObserved.load(std::memory_order_acquire), "the target actually exited"))
            return false;
        return _plugin_testassert(exitCode.load() == expected, "actual stale target exit code is %lu, expected %lu", exitCode.load(), expected);
    }

    bool CacheBreakpointAddress(int argc, char** argv)
    {
        if(!_plugin_testassert(argc == 2 && DbgIsValidExpression(argv[1]), "staleaddress requires one valid address expression"))
            return false;
        const auto address = DbgValFromString(argv[1]);
        if(!_plugin_testassert(address != 0, "the dynamic breakpoint address is nonzero"))
            return false;
        breakpointAddress.store(address);
        return true;
    }

    bool AssertStaleEvents(int, char**)
    {
        return _plugin_testassert(dynamicEvents.load() >= 2, "queued dynamic breakpoint events were actually processed, observed %u", dynamicEvents.load());
    }
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* info)
{
    info->pluginVersion = 1;
    info->sdkVersion = PLUG_SDKVERSION;
    strcpy_s(info->pluginName, "stale-breakpoint-reference");
    const auto handle = info->pluginHandle;
    for(const auto type : {CB_INITDEBUG, CB_SYSTEMBREAKPOINT, CB_EXCEPTION, CB_EXITPROCESS, CB_DEBUGEVENT})
        _plugin_registercallback(handle, type, CaptureEvent);
    return _plugin_registercommand(handle, "stalesystem", AssertSystemStop, true) &&
           _plugin_registercommand(handle, "staleexit", AssertExit, false) &&
           _plugin_registercommand(handle, "staleaddress", CacheBreakpointAddress, true) &&
           _plugin_registercommand(handle, "staleevents", AssertStaleEvents, true);
}

extern "C" __declspec(dllexport) bool plugstop()
{
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT*)
{
}
