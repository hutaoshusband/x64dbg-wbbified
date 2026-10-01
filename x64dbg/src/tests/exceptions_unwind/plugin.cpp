#include <windows.h>
#include <array>
#include <atomic>
#include <charconv>
#include <cstring>
#include <string>
#include <utility>
#include "_plugins.h"
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace
{
    int gPluginHandle = 0;
    struct ExceptionEvent
    {
        DWORD code, firstChance, flags, parameters, processId, threadId;
        duint address;
    };
    std::array<ExceptionEvent, 2> gExceptionEvents{};
    std::atomic<unsigned> gExceptionCount{0};
    std::atomic<unsigned> gExceptionBreakpointCount{0};
    std::atomic<bool> gExceptionOverflow{false};
    std::atomic<duint> gFaultAddress{0};
    std::atomic<DWORD> gExitCode{0};
    std::atomic<bool> gExitObserved{false};
    unsigned gExpectedMode = 0;

    void cbExceptionEvent(CBTYPE type, void* callbackInfo)
    {
        if(type == CB_INITDEBUG)
        {
            gExceptionCount = 0;
            gExceptionBreakpointCount = 0;
            gExceptionOverflow = false;
            gFaultAddress = 0;
            gExitCode = 0;
            gExitObserved = false;
            gExpectedMode = 0;
        }
        else if(type == CB_DEBUGEVENT)
        {
            const auto info = static_cast<PLUG_CB_DEBUGEVENT*>(callbackInfo);
            if(!info || !info->DebugEvent || info->DebugEvent->dwDebugEventCode != EXCEPTION_DEBUG_EVENT)
                return;
            const auto& event = *info->DebugEvent;
            const auto& exception = event.u.Exception;
            const auto address = reinterpret_cast<duint>(exception.ExceptionRecord.ExceptionAddress);
            if(exception.ExceptionRecord.ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION || address == 0 || address != gFaultAddress.load(std::memory_order_acquire))
                return;
            const auto count = gExceptionCount.load(std::memory_order_relaxed);
            if(count >= gExceptionEvents.size())
            {
                gExceptionOverflow.store(true, std::memory_order_release);
                return;
            }
            gExceptionEvents[count] = {exception.ExceptionRecord.ExceptionCode, exception.dwFirstChance, exception.ExceptionRecord.ExceptionFlags,
                                      exception.ExceptionRecord.NumberParameters, event.dwProcessId, event.dwThreadId, address};
            gExceptionCount.store(count + 1, std::memory_order_release);
        }
        else if(type == CB_BREAKPOINT)
        {
            const auto info = static_cast<PLUG_CB_BREAKPOINT*>(callbackInfo);
            if(info && info->breakpoint && info->breakpoint->type == bp_exception && info->breakpoint->addr == EXCEPTION_ILLEGAL_INSTRUCTION)
                gExceptionBreakpointCount.fetch_add(1, std::memory_order_release);
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
        const auto expression = std::string("exceptions_unwind:") + name;
        const auto address = DbgValFromString(expression.c_str());
        return _plugin_testassert(address != 0 && DbgMemRead(address, &value, sizeof(value)), "read exception fixture field %s", name);
    }
    bool ParseUnsigned(int argc, char** argv, unsigned& value)
    {
        if(!_plugin_testassert(argc == 2, "exception command requires one declared value"))
            return false;
        const auto end = argv[1] + strlen(argv[1]);
        const auto parsed = std::from_chars(argv[1], end, value);
        return _plugin_testassert(parsed.ec == std::errc{} && parsed.ptr == end, "exception command value is decimal and bounded");
    }
    bool cbPrepare(int argc, char** argv)
    {
        unsigned mode = 0, actualMode = 0, phase = 0;
        if(!ParseUnsigned(argc, argv, mode) || !ReadTarget("gExceptionMode", actualMode) || !ReadTarget("gExceptionPhase", phase))
            return false;
        const auto fault = DbgValFromString("exceptions_unwind:ExceptionFault");
        const auto after = DbgValFromString("exceptions_unwind:ExceptionAfterFault");
        std::array<unsigned char, 2> bytes{};
        if(!_plugin_testassert(mode >= 1 && mode <= 3 && actualMode == mode && phase == 1 && gExceptionCount.load(std::memory_order_acquire) == 0,
                              "exception reference is prepared before its fault"))
            return false;
        if(!_plugin_testassert(fault != 0 && after == fault + 2 && DbgMemRead(fault, bytes.data(), bytes.size()) && bytes == std::array<unsigned char, 2>{0x0F, 0x0B}, "fault stop has the exact UD2 bytes and following instruction address"))
            return false;
        gExpectedMode = mode;
        gFaultAddress.store(fault, std::memory_order_release);
        return true;
    }

    class CallStack
    {
    public:
        CallStack() { DbgFunctions()->GetCallStackEx(&value, false); }
        ~CallStack() { if(value.entries) BridgeFree(value.entries); }
        CallStack(const CallStack&) = delete;
        CallStack& operator=(const CallStack&) = delete;
        DBGCALLSTACK value{};
    };
    bool CheckFrames()
    {
        std::array<duint, 3> returns{};
        if(!ReadTarget("gExceptionProbeReturn", returns[0]) || !ReadTarget("gExceptionProtectedReturn", returns[1]) || !ReadTarget("gExceptionHandledReturn", returns[2]))
            return false;
        if(!_plugin_testassert(returns[0] != 0 && returns[1] != 0 && returns[2] == DbgValFromString("exceptions_unwind:ExceptionAfterHandled"), "target stores the actual nested return addresses"))
            return false;
        CallStack stack;
        if(!_plugin_testassert(stack.value.total >= 3 && stack.value.total <= 256 && stack.value.entries != nullptr, "native call stack has bounded real exception frames"))
            return false;
        unsigned next = 0;
        for(int index = 0; index < stack.value.total; ++index)
        {
            const auto& frame = stack.value.entries[index];
            _plugin_logprintf("EXCEPTION_FRAME index=%u address=%p from=%p to=%p\n", index, reinterpret_cast<void*>(frame.addr), reinterpret_cast<void*>(frame.from), reinterpret_cast<void*>(frame.to));
            if(next < returns.size() && frame.to == returns[next])
                ++next;
        }
        return _plugin_testassert(next == returns.size(), "native call stack contains the three target-observed nested callers in order");
    }
    bool CheckStop(bool second)
    {
        const unsigned expectedCount = second ? 2 : 1;
        const auto count = gExceptionCount.load(std::memory_order_acquire);
        if(!_plugin_testassert(gExpectedMode >= 1 && gExpectedMode <= 3 && (!second || gExpectedMode == 2) && !gExceptionOverflow.load(std::memory_order_acquire)
                              && count == expectedCount && gExceptionBreakpointCount.load(std::memory_order_acquire) == expectedCount,
                              "actual exception and breakpoint event counts match the requested chance"))
            return false;
        const auto& event = gExceptionEvents[count - 1];
        if(!_plugin_testassert(event.code == EXCEPTION_ILLEGAL_INSTRUCTION && event.firstChance == (second ? 0u : 1u) && event.flags == 0 && event.parameters == 0
                              && event.address == gFaultAddress.load(std::memory_order_acquire) && event.processId == DbgGetProcessId() && event.threadId == DbgGetThreadId(),
                              "raw Windows exception has the exact chance, code, source address, PID and active thread"))
            return false;
        REGDUMP dump{};
        duint stack = 0;
        unsigned phase = 0;
        if(!ReadTarget("gExceptionFaultStack", stack) || !ReadTarget("gExceptionPhase", phase))
            return false;
        if(!_plugin_testassert(DbgGetRegDumpEx(reinterpret_cast<REGDUMP_AVX512*>(&dump), sizeof(dump)) && dump.regcontext.cip == event.address
                              && dump.regcontext.csp == stack && stack != 0 && dump.regcontext.cax == 0x11223344 && phase == 2,
                              "actual fault context agrees with target stack, source instruction and known accumulator"))
            return false;
        std::array<unsigned char, 16> expected{};
        for(unsigned index = 0; index < expected.size(); ++index)
            expected[index] = static_cast<unsigned char>(index ^ 0x5A);
        if(!_plugin_testassert(memcmp(&dump.regcontext.XmmRegisters[6], expected.data(), expected.size()) == 0, "actual XMM6 fault context contains all known bytes"))
            return false;
#ifdef _WIN64
        if(!_plugin_testassert(dump.regcontext.cbx == 0x2233445566778899ULL && dump.regcontext.r12 == 0x9988776655443322ULL, "actual x64 fault context contains the changed nonvolatile registers"))
            return false;
#endif
        if(!CheckFrames())
            return false;
        unsigned filters = 0;
        if(!ReadTarget("gExceptionFilterCount", filters) || !_plugin_testassert(filters == (second ? 1u : 0u), "actual target filter runs between the first and second chance only"))
            return false;
        _plugin_logprintf("EXCEPTION_STOP chance=%u code=%08X address=%p stack=%p pid=%u thread=%u\n", second ? 2u : 1u, event.code,
                          reinterpret_cast<void*>(event.address), reinterpret_cast<void*>(stack), event.processId, event.threadId);
        return true;
    }
    bool CheckResult()
    {
        const bool continued = gExpectedMode == 3;
        if(!_plugin_testassert(gExpectedMode == 1 || continued, "completed exception path is handled or continued"))
            return false;
        const std::array<std::pair<const char*, unsigned>, 14> fields{{
            {"gExceptionPhase", 3}, {"gExceptionFilterCount", 1}, {"gExceptionHandledCount", continued ? 0u : 1u},
            {"gExceptionFinallyCount", 1}, {"gExceptionAbnormal", continued ? 0u : 1u}, {"gExceptionAfterProbe", continued ? 1u : 0u},
            {"gExceptionAfterProtected", continued ? 1u : 0u}, {"gExceptionHandlerMarker", continued ? 0u : 22u}, {"gExceptionWrapperCompleted", 1},
            {"gExceptionInstructionValue", continued ? 0x2468ACE0u : 0u}, {"gExceptionCode", EXCEPTION_ILLEGAL_INSTRUCTION}, {"gExceptionFlags", 0},
            {"gExceptionParameters", 0}, {"gExceptionMode", gExpectedMode}}};
        for(const auto& field : fields)
        {
            unsigned value = 0;
            if(!ReadTarget(field.first, value) || !_plugin_testassert(value == field.second, "executed exception result %s matches its known value", field.first))
                return false;
        }
        duint stack = 0, afterStack = 0, ip = 0, observedStack = 0, faultStack = 0, accumulator = 0;
        unsigned contextFlags = 0;
        std::array<duint, 2> after{};
        std::array<duint, 2> faultNonVolatile{};
        std::array<unsigned char, 16> faultXmm{}, afterXmm{};
        if(!ReadTarget("gExceptionWrapperStack", stack) || !ReadTarget("gExceptionAfterStack", afterStack) || !ReadTarget("gExceptionAfterGeneral", after)
                || !ReadTarget("gExceptionObservedIp", ip) || !ReadTarget("gExceptionObservedStack", observedStack) || !ReadTarget("gExceptionFaultStack", faultStack)
                || !ReadTarget("gExceptionObservedAccumulator", accumulator) || !ReadTarget("gExceptionObservedXmm", faultXmm) || !ReadTarget("gExceptionAfterXmm", afterXmm))
            return false;
        if(!ReadTarget("gExceptionContextFlags", contextFlags) || !ReadTarget("gExceptionObservedNonVolatile", faultNonVolatile))
            return false;
        const DWORD requiredContext = sizeof(duint) == 8 ? 0x100008 : 0x10020;
        if(!_plugin_testassert((contextFlags & requiredContext) == requiredContext
                              && faultNonVolatile[0] == (sizeof(duint) == 8 ? duint(0x2233445566778899ULL) : 0)
                              && faultNonVolatile[1] == (sizeof(duint) == 8 ? duint(0x9988776655443322ULL) : 0), "target exception record has valid architecture-specific SIMD and saved nonvolatile values"))
            return false;
        if(!_plugin_testassert(stack != 0 && afterStack == stack && ip == gFaultAddress.load(std::memory_order_acquire) && observedStack == faultStack
                              && accumulator == 0x11223344 && after[0] == (sizeof(duint) == 8 ? duint(0x1122334455667788ULL) : duint(0x55667788))
                              && after[1] == (sizeof(duint) == 8 ? duint(0x8877665544332211ULL) : duint(0x44332211)), "target instructions saved the restored caller context and original exception context"))
            return false;
        for(unsigned index = 0; index < 16; ++index)
            if(!_plugin_testassert(faultXmm[index] == static_cast<unsigned char>(index ^ 0x5A) && afterXmm[index] == (sizeof(duint) == 8 ? static_cast<unsigned char>(index ^ 0xA5) : 0), "target exception and valid restored SIMD byte %u match", index))
                return false;
        return _plugin_testassert(gExceptionCount.load(std::memory_order_acquire) == 1 && gExceptionBreakpointCount.load(std::memory_order_acquire) == 1, "handled or continued exception produces no second-chance event");
    }
    bool cbCheck(int argc, char** argv)
    {
        if(!_plugin_testassert(argc == 2, "exceptioncheck requires one declared stage"))
            return false;
        if(strcmp(argv[1], "first") == 0)
            return CheckStop(false);
        if(strcmp(argv[1], "second") == 0)
            return CheckStop(true);
        if(strcmp(argv[1], "result") == 0)
            return CheckResult();
        return _plugin_testassert(false, "exception stage is recognized");
    }
    bool cbExit(int argc, char** argv)
    {
        unsigned expected = 0;
        if(!ParseUnsigned(argc, argv, expected))
            return false;
        const auto count = gExceptionCount.load(std::memory_order_acquire);
        if(!_plugin_testassert(gExpectedMode != 0 && gExitObserved.load(std::memory_order_acquire) && !gExceptionOverflow.load(std::memory_order_acquire)
                              && gExitCode.load(std::memory_order_relaxed) == expected && count == (gExpectedMode == 2 ? 2u : 1u), "actual exception target exit and chance count match the known path"))
            return false;
        _plugin_logprintf("EXCEPTION_EXIT mode=%u actual=%u events=%u\n", gExpectedMode, gExitCode.load(std::memory_order_relaxed), count);
        return true;
    }
}
extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* init)
{
    init->pluginVersion = 1;
    init->sdkVersion = PLUG_SDKVERSION;
    strcpy_s(init->pluginName, "exception-reference");
    gPluginHandle = init->pluginHandle;
    for(const auto type : {CB_INITDEBUG, CB_DEBUGEVENT, CB_BREAKPOINT, CB_EXITPROCESS})
        _plugin_registercallback(gPluginHandle, type, cbExceptionEvent);
    _plugin_registercommand(gPluginHandle, "exceptionprepare", cbPrepare, true);
    _plugin_registercommand(gPluginHandle, "exceptioncheck", cbCheck, true);
    _plugin_registercommand(gPluginHandle, "exceptionexit", cbExit, false);
    return true;
}
extern "C" __declspec(dllexport) bool plugstop() { return true; }
extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT*) {}
