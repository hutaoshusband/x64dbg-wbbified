#include <Windows.h>

#include <array>
#include <atomic>
#include <charconv>
#include <cstring>

#include "_plugins.h"
#include "bridgemain.h"

namespace
{
    int gPluginHandle = 0;

    bool cbIssue3803Assert(int, char**)
    {
        if(!_plugin_testassert(!DbgCmdExecDirect("_K0=5"), "scalar expression assignment to _K0 should fail"))
            return false;
        if(!_plugin_testassert(!DbgCmdExecDirect("_ZMM0=5"), "scalar expression assignment to _ZMM0 should fail"))
            return false;
        if(!_plugin_testassert(!DbgCmdExecDirect("mov _K0, 5"), "mov _K0, 5 should fail"))
            return false;
        if(!_plugin_testassert(!DbgCmdExecDirect("mov _ZMM0, 5"), "mov _ZMM0, 5 should fail"))
            return false;
        if(!_plugin_testassert(!DbgValSetScalar("_K0", 5), "DbgValSetScalar should reject raw K registers"))
            return false;
        if(!_plugin_testassert(!DbgValSetScalar("_ZMM0", 5), "DbgValSetScalar should reject raw ZMM registers"))
            return false;

        ULONGLONG opmask = 0x0123456789ABCDEFULL;
        if(!_plugin_testassert(!DbgValSetBuffer("_K0", &opmask, sizeof(DWORD)), "DbgValSetBuffer should require the full K register size"))
            return false;
        if(!_plugin_testassert(DbgValSetBuffer("_K0", &opmask, sizeof(opmask)), "DbgValSetBuffer failed for _K0"))
            return false;

        std::array<unsigned char, sizeof(ZMMREGISTER)> zmm = {};
        for(size_t i = 0; i < zmm.size(); i++)
            zmm[i] = static_cast<unsigned char>(i ^ 0x5A);
        if(!_plugin_testassert(!DbgValSetBuffer("_ZMM0", zmm.data(), sizeof(XMMREGISTER)), "DbgValSetBuffer should require the full ZMM register size"))
            return false;
        if(!_plugin_testassert(DbgValSetBuffer("_ZMM0", zmm.data(), zmm.size()), "DbgValSetBuffer failed for _ZMM0"))
            return false;

        if(!_plugin_testassert(DbgCmdExecDirect("alloc 40"), "alloc 40 failed"))
            return false;
        const auto result = DbgValFromString("$result");
        if(!_plugin_testassert(result != 0, "alloc did not populate $result"))
            return false;
        if(!_plugin_testassert(DbgCmdExecDirect("vmovdqu [$result], zmm0"), "vmovdqu [$result], zmm0 failed"))
            return false;
        std::array<unsigned char, sizeof(ZMMREGISTER)> written = {};
        if(!_plugin_testassert(DbgMemRead(result, written.data(), written.size()), "DbgMemRead failed for ZMM spill buffer"))
            return false;
        if(!_plugin_testassert(memcmp(written.data(), zmm.data(), sizeof(XMMREGISTER)) == 0, "ZMM0 low lane mismatch"))
            return false;

        return true;
    }

    std::atomic<DWORD> gRegisterExitCode{0};
    std::atomic<bool> gRegisterExitObserved{false};

    void cbRegisterEvent(CBTYPE type, void* callbackInfo)
    {
        if(type == CB_INITDEBUG)
        {
            gRegisterExitCode = 0;
            gRegisterExitObserved = false;
        }
        else if(type == CB_EXITPROCESS)
        {
            const auto info = static_cast<PLUG_CB_EXITPROCESS*>(callbackInfo);
            gRegisterExitCode.store(info->ExitProcess->dwExitCode, std::memory_order_relaxed);
            gRegisterExitObserved.store(true, std::memory_order_release);
        }
    }

    template<typename Value>
    bool ReadRegisterTarget(const char* expression, Value& value)
    {
        const auto address = DbgValFromString(expression);
        return _plugin_testassert(address != 0 && DbgMemRead(address, &value, sizeof(value)), "read target register fixture field %s", expression);
    }

    bool CheckRegisterValues(bool mutated, bool stored)
    {
        constexpr size_t RegisterCount = sizeof(duint) == 8 ? 16 : 8;
        std::array<duint, RegisterCount> general{};
        std::array<std::array<unsigned char, 16>, RegisterCount> xmm{};
        std::array<std::array<unsigned char, 32>, RegisterCount> ymm{};
        unsigned available = 0;
        unsigned phase = 0;
        duint stack = 0;
        duint flags = 0;
        unsigned mxcsr = 0;
        if(!ReadRegisterTarget("issue3803:gRegisterAvxAvailable", available) || !ReadRegisterTarget("issue3803:gRegisterPhase", phase)
                || !ReadRegisterTarget("issue3803:gRegisterStack", stack))
            return false;
        if(!_plugin_testassert(available <= 1 && stack != 0 && (stack & 15) == 0, "valid target SIMD availability and aligned probe stack"))
            return false;
        if(!_plugin_testassert(phase == (stored ? 3u : 1u), "register fixture is at its expected executed phase"))
            return false;
        if(stored)
        {
            if(!ReadRegisterTarget("issue3803:gRegisterGeneral", general) || !ReadRegisterTarget("issue3803:gRegisterFlags", flags)
                    || !ReadRegisterTarget("issue3803:gRegisterMxCsr", mxcsr) || !ReadRegisterTarget("issue3803:gRegisterXmm", xmm)
                    || !ReadRegisterTarget("issue3803:gRegisterYmm", ymm))
                return false;
        }
        else
        {
            REGDUMP dump{};
            if(!_plugin_testassert(DbgGetRegDumpEx(reinterpret_cast<REGDUMP_AVX512*>(&dump), sizeof(dump)), "native register context was read"))
                return false;
            const auto& context = dump.regcontext;
            if(!_plugin_testassert(context.cip == DbgValFromString("issue3803:RegisterStop"), "native context is at the real register capture stop"))
                return false;
            general[0] = context.cax;
            general[1] = context.cbx;
            general[2] = context.ccx;
            general[3] = context.cdx;
            general[4] = context.csi;
            general[5] = context.cdi;
            general[6] = context.cbp;
            general[7] = context.csp;
#ifdef _WIN64
            general[8] = context.r8;
            general[9] = context.r9;
            general[10] = context.r10;
            general[11] = context.r11;
            general[12] = context.r12;
            general[13] = context.r13;
            general[14] = context.r14;
            general[15] = context.r15;
#endif
            flags = context.eflags;
            mxcsr = context.MxCsr;
            memcpy(xmm.data(), context.XmmRegisters, sizeof(xmm));
            memcpy(ymm.data(), context.YmmRegisters, sizeof(ymm));
        }
        const duint prefix = sizeof(duint) == 8 ? static_cast<duint>(0x1020304000000000ULL) : 0;
        for(size_t index = 0; index < general.size(); ++index)
        {
            const duint baseline = index == 7 ? stack : prefix + 0x11223300 + index;
            const duint expected = index == 0 && mutated ? 0xABCDEF01 : baseline;
            if(!_plugin_testassert(general[index] == expected, "general register %u matches its independent known value", static_cast<unsigned>(index)))
                return false;
        }
        if(!_plugin_testassert((flags & 0x8C5) == (mutated ? 0x880u : 0x45u), "arithmetic flags match the executed or selected values"))
            return false;
        if(!_plugin_testassert(mxcsr == (mutated ? 0x3F80u : 0x1F80u), "MXCSR matches the executed or selected value"))
            return false;
        for(size_t index = 0; index < xmm.size(); ++index)
        {
            std::array<unsigned char, 32> expected{};
            for(size_t lane = 0; lane < expected.size(); ++lane)
                expected[lane] = static_cast<unsigned char>((index == 0 && mutated ? lane ^ 0xA5 : (index * 32 + lane) ^ 0x5A));
            if(!_plugin_testassert(memcmp(xmm[index].data(), expected.data(), 16) == 0, "XMM register %u matches all 16 expected bytes", static_cast<unsigned>(index)))
                return false;
            if(available && !_plugin_testassert(ymm[index] == expected, "YMM register %u matches all 32 expected bytes", static_cast<unsigned>(index)))
                return false;
            if(stored && !available && !_plugin_testassert(ymm[index] == std::array<unsigned char, 32>{}, "unavailable YMM register %u was not captured", static_cast<unsigned>(index)))
                return false;
        }
        _plugin_logprintf("REGISTER_CONTEXT source=%s mutation=%u avxAvailable=%u phase=%u\n", stored ? "target" : "debugger", mutated ? 1u : 0u, available, phase);
        return true;
    }

    bool cbRegisterCheck(int argc, char** argv)
    {
        if(!_plugin_testassert(argc == 2, "registercheck requires one declared stage"))
            return false;
        const bool baseline = strcmp(argv[1], "baseline") == 0;
        const bool mutated = strcmp(argv[1], "mutated") == 0;
        const bool storedBaseline = strcmp(argv[1], "stored-baseline") == 0;
        const bool storedMutated = strcmp(argv[1], "stored-mutated") == 0;
        if(!_plugin_testassert(baseline || mutated || storedBaseline || storedMutated, "registercheck stage is recognized"))
            return false;
        return CheckRegisterValues(mutated || storedMutated, storedBaseline || storedMutated);
    }

    bool cbRegisterMutate(int argc, char**)
    {
        if(!_plugin_testassert(argc == 1, "registermutate has no arguments") || !CheckRegisterValues(false, false))
            return false;
        if(!_plugin_testassert(DbgValSetScalar("cax", 0xABCDEF01), "selected general register mutation succeeded")
                || !_plugin_testassert(DbgValSetScalar("_CF", 0) && DbgValSetScalar("_PF", 0) && DbgValSetScalar("_ZF", 0)
                                      && DbgValSetScalar("_SF", 1) && DbgValSetScalar("_OF", 1), "selected arithmetic flag mutations succeeded")
                || !_plugin_testassert(DbgValSetScalar("_MxCsr", 0x3F80), "selected MXCSR mutation succeeded"))
            return false;
        unsigned available = 0;
        if(!ReadRegisterTarget("issue3803:gRegisterAvxAvailable", available))
            return false;
        std::array<unsigned char, 32> mutation{};
        for(size_t lane = 0; lane < mutation.size(); ++lane)
            mutation[lane] = static_cast<unsigned char>(lane ^ 0xA5);
        if(!_plugin_testassert(DbgValSetBuffer(available ? "_YMM0" : "_XMM0", mutation.data(), available ? 32 : 16), "selected SIMD register mutation succeeded"))
            return false;
        return CheckRegisterValues(true, false);
    }

    bool cbRegisterExit(int argc, char** argv)
    {
        if(!_plugin_testassert(argc == 2, "registerexit requires one decimal exit code"))
            return false;
        DWORD expected = 0;
        const auto end = argv[1] + strlen(argv[1]);
        const auto parsed = std::from_chars(argv[1], end, expected);
        if(!_plugin_testassert(parsed.ec == std::errc{} && parsed.ptr == end, "registerexit requires a valid 32-bit decimal exit code"))
            return false;
        if(!_plugin_testassert(gRegisterExitObserved.load(std::memory_order_acquire), "the register target actually exited"))
            return false;
        return _plugin_testassert(gRegisterExitCode.load() == expected, "actual register target exit is %lu, expected %lu", gRegisterExitCode.load(), expected);
    }
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = 1;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, sizeof(initStruct->pluginName), X64DBG_TEST_NAME, _TRUNCATE);
    gPluginHandle = initStruct->pluginHandle;
    _plugin_registercommand(gPluginHandle, "issue3803assert", cbIssue3803Assert, false);
    _plugin_registercallback(gPluginHandle, CB_INITDEBUG, cbRegisterEvent);
    _plugin_registercallback(gPluginHandle, CB_EXITPROCESS, cbRegisterEvent);
    return _plugin_registercommand(gPluginHandle, "registercheck", cbRegisterCheck, true)
           && _plugin_registercommand(gPluginHandle, "registermutate", cbRegisterMutate, true)
           && _plugin_registercommand(gPluginHandle, "registerexit", cbRegisterExit, false);
}

extern "C" __declspec(dllexport) bool plugstop()
{
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT*)
{
}
