#include <windows.h>
#include <array>
#include <cstdio>
#include <cstring>
#include <intrin.h>
#include <utility>

extern "C"
{
    __declspec(dllexport) volatile unsigned gExceptionMode = 0;
    __declspec(dllexport) volatile unsigned gExceptionPhase = 0;
    __declspec(dllexport) volatile unsigned gExceptionFilterCount = 0;
    __declspec(dllexport) volatile unsigned gExceptionHandledCount = 0;
    __declspec(dllexport) volatile unsigned gExceptionFinallyCount = 0;
    __declspec(dllexport) volatile unsigned gExceptionAbnormal = 0;
    __declspec(dllexport) volatile unsigned gExceptionAfterProbe = 0;
    __declspec(dllexport) volatile unsigned gExceptionAfterProtected = 0;
    __declspec(dllexport) volatile unsigned gExceptionHandlerMarker = 0;
    __declspec(dllexport) volatile unsigned gExceptionWrapperCompleted = 0;
    __declspec(dllexport) volatile unsigned gExceptionInstructionValue = 0;
    __declspec(dllexport) volatile unsigned gExceptionCode = 0;
    __declspec(dllexport) volatile unsigned gExceptionFlags = 0;
    __declspec(dllexport) volatile unsigned gExceptionParameters = 0;
    __declspec(dllexport) volatile unsigned gExceptionContextFlags = 0;
    __declspec(dllexport) volatile ULONG_PTR gExceptionFaultStack = 0;
    __declspec(dllexport) volatile ULONG_PTR gExceptionObservedStack = 0;
    __declspec(dllexport) volatile ULONG_PTR gExceptionObservedIp = 0;
    __declspec(dllexport) volatile ULONG_PTR gExceptionObservedAccumulator = 0;
    __declspec(dllexport) volatile ULONG_PTR gExceptionObservedNonVolatile[2] = {};
    __declspec(dllexport) volatile ULONG_PTR gExceptionWrapperStack = 0;
    __declspec(dllexport) volatile ULONG_PTR gExceptionAfterStack = 0;
    __declspec(dllexport) volatile ULONG_PTR gExceptionAfterGeneral[2] = {};
    __declspec(dllexport) volatile ULONG_PTR gExceptionProbeReturn = 0;
    __declspec(dllexport) volatile ULONG_PTR gExceptionProtectedReturn = 0;
    __declspec(dllexport) volatile ULONG_PTR gExceptionHandledReturn = 0;
    __declspec(dllexport) unsigned char gExceptionObservedXmm[16] = {};
    __declspec(dllexport) unsigned char gExceptionAfterXmm[16] = {};
    __declspec(dllexport) unsigned char gExceptionCallerSeed[16] = {};
    __declspec(dllexport) unsigned char gExceptionFaultSeed[16] = {};
    void ExceptionRun();
    void ExceptionProbe();
    void ExceptionFault();
    void ExceptionAfterFault();
    void ExceptionAfterHandled();
}

int ObserveException(EXCEPTION_POINTERS* information)
{
    if(information->ExceptionRecord->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION || information->ExceptionRecord->ExceptionAddress != reinterpret_cast<void*>(ExceptionFault))
        return EXCEPTION_CONTINUE_SEARCH;
    ++gExceptionFilterCount;
    gExceptionCode = information->ExceptionRecord->ExceptionCode;
    gExceptionFlags = information->ExceptionRecord->ExceptionFlags;
    gExceptionParameters = information->ExceptionRecord->NumberParameters;
    gExceptionContextFlags = information->ContextRecord->ContextFlags;
#ifdef _WIN64
    gExceptionObservedIp = information->ContextRecord->Rip;
    gExceptionObservedStack = information->ContextRecord->Rsp;
    gExceptionObservedAccumulator = information->ContextRecord->Rax;
    gExceptionObservedNonVolatile[0] = information->ContextRecord->Rbx;
    gExceptionObservedNonVolatile[1] = information->ContextRecord->R12;
    memcpy(gExceptionObservedXmm, &information->ContextRecord->Xmm6, 16);
#else
    gExceptionObservedIp = information->ContextRecord->Eip;
    gExceptionObservedStack = information->ContextRecord->Esp;
    gExceptionObservedAccumulator = information->ContextRecord->Eax;
    memcpy(gExceptionObservedXmm, information->ContextRecord->ExtendedRegisters + 160 + 6 * 16, 16);
#endif
    if(gExceptionMode == 3)
    {
#ifdef _WIN64
        information->ContextRecord->Rip = reinterpret_cast<ULONG_PTR>(ExceptionAfterFault);
        information->ContextRecord->Rax = 0x2468ACE0;
#else
        information->ContextRecord->Eip = reinterpret_cast<ULONG_PTR>(ExceptionAfterFault);
        information->ContextRecord->Eax = 0x2468ACE0;
#endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if(gExceptionMode == 2)
    {
        printf("unhandledSearch=1\ncode=%08x\nsourceMatch=%u\nfilters=%u\n", gExceptionCode,
               gExceptionObservedIp == reinterpret_cast<ULONG_PTR>(ExceptionFault) ? 1u : 0u, gExceptionFilterCount);
        fflush(stdout);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

extern "C" __declspec(dllexport) __declspec(noinline) void ExceptionProtected()
{
    gExceptionProtectedReturn = reinterpret_cast<ULONG_PTR>(_ReturnAddress());
    __try
    {
        ExceptionProbe();
    }
    __finally
    {
        ++gExceptionFinallyCount;
        gExceptionAbnormal = AbnormalTermination() ? 1 : 0;
    }
}

extern "C" __declspec(dllexport) __declspec(noinline) void ExceptionHandled()
{
    gExceptionHandledReturn = reinterpret_cast<ULONG_PTR>(_ReturnAddress());
    __try
    {
        ExceptionProtected();
        ++gExceptionAfterProtected;
    }
    __except(ObserveException(GetExceptionInformation()))
    {
        ++gExceptionHandledCount;
        gExceptionHandlerMarker = 22;
    }
}

extern "C" __declspec(dllexport) __declspec(noinline) void ExceptionReady()
{
    gExceptionPhase = 1;
}

extern "C" __declspec(dllexport) __declspec(noinline) void ExceptionFinish()
{
    gExceptionPhase = 3;
}

bool ExceptionValuesMatch()
{
    const bool continued = gExceptionMode == 3;
    std::array<unsigned char, 16> caller{}, fault{};
    for(unsigned index = 0; index < 16; ++index)
    {
        caller[index] = static_cast<unsigned char>(index ^ 0xA5);
        fault[index] = static_cast<unsigned char>(index ^ 0x5A);
    }
    const bool common = gExceptionFilterCount == 1 && gExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION && gExceptionFlags == 0 && gExceptionParameters == 0
                        && gExceptionObservedIp == reinterpret_cast<ULONG_PTR>(ExceptionFault) && gExceptionObservedStack == gExceptionFaultStack
                        && gExceptionObservedAccumulator == 0x11223344 && memcmp(gExceptionObservedXmm, fault.data(), 16) == 0
                        && gExceptionFinallyCount == 1 && gExceptionAbnormal == (continued ? 0u : 1u) && gExceptionHandledCount == (continued ? 0u : 1u)
                        && gExceptionHandlerMarker == (continued ? 0u : 22u) && gExceptionAfterProbe == (continued ? 1u : 0u)
                        && gExceptionAfterProtected == (continued ? 1u : 0u) && gExceptionInstructionValue == (continued ? 0x2468ACE0u : 0u)
                        && gExceptionWrapperCompleted == 1 && gExceptionAfterStack == gExceptionWrapperStack
                        && gExceptionProbeReturn != 0 && gExceptionProtectedReturn != 0 && gExceptionHandledReturn == reinterpret_cast<ULONG_PTR>(ExceptionAfterHandled);
#ifdef _WIN64
    return common && (gExceptionContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT
           && gExceptionAfterGeneral[0] == 0x1122334455667788ULL && gExceptionAfterGeneral[1] == 0x8877665544332211ULL
           && gExceptionObservedNonVolatile[0] == 0x2233445566778899ULL && gExceptionObservedNonVolatile[1] == 0x9988776655443322ULL
           && memcmp(gExceptionAfterXmm, caller.data(), 16) == 0;
#else
    return common && (gExceptionContextFlags & CONTEXT_EXTENDED_REGISTERS) == CONTEXT_EXTENDED_REGISTERS
           && gExceptionAfterGeneral[0] == 0x55667788 && gExceptionAfterGeneral[1] == 0x44332211;
#endif
}

void PrintExceptionValues(bool verified)
{
    printf("mode=%u\nphase=%u\nfilters=%u\nhandled=%u\nfinally=%u\nabnormal=%u\nafterProbe=%u\nafterProtected=%u\nhandlerMarker=%u\nwrapperCompleted=%u\ninstructionValue=%x\ncode=%08x\nflags=%u\nparameters=%u\n",
           gExceptionMode, gExceptionPhase, gExceptionFilterCount, gExceptionHandledCount, gExceptionFinallyCount, gExceptionAbnormal, gExceptionAfterProbe,
           gExceptionAfterProtected, gExceptionHandlerMarker, gExceptionWrapperCompleted, gExceptionInstructionValue, gExceptionCode, gExceptionFlags, gExceptionParameters);
    printf("faultStack=%llx\nobservedStack=%llx\nobservedIp=%llx\nfault=%llx\naccumulator=%llx\nwrapperStack=%llx\nafterStack=%llx\nafterGeneral0=%llx\nafterGeneral1=%llx\nverified=%u\n",
           static_cast<unsigned long long>(gExceptionFaultStack), static_cast<unsigned long long>(gExceptionObservedStack), static_cast<unsigned long long>(gExceptionObservedIp),
           static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(ExceptionFault)), static_cast<unsigned long long>(gExceptionObservedAccumulator),
           static_cast<unsigned long long>(gExceptionWrapperStack), static_cast<unsigned long long>(gExceptionAfterStack), static_cast<unsigned long long>(gExceptionAfterGeneral[0]),
           static_cast<unsigned long long>(gExceptionAfterGeneral[1]), verified ? 1u : 0u);
    printf("contextFlags=%x\nobservedNonVol0=%llx\nobservedNonVol1=%llx\nprobeReturn=%llx\nprotectedReturn=%llx\nhandledReturn=%llx\nafterHandled=%llx\nimageBase=%llx\n",
           gExceptionContextFlags, static_cast<unsigned long long>(gExceptionObservedNonVolatile[0]), static_cast<unsigned long long>(gExceptionObservedNonVolatile[1]),
           static_cast<unsigned long long>(gExceptionProbeReturn), static_cast<unsigned long long>(gExceptionProtectedReturn), static_cast<unsigned long long>(gExceptionHandledReturn),
           static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(ExceptionAfterHandled)), static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(GetModuleHandleW(nullptr))));
    for(const auto& row : {std::pair<const char*, const unsigned char*>("faultXmm", gExceptionObservedXmm), {"afterXmm", gExceptionAfterXmm}})
    {
        printf("%s=", row.first);
        for(unsigned index = 0; index < 16; ++index)
            printf("%02x", row.second[index]);
        puts("");
    }
}

int main()
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    wchar_t normalValue[2] = {};
    const bool normal = GetEnvironmentVariableW(L"WININSPECT_TEST_NORMAL", normalValue, 2) == 1 && normalValue[0] == L'1';
    if(normal)
    {
        wchar_t mode[2] = {};
        if(GetEnvironmentVariableW(L"WININSPECT_TEST_EXCEPTION_MODE", mode, 2) != 1 || mode[0] < L'1' || mode[0] > L'3')
            return 238;
        gExceptionMode = mode[0] - L'0';
    }
    if(gExceptionMode == 0)
        return 0;
    if(gExceptionMode > 3)
        return 238;
    for(unsigned index = 0; index < 16; ++index)
    {
        gExceptionCallerSeed[index] = static_cast<unsigned char>(index ^ 0xA5);
        gExceptionFaultSeed[index] = static_cast<unsigned char>(index ^ 0x5A);
    }
    ExceptionReady();
    gExceptionPhase = 2;
    ExceptionRun();
    ExceptionFinish();
    const bool verified = ExceptionValuesMatch();
    if(normal)
        PrintExceptionValues(verified);
    if(!verified)
        return 106;
    return gExceptionMode == 1 ? 73 : 74;
}
