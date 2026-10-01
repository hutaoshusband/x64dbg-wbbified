#include <windows.h>
#include <intrin.h>
#include <cstdio>

constexpr unsigned RegisterCount = sizeof(void*) == 8 ? 16 : 8;
constexpr unsigned GeneralCount = sizeof(void*) == 8 ? 16 : 8;
extern "C" __declspec(dllexport) volatile unsigned gRegisterMode = 0;
extern "C" __declspec(dllexport) volatile unsigned gRegisterPhase = 0;
extern "C" __declspec(dllexport) volatile unsigned gRegisterAvxAvailable = 0;
extern "C" __declspec(dllexport) volatile unsigned gRegisterForceSse = 0;
extern "C" __declspec(dllexport) ULONG_PTR gRegisterStack = 0;
extern "C" __declspec(dllexport) ULONG_PTR gRegisterGeneral[GeneralCount] = {};
extern "C" __declspec(dllexport) ULONG_PTR gRegisterFlags = 0;
extern "C" __declspec(dllexport) unsigned gRegisterMxCsr = 0;
extern "C" __declspec(dllexport) unsigned gRegisterMxCsrInput = 0x1F80;
extern "C" __declspec(dllexport) unsigned char gRegisterSeed[RegisterCount][32] = {};
extern "C" __declspec(dllexport) unsigned char gRegisterXmm[RegisterCount][16] = {};
extern "C" __declspec(dllexport) unsigned char gRegisterYmm[RegisterCount][32] = {};
extern "C" __declspec(dllexport) void RegisterProbe();
extern "C" __declspec(dllexport) void RegisterStop();

extern "C" __declspec(dllexport) __declspec(noinline) void RegisterFinish()
{
    gRegisterPhase = 3;
}

bool RegisterValuesMatch()
{
    const ULONG_PTR prefix = sizeof(void*) == 8 ? static_cast<ULONG_PTR>(0x1020304000000000ULL) : 0;
    for(unsigned index = 0; index < GeneralCount; ++index)
    {
        const ULONG_PTR expected = index == 7 ? gRegisterStack : prefix + 0x11223300 + index;
        const ULONG_PTR selected = index == 0 && gRegisterMode == 2 ? 0xABCDEF01 : expected;
        if(gRegisterGeneral[index] != selected)
            return false;
    }
    if((gRegisterFlags & 0x8C5) != (gRegisterMode == 2 ? 0x880 : 0x45))
        return false;
    if(gRegisterMxCsr != (gRegisterMode == 2 ? 0x3F80u : 0x1F80u))
        return false;
    for(unsigned index = 0; index < RegisterCount; ++index)
    {
        for(unsigned lane = 0; lane < 32; ++lane)
        {
            const unsigned char expected = index == 0 && gRegisterMode == 2 ? static_cast<unsigned char>(lane ^ 0xA5) : static_cast<unsigned char>((index * 32 + lane) ^ 0x5A);
            if(lane < 16 && gRegisterXmm[index][lane] != expected)
                return false;
            if(gRegisterAvxAvailable && gRegisterYmm[index][lane] != expected)
                return false;
            if(!gRegisterAvxAvailable && gRegisterYmm[index][lane] != 0)
                return false;
        }
    }
    return true;
}

int main()
{
    wchar_t normalMode[2] = {};
    const bool normal = GetEnvironmentVariableW(L"WININSPECT_TEST_NORMAL", normalMode, 2) == 1 && normalMode[0] == L'1';
    if(normal)
        gRegisterMode = 1;
    if(gRegisterMode == 0)
    {
        Sleep(10);
        return 0;
    }
    if(gRegisterMode != 1 && gRegisterMode != 2)
        return 104;
    int features[4] = {};
    __cpuid(features, 1);
    if(!(features[3] & (1 << 26)))
        return 105;
    if((features[2] & 0x1C000000) == 0x1C000000 && (_xgetbv(0) & 6) == 6)
        gRegisterAvxAvailable = 1;
    wchar_t forceSse[2] = {};
    if(gRegisterForceSse || (GetEnvironmentVariableW(L"WININSPECT_TEST_REGISTER_SSE", forceSse, 2) == 1 && forceSse[0] == L'1'))
        gRegisterAvxAvailable = 0;
    for(unsigned index = 0; index < RegisterCount; ++index)
        for(unsigned lane = 0; lane < 32; ++lane)
            gRegisterSeed[index][lane] = static_cast<unsigned char>((index * 32 + lane) ^ 0x5A);
    gRegisterPhase = 1;
    RegisterProbe();
    RegisterFinish();
    const bool verified = RegisterValuesMatch();
    if(normal)
    {
        printf("phase=%u\navxAvailable=%u\nflags=%llx\nmxcsr=%x\nstack=%llx\n", gRegisterPhase, gRegisterAvxAvailable,
               static_cast<unsigned long long>(gRegisterFlags & 0x8C5), gRegisterMxCsr, static_cast<unsigned long long>(gRegisterStack));
        for(unsigned index = 0; index < GeneralCount; ++index)
            printf("gpr%u=%llx\n", index, static_cast<unsigned long long>(gRegisterGeneral[index]));
        for(unsigned index = 0; index < RegisterCount; ++index)
        {
            printf("xmm%u=", index);
            for(unsigned lane = 0; lane < 16; ++lane)
                printf("%02x", gRegisterXmm[index][lane]);
            printf("\nymm%u=", index);
            for(unsigned lane = 0; lane < 32; ++lane)
                printf("%02x", gRegisterYmm[index][lane]);
            printf("\n");
        }
        printf("verified=%u\n", verified ? 1u : 0u);
    }
    return verified ? (gRegisterMode == 2 ? 70 : 69) : 106;
}
