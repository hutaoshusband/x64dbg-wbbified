#include <windows.h>
#include <cstdio>
#include <cstring>

extern "C"
{
    __declspec(dllexport) volatile unsigned gPatchMode = 0;
    __declspec(dllexport) volatile unsigned gPatchMutation = 0;
    __declspec(dllexport) volatile unsigned gPatchPhase = 0;
    __declspec(dllexport) DWORD gPatchPid = 0;
    __declspec(dllexport) DWORD gPatchThread = 0;
    __declspec(dllexport) uintptr_t gPatchImageBase = 0;
    __declspec(dllexport) DWORD gPatchValues[3]{};
    __declspec(dllexport) char gPatchMarkers[3][9]{};
    __declspec(dllexport) DWORD gPatchCompleted = 0;
    __declspec(dllexport) DWORD gPatchVerified = 0;
    DWORD PatchCall();
}
extern "C" __declspec(dllexport) __declspec(noinline) void PatchReady()
{
    InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&gPatchPhase), 1, 1);
}
extern "C" __declspec(dllexport) __declspec(noinline) void PatchFinish()
{
    InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&gPatchPhase), 4, 4);
}
int main()
{
    wchar_t selected[4]{};
    const bool normal = GetEnvironmentVariableW(L"WININSPECT_TEST_NORMAL", selected, 4) == 1 && selected[0] == L'1';
    if(normal)
    {
        if(GetEnvironmentVariableW(L"WININSPECT_TEST_PATCH_MODE", selected, 4) != 1 || (selected[0] != L'1' && selected[0] != L'2'))
            return 238;
        gPatchMode = selected[0] - L'0';
    }
    if((gPatchMode != 1 && gPatchMode != 2) || gPatchMutation > 1)
        return normal ? 238 : 239;
    gPatchPid = GetCurrentProcessId();
    gPatchThread = GetCurrentThreadId();
    gPatchImageBase = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const unsigned count = gPatchMode == 1 ? 3 : 1;
    DWORD sum = 0;
    for(unsigned index = 0; index < count; ++index)
    {
        gPatchPhase = index + 1;
        PatchReady();
        gPatchValues[index] = PatchCall();
        const char* marker = gPatchValues[index] == 7 ? "original" : gPatchValues[index] == 42 ? "patched" : "invalid";
        strcpy_s(gPatchMarkers[index], marker);
        sum += gPatchValues[index];
        ++gPatchCompleted;
    }
    gPatchPhase = 4;
    gPatchVerified = gPatchMode == 1 ? (gPatchValues[0] == 7 && gPatchValues[1] == (gPatchMutation ? 42u : 7u) && gPatchValues[2] == 7)
                     : (gPatchValues[0] == 7 || gPatchValues[0] == 42);
    if(normal)
    {
        printf("mode=%u\nmutation=%u\nphase=%u\npid=%lu\nthread=%lu\nimageBase=%llx\ncompleted=%lu\nverified=%lu\nsum=%lu\n",
               gPatchMode, gPatchMutation, gPatchPhase, gPatchPid, gPatchThread,
               static_cast<unsigned long long>(gPatchImageBase), gPatchCompleted, gPatchVerified, sum);
        for(unsigned index = 0; index < count; ++index)
            printf("value%u=%lu\nmarker%u=%s\n", index, gPatchValues[index], index, gPatchMarkers[index]);
        fflush(stdout);
    }
    PatchFinish();
    return gPatchVerified ? static_cast<int>(sum) : 108;
}
