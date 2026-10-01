#include <windows.h>
#include <cstdio>

static volatile int gValue = 0;
extern "C" __declspec(dllexport) volatile unsigned gExecutionMode = 0;
extern "C" __declspec(dllexport) volatile unsigned gExecutionPhase = 0;
extern "C" __declspec(dllexport) volatile unsigned gObservedBase = 0;
extern "C" __declspec(dllexport) volatile unsigned gLoopCount = 0;
extern "C" __declspec(dllexport) volatile unsigned gOuterCount = 0;
extern "C" __declspec(dllexport) volatile unsigned gInnerCount = 0;
extern "C" __declspec(dllexport) volatile unsigned gEvenCount = 0;
extern "C" __declspec(dllexport) volatile unsigned gOddCount = 0;
extern "C" __declspec(dllexport) volatile unsigned gExecutionResult = 0;

extern "C" __declspec(dllexport) __declspec(noinline) void OuterHit()
{
    gValue += 1;
}

extern "C" __declspec(dllexport) __declspec(noinline) void InnerHit()
{
    gValue += 2;
}

extern "C" __declspec(dllexport) __declspec(noinline) unsigned CanaryValue()
{
    return 7;
}

extern "C" __declspec(dllexport) __declspec(noinline) unsigned ExecutionEven(unsigned index)
{
    ++gEvenCount;
    return index + 1;
}

extern "C" __declspec(dllexport) __declspec(noinline) unsigned ExecutionOdd(unsigned index)
{
    ++gOddCount;
    return index + 3;
}

extern "C" __declspec(dllexport) __declspec(noinline) unsigned ExecutionInner(unsigned index)
{
    ++gInnerCount;
    return (index & 1) ? ExecutionOdd(index) : ExecutionEven(index);
}

extern "C" __declspec(dllexport) __declspec(noinline) unsigned ExecutionOuter(unsigned index)
{
    ++gOuterCount;
    return gObservedBase + ExecutionInner(index);
}

extern "C" __declspec(dllexport) __declspec(noinline) unsigned ExecutionCall(unsigned index)
{
    volatile unsigned result = ExecutionOuter(index);
    return result;
}

extern "C" __declspec(dllexport) __declspec(noinline) void ExecutionReady()
{
    gExecutionPhase = 1;
}

extern "C" __declspec(dllexport) __declspec(noinline) void ExecutionFinish()
{
    gExecutionPhase = 2;
}

int main()
{
    OuterHit();
    InnerHit();
    wchar_t normalMode[2] = {};
    const bool normal = GetEnvironmentVariableW(L"WININSPECT_TEST_NORMAL", normalMode, 2) == 1 && normalMode[0] == L'1';
    if(normal)
        gExecutionMode = 1;
    if(gExecutionMode == 0)
        return gValue == 3 ? 0 : 1;
    if(gExecutionMode != 1)
        return 104;
    ExecutionReady();
    gObservedBase = CanaryValue();
    for(unsigned index = 0; index < 4; ++index)
    {
        gExecutionResult += ExecutionCall(index);
        ++gLoopCount;
    }
    ExecutionFinish();
    if(normal)
        printf("phase=%u\noriginalValue=%d\nbase=%u\nloops=%u\nouterCalls=%u\ninnerCalls=%u\nevenBranches=%u\noddBranches=%u\nresult=%u\n",
               gExecutionPhase, gValue, gObservedBase, gLoopCount, gOuterCount, gInnerCount, gEvenCount, gOddCount, gExecutionResult);
    return static_cast<int>(gExecutionResult);
}
