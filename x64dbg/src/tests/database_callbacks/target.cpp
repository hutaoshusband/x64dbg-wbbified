#include <Windows.h>
#include <stdio.h>

#pragma section(".mbd3", read, write)

extern "C"
{
    __declspec(allocate(".mbd3")) __declspec(dllexport) volatile signed char VariableTarget = 1;
    __declspec(allocate(".mbd3")) __declspec(dllexport) volatile LONG FunctionCalls = 0;

#pragma code_seg(push, database_cb_code, ".mbc")
    __declspec(dllexport) __declspec(noinline) void FunctionTarget()
    {
        InterlockedIncrement(&FunctionCalls);
    }
}

int main()
{
    wchar_t selection[2] = {};
    if(GetEnvironmentVariableW(L"WININSPECT_TEST_NORMAL", selection, 2) == 1 && selection[0] == L'1')
    {
        FunctionTarget();
        printf("completed=1\nvalue=%d\nfunctionCalls=%ld\n", static_cast<int>(VariableTarget), FunctionCalls);
        return VariableTarget;
    }
    Sleep(1000);
};
#pragma code_seg(pop, membp_code)

