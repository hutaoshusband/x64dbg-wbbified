#include <windows.h>
#include <stdio.h>

typedef bool (*CBRET)();

unsigned int globalvar = 0;

extern "C"
{
    __declspec(dllexport) unsigned char* GuardedPage = nullptr;
    __declspec(dllexport) unsigned int GuardPageReady = 0;
    __declspec(dllexport) unsigned int GuardPageCompleted = 0;
    __declspec(dllexport) unsigned int ExecutedValue = 0;
}

unsigned int normalExceptionCount = 0;
DWORD normalExceptionCode = 0;
void* normalExceptionAddress = nullptr;

int ObserveNormalGuardException(EXCEPTION_POINTERS* exception)
{
    if(exception->ExceptionRecord->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    ++normalExceptionCount;
    normalExceptionCode = exception->ExceptionRecord->ExceptionCode;
    normalExceptionAddress = exception->ExceptionRecord->ExceptionAddress;
    return EXCEPTION_EXECUTE_HANDLER;
}

int main()
{
    wchar_t normalMode[2] = {};
    const bool normal = GetEnvironmentVariableW(L"WININSPECT_TEST_NORMAL", normalMode, 2) == 1 && normalMode[0] == L'1';
    unsigned int lol;
    unsigned char* page = (unsigned char*)VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(!page)
    {
        puts("error: VirtualAlloc");
        return 1;
    }
    page[0] = 0x6A;
    puts("write");
    page[1] = 0x01;
    puts("write");
    page[2] = 0x58;
    puts("write");
    page[3] = 0xC3;
    puts("write");
    DWORD oldProtect = 0;
    if(!VirtualProtect(page, 0x1000, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &oldProtect))
    {
        puts("error: VirtualProtect");
        VirtualFree(page, 0, MEM_RELEASE);
        return 2;
    }
    GuardedPage = page;
    GuardPageReady = 1;
    CBRET cb = (CBRET)page;
    if(normal)
    {
        __try
        {
            ExecutedValue = cb();
        }
        __except(ObserveNormalGuardException(GetExceptionInformation()))
        {
            ExecutedValue = cb();
        }
    }
    else
        ExecutedValue = cb();
    puts("exec");
    lol = globalvar;
    puts("read");
    lol = page[1];
    puts("read");
    lol = page[3];
    puts("read");
    lol = page[2];
    puts("read");
    GuardPageCompleted = 1;
    if(normal)
    {
        MEMORY_BASIC_INFORMATION region = {};
        if(VirtualQuery(page, &region, sizeof(region)) != sizeof(region))
        {
            VirtualFree(page, 0, MEM_RELEASE);
            return 3;
        }
        printf("ready=%u\ncompleted=%u\nvalue=%u\nexceptionCount=%u\nexceptionCode=%08lx\nexceptionAtPage=%u\nprotection=%08lx\npageBytes=%02x%02x%02x%02x\n",
               GuardPageReady, GuardPageCompleted, ExecutedValue, normalExceptionCount, normalExceptionCode,
               static_cast<unsigned int>(normalExceptionAddress == page), region.Protect,
               static_cast<unsigned int>(page[0]), static_cast<unsigned int>(page[1]),
               static_cast<unsigned int>(page[2]), static_cast<unsigned int>(page[3]));
    }
    else
        __debugbreak();
    if(!VirtualFree(page, 0, MEM_RELEASE))
        return 4;
    return 0;
}
