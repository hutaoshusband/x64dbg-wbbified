#include <windows.h>
#include <stdio.h>

extern "C" void __declspec(dllexport) TestFunction(const char* message)
{
    printf("TestFunction: %s\n", message);
}


extern "C" __declspec(dllexport) volatile unsigned gModuleAttachCount = 0;
extern "C" __declspec(dllexport) volatile unsigned gModuleCallCount = 0;
extern "C" __declspec(dllexport) volatile unsigned gModuleLastArgument = 0;
extern "C" __declspec(dllexport) volatile unsigned gModuleCallerProcessId = 0;
static volatile LONG* gModuleDetachObserver = nullptr;

extern "C" __declspec(dllexport) __declspec(noinline) unsigned ModuleValue(unsigned index)
{
    ++gModuleCallCount;
    gModuleLastArgument = index;
    gModuleCallerProcessId = GetCurrentProcessId();
    return 17 + index * 3;
}

extern "C" __declspec(dllexport) void ModuleObserveDetach(volatile LONG* observer)
{
    gModuleDetachObserver = observer;
}

extern "C" BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch(fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        ++gModuleAttachCount;
        printf("Random DLL loaded! Instance: 0x%p\n", hinstDLL);
        break;
    case DLL_PROCESS_DETACH:
        if(gModuleDetachObserver)
            InterlockedIncrement(gModuleDetachObserver);
        printf("Random DLL unloaded!\n");
        break;
    default:
        break;
    }

    return TRUE;
}
