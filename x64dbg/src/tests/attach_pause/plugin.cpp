#include <windows.h>
#include <cstring>
#include <cstdio>
#include "_plugins.h"
#include "bridgemain.h"
#include "handle.h"

static bool Observe(int argc, char* argv[])
{
    if(argc == 2 && strcmp(argv[1], "boundary") == 0)
    {
        if(!DbgIsDebugging() || DbgIsRunning())
            return false;
        GuiAddLogMessage("\nATTACH_STATE_PREFIX");
        GuiSetDebugState(paused);
        GuiAddLogMessage("ATTACH_BOUNDARY emitted=1\n");
        return true;
    }
    if(argc != 2 || (strcmp(argv[1], "before") != 0 && strcmp(argv[1], "paused") != 0))
        return false;
    const auto pid = DbgGetProcessId();
    const auto tid = DbgGetThreadId();
    const auto running = DbgIsRunning();
    Handle process(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
    Handle thread(OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, tid));
    FILETIME creation{}, exit{}, kernel{}, user{};
    if(!DbgIsDebugging() || !process || !thread || GetProcessIdOfThread(thread) != pid ||
            !GetThreadTimes(thread, &creation, &exit, &kernel, &user))
        return false;
    const auto threadCreation = (static_cast<unsigned long long>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
    REGDUMP_AVX512 registers{};
    CONTEXT native{};
    native.ContextFlags = CONTEXT_CONTROL;
    const bool sdkContext = !running && DbgGetRegDumpEx(&registers, sizeof(registers));
    const bool nativeContext = !running && GetThreadContext(thread, &native);
#ifdef _WIN64
    const auto nativeIp = native.Rip;
#else
    const auto nativeIp = native.Eip;
#endif
    char output[512]{};
    sprintf_s(output, "\nATTACH_OBSERVE label=%s pid=%lu tid=%lu creation=%llu running=%u sdk=%u native=%u ip=%llx nativeIp=%llx\n",
              argv[1], pid, tid, threadCreation, unsigned(running), unsigned(sdkContext), unsigned(nativeContext),
              static_cast<unsigned long long>(registers.regcontext.cip), static_cast<unsigned long long>(nativeIp));
    GuiAddLogMessage(output);
    return true;
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* init)
{
    if(!_plugin_registercommand(init->pluginHandle, "attachobserve", Observe, false))
        return false;
    init->pluginVersion = 1;
    init->sdkVersion = PLUG_SDKVERSION;
    strcpy_s(init->pluginName, "attach-pause-reference");
    return true;
}

extern "C" __declspec(dllexport) bool plugstop()
{
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT*)
{
}
