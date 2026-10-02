#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include "_plugins.h"
#include "bridgemain.h"

namespace
{
    int gLanguage = -1;
    bool Execute(const char* command)
    {
        bool result = true;
        if(strncmp(command, "load ", 5) == 0)
        {
            DbgScriptLoad(command + 5);
            result = DbgScriptGetLineType(1) == linecommand;
        }
        else if(strcmp(command, "runapi .3") == 0)
        {
            DbgScriptRun(3);
            result = DbgScriptCmdExec("nop");
        }
        else
            result = DbgScriptCmdExec(command);
        char output[512]{};
        sprintf_s(output, "SCRIPT_OBSERVE command=%s result=%u counter=%llu thread=%lu\n", command, result ? 1 : 0,
                  static_cast<unsigned long long>(DbgValFromString("$workflow_counter")), GetCurrentThreadId());
        GuiAddLogMessage(output);
        return true;
    }
}
extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* init)
{
    init->pluginVersion = 1;
    init->sdkVersion = PLUG_SDKVERSION;
    strcpy_s(init->pluginName, "script-control-reference");
    return true;
}
extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT*)
{
    SCRIPTTYPEINFO info{};
    strcpy_s(info.name, "Owned Script Control");
    info.execute = Execute;
    GuiRegisterScriptLanguage(&info);
    gLanguage = info.id;
    char output[128]{};
    sprintf_s(output, "SCRIPT_PROVIDER id=%d thread=%lu\n", gLanguage, GetCurrentThreadId());
    GuiAddLogMessage(output);
}
extern "C" __declspec(dllexport) bool plugstop()
{
    if(gLanguage >= 0) GuiUnregisterScriptLanguage(gLanguage);
    return true;
}
