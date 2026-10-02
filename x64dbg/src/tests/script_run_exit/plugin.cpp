#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <atomic>
#include <thread>
#include "_plugins.h"
#include "bridgemain.h"
#include "gui_control.h"
#include "yield_control.h"
#include "workflow_control.h"

namespace
{
    void ScriptEvent(CBTYPE type, void* value)
    {
        ScriptYieldControl::Callback(type, value);
        ScriptWorkflowControl::Callback(type, value);
    }

    std::atomic<DWORD> gBlockedWorker{ 0 };
    std::atomic<bool> gReleaseWorker{ false };
    std::atomic<bool> gBlockCompleted{ false };

    bool BlockWorker(int, char**)
    {
        gBlockedWorker = GetCurrentThreadId();
        const auto deadline = GetTickCount64() + 5000;
        while(!gReleaseWorker && GetTickCount64() < deadline)
            Sleep(1);
        gBlockCompleted = gReleaseWorker.load();
        return gReleaseWorker;
    }

    bool UnloadWorker(int, char**)
    {
        const auto before = static_cast<unsigned long long>(DbgValFromString("$workflow_counter"));
        DbgScriptUnload();
        char output[256]{};
        sprintf_s(output, "SCRIPT_WORKER_UNLOAD before=%llu after=%llu line=%u thread=%lu\n", before,
                  static_cast<unsigned long long>(DbgValFromString("$workflow_counter")), unsigned(DbgScriptGetLineType(1)), GetCurrentThreadId());
        GuiAddLogMessage(output);
        return true;
    }

    int gLanguage = -1;
    unsigned long long gActiveCounter = 0;
    bool Execute(const char* command)
    {
        bool result = true;
        if(strncmp(command, "load ", 5) == 0)
        {
            DbgScriptLoad(command + 5);
            result = DbgScriptGetLineType(1) == linecommand;
        }
        else if(strcmp(command, "startloopapi") == 0)
        {
            DbgScriptRun(0);
            const auto deadline = GetTickCount64() + 5000;
            while(GetTickCount64() < deadline && DbgValFromString("$workflow_counter") < 16)
                Sleep(1);
            gActiveCounter = static_cast<unsigned long long>(DbgValFromString("$workflow_counter"));
            result = gActiveCounter >= 16;
            char active[128]{};
            sprintf_s(active, "SCRIPT_ACTIVE counter=%llu thread=%lu\n", gActiveCounter, GetCurrentThreadId());
            GuiAddLogMessage(active);
        }
        else if(strcmp(command, "queuedrununloadapi") == 0 || strcmp(command, "queuedstepunloadapi") == 0)
        {
            gBlockedWorker = 0;
            gReleaseWorker = false;
            gBlockCompleted = false;
            bool blockedResult = false;
            std::thread blocked([&]() { blockedResult = DbgScriptCmdExec("scriptqueueblock"); });
            const auto deadline = GetTickCount64() + 5000;
            while(!gBlockedWorker && GetTickCount64() < deadline)
                Sleep(1);
            const bool entered = gBlockedWorker != 0;
            if(strcmp(command, "queuedrununloadapi") == 0)
                DbgScriptRun(0);
            else
                DbgScriptStep();
            char queued[256]{};
            sprintf_s(queued, "SCRIPT_QUEUED worker=%lu owner=%lu counter=%llu released=%u\n", gBlockedWorker.load(), GetCurrentThreadId(),
                      static_cast<unsigned long long>(DbgValFromString("$workflow_counter")), gReleaseWorker ? 1 : 0);
            GuiAddLogMessage(queued);
            std::thread release([]() { Sleep(50); gReleaseWorker = true; });
            DbgScriptUnload();
            blocked.join();
            release.join();
            const auto line = DbgScriptGetLineType(1);
            char drained[256]{};
            sprintf_s(drained, "SCRIPT_QUEUE_DRAIN callback=%u wrapper=%u line=%u thread=%lu\n", gBlockCompleted ? 1 : 0,
                      blockedResult ? 1 : 0, unsigned(line), GetCurrentThreadId());
            GuiAddLogMessage(drained);
            result = entered && gBlockCompleted && !blockedResult && DbgScriptCmdExec("nop") && line == lineempty;
        }
        else if(strcmp(command, "workerunloadapi") == 0)
        {
            DbgScriptRun(0);
            result = DbgScriptCmdExec("nop") && DbgScriptCmdExec("nop") && DbgScriptGetLineType(1) == lineempty;
        }
        else if(strcmp(command, "activeunloadapi") == 0)
        {
            DbgScriptUnload();
            result = DbgScriptCmdExec("nop");
            const auto stopped = static_cast<unsigned long long>(DbgValFromString("$workflow_counter"));
            Sleep(50);
            const auto stable = static_cast<unsigned long long>(DbgValFromString("$workflow_counter"));
            char unloaded[256]{};
            sprintf_s(unloaded, "SCRIPT_UNLOAD active=%llu stopped=%llu stable=%llu line=%u debugging=%u thread=%lu\n",
                      gActiveCounter, stopped, stable, unsigned(DbgScriptGetLineType(1)), DbgIsDebugging() ? 1 : 0, GetCurrentThreadId());
            GuiAddLogMessage(unloaded);
        }
        else if(strcmp(command, "abortapi") == 0)
        {
            DbgScriptAbort();
            result = DbgScriptCmdExec("nop");
            const auto stopped = static_cast<unsigned long long>(DbgValFromString("$workflow_counter"));
            Sleep(50);
            const auto stable = static_cast<unsigned long long>(DbgValFromString("$workflow_counter"));
            char aborted[256]{};
            sprintf_s(aborted, "SCRIPT_ABORT active=%llu stopped=%llu stable=%llu line=%u debugging=%u thread=%lu\n",
                      gActiveCounter, stopped, stable, unsigned(DbgScriptGetLineType(1)), DbgIsDebugging() ? 1 : 0, GetCurrentThreadId());
            GuiAddLogMessage(aborted);
        }
        else if(strcmp(command, "runapi .3") == 0)
        {
            DbgScriptRun(3);
            result = DbgScriptCmdExec("nop");
        }
        else if(strcmp(command, "runapi 0") == 0)
        {
            DbgScriptRun(0);
            result = DbgScriptCmdExec("nop");
        }
        else if(strcmp(command, "stepapi") == 0)
        {
            DbgScriptStep();
            result = DbgScriptCmdExec("nop");
        }
        else if(strcmp(command, "setipapi .4") == 0)
        {
            DbgScriptSetIp(4);
            result = DbgScriptCmdExec("nop");
        }
        else if(strcmp(command, "bptoggleapi .3") == 0)
            result = DbgScriptBpToggle(3);
        else if(strcmp(command, "bpgetapi .3") == 0)
            result = DbgScriptBpGet(3);
        else if(strcmp(command, "branchapi .5") == 0)
        {
            SCRIPTBRANCH branch{};
            result = DbgScriptGetBranchInfo(5, &branch);
            char metadata[512]{};
            sprintf_s(metadata, "SCRIPT_BRANCH result=%u type=%u destination=%d label=%s\n", result ? 1 : 0, unsigned(branch.type), branch.dest, branch.branchlabel);
            GuiAddLogMessage(metadata);
        }
        else if(strcmp(command, "unloadapi") == 0)
        {
            DbgScriptUnload();
            result = DbgScriptGetLineType(1) == lineempty;
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
    if(!_plugin_registercommand(init->pluginHandle, "scriptqueueblock", BlockWorker, false)
            || !_plugin_registercommand(init->pluginHandle, "scriptunloadprobe", UnloadWorker, false)
            || !ScriptGuiControl::Register(init->pluginHandle)
            || !ScriptYieldControl::Register(init->pluginHandle)
            || !ScriptWorkflowControl::Register(init->pluginHandle))
        return false;
    _plugin_registercallback(init->pluginHandle, CB_BREAKPOINT, ScriptEvent);
    _plugin_registercallback(init->pluginHandle, CB_EXITPROCESS, ScriptEvent);
    _plugin_registercallback(init->pluginHandle, CB_PAUSEDEBUG, ScriptEvent);
    init->pluginVersion = 1;
    init->sdkVersion = PLUG_SDKVERSION;
    strcpy_s(init->pluginName, "script-control-reference");
    return true;
}
extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT*)
{
    ScriptWorkflowControl::gOwner = GetCurrentThreadId();
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
