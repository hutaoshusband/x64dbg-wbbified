#pragma once

#include "gui_control.h"

namespace ScriptYieldControl
{
    std::atomic<bool> gEnabled{ false };
    std::atomic<bool> gHit{ false };
    std::atomic<bool> gRelease{ false };
    std::atomic<bool> gLeft{ false };
    std::atomic<bool> gExpired{ false };
    std::atomic<bool> gPaused{ false };
    std::atomic<bool> gExit{ false };
    std::atomic<DWORD> gExitCode{ 0 };
    std::atomic<DWORD> gCallbackThread{ 0 };
    std::atomic<duint> gHitAddress{ 0 };

    struct ScopedProbe
    {
        ~ScopedProbe()
        {
            gRelease = true;
            gEnabled = false;
        }
    };

    void Callback(CBTYPE type, void* value)
    {
        if(!gEnabled)
            return;
        if(type == CB_PAUSEDEBUG && gHit && gLeft)
        {
            gPaused = true;
            return;
        }
        if(type == CB_EXITPROCESS)
        {
            gExitCode = static_cast<PLUG_CB_EXITPROCESS*>(value)->ExitProcess->dwExitCode;
            gExit = true;
            return;
        }
        if(type != CB_BREAKPOINT)
            return;
        const auto breakpoint = static_cast<PLUG_CB_BREAKPOINT*>(value)->breakpoint;
        const auto ready = DbgValFromString("patch_canary:PatchReady");
        if(!ready || !breakpoint || breakpoint->addr != ready)
            return;
        gCallbackThread = GetCurrentThreadId();
        gHitAddress = breakpoint->addr;
        gHit = true;
        const auto deadline = GetTickCount64() + 10000;
        while(!gRelease && GetTickCount64() < deadline)
            Sleep(1);
        gExpired = !gRelease.load();
        gLeft = true;
    }

    unsigned ReadUnsigned(HANDLE process, const char* name)
    {
        unsigned value = ~0u;
        SIZE_T copied = 0;
        if(!ReadProcessMemory(process, reinterpret_cast<void*>(DbgValFromString(name)), &value, sizeof(value), &copied) || copied != sizeof(value))
            return ~0u;
        return value;
    }

    bool Gate(const wchar_t* name)
    {
        std::unique_ptr<void, decltype(&CloseHandle)> event(OpenEventW(SYNCHRONIZE, FALSE, ScriptGuiControl::Variable(name).c_str()), CloseHandle);
        return event && WaitForSingleObject(event.get(), 5000) == WAIT_OBJECT_0;
    }

    void Target(const char* phase, HANDLE process)
    {
        FILE* raw = nullptr;
        if(_wfopen_s(&raw, ScriptGuiControl::Variable(L"WI_REENTRY_OUTPUT").c_str(), L"ab") || !raw)
            return;
        std::unique_ptr<FILE, decltype(&fclose)> file(raw, fclose);
        FILETIME creation{}, exited{}, kernel{}, user{};
        GetProcessTimes(process, &creation, &exited, &kernel, &user);
        const auto created = (static_cast<unsigned long long>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
        DWORD exit = 0;
        GetExitCodeProcess(process, &exit);
        unsigned char code[6]{};
        SIZE_T copied = 0;
        const auto address = DbgValFromString("patch_canary:PatchValue");
        const auto read = ReadProcessMemory(process, reinterpret_cast<void*>(address), code, sizeof(code), &copied);
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL;
        const auto captured = GetThreadContext(DbgGetThreadHandle(), &context);
#ifdef _WIN64
        const auto ip = context.Rip;
#else
        const auto ip = context.Eip;
#endif
        fprintf(file.get(), "YIELD_TARGET phase=%s guiPid=%lu owner=%lu worker=%lu callback=%lu pid=%lu creation=%llu targetThread=%lu alive=%lu exit=%lu debugging=%u sdkIp=%llx osIp=%llx context=%u ready=%llx base=%llx value=%llx copied=%llu bytes=%02x%02x%02x%02x%02x%02x mode=%u targetPhase=%u completed=%u scriptCounter=%llu startupStops=%llu line=%u hit=%u left=%u expired=%u\n",
                phase, GetCurrentProcessId(), GuiGetMainThreadId(), ScriptGuiControl::gWorker.load(), gCallbackThread.load(), GetProcessId(process), created, GetThreadId(DbgGetThreadHandle()),
                WaitForSingleObject(process, 0), exit, DbgIsDebugging() ? 1 : 0, static_cast<unsigned long long>(DbgValFromString("cip")), static_cast<unsigned long long>(ip), captured ? 1 : 0,
                static_cast<unsigned long long>(gHitAddress.load()), static_cast<unsigned long long>(DbgValFromString("patch_canary")), static_cast<unsigned long long>(address), static_cast<unsigned long long>(read ? copied : 0),
                code[0], code[1], code[2], code[3], code[4], code[5], ReadUnsigned(process, "patch_canary:gPatchMode"), ReadUnsigned(process, "patch_canary:gPatchPhase"), ReadUnsigned(process, "patch_canary:gPatchCompleted"),
                static_cast<unsigned long long>(DbgValFromString("$workflow_counter")), static_cast<unsigned long long>(DbgValFromString("$startup_stops")), unsigned(DbgScriptGetLineType(1)), gHit ? 1 : 0, gLeft ? 1 : 0, gExpired ? 1 : 0);
    }

    void Exit(HANDLE process, bool removed, bool resumed)
    {
        DWORD exit = 0;
        const auto actual = GetExitCodeProcess(process, &exit);
        FILE* raw = nullptr;
        if(_wfopen_s(&raw, ScriptGuiControl::Variable(L"WI_REENTRY_OUTPUT").c_str(), L"ab") || !raw)
            return;
        std::unique_ptr<FILE, decltype(&fclose)> file(raw, fclose);
        fprintf(file.get(), "YIELD_EXIT removed=%u resumed=%u wait=%lu actual=%u exit=%lu callbackExit=%lu observed=%u left=%u expired=%u debugging=%u counter=%llu\n", removed ? 1 : 0, resumed ? 1 : 0,
                WaitForSingleObject(process, 0), actual ? 1 : 0, exit, gExitCode.load(), gExit ? 1 : 0, gLeft ? 1 : 0, gExpired ? 1 : 0, DbgIsDebugging() ? 1 : 0, static_cast<unsigned long long>(DbgValFromString("$workflow_counter")));
    }

    void Probe(void*)
    {
        if(gEnabled.exchange(true))
            return;
        ScopedProbe activation;
        ScriptGuiControl::Observe("ready");
        if(!Gate(L"WI_REENTRY_EVENT"))
        {
            ScriptGuiControl::Observe("gate_failed");
            ScriptGuiControl::CloseOwnedWindow();
            return;
        }
        ScriptGuiControl::gRelease = true;
        const auto source = ScriptGuiControl::Utf8(ScriptGuiControl::Variable(L"WI_YIELD_SOURCE"));
        const auto finite = ScriptGuiControl::Utf8(ScriptGuiControl::Variable(L"WI_REENTRY_FINITE"));
        DbgScriptLoad(source.c_str());
        DbgScriptRun(0);
        const auto deadline = GetTickCount64() + 10000;
        while(!gHit && GetTickCount64() < deadline)
            Sleep(1);
        HANDLE raw = nullptr;
        if(!gHit || !DuplicateHandle(GetCurrentProcess(), DbgGetProcessHandle(), GetCurrentProcess(), &raw, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            ScriptGuiControl::Observe("target_failed");
            ScriptGuiControl::CloseOwnedWindow();
            return;
        }
        std::unique_ptr<void, decltype(&CloseHandle)> process(raw, CloseHandle);
        Target("yielded", process.get());
        if(!Gate(L"WI_YIELD_BEFORE"))
        {
            ScriptGuiControl::Observe("yield_gate_failed");
            ScriptGuiControl::CloseOwnedWindow();
            return;
        }
        DbgScriptUnload();
        Target("unloaded", process.get());
        if(!Gate(L"WI_YIELD_AFTER"))
        {
            ScriptGuiControl::Observe("unload_gate_failed");
            ScriptGuiControl::CloseOwnedWindow();
            return;
        }
        gRelease = true;
        const auto pauseDeadline = GetTickCount64() + 5000;
        while(!gPaused && GetTickCount64() < pauseDeadline)
        {
            GuiProcessEvents();
            Sleep(1);
        }
        ScriptGuiControl::Observe(gPaused ? "pause_observed" : "pause_missing");
        if(!gPaused)
        {
            ScriptGuiControl::CloseOwnedWindow();
            return;
        }
        ScriptGuiControl::Observe("delete_enter");
        const auto removed = DbgCmdExecDirect("bpd patch_canary:PatchReady");
        ScriptGuiControl::Observe("delete_leave");
        ScriptGuiControl::Observe("continue_enter");
        const auto resumed = DbgCmdExecDirect("run");
        ScriptGuiControl::Observe("continue_leave");
        const auto exitDeadline = GetTickCount64() + 5000;
        while((!gExit || DbgIsDebugging()) && GetTickCount64() < exitDeadline)
        {
            GuiProcessEvents();
            Sleep(1);
        }
        Exit(process.get(), removed, resumed);
        DbgScriptCmdExec("vardel $workflow_counter");
        DbgScriptLoad(finite.c_str());
        ScriptGuiControl::Observe("reloaded");
        const auto executed = DbgScriptCmdExec("scriptrun");
        ScriptGuiControl::Observe(executed ? "reused" : "reuse_failed");
        DbgScriptUnload();
        ScriptGuiControl::Observe("finished");
        ScriptGuiControl::CloseOwnedWindow();
    }

    bool Queue(int, char**)
    {
        GuiExecuteOnGuiThreadEx(Probe, nullptr);
        return true;
    }

    bool Register(int plugin)
    {
        _plugin_registercallback(plugin, CB_BREAKPOINT, Callback);
        _plugin_registercallback(plugin, CB_EXITPROCESS, Callback);
        _plugin_registercallback(plugin, CB_PAUSEDEBUG, Callback);
        return _plugin_registercommand(plugin, "scriptyieldunload", Queue, false);
    }
}
