#pragma once

#include <windows.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include "_plugins.h"
#include "bridgemain.h"

namespace ScriptGuiControl
{
    std::atomic<DWORD> gWorker{ 0 };
    std::atomic<bool> gRelease{ false };
    std::atomic<bool> gCompleted{ false };
    bool gOuterWaiting = false;
    DWORD gNestedThread = 0;
    unsigned gNestedCount = 0;

    std::wstring Variable(const wchar_t* name)
    {
        const auto count = GetEnvironmentVariableW(name, nullptr, 0);
        if(!count || count > 32768)
            return {};
        std::wstring value(count, L'\0');
        const auto copied = GetEnvironmentVariableW(name, value.data(), count);
        if(!copied || copied >= count)
            return {};
        value.resize(copied);
        return value;
    }

    std::string Utf8(const std::wstring& value)
    {
        const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), int(value.size()), nullptr, 0, nullptr, nullptr);
        std::string result(count, '\0');
        if(count)
            WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), int(value.size()), result.data(), count, nullptr, nullptr);
        return result;
    }

    void Observe(const char* phase)
    {
        FILE* raw = nullptr;
        if(_wfopen_s(&raw, Variable(L"WI_REENTRY_OUTPUT").c_str(), L"ab") || !raw)
            return;
        std::unique_ptr<FILE, decltype(&fclose)> file(raw, fclose);
        fprintf(file.get(), "GUI_REENTRY phase=%s pid=%lu thread=%lu owner=%lu worker=%lu nestedThread=%lu nestedCount=%u outer=%u counter=%llu line=%u completed=%u\n",
                phase, GetCurrentProcessId(), GetCurrentThreadId(), GuiGetMainThreadId(), gWorker.load(), gNestedThread, gNestedCount,
                gOuterWaiting ? 1 : 0, static_cast<unsigned long long>(DbgValFromString("$workflow_counter")), unsigned(DbgScriptGetLineType(1)), gCompleted ? 1 : 0);
    }

    bool BlockWorker(int, char**)
    {
        gWorker = GetCurrentThreadId();
        const auto deadline = GetTickCount64() + 5000;
        while(!gRelease && GetTickCount64() < deadline)
            Sleep(1);
        gCompleted = gRelease.load();
        return gCompleted;
    }

    void Reenter(void*)
    {
        gNestedThread = GetCurrentThreadId();
        ++gNestedCount;
        Observe("nested_enter");
        DbgScriptStep();
        DbgScriptUnload();
        Observe("nested_leave");
    }

    void CloseOwnedWindow()
    {
        const auto window = static_cast<HWND>(GuiGetWindowHandle());
        DWORD owner = 0;
        const auto thread = GetWindowThreadProcessId(window, &owner);
        if(owner == GetCurrentProcessId() && thread == GuiGetMainThreadId())
            PostMessageW(window, WM_CLOSE, 0, 0);
    }

    void Probe(void*)
    {
        std::unique_ptr<void, decltype(&CloseHandle)> event(OpenEventW(SYNCHRONIZE, FALSE, Variable(L"WI_REENTRY_EVENT").c_str()), CloseHandle);
        Observe("ready");
        const auto released = event && WaitForSingleObject(event.get(), 5000) == WAIT_OBJECT_0;
        if(!released)
        {
            Observe("gate_failed");
            CloseOwnedWindow();
            return;
        }
        const auto queued = Utf8(Variable(L"WI_REENTRY_QUEUED"));
        const auto finite = Utf8(Variable(L"WI_REENTRY_FINITE"));
        DbgScriptLoad(queued.c_str());
        gWorker = 0;
        gRelease = false;
        gCompleted = false;
        bool wrapper = false;
        std::thread blocked([&]() { wrapper = DbgScriptCmdExec("scriptguireentryblock"); });
        const auto deadline = GetTickCount64() + 5000;
        while(!gWorker && GetTickCount64() < deadline)
            Sleep(1);
        Observe("queued");
        DbgScriptRun(0);
        std::thread nested([]() { Sleep(50); GuiExecuteOnGuiThreadEx(Reenter, nullptr); });
        std::thread release([]() { Sleep(350); gRelease = true; });
        gOuterWaiting = true;
        Observe("outer_enter");
        DbgScriptUnload();
        Observe("outer_leave");
        gOuterWaiting = false;
        blocked.join();
        nested.join();
        release.join();
        Observe(wrapper ? "wrapper_success" : "wrapper_canceled");
        DbgScriptCmdExec("vardel $workflow_counter");
        Observe("reset");
        DbgScriptLoad(finite.c_str());
        Observe("reloaded");
        const auto executed = DbgScriptCmdExec("scriptrun");
        Observe(executed ? "reused" : "reuse_failed");
        DbgScriptUnload();
        Observe("finished");
        CloseOwnedWindow();
    }

    bool QueueProbe(int, char**)
    {
        GuiExecuteOnGuiThreadEx(Probe, nullptr);
        return true;
    }

    void ProbeReload(void*)
    {
        std::unique_ptr<void, decltype(&CloseHandle)> event(OpenEventW(SYNCHRONIZE, FALSE, Variable(L"WI_REENTRY_EVENT").c_str()), CloseHandle);
        Observe("ready");
        if(!event || WaitForSingleObject(event.get(), 5000) != WAIT_OBJECT_0)
        {
            Observe("gate_failed");
            CloseOwnedWindow();
            return;
        }
        gWorker = 0;
        gRelease = false;
        gCompleted = false;
        bool wrapper = false;
        std::thread blocked([&]() { wrapper = DbgScriptCmdExec("scriptguireentryblock"); });
        const auto deadline = GetTickCount64() + 5000;
        while(!gWorker && GetTickCount64() < deadline)
            Sleep(1);
        gRelease = true;
        blocked.join();
        Observe(wrapper ? "worker_completed" : "worker_failed");
        std::thread nested([]() { GuiExecuteOnGuiThreadEx(Reenter, nullptr); });
        nested.join();
        const auto finite = Utf8(Variable(L"WI_REENTRY_FINITE"));
        gOuterWaiting = true;
        Observe("reload_enter");
        DbgScriptLoad(finite.c_str());
        Observe("reload_canceled");
        gOuterWaiting = false;
        DbgScriptLoad(finite.c_str());
        Observe("reloaded");
        const auto executed = DbgScriptCmdExec("scriptrun");
        Observe(executed ? "reused" : "reuse_failed");
        DbgScriptUnload();
        Observe("finished");
        CloseOwnedWindow();
    }

    bool QueueProbeReload(int, char**)
    {
        GuiExecuteOnGuiThreadEx(ProbeReload, nullptr);
        return true;
    }

    void ProbeError(void*)
    {
        std::unique_ptr<void, decltype(&CloseHandle)> event(OpenEventW(SYNCHRONIZE, FALSE, Variable(L"WI_REENTRY_EVENT").c_str()), CloseHandle);
        Observe("ready");
        if(!event || WaitForSingleObject(event.get(), 5000) != WAIT_OBJECT_0)
        {
            Observe("gate_failed");
            CloseOwnedWindow();
            return;
        }
        gRelease = true;
        const auto source = Utf8(Variable(L"WI_REENTRY_QUEUED"));
        const auto finite = Utf8(Variable(L"WI_REENTRY_FINITE"));
        DbgScriptLoad(source.c_str());
        DbgScriptRun(0);
        const auto barrier = DbgScriptCmdExec("nop");
        Observe(barrier ? "error_returned" : "barrier_failed");
        DbgScriptCmdExec("vardel $workflow_counter");
        DbgScriptLoad(finite.c_str());
        Observe("reloaded");
        const auto executed = DbgScriptCmdExec("scriptrun");
        Observe(executed ? "reused" : "reuse_failed");
        DbgScriptUnload();
        Observe("finished");
        CloseOwnedWindow();
    }

    bool QueueError(int, char**)
    {
        GuiExecuteOnGuiThreadEx(ProbeError, nullptr);
        return true;
    }

    bool Register(int plugin)
    {
        return _plugin_registercommand(plugin, "scriptguireentryblock", BlockWorker, false)
               && _plugin_registercommand(plugin, "scriptguireentry", QueueProbe, false)
               && _plugin_registercommand(plugin, "scriptguireentryreload", QueueProbeReload, false)
               && _plugin_registercommand(plugin, "scriptguierror", QueueError, false);
    }
}
