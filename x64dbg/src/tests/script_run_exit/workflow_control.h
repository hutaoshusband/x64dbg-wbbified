#pragma once
#include "gui_control.h"
#include "_dbgfunctions.h"
#include <array>
#include <vector>

namespace ScriptWorkflowControl
{
    std::unique_ptr<void, decltype(&CloseHandle)> gProcess(nullptr, CloseHandle);
    std::atomic<bool> gEnabled{ false };
    std::atomic<bool> gOverflow{ false };
    std::atomic<duint> gReady{ 0 }, gFinish{ 0 };
    std::atomic<unsigned> gHits{ 0 };
    std::atomic<bool> gExited{ false };
    std::atomic<DWORD> gExit{ 0 };
    std::array<unsigned, 3> gValues{};
    DWORD gWorker = 0;
    DWORD gOwner = 0;
    using SafeReadFunction = bool(*)(HANDLE, void*, void*, SIZE_T, SIZE_T*);
    SafeReadFunction gSafeRead = nullptr;
    HANDLE gBorrowedProcess = nullptr;
    DWORD gProcessId = 0;
    duint gReadAddress = 0;

    bool SafeRead(const char* phase, bool expected)
    {
        unsigned char code[6]{};
        SIZE_T copied = 0;
        SetLastError(ERROR_SUCCESS);
        const auto result = gSafeRead && gSafeRead(gBorrowedProcess, reinterpret_cast<void*>(gReadAddress), code, sizeof(code), &copied);
        const auto error = GetLastError();
        char output[512]{};
        sprintf_s(output, "WORKFLOW_SAFE_READ phase=%s pid=%lu handle=%llx address=%llx result=%u copied=%llu code=%02x%02x%02x%02x%02x%02x worker=%lu error=%lu\n",
                  phase, gProcessId, static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(gBorrowedProcess)), static_cast<unsigned long long>(gReadAddress), result ? 1 : 0,
                  static_cast<unsigned long long>(copied), code[0], code[1], code[2], code[3], code[4], code[5], GetCurrentThreadId(), error);
        GuiAddLogMessage(output);
        return result == expected && copied == (expected ? sizeof(code) : 0);
    }

    void Callback(CBTYPE type, void* value)
    {
        if(!gEnabled)
            return;
        if(type == CB_BREAKPOINT)
        {
            const auto breakpoint = static_cast<PLUG_CB_BREAKPOINT*>(value)->breakpoint;
            if(breakpoint && gReady && (breakpoint->addr == gReady || breakpoint->addr == gFinish))
            {
                auto count = gHits.load();
                while(count < 5 && !gHits.compare_exchange_weak(count, count + 1))
                {
                }
                if(count >= 4)
                    gOverflow = true;
            }
        }
        else if(type == CB_EXITPROCESS && gReady)
        {
            gExit = static_cast<PLUG_CB_EXITPROCESS*>(value)->ExitProcess->dwExitCode;
            gExited = true;
        }
    }

    unsigned Read(const char* name)
    {
        unsigned value = ~0u;
        SIZE_T copied = 0;
        const auto address = DbgValFromString((std::string("patch_canary:") + name).c_str());
        return ReadProcessMemory(gProcess.get(), reinterpret_cast<void*>(address), &value, sizeof(value), &copied) && copied == sizeof(value) ? value : ~0u;
    }

    bool Begin(int, char**)
    {
        if(gEnabled || !DbgIsDebugging())
            return false;
        HANDLE process = nullptr;
        if(!DuplicateHandle(GetCurrentProcess(), DbgGetProcessHandle(), GetCurrentProcess(), &process, 0, FALSE, DUPLICATE_SAME_ACCESS))
            return false;
        gProcess.reset(process);
        gHits = 0;
        gOverflow = false;
        gExited = false;
        gExit = 0;
        gValues = {};
        gReady = DbgValFromString("patch_canary:PatchReady");
        gFinish = DbgValFromString("patch_canary:PatchFinish");
        gWorker = GetCurrentThreadId();
        gBorrowedProcess = DbgGetProcessHandle();
        gProcessId = GetProcessId(gProcess.get());
        gReadAddress = DbgValFromString("patch_canary:PatchValue");
        gSafeRead = reinterpret_cast<SafeReadFunction>(GetProcAddress(GetModuleHandleW(L"TitanEngine.dll"), "MemoryReadSafe"));
        gEnabled = gReady && gFinish && gSafeRead;
        return gEnabled && SafeRead("before", true);
    }

    bool Observe(int argc, char** argv)
    {
        if(argc != 2 || !gProcess || !gEnabled)
            return false;
        const std::array<const char*, 6> phases{ "initial", "before", "patched", "executed", "restored", "complete" };
        bool known = false;
        for(const auto phase : phases)
            known = known || strcmp(argv[1], phase) == 0;
        if(!known)
            return false;
        const auto address = DbgValFromString("patch_canary:PatchValue");
        unsigned char code[6]{};
        SIZE_T copied = 0;
        if(!ReadProcessMemory(gProcess.get(), reinterpret_cast<void*>(address), code, sizeof(code), &copied) || copied != sizeof(code))
            return false;
        FILETIME creation{}, exited{}, kernel{}, user{};
        if(!GetProcessTimes(gProcess.get(), &creation, &exited, &kernel, &user))
            return false;
        const auto created = (static_cast<unsigned long long>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL;
        if(!GetThreadContext(DbgGetThreadHandle(), &context))
            return false;
#ifdef _WIN64
        const auto ip = context.Rip;
#else
        const auto ip = context.Eip;
#endif
        const auto values = DbgValFromString("patch_canary:gPatchValues");
        if(!ReadProcessMemory(gProcess.get(), reinterpret_cast<void*>(values), gValues.data(), sizeof(gValues), &copied) || copied != sizeof(gValues))
            return false;
        char output[1024]{};
        sprintf_s(output, "WORKFLOW_TARGET phase=%s pid=%lu creation=%llu owner=%lu worker=%lu thread=%lu ip=%llx osIp=%llx base=%llx address=%llx mode=%u mutation=%u targetPhase=%u completed=%u verified=%u hits=%u overflow=%u wait=%lu counter=%llu bytes=%02x%02x%02x%02x%02x%02x values=%u,%u,%u\n",
                  argv[1], GetProcessId(gProcess.get()), created, gOwner, GetCurrentThreadId(), GetThreadId(DbgGetThreadHandle()),
                  static_cast<unsigned long long>(DbgValFromString("cip")), static_cast<unsigned long long>(ip), static_cast<unsigned long long>(DbgValFromString("patch_canary")), static_cast<unsigned long long>(address),
                  Read("gPatchMode"), Read("gPatchMutation"), Read("gPatchPhase"), Read("gPatchCompleted"), Read("gPatchVerified"), gHits.load(), gOverflow ? 1 : 0, WaitForSingleObject(gProcess.get(), 0),
                  static_cast<unsigned long long>(DbgValFromString("$workflow_counter")), code[0], code[1], code[2], code[3], code[4], code[5], gValues[0], gValues[1], gValues[2]);
        GuiAddLogMessage(output);
        if(GetCurrentThreadId() != gWorker)
            return false;
        std::wstring variable = L"WI_WORKFLOW_GATE_";
        for(const char* character = argv[1]; *character; ++character)
            variable.push_back(wchar_t(*character));
        std::unique_ptr<void, decltype(&CloseHandle)> event(OpenEventW(SYNCHRONIZE, FALSE, ScriptGuiControl::Variable(variable.c_str()).c_str()), CloseHandle);
        return event && WaitForSingleObject(event.get(), 5000) == WAIT_OBJECT_0;
    }

    bool Patch(int, char**)
    {
        char error[MAX_ERROR_SIZE]{};
        return DbgFunctions()->AssembleAtEx(DbgValFromString("patch_canary:PatchValue"), "mov eax, 0x2A", error, false);
    }

    bool Restore(int, char**)
    {
        const auto address = DbgValFromString("patch_canary:PatchValue");
        DbgFunctions()->PatchRestoreRange(address, address + 5);
        return !DbgFunctions()->PatchInRange(address, address + 5);
    }

    bool Persist(int, char**)
    {
        size_t size = 0;
        if(!DbgFunctions()->PatchEnum(nullptr, &size) || !size || size % sizeof(DBGPATCHINFO) || size > 4096 * sizeof(DBGPATCHINFO))
            return false;
        std::vector<DBGPATCHINFO> patches(size / sizeof(DBGPATCHINFO));
        if(!DbgFunctions()->PatchEnum(patches.data(), &size) || size > patches.size() * sizeof(DBGPATCHINFO) || size % sizeof(DBGPATCHINFO))
            return false;
        const auto address = DbgValFromString("patch_canary:PatchValue");
        std::vector<DBGPATCHINFO> selected;
        for(const auto& patch : patches)
            if(patch.addr >= address && patch.addr < address + 6)
                selected.push_back(patch);
        if(selected.size() != 1 || selected[0].addr != address + 1 || selected[0].oldbyte != 7 || selected[0].newbyte != 42)
            return false;
        const auto destination = ScriptGuiControl::Utf8(ScriptGuiControl::Variable(L"WI_WORKFLOW_SAVE"));
        char error[MAX_ERROR_SIZE]{};
        const auto count = DbgFunctions()->PatchFile(selected.data(), int(selected.size()), destination.c_str(), error);
        char output[256]{};
        sprintf_s(output, "WORKFLOW_SAVED patches=%d selected=%u tracked=%u\n", count, unsigned(selected.size()), unsigned(size / sizeof(DBGPATCHINFO)));
        GuiAddLogMessage(output);
        return count == 1;
    }

    bool Finish(int, char**)
    {
        DWORD exit = 0;
        if(!gProcess || !GetExitCodeProcess(gProcess.get(), &exit))
            return false;
        const auto wait = WaitForSingleObject(gProcess.get(), 0);
        char output[256]{};
        sprintf_s(output, "WORKFLOW_EXIT actual=%lu callback=%lu observed=%u wait=%lu values=%u,%u,%u worker=%lu\n", exit, gExit.load(), gExited ? 1 : 0, wait, gValues[0], gValues[1], gValues[2], GetCurrentThreadId());
        GuiAddLogMessage(output);
        gEnabled = false;
        if(!SafeRead("after", false))
            return false;
        FILE* raw = nullptr;
        if(_wfopen_s(&raw, ScriptGuiControl::Variable(L"WI_WORKFLOW_REPORT").c_str(), L"wb") || !raw)
            return false;
        std::unique_ptr<FILE, decltype(&fclose)> file(raw, fclose);
        fprintf(file.get(), "original=%u\npatched=%u\nrestored=%u\nsum=%lu\n", gValues[0], gValues[1], gValues[2], exit);
        return wait == WAIT_OBJECT_0 && gExited && exit == 56 && gExit == exit;
    }

    bool Register(int plugin)
    {
        return _plugin_registercommand(plugin, "workflowbegin", Begin, false)
               && _plugin_registercommand(plugin, "workflowobserve", Observe, true)
               && _plugin_registercommand(plugin, "workflowpatch", Patch, true)
               && _plugin_registercommand(plugin, "workflowrestore", Restore, true)
               && _plugin_registercommand(plugin, "workflowpersist", Persist, true)
               && _plugin_registercommand(plugin, "workflowfinish", Finish, false);
    }
}
