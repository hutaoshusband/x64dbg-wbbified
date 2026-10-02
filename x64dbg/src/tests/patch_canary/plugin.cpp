#include <windows.h>
#include <array>
#include <atomic>
#include <string>
#include <vector>
#include "_plugins.h"
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace
{
    int gPluginHandle = 0;
    std::atomic<duint> gAddress{0};
    std::atomic<DWORD> gPid{0}, gThread{0}, gExit{0};
    std::atomic<unsigned> gHitCount{0};
    std::atomic<bool> gOverflow{false}, gExited{false};
    struct Hit { duint address; DWORD pid, thread; BPXTYPE type; bool enabled; };
    std::array<Hit, 8> gHits{};
    const std::array<unsigned char, 6> Original{0xb8, 7, 0, 0, 0, 0xc3};
    const std::array<unsigned char, 6> Patched{0x66, 0xb8, 0x2a, 0, 0x90, 0xc3};
    struct ScopedProcess
    {
        HANDLE value;
        explicit ScopedProcess(DWORD pid) : value(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid)) {}
        ScopedProcess(const ScopedProcess&) = delete;
        ScopedProcess& operator=(const ScopedProcess&) = delete;
        ~ScopedProcess() { if(value) CloseHandle(value); }
    };
    duint FieldAddress(const char* name)
    {
        return DbgValFromString((std::string("patch_canary:") + name).c_str());
    }
    template<typename Value> bool ReadTarget(const char* name, Value& value)
    {
        const auto address = FieldAddress(name);
        return _plugin_testassert(address && DbgMemRead(address, &value, sizeof(value)), "read patch fixture field %s", name);
    }
    void cbPatchEvent(CBTYPE type, void* callbackInfo)
    {
        if(type == CB_INITDEBUG)
        {
            gAddress = 0; gPid = 0; gThread = 0; gExit = 0; gHitCount = 0; gOverflow = false; gExited = false;
        }
        else if(type == CB_DEBUGEVENT)
        {
            const auto info = static_cast<PLUG_CB_DEBUGEVENT*>(callbackInfo);
            if(info && info->DebugEvent)
            {
                gPid.store(info->DebugEvent->dwProcessId, std::memory_order_relaxed);
                gThread.store(info->DebugEvent->dwThreadId, std::memory_order_release);
            }
        }
        else if(type == CB_BREAKPOINT)
        {
            const auto info = static_cast<PLUG_CB_BREAKPOINT*>(callbackInfo);
            if(!info || !info->breakpoint || info->breakpoint->addr != gAddress.load(std::memory_order_acquire))
                return;
            const auto count = gHitCount.load(std::memory_order_relaxed);
            if(count >= gHits.size())
            {
                gOverflow.store(true, std::memory_order_release);
                return;
            }
            gHits[count] = {info->breakpoint->addr, gPid.load(std::memory_order_relaxed), gThread.load(std::memory_order_acquire), info->breakpoint->type, info->breakpoint->enabled};
            gHitCount.store(count + 1, std::memory_order_release);
        }
        else if(type == CB_EXITPROCESS)
        {
            const auto info = static_cast<PLUG_CB_EXITPROCESS*>(callbackInfo);
            if(info && info->ExitProcess)
            {
                gExit.store(info->ExitProcess->dwExitCode, std::memory_order_relaxed);
                gExited.store(true, std::memory_order_release);
            }
        }
    }
    bool CheckBytes(bool patched, bool trapped)
    {
        const auto address = FieldAddress("PatchValue");
        const auto& expected = patched ? Patched : Original;
        std::array<unsigned char, 6> logical{}, raw{};
        const ScopedProcess process(DbgGetProcessId());
        SIZE_T read = 0;
        if(!_plugin_testassert(process.value && DbgMemRead(address, logical.data(), logical.size()) && logical == expected
                              && ReadProcessMemory(process.value, reinterpret_cast<const void*>(address), raw.data(), raw.size(), &read) && read == raw.size(),
                              "logical patch bytes and independent OS read are available"))
            return false;
        auto expectedRaw = expected;
        if(trapped) expectedRaw[0] = 0xcc;
        if(!_plugin_testassert(raw == expectedRaw && FieldAddress("PatchValueEnd") == address + expected.size(), "software trap, logical opcode and exact function boundary agree"))
            return false;
        BASIC_INSTRUCTION_INFO first{}, terminal{};
        DbgDisasmFastAt(address, &first);
        DbgDisasmFastAt(address + 5, &terminal);
        if(!_plugin_testassert(first.size == (patched ? 4 : 5) && terminal.size == 1, "native disassembly retains the exact installed MOV and RET boundaries"))
            return false;
        std::string logicalHex, rawHex;
        const char digits[] = "0123456789abcdef";
        for(unsigned index = 0; index < raw.size(); ++index)
        {
            for(auto pair : {std::pair<std::string*, unsigned char>{&logicalHex, logical[index]}, {&rawHex, raw[index]}})
            {
                pair.first->push_back(digits[pair.second >> 4]);
                pair.first->push_back(digits[pair.second & 15]);
            }
        }
        _plugin_logprintf("PATCH_BYTES patched=%u trapped=%u address=%llx logical=%s raw=%s\n", patched ? 1 : 0, trapped ? 1 : 0,
                          static_cast<unsigned long long>(address), logicalHex.c_str(), rawHex.c_str());
        return true;
    }
    bool CheckTracking(bool patched)
    {
        size_t size = 0;
        if(!_plugin_testassert(DbgFunctions()->PatchEnum(nullptr, &size) && size == (patched ? 4 * sizeof(DBGPATCHINFO) : 0), "patch enumeration contains only actual changed bytes"))
            return false;
        std::vector<DBGPATCHINFO> entries(size / sizeof(DBGPATCHINFO));
        if(size && !_plugin_testassert(DbgFunctions()->PatchEnum(entries.data(), &size) && size == entries.size() * sizeof(DBGPATCHINFO), "patch enumeration completes with the same bounded size"))
            return false;
        for(unsigned index = 0; index < Original.size(); ++index)
        {
            DBGPATCHINFO entry{};
            const auto address = FieldAddress("PatchValue") + index;
            const bool changed = patched && Original[index] != Patched[index];
            const bool found = DbgFunctions()->PatchGetEx(address, &entry);
            if(!_plugin_testassert(found == changed && (!found || (entry.addr == address && entry.oldbyte == Original[index] && entry.newbyte == Patched[index]
                                      && strcmp(entry.mod, "patch_canary.exe") == 0)), "patch lookup preserves the original byte and installed byte at offset %u", index))
                return false;
            if(found)
                _plugin_logprintf("PATCH_RECORD address=%llx old=%02x new=%02x module=%s\n", static_cast<unsigned long long>(entry.addr), entry.oldbyte, entry.newbyte, entry.mod);
        }
        for(const auto& entry : entries)
            if(!_plugin_testassert(entry.addr >= FieldAddress("PatchValue") && entry.addr < FieldAddress("PatchValue") + Original.size()
                                  && entry.oldbyte == Original[entry.addr - FieldAddress("PatchValue")] && entry.newbyte == Patched[entry.addr - FieldAddress("PatchValue")],
                                  "enumerated patch belongs to the declared instruction span"))
                return false;
        return true;
    }
    bool CheckPhase(unsigned phase, const std::array<DWORD, 3>& expected)
    {
        unsigned observed = 0;
        DWORD completed = 0;
        std::array<DWORD, 3> values{};
        return ReadTarget("gPatchPhase", observed) && ReadTarget("gPatchCompleted", completed) && ReadTarget("gPatchValues", values)
               && _plugin_testassert(observed == phase && completed == phase - 1 && values == expected && DbgValFromString("cip") == FieldAddress("PatchReady"),
                                     "patch action starts only at its exact target barrier with actual prior values");
    }
    bool cbPrepare(int, char**)
    {
        if(!CheckPhase(1, {0, 0, 0}) || !CheckBytes(false, true) || !CheckTracking(false)) return false;
        DWORD pid = 0, thread = 0;
        uintptr_t base = 0;
        if(!ReadTarget("gPatchPid", pid) || !ReadTarget("gPatchThread", thread) || !ReadTarget("gPatchImageBase", base)) return false;
        const ScopedProcess process(pid);
        FILETIME creation{}, exit{}, kernel{}, user{};
        if(!_plugin_testassert(pid == DbgGetProcessId() && thread == DbgGetThreadId() && process.value && GetProcessTimes(process.value, &creation, &exit, &kernel, &user),
                              "patch target has the exact debugger and actual OS identity")) return false;
        gAddress.store(FieldAddress("PatchValue"), std::memory_order_release);
        _plugin_logprintf("PATCH_LAYOUT pid=%lu thread=%lu base=%llx address=%llx creation=%llu\n", pid, thread,
                          static_cast<unsigned long long>(base), static_cast<unsigned long long>(gAddress.load()),
                          (static_cast<unsigned long long>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime);
        return true;
    }
    bool cbSelect(int, char**)
    {
        unsigned mode = 0, mutation = 0;
        const unsigned selected = 1;
        if(!ReadTarget("gPatchMode", mode) || !ReadTarget("gPatchMutation", mutation)) return false;
        if(!_plugin_testassert(DbgValFromString("cip") == FieldAddress("entry") && mode == 0 && mutation == 0
                              && DbgMemWrite(FieldAddress("gPatchMode"), &selected, sizeof(selected))
                              && DbgMemWrite(FieldAddress("gPatchMutation"), &selected, sizeof(selected)), "reference selection uses separate untracked data writes at the actual entry")) return false;
        return ReadTarget("gPatchMode", mode) && ReadTarget("gPatchMutation", mutation) && CheckTracking(false)
               && _plugin_testassert(mode == 1 && mutation == 1, "reference mode and mutation read back exactly");
    }
    bool cbApply(int, char**)
    {
        if(!CheckPhase(2, {7, 0, 0}) || !CheckBytes(false, true) || !CheckTracking(false)) return false;
        std::array<unsigned char, 16> encoded{};
        int size = 0;
        char error[MAX_ERROR_SIZE]{};
        const auto address = FieldAddress("PatchValue");
        if(!_plugin_testassert(DbgFunctions()->Assemble(address, encoded.data(), &size, "mov ax,0x2a", error) && size == 4
                              && memcmp(encoded.data(), Patched.data(), 4) == 0, "pure assembly encodes the requested opcode at the actual target origin")) return false;
        const auto destination = address + 0x1000;
        char branch[MAX_ERROR_SIZE]{};
        sprintf_s(branch, "jmp 0x%llx", static_cast<unsigned long long>(destination));
        for(unsigned offset : {0u, 0x20u})
        {
            std::array<unsigned char, 5> expected{0xe9, 0, 0, 0, 0};
            const auto displacement = static_cast<int32_t>(destination - (address + offset + expected.size()));
            memcpy(expected.data() + 1, &displacement, sizeof(displacement));
            if(!_plugin_testassert(DbgFunctions()->Assemble(address + offset, encoded.data(), &size, branch, error) && size == 5
                                  && memcmp(encoded.data(), expected.data(), expected.size()) == 0, "pure branch encoding binds its displacement to the supplied real origin")) return false;
            _plugin_logprintf("PATCH_BRANCH origin=%llx destination=%llx displacement=%x\n", static_cast<unsigned long long>(address + offset),
                              static_cast<unsigned long long>(destination), static_cast<unsigned>(displacement));
        }
        if(!CheckBytes(false, true) || !CheckTracking(false)) return false;
        if(!_plugin_testassert(!DbgFunctions()->AssembleAtEx(address, "definitely_invalid_instruction", error, true) && error[0], "invalid assembly rejects with an actual error")) return false;
        if(!CheckBytes(false, true) || !CheckTracking(false)) return false;
        error[0] = 0;
        const std::string oversized(256, 'a');
        if(!_plugin_testassert(!DbgFunctions()->AssembleAtEx(address, oversized.c_str(), error, true), "oversized native assembly text rejects before writing")) return false;
        if(!CheckBytes(false, true) || !CheckTracking(false)) return false;
        _plugin_logprintf("PATCH_ASSEMBLY origin=%llx instruction=mov_ax_0x2a encoded=66b82a00 fill=90 invalidRejected=1 oversizedTextRejected=1 oversizedHasError=%u\n", static_cast<unsigned long long>(address), error[0] ? 1 : 0);
        if(!_plugin_testassert(DbgFunctions()->AssembleAtEx(address, "mov ax,0x2a", error, true), "requested assembly installs with explicit native NOP fill")) return false;
        return CheckBytes(true, true) && CheckTracking(true);
    }
    bool cbUndo(int, char**)
    {
        if(!CheckPhase(3, {7, 42, 0}) || !CheckBytes(true, true) || !CheckTracking(true)) return false;
        const auto address = FieldAddress("PatchValue");
        DbgFunctions()->PatchRestoreRange(address, address + 4);
        return CheckBytes(false, true) && CheckTracking(false);
    }
    bool cbHit(int argc, char** argv)
    {
        const auto index = argc == 2 && strlen(argv[1]) == 1 && argv[1][0] >= '0' && argv[1][0] <= '2' ? unsigned(argv[1][0] - '0') : 3;
        const auto count = gHitCount.load(std::memory_order_acquire);
        if(!_plugin_testassert(index < 3 && count == index + 1 && !gOverflow.load() && DbgValFromString("cip") == FieldAddress("PatchValue"), "breakpoint actually stops each selected function call")) return false;
        const auto& hit = gHits[index];
        if(!_plugin_testassert(hit.address == FieldAddress("PatchValue") && hit.pid == DbgGetProcessId() && hit.thread == DbgGetThreadId() && hit.type == bp_normal && hit.enabled,
                              "bounded raw breakpoint event has the actual software breakpoint and OS identity")) return false;
        _plugin_logprintf("PATCH_HIT index=%u address=%llx pid=%lu thread=%lu\n", index, static_cast<unsigned long long>(hit.address), hit.pid, hit.thread);
        return true;
    }
    bool cbFinish(int, char**)
    {
        unsigned phase = 0;
        DWORD completed = 0, verified = 0;
        std::array<DWORD, 3> values{};
        std::array<std::array<char, 9>, 3> markers{};
        if(!ReadTarget("gPatchPhase", phase) || !ReadTarget("gPatchCompleted", completed) || !ReadTarget("gPatchVerified", verified)
                || !ReadTarget("gPatchValues", values) || !ReadTarget("gPatchMarkers", markers)) return false;
        if(!_plugin_testassert(phase == 4 && completed == 3 && verified == 1 && values == std::array<DWORD, 3>{7, 42, 7}
                              && strcmp(markers[0].data(), "original") == 0 && strcmp(markers[1].data(), "patched") == 0 && strcmp(markers[2].data(), "original") == 0
                              && DbgValFromString("cip") == FieldAddress("PatchFinish"), "actual target calls and markers prove original, changed and restored execution")) return false;
        _plugin_logprintf("PATCH_RESULT values=%lu/%lu/%lu markers=%s/%s/%s completed=%lu verified=%lu\n", values[0], values[1], values[2],
                          markers[0].data(), markers[1].data(), markers[2].data(), completed, verified);
        return CheckBytes(false, true) && CheckTracking(false);
    }
    bool cbExit(int, char**)
    {
        _plugin_logprintf("PATCH_EXIT code=%lu observed=%u debugging=%u\n", gExit.load(), gExited.load() ? 1 : 0, DbgIsDebugging() ? 1 : 0);
        return _plugin_testassert(gExited.load(std::memory_order_acquire) && gExit.load() == 56 && !DbgIsDebugging(), "patch target actually exits with its independently known executed sum");
    }
}
extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* init)
{
    init->pluginVersion = 1;
    init->sdkVersion = PLUG_SDKVERSION;
    strcpy_s(init->pluginName, "patch-execution-reference");
    gPluginHandle = init->pluginHandle;
    for(const auto type : {CB_INITDEBUG, CB_DEBUGEVENT, CB_BREAKPOINT, CB_EXITPROCESS})
        _plugin_registercallback(gPluginHandle, type, cbPatchEvent);
    return _plugin_registercommand(gPluginHandle, "patchselect", cbSelect, true)
           && _plugin_registercommand(gPluginHandle, "patchprepare", cbPrepare, true)
           && _plugin_registercommand(gPluginHandle, "patchapply", cbApply, true)
           && _plugin_registercommand(gPluginHandle, "patchundo", cbUndo, true)
           && _plugin_registercommand(gPluginHandle, "patchhit", cbHit, true)
           && _plugin_registercommand(gPluginHandle, "patchfinish", cbFinish, true)
           && _plugin_registercommand(gPluginHandle, "patchexit", cbExit, false);
}
extern "C" __declspec(dllexport) bool plugstop() { return true; }
