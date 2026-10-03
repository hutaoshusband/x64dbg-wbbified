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
    BPXTYPE gBreakpointType = bp_normal;
    DWORD gOriginalProtection = 0;
    unsigned gStepCount = 0, gArmCount = 0, gHardwareSlot = MAXDWORD;
    bool gSingleShot = false;
    duint gFailureAddress = 0;
    SIZE_T gFailureWritten = 0;
    std::atomic<duint> gAddress{0};
    std::atomic<DWORD> gPid{0}, gThread{0}, gExit{0};
    std::atomic<unsigned> gHitCount{0};
    std::atomic<bool> gOverflow{false}, gExited{false};
    struct Hit { duint address; DWORD pid, thread; BPXTYPE type; bool enabled, singleshoot; };
    std::array<Hit, 8> gHits{};
    const std::array<unsigned char, 6> Original{0xb8, 7, 0, 0, 0, 0xc3};
    const std::array<unsigned char, 6> Patched{0x66, 0xb8, 0x2a, 0, 0x90, 0xc3};
    struct ScopedProcess
    {
        HANDLE value;
        explicit ScopedProcess(DWORD pid, DWORD extra = 0) : value(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | extra, FALSE, pid)) {}
        ScopedProcess(const ScopedProcess&) = delete;
        ScopedProcess& operator=(const ScopedProcess&) = delete;
        ~ScopedProcess() { if(value) CloseHandle(value); }
    };
    struct ScopedThread
    {
        HANDLE value;
        explicit ScopedThread(DWORD id) : value(OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, id)) {}
        ScopedThread(const ScopedThread&) = delete;
        ScopedThread& operator=(const ScopedThread&) = delete;
        ~ScopedThread() { if(value) CloseHandle(value); }
    };
    struct ScopedFile
    {
        HANDLE value;
        ScopedFile(const wchar_t* path, DWORD access, DWORD sharing, DWORD disposition) : value(path && path[0] ? CreateFileW(path, access, sharing, nullptr, disposition, FILE_ATTRIBUTE_NORMAL, nullptr) : INVALID_HANDLE_VALUE) {}
        ScopedFile(const ScopedFile&) = delete;
        ScopedFile& operator=(const ScopedFile&) = delete;
        ~ScopedFile() { if(value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    };
    std::wstring DecodePath(const char* text)
    {
        const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, nullptr, 0);
        if(count < 2) return {};
        std::vector<wchar_t> value(count);
        if(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, value.data(), count) != count) return {};
        return std::wstring(value.data(), count - 1);
    }
    std::string EncodePath(const std::wstring& text)
    {
        const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if(count < 2) return {};
        std::vector<char> value(count);
        if(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.c_str(), -1, value.data(), count, nullptr, nullptr) != count) return {};
        return std::string(value.data(), count - 1);
    }
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
            gAddress = 0; gPid = 0; gThread = 0; gExit = 0; gHitCount = 0; gOverflow = false; gExited = false; gBreakpointType = bp_normal; gOriginalProtection = 0; gStepCount = 0; gFailureAddress = 0; gFailureWritten = 0; gArmCount = 0; gHardwareSlot = MAXDWORD; gSingleShot = false;
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
            gHits[count] = {info->breakpoint->addr, gPid.load(std::memory_order_relaxed), gThread.load(std::memory_order_acquire), info->breakpoint->type, info->breakpoint->enabled, info->breakpoint->singleshoot};
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
    bool CheckBreakpoint()
    {
        const auto address = FieldAddress("PatchValue");
        BRIDGEBP breakpoint{};
        if(gSingleShot)
        {
            const bool present = DbgFunctions()->GetBridgeBp(bp_hardware, address, &breakpoint);
            const bool armed = gArmCount > gHitCount.load(std::memory_order_acquire);
            const ScopedThread thread(DbgGetThreadId());
            CONTEXT context{};
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            const bool read = thread.value && GetThreadContext(thread.value, &context);
            const std::array<duint, 4> slots{context.Dr0, context.Dr1, context.Dr2, context.Dr3};
            if(!_plugin_testassert(read && gHardwareSlot < slots.size() && present == armed &&
                                  (armed ? slots[gHardwareSlot] == address && (context.Dr7 & (3ull << (gHardwareSlot * 2))) && ((context.Dr7 >> (16 + gHardwareSlot * 4)) & 15) == 0 && breakpoint.singleshoot : (context.Dr7 & 0xff) == 0),
                                  "single-shot hardware ownership agrees with actual enabled OS debug slots")) return false;
            _plugin_logprintf("PATCH_SINGLESHOT address=%llx slot=%u actualSlot=%llx dr7=%llx present=%u armed=%u hits=%u arms=%u\n", static_cast<unsigned long long>(address), gHardwareSlot,
                              static_cast<unsigned long long>(slots[gHardwareSlot]), static_cast<unsigned long long>(context.Dr7), unsigned(present), unsigned(armed), gHitCount.load(), gArmCount);
            if(!armed)
            {
                const ScopedProcess process(DbgGetProcessId());
                MEMORY_BASIC_INFORMATION region{};
                return _plugin_testassert(process.value && VirtualQueryEx(process.value, reinterpret_cast<const void*>(address), &region, sizeof(region)) == sizeof(region)
                                          && region.State == MEM_COMMIT && region.Type == MEM_IMAGE && region.Protect == gOriginalProtection,
                                          "removed hardware breakpoint leaves the actual executable image protection unchanged");
            }
        }
        if(!_plugin_testassert(DbgFunctions()->GetBridgeBp(gBreakpointType, address, &breakpoint) && breakpoint.addr == address
                              && breakpoint.type == gBreakpointType && breakpoint.enabled && breakpoint.active && breakpoint.singleshoot == gSingleShot,
                              "the selected breakpoint remains active at the exact source function")) return false;
        const ScopedProcess process(DbgGetProcessId());
        MEMORY_BASIC_INFORMATION region{};
        if(!_plugin_testassert(process.value && VirtualQueryEx(process.value, reinterpret_cast<const void*>(address), &region, sizeof(region)) == sizeof(region)
                              && region.State == MEM_COMMIT && region.Type == MEM_IMAGE && region.RegionSize >= 0x1000,
                              "the isolated function has an actual committed image page")) return false;
        if(gBreakpointType == bp_hardware)
        {
            const ScopedThread thread(DbgGetThreadId());
            CONTEXT context{};
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            const bool read = thread.value && GetThreadContext(thread.value, &context);
            const std::array<duint, 4> slots{context.Dr0, context.Dr1, context.Dr2, context.Dr3};
            const unsigned slot = breakpoint.slot;
            if(!_plugin_testassert(read && slot < slots.size() && slots[slot] == address && (context.Dr7 & (3ull << (slot * 2))) != 0
                                  && ((context.Dr7 >> (16 + slot * 4)) & 15) == 0 && breakpoint.typeEx == hw_execute && breakpoint.hwSize == hw_byte
                                  && region.Protect == gOriginalProtection,
                                  "actual OS debug registers retain the exact executable hardware slot and page protection")) return false;
            _plugin_logprintf("PATCH_HARDWARE slot=%u address=%llx dr7=%llx\n", slot, static_cast<unsigned long long>(slots[slot]), static_cast<unsigned long long>(context.Dr7));
        }
        else if(gBreakpointType == bp_memory)
        {
            if(!_plugin_testassert(breakpoint.typeEx == mem_execute && DbgFunctions()->MemBpSize(address) == 1
                                  && (region.Protect != gOriginalProtection) && ((region.Protect & PAGE_GUARD) || (region.Protect & 0xf0) == 0),
                                  "the memory breakpoint keeps its exact execute range and actual OS trap protection")) return false;
        }
        else if(!_plugin_testassert(region.Protect == gOriginalProtection, "software trapping preserves the original OS page protection")) return false;
        _plugin_logprintf("PATCH_BREAKPOINT type=%u address=%llx typeEx=%u enabled=%u active=%u singleshoot=%u hits=%u protection=%lx originalProtection=%lx\n",
                          unsigned(breakpoint.type), static_cast<unsigned long long>(breakpoint.addr), unsigned(breakpoint.typeEx), breakpoint.enabled ? 1 : 0,
                          breakpoint.active ? 1 : 0, breakpoint.singleshoot ? 1 : 0, breakpoint.hitCount, region.Protect, gOriginalProtection);
        return true;
    }
    bool CheckBytes(bool patched, bool trapped)
    {
        const auto address = FieldAddress("PatchValue");
        const auto& expected = patched ? Patched : Original;
        trapped = trapped && gBreakpointType == bp_normal;
        if(!CheckBreakpoint()) return false;
        std::array<unsigned char, 6> logical{}, raw{};
        const ScopedProcess process(DbgGetProcessId());
        SIZE_T read = 0;
        MEMORY_BASIC_INFORMATION before{}, after{};
        if(process.value) VirtualQueryEx(process.value, reinterpret_cast<const void*>(address), &before, sizeof(before));
        if(!_plugin_testassert(process.value && DbgMemRead(address, logical.data(), logical.size()) && logical == expected
                              && ReadProcessMemory(process.value, reinterpret_cast<const void*>(address), raw.data(), raw.size(), &read) && read == raw.size(),
                              "logical patch bytes and independent OS read are available"))
            return false;
        if(!_plugin_testassert(VirtualQueryEx(process.value, reinterpret_cast<const void*>(address), &after, sizeof(after)) == sizeof(after)
                              && before.Protect == after.Protect, "logical and OS reads preserve the breakpoint's actual page protection")) return false;
        auto expectedRaw = expected;
        if(trapped) expectedRaw[0] = 0xcc;
        if(!_plugin_testassert(raw == expectedRaw && FieldAddress("PatchValueEnd") == address + expected.size(), "selected trap, logical opcode and exact function boundary agree"))
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
    bool cbSelect(int argc, char** argv)
    {
        if(!_plugin_testassert(argc == 1 || ((argc == 2 || (argc == 3 && strcmp(argv[2], "ss") == 0 && strcmp(argv[1], "2") == 0))
                              && strlen(argv[1]) == 1 && (argv[1][0] == '1' || argv[1][0] == '2' || argv[1][0] == '4')),
                              "reference declares an exact software, hardware or memory breakpoint type")) return false;
        gBreakpointType = argc == 1 ? bp_normal : static_cast<BPXTYPE>(argv[1][0] - '0');
        gSingleShot = argc == 3;
        const ScopedProcess process(DbgGetProcessId());
        MEMORY_BASIC_INFORMATION region{};
        if(!_plugin_testassert(process.value && VirtualQueryEx(process.value, reinterpret_cast<const void*>(FieldAddress("PatchValue")), &region, sizeof(region)) == sizeof(region)
                              && (region.Protect & 0xff) == PAGE_EXECUTE_READ, "reference captures its actual original executable page protection")) return false;
        gOriginalProtection = region.Protect;
        unsigned mode = 0, mutation = 0;
        const unsigned selected = 1;
        if(!ReadTarget("gPatchMode", mode) || !ReadTarget("gPatchMutation", mutation)) return false;
        if(!_plugin_testassert(DbgValFromString("cip") == FieldAddress("entry") && mode == 0 && mutation == 0
                              && DbgMemWrite(FieldAddress("gPatchMode"), &selected, sizeof(selected))
                              && DbgMemWrite(FieldAddress("gPatchMutation"), &selected, sizeof(selected)), "reference selection uses separate untracked data writes at the actual entry")) return false;
        return ReadTarget("gPatchMode", mode) && ReadTarget("gPatchMutation", mutation) && CheckTracking(false)
               && _plugin_testassert(mode == 1 && mutation == 1, "reference mode and mutation read back exactly");
    }
    bool cbSingleArm(int, char**)
    {
        const auto address = FieldAddress("PatchValue");
        BRIDGEBP breakpoint{};
        const ScopedThread thread(DbgGetThreadId());
        CONTEXT context{};
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        FILETIME creation{}, exit{}, kernel{}, user{};
        const bool read = thread.value && GetThreadContext(thread.value, &context) && GetThreadTimes(thread.value, &creation, &exit, &kernel, &user);
        const std::array<duint, 4> slots{context.Dr0, context.Dr1, context.Dr2, context.Dr3};
        if(!_plugin_testassert(gSingleShot && gBreakpointType == bp_hardware && gArmCount == gHitCount.load(std::memory_order_acquire) && gArmCount < 3 && read &&
                              GetProcessIdOfThread(thread.value) == DbgGetProcessId() && DbgFunctions()->GetBridgeBp(bp_hardware, address, &breakpoint) &&
                              breakpoint.addr == address && breakpoint.enabled && breakpoint.active && breakpoint.singleshoot && breakpoint.hitCount == 0 &&
                              breakpoint.slot < slots.size() && slots[breakpoint.slot] == address && (context.Dr7 & (3ull << (breakpoint.slot * 2))) &&
                              ((context.Dr7 >> (16 + breakpoint.slot * 4)) & 15) == 0 && breakpoint.typeEx == hw_execute && breakpoint.hwSize == hw_byte,
                              "single-shot is explicitly rearmed before each actual function call")) return false;
        gHardwareSlot = breakpoint.slot;
        ++gArmCount;
        _plugin_logprintf("PATCH_ARM index=%u address=%llx slot=%u dr7=%llx pid=%lu thread=%lu creation=%llu singleshoot=%u hits=%u\n", gArmCount - 1,
                          static_cast<unsigned long long>(address), gHardwareSlot, static_cast<unsigned long long>(context.Dr7), DbgGetProcessId(), DbgGetThreadId(),
                          (static_cast<unsigned long long>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime, unsigned(breakpoint.singleshoot), breakpoint.hitCount);
        return true;
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
    bool cbWriteFailure(int, char**)
    {
        if(!CheckPhase(2, {7, 0, 0}) || !CheckTracking(false)) return false;
        uintptr_t address = 0;
        if(!ReadTarget("gPatchWriteFailureRegion", address)) return false;
        const ScopedProcess process(DbgGetProcessId(), PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
        MEMORY_BASIC_INFORMATION first{}, second{}, after{};
        std::array<unsigned char, 0x1001> buffer{};
        buffer.fill(0x5b);
        if(!_plugin_testassert(gBreakpointType == bp_memory && process.value && address && (address & 0xfff) == 0
                              && VirtualQueryEx(process.value, reinterpret_cast<const void*>(address), &first, sizeof(first)) == sizeof(first)
                              && VirtualQueryEx(process.value, reinterpret_cast<const void*>(address + 0x1000), &second, sizeof(second)) == sizeof(second)
                              && first.State == MEM_COMMIT && first.Protect == PAGE_READONLY && second.State == MEM_RESERVE,
                              "controlled raw write spans an armed execute trap and a reserved inaccessible page")) return false;
        BRIDGEBP breakpoint{}, software{};
        if(!_plugin_testassert(DbgFunctions()->GetBridgeBp(bp_memory, address, &breakpoint) && breakpoint.enabled && breakpoint.typeEx == mem_execute
                              && DbgFunctions()->MemBpSize(address) == 1 && DbgFunctions()->GetBridgeBp(bp_normal, address + 0x10, &software)
                              && software.enabled && software.active && !software.singleshoot,
                              "controlled failure page has exact memory and overlapping software breakpoints")) return false;
        wchar_t path[MAX_PATH]{};
        const DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
        duint engine = 0;
        if(!_plugin_testassert(length && length < MAX_PATH && BridgeSettingGetUint("Engine", "DebugEngine", &engine) && engine <= 1,
                              "controlled write uses the actual selected native engine")) return false;
        std::wstring modulePath(path, length);
        modulePath.resize(modulePath.find_last_of(L"\\/") + 1);
        modulePath += engine == 0 ? L"TitanEngine.dll" : L"GleeBug\\TitanEngine.dll";
        const auto module = GetModuleHandleW(modulePath.c_str());
        using WriteMemory = bool(__cdecl*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
        const auto write = module ? reinterpret_cast<WriteMemory>(GetProcAddress(module, "MemoryWriteSafe")) : nullptr;
        if(!_plugin_testassert(write != nullptr, "controlled write resolves the source-built engine's exact raw safe-write export")) return false;
        SIZE_T written = 0;
        const bool success = write(process.value, reinterpret_cast<void*>(address), buffer.data(), buffer.size(), &written);
        const DWORD error = GetLastError();
        std::array<unsigned char, 0x1000> actual{}, logical{}, expected{};
        SIZE_T read = 0;
        if(!_plugin_testassert(!success && written <= actual.size(), "a partial raw write rejects full success and reports its actual prefix")) return false;
        for(SIZE_T index = 0; index < expected.size(); ++index) expected[index] = index < written ? 0x5b : 0x5a;
        if(!_plugin_testassert(VirtualQueryEx(process.value, reinterpret_cast<const void*>(address), &after, sizeof(after)) == sizeof(after)
                              && after.Protect == first.Protect && DbgMemRead(address, logical.data(), logical.size()) && logical == expected
                              && ReadProcessMemory(process.value, reinterpret_cast<const void*>(address), actual.data(), actual.size(), &read) && read == actual.size(),
                              "failed raw write restores trap protection and logical bytes reflect its actual written prefix")) return false;
        expected[0x10] = 0xcc;
        if(!_plugin_testassert(actual == expected, "independent OS bytes retain the software trap and exact changed prefix")) return false;
        gFailureAddress = address;
        gFailureWritten = written;
        _plugin_logprintf("PATCH_WRITE_FAILURE engine=%llu address=%llx requested=%llu written=%llu success=%u before=%lx after=%lx reserved=%lx error=%lu softwareOffset=16 softwareLogical=%02x softwareRaw=%02x prefix=5b remainder=5a\n",
                          static_cast<unsigned long long>(engine), static_cast<unsigned long long>(address), static_cast<unsigned long long>(buffer.size()),
                          static_cast<unsigned long long>(written), success ? 1 : 0, first.Protect, after.Protect, second.State, error, logical[0x10], actual[0x10]);
        return CheckTracking(false) && CheckBytes(false, true);
    }
    bool cbFailureFinish(int, char**)
    {
        if(!CheckPhase(2, {7, 0, 0}) || !CheckTracking(false)) return false;
        uintptr_t address = 0;
        if(!ReadTarget("gPatchWriteFailureRegion", address)) return false;
        const ScopedProcess process(DbgGetProcessId());
        MEMORY_BASIC_INFORMATION region{};
        BRIDGEBP breakpoint{};
        std::array<unsigned char, 0x1000> actual{}, logical{}, expected{};
        SIZE_T read = 0;
        for(SIZE_T index = 0; index < expected.size(); ++index) expected[index] = index < gFailureWritten ? 0x5b : 0x5a;
        if(!_plugin_testassert(address && address == gFailureAddress && gFailureWritten <= expected.size() && process.value
                              && !DbgFunctions()->GetBridgeBp(bp_memory, address, &breakpoint) && !DbgFunctions()->GetBridgeBp(bp_normal, address + 0x10, &breakpoint)
                              && VirtualQueryEx(process.value, reinterpret_cast<const void*>(address), &region, sizeof(region)) == sizeof(region) && region.Protect == PAGE_EXECUTE_READ
                              && DbgMemRead(address, logical.data(), logical.size()) && logical == expected
                              && ReadProcessMemory(process.value, reinterpret_cast<const void*>(address), actual.data(), actual.size(), &read) && read == actual.size() && actual == expected,
                              "clearing both overlap breakpoints restores the actual partial-write bytes and original OS protection")) return false;
        _plugin_logprintf("PATCH_WRITE_RESTORE address=%llx written=%llu protection=%lx logical=%02x raw=%02x\n", static_cast<unsigned long long>(address),
                          static_cast<unsigned long long>(gFailureWritten), region.Protect, logical[0x10], actual[0x10]);
        return true;
    }
    bool cbExport(int argc, char** argv)
    {
        if(!_plugin_testassert(argc == 3 && strlen(argv[2]) == 1 && argv[2][0] >= '0' && argv[2][0] <= '8', "file reference declares destination and exact patch selection")) return false;
        if(!CheckPhase(2, {7, 0, 0}) || !CheckBytes(true, true) || !CheckTracking(true)) return false;
        const unsigned kind = argv[2][0] - '0';
        std::vector<DBGPATCHINFO> patches;
        if(kind == 0 || kind >= 4)
        {
            size_t size = 0;
            if(!_plugin_testassert(DbgFunctions()->PatchEnum(nullptr, &size) && size == 4 * sizeof(DBGPATCHINFO), "export selects exactly the declared tracked patch bytes")) return false;
            patches.resize(size / sizeof(DBGPATCHINFO));
            if(!_plugin_testassert(DbgFunctions()->PatchEnum(patches.data(), &size) && size == patches.size() * sizeof(DBGPATCHINFO), "export captures all actual patch records")) return false;
        }
        else
        {
            const duint address = kind == 1 ? FieldAddress("PatchVirtualTail") : kind == 2 ? DbgModBaseFromName("patch_canary.exe") + 0x1c : FieldAddress("PatchRelocation");
            const unsigned size = kind == 3 ? sizeof(duint) : 1;
            std::array<unsigned char, sizeof(duint)> original{}, replacement{};
            if(!_plugin_testassert(address && DbgMemRead(address, original.data(), size), "layout reference reads its actual live exported or header bytes")) return false;
            if(kind == 3)
            {
                duint pointer = 0;
                memcpy(&pointer, original.data(), sizeof(pointer));
                if(!_plugin_testassert(pointer == FieldAddress("PatchValue"), "actual loader relocation points to the exact function")) return false;
                memcpy(replacement.data(), &pointer, sizeof(pointer));
            }
            else
            {
                if(!_plugin_testassert(original[0] == 0, "virtual zero-tail or reserved header byte has its known actual value")) return false;
                replacement[0] = 0x5b;
            }
            for(unsigned index = 0; index < size; ++index)
            {
                DBGPATCHINFO entry{};
                strcpy_s(entry.mod, "patch_canary.exe");
                entry.addr = address + index;
                entry.oldbyte = original[index];
                entry.newbyte = replacement[index];
                patches.push_back(entry);
                _plugin_logprintf("FILE_SELECTION kind=%u address=%llx old=%02x new=%02x\n", kind, static_cast<unsigned long long>(entry.addr), entry.oldbyte, entry.newbyte);
            }
        }
        if(kind == 5) strcpy_s(patches[1].mod, "different_module.dll");
        if(kind == 6) patches.clear();
        const auto path = DecodePath(argv[1]);
        if(!_plugin_testassert(!path.empty(), "export destination has an exact UTF-8 to UTF-16 representation")) return false;
        const ScopedFile locked(kind == 4 ? path.c_str() : L"", GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING);
        if(!_plugin_testassert(kind != 4 || locked.value != INVALID_HANDLE_VALUE, "locked-destination control owns its real write-denying OS file handle")) return false;
        char error[MAX_ERROR_SIZE]{};
        const int written = DbgFunctions()->PatchFile(patches.data(), static_cast<int>(patches.size()), argv[1], error);
        _plugin_logprintf("FILE_EXPORT kind=%u requested=%u written=%d errorPresent=%u\n", kind, static_cast<unsigned>(patches.size()), written, error[0] ? 1 : 0);
        if(!_plugin_testassert(written == (kind >= 4 ? -1 : kind == 1 ? 0 : static_cast<int>(patches.size())) && bool(error[0]) == (kind >= 4), "native file export count preserves the actual legacy mapping boundary")) return false;
        return CheckBytes(true, true) && CheckTracking(true);
    }
    bool cbFileExports(int argc, char** argv)
    {
        if(!_plugin_testassert(argc == 1 || argc == 2, "file reference accepts one explicit private output directory")) return false;
        const auto directory = argc == 2 ? DecodePath(argv[1]) : std::wstring(BridgeUserDirectory()) + L"\\patch-files-" + std::to_wstring(GetCurrentProcessId());
        if(!_plugin_testassert(!directory.empty() && CreateDirectoryW(directory.c_str(), nullptr), "file reference creates a new private directory without replacing existing files")) return false;
        const char digits[] = "0123456789abcdef";
        std::string encoded;
        for(const wchar_t character : directory)
            for(unsigned byte : {unsigned(character & 255), unsigned(character >> 8)})
            {
                encoded.push_back(digits[byte >> 4]);
                encoded.push_back(digits[byte & 15]);
            }
        _plugin_logprintf("FILE_DIRECTORY utf16=%s\n", encoded.c_str());
        const auto relocation = FieldAddress("PatchRelocation"), tail = FieldAddress("PatchVirtualTail");
        duint pointer = 0;
        std::array<unsigned char, 8192> zeros{};
        if(!_plugin_testassert(relocation && tail && DbgMemRead(relocation, &pointer, sizeof(pointer)) && pointer == FieldAddress("PatchValue")
                              && DbgMemRead(tail, zeros.data(), zeros.size()) && zeros == std::array<unsigned char, 8192>{},
                              "actual OS loader supplies the source-bound relocated pointer and complete zero virtual tail")) return false;
        _plugin_logprintf("FILE_LAYOUT relocation=%llx pointer=%llx virtual=%llx zeros=%u\n", static_cast<unsigned long long>(relocation),
                          static_cast<unsigned long long>(pointer), static_cast<unsigned long long>(tail), static_cast<unsigned>(zeros.size()));
        for(unsigned kind = 0; kind < 9; ++kind)
        {
            const auto path = directory + (kind == 7 ? L"\\missing\\" : L"\\") + L"file-" + std::to_wstring(kind) + L".exe";
            if(kind == 4 || kind == 8)
            {
                const ScopedFile file(path.c_str(), GENERIC_WRITE, 0, CREATE_NEW);
                const std::array<unsigned char, 16> sentinel{'W', 'B', 'B', '_', 'F', 'I', 'L', 'E', '_', 'G', 'U', 'A', 'R', 'D', 0, 0x5a};
                DWORD written = 0;
                if(!_plugin_testassert(file.value != INVALID_HANDLE_VALUE && WriteFile(file.value, sentinel.data(), DWORD(sentinel.size()), &written, nullptr)
                                      && written == sentinel.size() && FlushFileBuffers(file.value), "guard control creates its exact private destination before the native export")) return false;
            }
            if(kind == 8 && !_plugin_testassert(SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_READONLY), "read-only control sets its actual OS protection")) return false;
            auto utf8 = EncodePath(path);
            auto selection = std::to_string(kind);
            char command[] = "patchexport";
            char* arguments[]{command, utf8.data(), selection.data()};
            if(!cbExport(3, arguments)) return false;
        }
        return true;
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
        if(!_plugin_testassert(hit.address == FieldAddress("PatchValue") && hit.pid == DbgGetProcessId() && hit.thread == DbgGetThreadId() && hit.type == gBreakpointType && hit.enabled && hit.singleshoot == gSingleShot,
                              "bounded raw breakpoint event has the actual selected breakpoint and OS identity")) return false;
        _plugin_logprintf("PATCH_HIT index=%u address=%llx pid=%lu thread=%lu type=%u\n", index, static_cast<unsigned long long>(hit.address), hit.pid, hit.thread, unsigned(hit.type));
        return !gSingleShot || CheckBreakpoint();
    }
    bool cbStep(int argc, char** argv)
    {
        const unsigned index = argc == 2 && strlen(argv[1]) == 1 && argv[1][0] >= '0' && argv[1][0] <= '6' ? unsigned(argv[1][0] - '0') : 7;
        if(!_plugin_testassert(index < 7 && index == gStepCount, "each real CPU step has its declared sequence index")) return false;
        const std::array<unsigned, 7> offsets{5, 0, 4, 5, 0, 5, 0};
        const std::array<unsigned, 7> hits{1, 1, 2, 2, 2, 3, 3};
        const std::array<duint, 7> values{7, 7, 42, 42, 42, 7, 7};
        const auto expectedIP = offsets[index] ? FieldAddress("PatchValue") + offsets[index] : FieldAddress("PatchAfterCall");
        REGDUMP dump{};
        const bool nativeRead = DbgGetRegDumpEx(reinterpret_cast<REGDUMP_AVX512*>(&dump), sizeof(dump));
        const ScopedThread thread(DbgGetThreadId());
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
        const bool read = thread.value && GetThreadContext(thread.value, &context);
#ifdef _WIN64
        const duint ip = context.Rip, ax = context.Rax;
#else
        const duint ip = context.Eip, ax = context.Eax;
#endif
        _plugin_logprintf("PATCH_STEP index=%u hits=%u nativeIP=%llx nativeAX=%llx osRead=%u osIP=%llx osAX=%llx flags=%lx dr6=%llx dr7=%llx\n", index, hits[index],
                          static_cast<unsigned long long>(dump.regcontext.cip), static_cast<unsigned long long>(dump.regcontext.cax), read ? 1 : 0,
                          static_cast<unsigned long long>(ip), static_cast<unsigned long long>(ax), context.EFlags,
                          static_cast<unsigned long long>(context.Dr6), static_cast<unsigned long long>(context.Dr7));
        if(!_plugin_testassert(nativeRead && read && gHitCount.load(std::memory_order_acquire) == hits[index]
                              && dump.regcontext.cip == expectedIP && ip == expectedIP && dump.regcontext.cax == values[index] && ax == values[index],
                              "native and independent OS contexts prove that the requested instruction actually executed")) return false;
        if(gSingleShot)
        {
            BRIDGEBP breakpoint{};
            const bool present = DbgFunctions()->GetBridgeBp(bp_hardware, FieldAddress("PatchValue"), &breakpoint);
            if(!_plugin_testassert(!present && (context.Dr7 & 0xff) == 0, "actual CPU step keeps the consumed single-shot hardware slot disabled")) return false;
            _plugin_logprintf("PATCH_SINGLESTEP index=%u present=%u dr7=%llx\n", index, unsigned(present), static_cast<unsigned long long>(context.Dr7));
        }
        ++gStepCount;
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
        if(!_plugin_testassert(phase == 4 && completed == 3 && verified == 1 && gStepCount == 7 && (!gSingleShot || gArmCount == 3) && values == std::array<DWORD, 3>{7, 42, 7}
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
    return _plugin_registercommand(gPluginHandle, "patchsinglearm", cbSingleArm, true)
           && _plugin_registercommand(gPluginHandle, "patchstep", cbStep, true)
           && _plugin_registercommand(gPluginHandle, "patchselect", cbSelect, true)
           && _plugin_registercommand(gPluginHandle, "patchprepare", cbPrepare, true)
           && _plugin_registercommand(gPluginHandle, "patchapply", cbApply, true)
           && _plugin_registercommand(gPluginHandle, "patchwritefailure", cbWriteFailure, true)
           && _plugin_registercommand(gPluginHandle, "patchfailurefinish", cbFailureFinish, true)
           && _plugin_registercommand(gPluginHandle, "patchfileexports", cbFileExports, true)
           && _plugin_registercommand(gPluginHandle, "patchexport", cbExport, true)
           && _plugin_registercommand(gPluginHandle, "patchundo", cbUndo, true)
           && _plugin_registercommand(gPluginHandle, "patchhit", cbHit, true)
           && _plugin_registercommand(gPluginHandle, "patchfinish", cbFinish, true)
           && _plugin_registercommand(gPluginHandle, "patchexit", cbExit, false);
}
extern "C" __declspec(dllexport) bool plugstop() { return true; }
