#include <windows.h>
#include "../../dbg/native_breakin.h"
#include "../../dbg/native_breakin_payload.h"
#include <intrin.h>
#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>
#include <memory>

struct OwnedHandle
{
    HANDLE value = nullptr;

    explicit OwnedHandle(HANDLE handle) : value(handle)
    {
    }

    ~OwnedHandle()
    {
        if(value)
            CloseHandle(value);
    }

    OwnedHandle(const OwnedHandle&) = delete;
    OwnedHandle& operator=(const OwnedHandle&) = delete;
};

struct OwnedTarget
{
    PROCESS_INFORMATION information;

    explicit OwnedTarget(PROCESS_INFORMATION process) : information(process)
    {
    }

    ~OwnedTarget()
    {
        NativeBreakIn::EndTarget();
        NativeBreakIn::Shutdown();
        if(WaitForSingleObject(information.hProcess, 0) != WAIT_OBJECT_0)
        {
            TerminateProcess(information.hProcess, 15);
            WaitForSingleObject(information.hProcess, 3000);
        }
        CloseHandle(information.hThread);
        CloseHandle(information.hProcess);
    }
};

static void Identity(const char* role, HANDLE process)
{
    FILETIME creation{}, exit{}, kernel{}, user{};
    if(!GetProcessTimes(process, &creation, &exit, &kernel, &user))
        ExitProcess(11);
    const auto time = (static_cast<unsigned long long>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
    std::printf("IDENTITY role=%s pid=%lu creation=%llu\n", role, GetProcessId(process), time);
    std::fflush(stdout);
}

#ifndef _WIN64
static unsigned NativePeb(bool hide)
{
    struct BasicInformation64
    {
        LONG exitStatus;
        ULONG alignment;
        unsigned long long peb;
        unsigned long long affinity;
        LONG priority;
        ULONG priorityAlignment;
        unsigned long long pid;
        unsigned long long parent;
    };
    using Query = LONG(NTAPI*)(HANDLE, ULONG, void*, ULONG, ULONG*);
    using Read = LONG(NTAPI*)(HANDLE, unsigned long long, void*, unsigned long long, unsigned long long*);
    using Write = LONG(NTAPI*)(HANDLE, unsigned long long, const void*, unsigned long long, unsigned long long*);
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto query = reinterpret_cast<Query>(GetProcAddress(module, "NtWow64QueryInformationProcess64"));
    const auto read = reinterpret_cast<Read>(GetProcAddress(module, "NtWow64ReadVirtualMemory64"));
    const auto write = reinterpret_cast<Write>(GetProcAddress(module, "NtWow64WriteVirtualMemory64"));
    const auto process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, GetCurrentProcessId());
    OwnedHandle owner(process);
    BasicInformation64 information{};
    unsigned long long count = 0;
    unsigned char value = 0;
    if(!query || !read || !write || query(process, 0, &information, sizeof(information), nullptr) < 0 || information.pid != GetCurrentProcessId() || !information.peb || read(process, information.peb + 2, &value, 1, &count) < 0 || count != 1)
        ExitProcess(17);
    const auto original = value;
    if(hide)
    {
        value = 0;
        if(write(process, information.peb + 2, &value, 1, &count) < 0 || count != 1)
            ExitProcess(18);
    }
    if(read(process, information.peb + 2, &value, 1, &count) < 0 || count != 1)
        ExitProcess(19);
    std::printf("NATIVE_PEB address=%llx original=%u observed=%u\n", information.peb, unsigned(original), unsigned(value));
    return value;
}
#endif

static LONG CALLBACK ObserveException(EXCEPTION_POINTERS* pointers)
{
    static LONG count = 0;
    const auto ordinal = InterlockedIncrement(&count);
    if(ordinal <= 4)
    {
#ifdef _WIN64
        const auto ip = pointers->ContextRecord->Rip;
#else
        const auto ip = pointers->ContextRecord->Eip;
#endif
        std::printf("VEH count=%ld code=%08lx address=%p ip=%llx thread=%lu\n", ordinal, pointers->ExceptionRecord->ExceptionCode, pointers->ExceptionRecord->ExceptionAddress, static_cast<unsigned long long>(ip), GetCurrentThreadId());
        std::fflush(stdout);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int wmain(int argc, wchar_t** argv)
{
    const bool detached = argc > 3 && std::wcscmp(argv[3], L"detach") == 0;
    const bool nativeHidden = argc > 1 && std::wcscmp(argv[1], L"both") == 0;
    const bool hidden = nativeHidden || (argc > 1 && std::wcscmp(argv[1], L"hide") == 0);
    if(argc > 2 && std::wcscmp(argv[2], L"target") == 0)
    {
        if(argc != 5)
            return 24;
#ifdef _WIN64
        auto peb = reinterpret_cast<volatile unsigned char*>(__readgsqword(0x60));
#else
        auto peb = reinterpret_cast<volatile unsigned char*>(__readfsdword(0x30));
#endif
        const auto handler = AddVectoredExceptionHandler(1, ObserveException);
        if(!handler)
            return 23;
        const unsigned original = peb[2];
        if(hidden)
            peb[2] = 0;
#ifndef _WIN64
        NativePeb(nativeHidden);
#endif
        Identity("target", GetCurrentProcess());
        std::printf("TARGET original=%u hidden=%u api=%d\n", original, unsigned(peb[2]), IsDebuggerPresent());
        std::fflush(stdout);
        OutputDebugStringA("windows_reference: parking");
        std::printf("TARGET output_returned=1\n");
        std::fflush(stdout);
        __debugbreak();
        const auto completion = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::wcstoull(argv[3], nullptr, 10)));
        OwnedHandle completionOwner(completion);
        if(argc != 5 || WaitForSingleObject(completion, 20000) != WAIT_OBJECT_0)
            return 21;
        std::printf("TARGET breakpoint_returned=1\n");
        std::fflush(stdout);
        const bool expectedDetach = std::wcscmp(argv[4], L"detached") == 0;
        BOOL debugPort = FALSE;
        const auto portRead = CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugPort);
        std::printf("TARGET final_peb=%u final_port=%u detached=%u port_read=%u\n", unsigned(peb[2]), unsigned(debugPort), unsigned(expectedDetach), unsigned(portRead));
        std::fflush(stdout);
        RemoveVectoredExceptionHandler(handler);
        return original == 1 && portRead && bool(debugPort) == !expectedDetach && unsigned(peb[2]) == unsigned(!hidden && !expectedDetach) ? 7 : 12;
    }
    Identity("controller", GetCurrentProcess());
    wchar_t path[32768]{};
    if(!GetModuleFileNameW(nullptr, path, 32768))
        return 13;
    std::wstring command = L"\"" + std::wstring(path) + (nativeHidden ? L"\" both target" : hidden ? L"\" hide target" : L"\" show target");
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    const auto completion = CreateEventW(&attributes, TRUE, FALSE, nullptr);
    if(!completion)
        return 22;
    OwnedHandle completionOwner(completion);
    command += L" " + std::to_wstring(reinterpret_cast<std::uintptr_t>(completion)) + (detached ? L" detached" : L" attached");
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION process{};
    if(!CreateProcessW(path, &command[0], nullptr, nullptr, TRUE, DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process))
        return 14;
    OwnedTarget targetOwner(process);
    Identity("created", process.hProcess);
    unsigned strings = 0, breakpoints = 0;
    DWORD exitCode = 0;
    const auto deadline = GetTickCount64() + 20000;
    bool exited = false, requested = false, breakinResult = false;
    void* remoteCode = nullptr;
    HANDLE remoteThread = nullptr;
    std::unique_ptr<OwnedHandle> threadOwner;
    bool codeFreed = false;
    std::uintptr_t ntdllBase = 0;
    bool detachedNow = false;
    DWORD remoteId = 0;
    unsigned remoteCreated = 0, remoteExited = 0, remoteBroken = 0, matched = 0;
    while(GetTickCount64() < deadline)
    {
        DEBUG_EVENT event{};
        if(!WaitForDebugEvent(&event, 1000))
        {
            if(GetLastError() == ERROR_SEM_TIMEOUT)
                continue;
            break;
        }
        DWORD status = DBG_CONTINUE;
        if(event.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT)
        {
            char text[512]{};
            SIZE_T read = 0;
            const auto size = event.u.DebugString.nDebugStringLength;
            if(size < sizeof(text) && !event.u.DebugString.fUnicode && ReadProcessMemory(process.hProcess, event.u.DebugString.lpDebugStringData, text, size, &read) && read == size)
            {
                std::printf("DEBUG_STRING pid=%lu thread=%lu text=%s\n", event.dwProcessId, event.dwThreadId, text);
                if(std::string(text) == "windows_reference: parking")
                    ++strings;
            }
        }
        else if(event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            const auto& exception = event.u.Exception;
            std::printf("EXCEPTION pid=%lu thread=%lu code=%08lx first=%lu address=%p\n", event.dwProcessId, event.dwThreadId, exception.ExceptionRecord.ExceptionCode, exception.dwFirstChance, exception.ExceptionRecord.ExceptionAddress);
            if(exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
            {
                ++breakpoints;
                if(event.dwThreadId == remoteId)
                {
                    auto different = exception;
                    different.ExceptionRecord.ExceptionAddress = static_cast<unsigned char*>(different.ExceptionRecord.ExceptionAddress) + 1;
                    const auto wrongAddress = NativeBreakIn::Consume(event.dwProcessId, event.dwThreadId, different);
                    different = exception;
                    different.dwFirstChance = 0;
                    const auto wrongChance = NativeBreakIn::Consume(event.dwProcessId, event.dwThreadId, different);
                    different = exception;
                    different.ExceptionRecord.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
                    const auto wrongCode = NativeBreakIn::Consume(event.dwProcessId, event.dwThreadId, different);
                    const auto wrongProcess = NativeBreakIn::Consume(0, event.dwThreadId, exception);
                    const auto wrongThread = NativeBreakIn::Consume(event.dwProcessId, 0, exception);
                    const auto actual = NativeBreakIn::Consume(event.dwProcessId, event.dwThreadId, exception);
                    const auto repeated = NativeBreakIn::Consume(event.dwProcessId, event.dwThreadId, exception);
                    std::printf("MATCH actual=%u wrongAddress=%u wrongChance=%u wrongCode=%u wrongProcess=%u wrongThread=%u repeated=%u\n", unsigned(actual), unsigned(wrongAddress), unsigned(wrongChance), unsigned(wrongCode), unsigned(wrongProcess), unsigned(wrongThread), unsigned(repeated));
                    if(!actual || wrongAddress || wrongChance || wrongCode || wrongProcess || wrongThread || repeated)
                        break;
                    ++matched;
                    ++remoteBroken;
                }
            }
            else
                status = DBG_EXCEPTION_NOT_HANDLED;
        }
        else if(event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT)
        {
            NativeBreakIn::BindThread(event.dwProcessId, event.dwThreadId, event.u.CreateThread);
            MEMORY_BASIC_INFORMATION memory{};
            if(requested && !remoteThread && VirtualQueryEx(process.hProcess, event.u.CreateThread.lpStartAddress, &memory, sizeof(memory)) == sizeof(memory) && memory.Type == MEM_PRIVATE && memory.State == MEM_COMMIT && memory.Protect == PAGE_EXECUTE_READ && memory.AllocationBase == event.u.CreateThread.lpStartAddress)
            {
                remoteCode = event.u.CreateThread.lpStartAddress;
                remoteId = event.dwThreadId;
                if(!DuplicateHandle(GetCurrentProcess(), event.u.CreateThread.hThread, GetCurrentProcess(), &remoteThread, 0, FALSE, DUPLICATE_SAME_ACCESS))
                    break;
                threadOwner = std::make_unique<OwnedHandle>(remoteThread);
                ++remoteCreated;
                std::printf("CREATE_THREAD pid=%lu thread=%lu start=%p\n", event.dwProcessId, remoteId, remoteCode);
                if(detached && SuspendThread(remoteThread) != 0)
                    break;
            }
        }

        else if(event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT)
        {
            std::printf("EXIT_THREAD pid=%lu thread=%lu exit=%lu\n", event.dwProcessId, event.dwThreadId, event.u.ExitThread.dwExitCode);
            if(event.dwThreadId == remoteId)
                ++remoteExited;
        }
        else if(event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
        {
            if(event.u.CreateProcessInfo.hFile)
                CloseHandle(event.u.CreateProcessInfo.hFile);
        }
        else if(event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
        {
            if(event.u.LoadDll.hFile)
            {
                wchar_t name[32768]{};
                if(GetFinalPathNameByHandleW(event.u.LoadDll.hFile, name, 32768, FILE_NAME_NORMALIZED))
                {
                    std::wprintf(L"MODULE base=%p path=%s\n", event.u.LoadDll.lpBaseOfDll, name);
                    const auto length = std::wcslen(name);
                    if(length >= 9 && _wcsicmp(name + length - 9, L"ntdll.dll") == 0)
                        ntdllBase = reinterpret_cast<std::uintptr_t>(event.u.LoadDll.lpBaseOfDll);
                }
                CloseHandle(event.u.LoadDll.hFile);
            }
        }
        else if(event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        {
            exited = true;
            exitCode = event.u.ExitProcess.dwExitCode;
        }
        std::fflush(stdout);
        if(detached && remoteCreated && !detachedNow)
        {
            if(!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status) || !DebugActiveProcessStop(process.dwProcessId))
                break;
            detachedNow = true;
            NativeBreakIn::EndTarget();
            if(ResumeThread(remoteThread) != 1 || WaitForSingleObject(remoteThread, 3000) != WAIT_OBJECT_0)
                break;
            DWORD threadExit = 0;
            if(!GetExitCodeThread(remoteThread, &threadExit) || threadExit != 0)
                break;
            MEMORY_BASIC_INFORMATION memory{};
            const auto cleanupDeadline = GetTickCount64() + 3000;
            while(GetTickCount64() < cleanupDeadline)
            {
                if(VirtualQueryEx(process.hProcess, remoteCode, &memory, sizeof(memory)) == sizeof(memory) && memory.State == MEM_FREE)
                {
                    codeFreed = true;
                    break;
                }
                Sleep(1);
            }
            std::printf("DETACHED thread=%lu exit=%lu freed=%u state=%08lx\n", remoteId, threadExit, unsigned(codeFreed), memory.State);
            if(!codeFreed || !SetEvent(completion) || WaitForSingleObject(process.hProcess, 6000) != WAIT_OBJECT_0 || !GetExitCodeProcess(process.hProcess, &exitCode))
                break;
            exited = true;
            break;
        }
        if(!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status))
            break;
        if(breakpoints == 2 && !requested)
        {
            requested = true;
            const auto readonlyProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process.dwProcessId);
            OwnedHandle readonlyOwner(readonlyProcess);
            if(!ntdllBase || !readonlyProcess || !NativeBreakIn::BeginTarget(readonlyProcess))
                break;
            const auto denied = NativeBreakIn::Create(ntdllBase);
            std::printf("READONLY rejected=%u error=%lu\n", unsigned(!denied.created), denied.error);
            if(denied.created || denied.error != ERROR_ACCESS_DENIED || !NativeBreakIn::BeginTarget(process.hProcess))
                break;
            const auto invalid = NativeBreakIn::Create(0);
            std::printf("INVALID_BASE rejected=%u\n", unsigned(!invalid.created));
            if(invalid.created)
                break;
            const auto requestImage = NativeBreakInPayload::Build(0, 1, 1);
            const auto overflowImage = NativeBreakInPayload::Build((std::numeric_limits<std::uintptr_t>::max)(), 1, 1);
            const auto missingRegistration = NativeBreakInPayload::Build(0x10000, 0, 1);
            const auto missingRemoval = NativeBreakInPayload::Build(0x10000, 1, 0);
            if(!requestImage.bytes.empty() || !overflowImage.bytes.empty() || !missingRegistration.bytes.empty() || !missingRemoval.bytes.empty())
                break;
            const auto result = NativeBreakIn::Create(ntdllBase);
            breakinResult = result.created;
            const auto duplicate = NativeBreakIn::Create(ntdllBase);
            std::printf("DUPLICATE rejected=%u error=%lu\n", unsigned(!duplicate.created), duplicate.error);
            if(duplicate.created || duplicate.error != ERROR_BUSY)
                break;
            std::printf("STUB status=%08lx error=%lu created=%u\n", result.status, result.error, unsigned(result.created));
            std::printf("BREAKIN requested=%u result=%u error=%lu\n", unsigned(requested), unsigned(breakinResult), GetLastError());
        }
        if(remoteExited && !codeFreed)
        {
            MEMORY_BASIC_INFORMATION allocation{};
            DWORD threadExit = 0;
            const auto wait = WaitForSingleObject(remoteThread, 3000);
            const auto terminal = wait == WAIT_OBJECT_0 && GetExitCodeThread(remoteThread, &threadExit) && threadExit == 0;
            const auto cleanupDeadline = GetTickCount64() + 3000;
            while(terminal && GetTickCount64() < cleanupDeadline)
            {
                if(VirtualQueryEx(process.hProcess, remoteCode, &allocation, sizeof(allocation)) == sizeof(allocation) && allocation.State == MEM_FREE)
                {
                    codeFreed = true;
                    break;
                }
                Sleep(1);
            }
            std::printf("STUB_CLEANUP terminal=%u exit=%lu freed=%u state=%08lx\n", unsigned(terminal), threadExit, unsigned(codeFreed), allocation.State);
            if(codeFreed)
                SetEvent(completion);
            if(!codeFreed)
                break;
        }
        if(exited)
            break;
    }
    const bool terminal = WaitForSingleObject(process.hProcess, 1000) == WAIT_OBJECT_0;
    if(!terminal)
    {
        TerminateProcess(process.hProcess, 15);
        WaitForSingleObject(process.hProcess, 3000);
    }
    NativeBreakIn::EndTarget();
    NativeBreakIn::Shutdown();

    std::printf("REFERENCE hidden=%u strings=%u breakpoints=%u target_exit=%lu exited=%u terminal=%u\n", unsigned(hidden), strings, breakpoints, exitCode, unsigned(exited), unsigned(terminal));
    std::printf("REMOTE created=%u exited=%u broken=%u result=%u tid=%lu\n", remoteCreated, remoteExited, remoteBroken, unsigned(breakinResult), remoteId);
    if(detached)
        return exited && terminal && exitCode == 7 && codeFreed && breakinResult ? 0 : 20;
    return exited && terminal && exitCode == 7 && matched == 1 && remoteCreated == 1 && remoteExited == 1 && remoteBroken == 1 && breakpoints == 2 + remoteBroken && breakinResult && codeFreed ? 0 : 16;
}
