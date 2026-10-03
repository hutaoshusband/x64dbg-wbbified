
#include <windows.h>
#include "../../dbg/native_breakin.h"
#include "session.h"
#include "../../dbg/native_breakin_payload.h"
#include "native_creator.h"
#include <cstdio>
#include <cwchar>
#include <string>
#include <memory>
#include <array>
#include <thread>
#include <tlhelp32.h>
#include <vector>
#include <tuple>
#include <algorithm>
#include <limits>

namespace BreakInSessions
{
    struct HandleCloser
    {
        void operator()(void* handle) const
        {
            if(handle)
                CloseHandle(handle);
        }
    };
    using OwnedHandle = std::unique_ptr<void, HandleCloser>;
    struct OwnedSessionTarget
    {
        OwnedHandle process, initialThread, completion, helper;
        DWORD processId = 0, threadId = 0;
        unsigned breaks = 0, helperBreaks = 0, exits = 0;
        std::uintptr_t ntdllBase = 0, imageBase = 0;
        std::array<unsigned char, NativeBreakInPayload::CodePageSize> originalCode{};
        void* remoteCode = nullptr;
        bool terminal = false;
        ~OwnedSessionTarget()
        {
            if(process && WaitForSingleObject(process.get(), 0) != WAIT_OBJECT_0)
            {
                TerminateProcess(process.get(), 15);
                WaitForSingleObject(process.get(), 1000);
            }
        }
    };
    static unsigned long long CreationTime(HANDLE handle, bool thread)
    {
        FILETIME creation{}, exit{}, kernel{}, user{};
        if(!(thread ? GetThreadTimes(handle, &creation, &exit, &kernel, &user) : GetProcessTimes(handle, &creation, &exit, &kernel, &user)))
            return 0;
        return (static_cast<unsigned long long>(creation.dwHighDateTime)<<32)|creation.dwLowDateTime;
    }
    static bool StartTarget(OwnedSessionTarget& target, const wchar_t* binary, const wchar_t* mode, const wchar_t* failure)
    {
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
        target.completion.reset(CreateEventW(&attributes, TRUE, FALSE, nullptr));
        if(!target.completion)
            return false;
        std::wstring command = L"\"" + std::wstring(binary) + L"\" " + mode + L" target " + std::to_wstring(reinterpret_cast<std::uintptr_t>(target.completion.get())) + L" attached";
        if(std::wcscmp(failure, L"register") == 0 || std::wcscmp(failure, L"remove") == 0)
            command += std::wstring(L" ") + failure;
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        PROCESS_INFORMATION process{};
        if(!CreateProcessW(binary, &command[0], nullptr, nullptr, TRUE, DEBUG_ONLY_THIS_PROCESS|CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process))
            return false;
        target.process.reset(process.hProcess);
        target.initialThread.reset(process.hThread);
        target.processId = process.dwProcessId;
        return true;
    }
    static bool VerifyPages(OwnedSessionTarget& target, unsigned role, bool freed)
    {
        const auto deadline = GetTickCount64() + 3000;
        do
        {
            MEMORY_BASIC_INFORMATION memory{};
            if(VirtualQueryEx(target.process.get(), target.remoteCode, &memory, sizeof(memory)) == sizeof(memory) && memory.State == (freed ? DWORD(MEM_FREE) : DWORD(MEM_COMMIT)))
            {
                std::printf("SESSION_PAGE role=%u pid=%lu code=%p freed=%u state=%08lx\n", role, target.processId, target.remoteCode, unsigned(freed), memory.State);
                std::fflush(stdout);
                return true;
            }
            Sleep(1);
        }
        while(GetTickCount64() < deadline);
        return false;
    }
    static bool VerifyRetainedPages(OwnedSessionTarget& target)
    {
        const auto begin = GetTickCount64();
        unsigned samples = 0;
        do
        {
            MEMORY_BASIC_INFORMATION code{}, data{};
            decltype(target.originalCode) observed{};
            SIZE_T copied = 0;
            if(WaitForSingleObject(target.process.get(), 0) != WAIT_TIMEOUT || VirtualQueryEx(target.process.get(), target.remoteCode, &code, sizeof(code)) != sizeof(code) || VirtualQueryEx(target.process.get(), static_cast<unsigned char*>(target.remoteCode) + NativeBreakInPayload::CodePageSize, &data, sizeof(data)) != sizeof(data) || code.AllocationBase != target.remoteCode || data.AllocationBase != target.remoteCode || code.State != MEM_COMMIT || data.State != MEM_COMMIT || code.Type != MEM_PRIVATE || data.Type != MEM_PRIVATE || code.Protect != PAGE_EXECUTE_READ || data.Protect != PAGE_READWRITE || !ReadProcessMemory(target.process.get(), target.remoteCode, observed.data(), observed.size(), &copied) || copied != observed.size() || observed != target.originalCode)
                return false;
            ++samples;
            Sleep(1);
        }
        while(GetTickCount64() - begin < 250);
        std::printf("SESSION_RETAIN pid=%lu code=%p alive=1 executable=00000020 data=00000004 unchanged=1 samples=%u elapsed=%llu\n", target.processId, target.remoteCode, samples, GetTickCount64() - begin);
        std::fflush(stdout);
        return true;
    }

    static int RunRound(const wchar_t* binary, const wchar_t* mode, const wchar_t* kind, unsigned round)
    {
        const bool partial = std::wcscmp(kind, L"partial") == 0;
        const bool registration = std::wcscmp(kind, L"register") == 0;
        const bool removal = std::wcscmp(kind, L"remove") == 0;
        const bool cleanupShutdown = std::wcscmp(kind, L"cleanup-shutdown") == 0;
        const bool cleanup = cleanupShutdown || std::wcscmp(kind, L"cleanup") == 0;
        const DWORD oldExit = registration ? 2u : removal ? 1u : 0u;
        OwnedHandle cleanupCompleted(cleanup ? CreateEventW(nullptr, TRUE, FALSE, nullptr) : nullptr);
        std::array<OwnedSessionTarget, 2> targets;
        for(unsigned role = 0; role < targets.size(); ++role)
            if(!StartTarget(targets[role], binary, mode, role ? L"normal" : kind))
                return 11;
        if(cleanup && (!cleanupCompleted || !FixtureNativeCleanup::ConfigureDeniedTarget(targets[0].process.get(), cleanupCompleted.get())))
            return 81;
        std::printf("SESSION round=%u old=%lu oldCreation=%llu next=%lu nextCreation=%llu partial=%u registration=%u removal=%u\n", round, targets[0].processId, CreationTime(targets[0].process.get(), false), targets[1].processId, CreationTime(targets[1].process.get(), false), unsigned(partial), unsigned(registration), unsigned(removal));
        if(cleanup)
        {
            std::printf("CLEANUP_PROFILE shutdown=%u pid=%lu creation=%llu controller=%lu controllerCreation=%llu\n", unsigned(cleanupShutdown), targets[0].processId, CreationTime(targets[0].process.get(), false), GetCurrentProcessId(), CreationTime(GetCurrentProcess(), false));
            std::fflush(stdout);
        }
        bool requested = false, released = false;
        FixtureNativeCreation::Observation oldCreation;
        const auto deadline = GetTickCount64() + 20000;
        while(GetTickCount64() < deadline)
        {
            DEBUG_EVENT event{};
            if(!WaitForDebugEvent(&event, 1000))
            {
                if(GetLastError() == ERROR_SEM_TIMEOUT)
                    continue;
                return 12;
            }
            auto index = event.dwProcessId == targets[0].processId ? 0u : event.dwProcessId == targets[1].processId ? 1u : 2u;
            if(index == 2)
                return 13;
            auto& target = targets[index];
            DWORD status = DBG_CONTINUE;
            if(event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && event.u.LoadDll.hFile)
            {
                wchar_t path[32768]{};
                if(GetFinalPathNameByHandleW(event.u.LoadDll.hFile, path, 32768, FILE_NAME_NORMALIZED))
                {
                    const auto length = std::wcslen(path);
                    if(length >= 9 && _wcsicmp(path+length-9, L"ntdll.dll") == 0)
                        target.ntdllBase = reinterpret_cast<std::uintptr_t>(event.u.LoadDll.lpBaseOfDll);
                }
                CloseHandle(event.u.LoadDll.hFile);
            }
            if(event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
            {
                target.imageBase = reinterpret_cast<std::uintptr_t>(event.u.CreateProcessInfo.lpBaseOfImage);
                if(event.u.CreateProcessInfo.hFile)
                    CloseHandle(event.u.CreateProcessInfo.hFile);
            }
            if(event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT)
            {
                NativeBreakIn::BindThread(event.dwProcessId, event.dwThreadId, event.u.CreateThread);
                MEMORY_BASIC_INFORMATION memory{};
                if(requested && !target.helper && VirtualQueryEx(target.process.get(), event.u.CreateThread.lpStartAddress, &memory, sizeof(memory)) == sizeof(memory) && memory.State == MEM_COMMIT && memory.Type == MEM_PRIVATE && memory.Protect == PAGE_EXECUTE_READ && memory.AllocationBase == event.u.CreateThread.lpStartAddress)
                {
                    HANDLE duplicate = nullptr;
                    if(!DuplicateHandle(GetCurrentProcess(), event.u.CreateThread.hThread, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
                        return 14;
                    target.helper.reset(duplicate);
                    target.remoteCode = event.u.CreateThread.lpStartAddress;
                    target.threadId = event.dwThreadId;
                    SIZE_T copied = 0;
                    if(GetProcessIdOfThread(target.helper.get()) != target.processId || GetThreadId(target.helper.get()) != target.threadId || !ReadProcessMemory(target.process.get(), target.remoteCode, target.originalCode.data(), target.originalCode.size(), &copied) || copied != target.originalCode.size())
                        return 28;
                    if(partial && index == 0 && (oldCreation.processId != target.processId || oldCreation.threadId != target.threadId || oldCreation.start != target.remoteCode || oldCreation.creation != CreationTime(target.helper.get(), true)))
                        return 15;
                    std::printf("SESSION_HELPER role=%u pid=%lu thread=%lu creation=%llu code=%p\n", index, target.processId, target.threadId, CreationTime(target.helper.get(), true), target.remoteCode);
                }
            }
            if(event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
            {
                const auto& exception = event.u.Exception;
                if(exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
                {
                    if(target.helper && event.dwThreadId == target.threadId)
                    {
                        const auto consumed = NativeBreakIn::Consume(event.dwProcessId, event.dwThreadId, exception);
                        const auto repeated = NativeBreakIn::Consume(event.dwProcessId, event.dwThreadId, exception);
                        std::printf("SESSION_CONSUME role=%u pid=%lu thread=%lu consumed=%u repeated=%u\n", index, target.processId, target.threadId, unsigned(consumed), unsigned(repeated));
                        if(consumed != bool(index) || repeated)
                            return 16;
                        ++target.helperBreaks;
                        status = index ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
                    }
                    else
                        ++target.breaks;
                }
                else
                    status = DBG_EXCEPTION_NOT_HANDLED;
            }
            if(event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT && event.dwThreadId == target.threadId)
                ++target.exits;
            if(event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
            {
                if(event.u.ExitProcess.dwExitCode != 7)
                    return 17;
                target.terminal = true;
            }
            std::fflush(stdout);
            if(!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status))
                return 18;
            if(!requested && targets[0].breaks == 2 && targets[1].breaks == 2)
            {
                requested = true;
                FixtureNativeCreation::Configure(partial ? FixtureNativeCreation::Mode::ControlledFailure : FixtureNativeCreation::Mode::Normal);
                if(!NativeBreakIn::BeginTarget(targets[0].process.get()))
                    return 19;
                const auto old = NativeBreakIn::Create(registration || removal ? targets[0].imageBase : targets[0].ntdllBase);
                oldCreation = FixtureNativeCreation::Capture();
                FixtureNativeCreation::Configure(FixtureNativeCreation::Mode::Normal);
                const DWORD expectedError = partial ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
                if(old.created == partial || old.status != (partial ? static_cast<LONG>(0xc0000022) : 0) || old.error != expectedError || !NativeBreakIn::BeginTarget(targets[1].process.get()))
                    return 20;
                const auto next = NativeBreakIn::Create(targets[1].ntdllBase);
                std::printf("SESSION_REQUEST oldStatus=%08lx oldCreated=%u nextStatus=%08lx nextCreated=%u\n", old.status, unsigned(old.created), next.status, unsigned(next.created));
                if(!next.created || next.status != 0 || next.error != 0)
                    return 21;
                const auto duplicate = NativeBreakIn::Create(targets[1].ntdllBase);
                std::printf("SESSION_DUPLICATE rejected=%u error=%lu\n", unsigned(!duplicate.created), duplicate.error);
                if(duplicate.created || duplicate.error != ERROR_BUSY)
                    return 29;
            }
            if(!released && targets[0].exits == 1 && targets[1].exits == 1)
            {
                for(unsigned role = 0; role < targets.size(); ++role)
                {
                    auto& item = targets[role];
                    DWORD exit = STILL_ACTIVE;
                    if(WaitForSingleObject(item.helper.get(), 3000) != WAIT_OBJECT_0 || !GetExitCodeThread(item.helper.get(), &exit) || exit != (role ? 0u : oldExit))
                        return 22;
                    std::printf("SESSION_THREAD_TERMINAL role=%u pid=%lu thread=%lu exit=%lu\n", role, item.processId, item.threadId, exit);
                }
                if(cleanup)
                {
                    if(WaitForSingleObject(cleanupCompleted.get(), 3000) != WAIT_OBJECT_0)
                        return 82;
                    const auto observation = FixtureNativeCleanup::Capture();
                    if(!observation.verified || observation.calls != 1 || observation.processId != targets[0].processId || observation.creation != CreationTime(targets[0].process.get(), false) || observation.address != targets[0].remoteCode)
                        return 83;
                }
                if(!VerifyPages(targets[0], 0, !partial && !removal && !cleanup) || !VerifyPages(targets[1], 1, true) || ((partial || removal || cleanup) && !VerifyRetainedPages(targets[0])))
                    return 23;
                if(cleanupShutdown)
                {
                    NativeBreakIn::Shutdown();
                    const auto rejected = NativeBreakIn::Create(targets[1].ntdllBase);
                    const auto beginRejected = !NativeBreakIn::BeginTarget(targets[0].process.get());
                    std::printf("CLEANUP_SHUTDOWN rejected=%u error=%lu beginRejected=%u\n", unsigned(!rejected.created), rejected.error, unsigned(beginRejected));
                    std::fflush(stdout);
                    if(rejected.created || rejected.error != ERROR_BUSY || !beginRejected || !VerifyRetainedPages(targets[0]))
                        return 84;
                }
                released = SetEvent(targets[0].completion.get()) && SetEvent(targets[1].completion.get());
                if(!released)
                    return 24;
            }
            if(targets[0].terminal && targets[1].terminal)
                break;
        }
        NativeBreakIn::EndTarget();
        for(unsigned role = 0; role < targets.size(); ++role)
        {
            auto& target = targets[role];
            DWORD exit = STILL_ACTIVE;
            if(!target.terminal || WaitForSingleObject(target.process.get(), 1000) != WAIT_OBJECT_0 || !GetExitCodeProcess(target.process.get(), &exit) || exit != 7)
                return 25;
            std::printf("SESSION_TARGET_TERMINAL role=%u pid=%lu exit=%lu breaks=%u helperBreaks=%u helperExits=%u\n", role, target.processId, exit, target.breaks, target.helperBreaks, target.exits);
        }
        if(targets[0].breaks != 2 || targets[1].breaks != 2 || targets[0].helperBreaks != unsigned(!registration) || targets[1].helperBreaks != 1 || targets[0].exits != 1 || targets[1].exits != 1)
            return 30;
        std::printf("SESSION_ROUND round=%u completed=1\n", round);
        std::fflush(stdout);
        if(cleanup)
            FixtureNativeCleanup::Reset();
        return 0;
    }

    struct PendingCreation
    {
        OwnedHandle reached{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        OwnedHandle release{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        OwnedHandle thread;
        std::thread worker;
        NativeBreakIn::Result result{};

        ~PendingCreation()
        {
            if(release)
                SetEvent(release.get());
            if(worker.joinable())
                worker.join();
            FixtureNativeCreation::ConfigureGate(nullptr, nullptr);
        }
    };

    int RunInFlight(const wchar_t* mode, const wchar_t* phase, const wchar_t* action)
    {
        const bool before = std::wcscmp(phase, L"before") == 0;
        const bool shutdown = std::wcscmp(action, L"shutdown") == 0;
        if((!before && std::wcscmp(phase, L"after")) || (!shutdown && std::wcscmp(action, L"end")) ||
                (std::wcscmp(mode, L"show") && std::wcscmp(mode, L"hide") && std::wcscmp(mode, L"both")))
            return 34;
        wchar_t binary[32768]{};
        OwnedSessionTarget target;
        PendingCreation pending;
        if(!pending.reached || !pending.release || !GetModuleFileNameW(nullptr, binary, 32768) || !StartTarget(target, binary, mode, L"normal"))
            return 35;
        std::printf("INFLIGHT phase=%ls action=%ls pid=%lu creation=%llu controllerCreation=%llu\n", phase, action, target.processId, CreationTime(target.process.get(), false), CreationTime(GetCurrentProcess(), false));
        std::fflush(stdout);
        bool requested = false, released = false;
        FixtureNativeCreation::Observation created;
        const auto deadline = GetTickCount64() + 20000;
        while(GetTickCount64() < deadline)
        {
            DEBUG_EVENT event{};
            if(!WaitForDebugEvent(&event, 1000))
            {
                if(GetLastError() == ERROR_SEM_TIMEOUT)
                    continue;
                return 36;
            }
            if(event.dwProcessId != target.processId)
                return 37;
            DWORD status = DBG_CONTINUE;
            if(event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && event.u.LoadDll.hFile)
            {
                wchar_t path[32768]{};
                if(GetFinalPathNameByHandleW(event.u.LoadDll.hFile, path, 32768, FILE_NAME_NORMALIZED))
                {
                    const auto length = std::wcslen(path);
                    if(length >= 9 && _wcsicmp(path + length - 9, L"ntdll.dll") == 0)
                        target.ntdllBase = reinterpret_cast<std::uintptr_t>(event.u.LoadDll.lpBaseOfDll);
                }
                CloseHandle(event.u.LoadDll.hFile);
            }
            if(event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && event.u.CreateProcessInfo.hFile)
                CloseHandle(event.u.CreateProcessInfo.hFile);
            if(event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT)
            {
                NativeBreakIn::BindThread(event.dwProcessId, event.dwThreadId, event.u.CreateThread);
                if(requested && event.dwThreadId == created.threadId)
                {
                    HANDLE duplicate = nullptr;
                    if(target.helper || event.u.CreateThread.lpStartAddress != target.remoteCode ||
                            !DuplicateHandle(GetCurrentProcess(), event.u.CreateThread.hThread, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
                        return 38;
                    target.helper.reset(duplicate);
                    target.threadId = event.dwThreadId;
                    if(GetProcessIdOfThread(target.helper.get()) != target.processId || CreationTime(target.helper.get(), true) != created.creation)
                        return 39;
                    std::printf("INFLIGHT_HELPER pid=%lu thread=%lu creation=%llu code=%p\n", target.processId, target.threadId, created.creation, target.remoteCode);
                }
            }
            if(event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
            {
                if(event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
                {
                    if(target.helper && event.dwThreadId == target.threadId)
                    {
                        const auto consumed = NativeBreakIn::Consume(event.dwProcessId, event.dwThreadId, event.u.Exception);
                        const auto repeated = NativeBreakIn::Consume(event.dwProcessId, event.dwThreadId, event.u.Exception);
                        std::printf("INFLIGHT_CONSUME pid=%lu thread=%lu consumed=%u repeated=%u\n", target.processId, target.threadId, unsigned(consumed), unsigned(repeated));
                        if(consumed || repeated)
                            return 40;
                        ++target.helperBreaks;
                        status = DBG_EXCEPTION_NOT_HANDLED;
                    }
                    else
                        ++target.breaks;
                }
                else
                    status = DBG_EXCEPTION_NOT_HANDLED;
            }
            if(event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT && target.helper && event.dwThreadId == target.threadId)
                ++target.exits;
            if(event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
            {
                if(event.u.ExitProcess.dwExitCode != 7)
                    return 41;
                target.terminal = true;
            }
            std::fflush(stdout);
            if(!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status))
                return 42;
            if(!requested && target.breaks == 2)
            {
                requested = true;
                FixtureNativeCreation::ConfigureGate(pending.reached.get(), pending.release.get());
                FixtureNativeCreation::Configure(before ? FixtureNativeCreation::Mode::HeldBeforeCreation : FixtureNativeCreation::Mode::HeldAfterCreation);
                if(!NativeBreakIn::BeginTarget(target.process.get()))
                    return 43;
                pending.worker = std::thread([&] { pending.result = NativeBreakIn::Create(target.ntdllBase); });
                if(WaitForSingleObject(pending.reached.get(), 5000) != WAIT_OBJECT_0)
                    return 44;
                HANDLE worker = nullptr;
                if(!DuplicateHandle(GetCurrentProcess(), pending.worker.native_handle(), GetCurrentProcess(), &worker, 0, FALSE, DUPLICATE_SAME_ACCESS))
                    return 55;
                pending.thread.reset(worker);
                const auto workerId = GetThreadId(worker);
                const auto workerCreation = CreationTime(worker, true);
                if(!workerId || !workerCreation || GetProcessIdOfThread(worker) != GetCurrentProcessId() || WaitForSingleObject(worker, 0) != WAIT_TIMEOUT || WaitForSingleObject(pending.release.get(), 0) != WAIT_TIMEOUT)
                    return 56;
                std::printf("INFLIGHT_WORKER pid=%lu thread=%lu creation=%llu alive=1 releasePending=1\n", GetCurrentProcessId(), workerId, workerCreation);
                const auto held = FixtureNativeCreation::Capture();
                target.remoteCode = held.start;
                SIZE_T copied = 0;
                if(held.processId != target.processId || !target.remoteCode || held.calls != 1 ||
                        (before ? held.threadId != 0 : !held.nativeCreated) ||
                        !ReadProcessMemory(target.process.get(), target.remoteCode, target.originalCode.data(), target.originalCode.size(), &copied) || copied != target.originalCode.size())
                    return 45;
                std::printf("INFLIGHT_RETENTION phase=held\n");
                if(!VerifyRetainedPages(target))
                    return 46;
                if(shutdown)
                    NativeBreakIn::Shutdown();
                else
                    NativeBreakIn::EndTarget();
                const auto rejected = NativeBreakIn::Create(0);
                if(rejected.created || rejected.error != ERROR_BUSY || (shutdown && NativeBreakIn::BeginTarget(target.process.get())))
                    return 47;
                if(WaitForSingleObject(worker, 0) != WAIT_TIMEOUT || WaitForSingleObject(pending.release.get(), 0) != WAIT_TIMEOUT)
                    return 57;
                std::printf("INFLIGHT_RETIRE action=%ls createRejected=1 error=%lu workerPending=1\n", action, rejected.error);
                std::printf("INFLIGHT_RETENTION phase=retired\n");
                if(!VerifyRetainedPages(target) || !SetEvent(pending.release.get()))
                    return 48;
                pending.worker.join();
                DWORD workerExit = STILL_ACTIVE;
                if(WaitForSingleObject(worker, 0) != WAIT_OBJECT_0 || !GetExitCodeThread(worker, &workerExit) || workerExit != 0)
                    return 58;
                std::printf("INFLIGHT_WORKER_TERMINAL pid=%lu thread=%lu creation=%llu exit=%lu\n", GetCurrentProcessId(), workerId, workerCreation, workerExit);
                created = FixtureNativeCreation::Capture();
                FixtureNativeCreation::Configure(FixtureNativeCreation::Mode::Normal);
                std::printf("INFLIGHT_RETURN created=%u status=%08lx error=%lu pid=%lu thread=%lu creation=%llu code=%p\n", unsigned(pending.result.created), pending.result.status, pending.result.error, created.processId, created.threadId, created.creation, created.start);
                std::fflush(stdout);
                if(!pending.result.created || pending.result.status != 0 || pending.result.error != 0 || !created.nativeCreated || !created.nativeHandleValid || created.handleClosed || created.processId != target.processId || created.start != target.remoteCode)
                    return 49;
            }
            if(!released && target.exits == 1)
            {
                DWORD exit = STILL_ACTIVE;
                if(WaitForSingleObject(target.helper.get(), 3000) != WAIT_OBJECT_0 || !GetExitCodeThread(target.helper.get(), &exit) || exit != 0)
                    return 50;
                std::printf("INFLIGHT_THREAD_TERMINAL pid=%lu thread=%lu exit=%lu\n", target.processId, target.threadId, exit);
                if(!VerifyPages(target, 0, !shutdown))
                    return 51;
                if(shutdown)
                {
                    std::printf("INFLIGHT_RETENTION phase=completed\n");
                    if(!VerifyRetainedPages(target))
                        return 52;
                }
                released = SetEvent(target.completion.get()) != FALSE;
                if(!released)
                    return 53;
            }
            if(target.terminal)
                break;
        }
        NativeBreakIn::EndTarget();
        NativeBreakIn::Shutdown();
        DWORD exit = STILL_ACTIVE;
        if(!target.terminal || !released || target.breaks != 2 || target.helperBreaks != 1 || target.exits != 1 ||
                WaitForSingleObject(target.process.get(), 1000) != WAIT_OBJECT_0 || !GetExitCodeProcess(target.process.get(), &exit) || exit != 7)
            return 54;
        std::printf("INFLIGHT_TARGET_TERMINAL pid=%lu exit=%lu breaks=%u helperBreaks=%u helperExits=%u\n", target.processId, exit, target.breaks, target.helperBreaks, target.exits);
        std::fflush(stdout);
        return 0;
    }

    constexpr unsigned RetainedRequestLimit = 64;

    struct NativeSnapshot
    {
        unsigned long long addressEnd = 0;
        std::vector<std::pair<DWORD, unsigned long long>> threads;
        std::vector<std::tuple<std::uintptr_t, SIZE_T, DWORD, DWORD, DWORD, std::uintptr_t>> memory;
    };

    static bool Snapshot(OwnedSessionTarget& target, NativeSnapshot& result)
    {
        OwnedHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
        if(snapshot.get() == INVALID_HANDLE_VALUE)
        {
            snapshot.release();
            return false;
        }
        THREADENTRY32 thread{};
        thread.dwSize = sizeof(thread);
        if(!snapshot || !Thread32First(snapshot.get(), &thread))
            return false;
        do
        {
            if(thread.th32OwnerProcessID != target.processId)
                continue;
            OwnedHandle handle(OpenThread(THREAD_QUERY_INFORMATION | SYNCHRONIZE, FALSE, thread.th32ThreadID));
            const auto creation = handle ? CreationTime(handle.get(), true) : 0;
            if(!creation || GetProcessIdOfThread(handle.get()) != target.processId || WaitForSingleObject(handle.get(), 0) != WAIT_TIMEOUT)
                return false;
            result.threads.emplace_back(thread.th32ThreadID, creation);
        }
        while(Thread32Next(snapshot.get(), &thread));
        if(GetLastError() != ERROR_NO_MORE_FILES)
            return false;
        std::sort(result.threads.begin(), result.threads.end());
        std::uintptr_t address = 0;
        while(true)
        {
            MEMORY_BASIC_INFORMATION region{};
            if(VirtualQueryEx(target.process.get(), reinterpret_cast<void*>(address), &region, sizeof(region)) != sizeof(region))
            {
                if(GetLastError() != ERROR_INVALID_PARAMETER || !address)
                    return false;
                break;
            }
            const auto base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
            const auto allocation = region.State == MEM_FREE ? 0 : reinterpret_cast<std::uintptr_t>(region.AllocationBase);
            result.memory.emplace_back(base, region.RegionSize, region.State, region.State == MEM_COMMIT ? region.Protect : 0, region.State == MEM_COMMIT ? region.Type : 0, allocation);
            result.addressEnd = static_cast<unsigned long long>(base) + region.RegionSize;
            if(region.RegionSize > std::numeric_limits<std::uintptr_t>::max() - base)
            {
                if constexpr(sizeof(std::uintptr_t) == 4)
                {
                    if(region.RegionSize - 1 != std::numeric_limits<std::uintptr_t>::max() - base)
                        return false;
                    break;
                }
                else
                    return false;
            }
            const auto next = base + region.RegionSize;
            if(next <= address)
                return false;
            address = next;
        }
        return !result.threads.empty() && WaitForSingleObject(target.process.get(), 0) == WAIT_TIMEOUT;
    }

    struct RetainedHelper
    {
        FixtureNativeCreation::Observation creation;
        OwnedHandle thread;
        std::array<unsigned char, NativeBreakInPayload::CodePageSize> code{};
        unsigned breaks = 0, exits = 0;
    };

    static bool VerifyQuotaPages(OwnedSessionTarget& target, const std::vector<RetainedHelper>& helpers, const char* phase)
    {
        const auto begin = GetTickCount64();
        unsigned samples = 0;
        do
        {
            if(WaitForSingleObject(target.process.get(), 0) != WAIT_TIMEOUT)
                return false;
            for(const auto& helper : helpers)
            {
                MEMORY_BASIC_INFORMATION code{}, data{};
                std::array<unsigned char, NativeBreakInPayload::CodePageSize> observed{};
                SIZE_T copied = 0;
                const auto start = helper.creation.start;
                if(VirtualQueryEx(target.process.get(), start, &code, sizeof(code)) != sizeof(code) ||
                        VirtualQueryEx(target.process.get(), static_cast<unsigned char*>(start) + NativeBreakInPayload::CodePageSize, &data, sizeof(data)) != sizeof(data) ||
                        code.AllocationBase != start || data.AllocationBase != start || code.State != MEM_COMMIT || data.State != MEM_COMMIT ||
                        code.Type != MEM_PRIVATE || data.Type != MEM_PRIVATE || code.Protect != PAGE_EXECUTE_READ || data.Protect != PAGE_READWRITE ||
                        !ReadProcessMemory(target.process.get(), start, observed.data(), observed.size(), &copied) || copied != observed.size() || observed != helper.code)
                    return false;
            }
            ++samples;
            Sleep(1);
        }
        while(GetTickCount64() - begin < 250);
        std::printf("QUOTA_RETAIN phase=%s pid=%lu requests=%zu alive=1 executable=00000020 data=00000004 unchanged=1 bytes=%zu samples=%u elapsed=%llu\n", phase, target.processId, helpers.size(), helpers.front().code.size(), samples, GetTickCount64() - begin);
        std::fflush(stdout);
        return helpers.size() == RetainedRequestLimit;
    }

    static bool FillQuota(std::array<OwnedSessionTarget, 2>& targets, std::vector<RetainedHelper>& helpers)
    {
        FixtureNativeCreation::Configure(FixtureNativeCreation::Mode::ControlledFailure);
        for(unsigned index = 0; index < RetainedRequestLimit; ++index)
        {
            if(!NativeBreakIn::BeginTarget(targets[0].process.get()))
                return false;
            const auto result = NativeBreakIn::Create(targets[0].ntdllBase);
            RetainedHelper helper;
            helper.creation = FixtureNativeCreation::Capture();
            SIZE_T copied = 0;
            if(result.created || result.status != static_cast<LONG>(0xc0000022) || result.error != ERROR_ACCESS_DENIED ||
                    !helper.creation.nativeCreated || !helper.creation.handleClosed || helper.creation.processId != targets[0].processId || helper.creation.calls != index + 1 ||
                    !ReadProcessMemory(targets[0].process.get(), helper.creation.start, helper.code.data(), helper.code.size(), &copied) || copied != helper.code.size())
                return false;
            for(const auto& previous : helpers)
                if(previous.creation.start == helper.creation.start || previous.creation.threadId == helper.creation.threadId)
                    return false;
            helpers.push_back(std::move(helper));
            NativeBreakIn::EndTarget();
        }
        if(!NativeBreakIn::BeginTarget(targets[1].process.get()) || !VerifyQuotaPages(targets[0], helpers, "full"))
            return false;
        std::array<NativeSnapshot, 2> before, after;
        for(unsigned role = 0; role < targets.size(); ++role)
            if(!Snapshot(targets[role], before[role]))
                return false;
        for(const auto& helper : helpers)
            if(std::find(before[0].threads.begin(), before[0].threads.end(), std::make_pair(helper.creation.threadId, helper.creation.creation)) == before[0].threads.end())
                return false;
        for(unsigned attempt = 0; attempt < 4; ++attempt)
        {
            const auto rejected = NativeBreakIn::Create(targets[1].ntdllBase);
            const auto unchanged = FixtureNativeCreation::Capture().calls == RetainedRequestLimit;
            std::printf("QUOTA_REJECT attempt=%u created=%u status=%08lx error=%lu calls=%u unchanged=%u\n", attempt, unsigned(rejected.created), rejected.status, rejected.error, FixtureNativeCreation::Capture().calls, unsigned(unchanged));
            if(rejected.created || rejected.status != 0 || rejected.error != ERROR_BUSY || !unchanged)
                return false;
        }
        for(unsigned role = 0; role < targets.size(); ++role)
        {
            if(!Snapshot(targets[role], after[role]) || before[role].threads != after[role].threads || before[role].memory != after[role].memory || before[role].addressEnd != after[role].addressEnd)
                return false;
            std::printf("QUOTA_NO_EFFECT role=%u pid=%lu threads=%zu regions=%zu addressEnd=%llx sameThreads=1 sameMemory=1\n", role, targets[role].processId, after[role].threads.size(), after[role].memory.size(), after[role].addressEnd);
        }
        std::fflush(stdout);
        return true;
    }

    int RunQuota(const wchar_t* mode)
    {
        if(std::wcscmp(mode, L"show") && std::wcscmp(mode, L"hide") && std::wcscmp(mode, L"both"))
            return 59;
        wchar_t binary[32768]{};
        std::array<OwnedSessionTarget, 2> targets;
        std::vector<RetainedHelper> helpers;
        helpers.reserve(RetainedRequestLimit);
        if(!GetModuleFileNameW(nullptr, binary, 32768))
            return 60;
        for(auto& target : targets)
            if(!StartTarget(target, binary, mode, L"normal"))
                return 61;
        std::printf("QUOTA limit=%u old=%lu oldCreation=%llu next=%lu nextCreation=%llu controller=%lu controllerCreation=%llu\n", RetainedRequestLimit, targets[0].processId, CreationTime(targets[0].process.get(), false), targets[1].processId, CreationTime(targets[1].process.get(), false), GetCurrentProcessId(), CreationTime(GetCurrentProcess(), false));
        std::fflush(stdout);
        bool filled = false, oldReleased = false, nextRequested = false, nextReleased = false;
        const auto deadline = GetTickCount64() + 20000;
        while(GetTickCount64() < deadline)
        {
            DEBUG_EVENT event{};
            if(!WaitForDebugEvent(&event, 1000))
            {
                if(GetLastError() == ERROR_SEM_TIMEOUT)
                    continue;
                return 62;
            }
            const auto role = event.dwProcessId == targets[0].processId ? 0u : event.dwProcessId == targets[1].processId ? 1u : 2u;
            if(role == 2)
                return 63;
            auto& target = targets[role];
            auto helper = std::find_if(helpers.begin(), helpers.end(), [&](const RetainedHelper& item) { return role == 0 && item.creation.threadId == event.dwThreadId; });
            DWORD status = DBG_CONTINUE;
            if(event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && event.u.LoadDll.hFile)
            {
                wchar_t path[32768]{};
                if(GetFinalPathNameByHandleW(event.u.LoadDll.hFile, path, 32768, FILE_NAME_NORMALIZED))
                {
                    const auto length = std::wcslen(path);
                    if(length >= 9 && _wcsicmp(path + length - 9, L"ntdll.dll") == 0)
                        target.ntdllBase = reinterpret_cast<std::uintptr_t>(event.u.LoadDll.lpBaseOfDll);
                }
                CloseHandle(event.u.LoadDll.hFile);
            }
            if(event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && event.u.CreateProcessInfo.hFile)
                CloseHandle(event.u.CreateProcessInfo.hFile);
            if(event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT)
            {
                NativeBreakIn::BindThread(event.dwProcessId, event.dwThreadId, event.u.CreateThread);
                if(helper != helpers.end())
                {
                    HANDLE duplicate = nullptr;
                    if(helper->thread || helper->creation.start != event.u.CreateThread.lpStartAddress ||
                            !DuplicateHandle(GetCurrentProcess(), event.u.CreateThread.hThread, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
                        return 64;
                    helper->thread.reset(duplicate);
                    if(GetProcessIdOfThread(duplicate) != target.processId || CreationTime(duplicate, true) != helper->creation.creation)
                        return 65;
                    std::printf("QUOTA_HELPER index=%zu pid=%lu thread=%lu creation=%llu code=%p\n", std::size_t(helper - helpers.begin()), target.processId, event.dwThreadId, helper->creation.creation, helper->creation.start);
                }
                else if(role == 1 && nextRequested)
                {
                    MEMORY_BASIC_INFORMATION memory{};
                    if(VirtualQueryEx(target.process.get(), event.u.CreateThread.lpStartAddress, &memory, sizeof(memory)) == sizeof(memory) && memory.State == MEM_COMMIT && memory.Type == MEM_PRIVATE && memory.Protect == PAGE_EXECUTE_READ && memory.AllocationBase == event.u.CreateThread.lpStartAddress)
                    {
                        HANDLE duplicate = nullptr;
                        if(target.helper || !DuplicateHandle(GetCurrentProcess(), event.u.CreateThread.hThread, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
                            return 66;
                        target.helper.reset(duplicate);
                        target.threadId = event.dwThreadId;
                        target.remoteCode = event.u.CreateThread.lpStartAddress;
                        std::printf("QUOTA_NEXT_HELPER pid=%lu thread=%lu creation=%llu code=%p\n", target.processId, target.threadId, CreationTime(duplicate, true), target.remoteCode);
                    }
                }
            }
            if(event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
            {
                if(event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
                {
                    if(helper != helpers.end() || (role == 1 && target.helper && event.dwThreadId == target.threadId))
                    {
                        const auto consumed = NativeBreakIn::Consume(event.dwProcessId, event.dwThreadId, event.u.Exception);
                        const auto repeated = NativeBreakIn::Consume(event.dwProcessId, event.dwThreadId, event.u.Exception);
                        std::printf("QUOTA_CONSUME role=%u thread=%lu consumed=%u repeated=%u\n", role, event.dwThreadId, unsigned(consumed), unsigned(repeated));
                        if(consumed != bool(role) || repeated)
                            return 67;
                        ++target.helperBreaks;
                        if(role == 0)
                        {
                            ++helper->breaks;
                            status = DBG_EXCEPTION_NOT_HANDLED;
                        }
                    }
                    else
                        ++target.breaks;
                }
                else
                    status = DBG_EXCEPTION_NOT_HANDLED;
            }
            if(event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT && (helper != helpers.end() || (role == 1 && target.helper && event.dwThreadId == target.threadId)))
            {
                if(role == 0)
                    ++helper->exits;
                ++target.exits;
            }
            if(event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
            {
                if(event.u.ExitProcess.dwExitCode != 7)
                    return 68;
                target.terminal = true;
            }
            std::fflush(stdout);
            if(!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status))
                return 69;
            if(!filled && targets[0].breaks == 2 && targets[1].breaks == 2)
            {
                if(!FillQuota(targets, helpers))
                    return 70;
                filled = true;
            }
            if(!oldReleased && targets[0].exits == RetainedRequestLimit)
            {
                for(std::size_t index = 0; index < helpers.size(); ++index)
                {
                    auto& item = helpers[index];
                    DWORD exit = STILL_ACTIVE;
                    if(!item.thread || item.breaks != 1 || item.exits != 1 || WaitForSingleObject(item.thread.get(), 1000) != WAIT_OBJECT_0 || !GetExitCodeThread(item.thread.get(), &exit) || exit != 0)
                        return 71;
                    std::printf("QUOTA_THREAD_TERMINAL index=%zu pid=%lu thread=%lu exit=%lu\n", index, targets[0].processId, item.creation.threadId, exit);
                }
                const auto rejected = NativeBreakIn::Create(targets[1].ntdllBase);
                if(rejected.created || rejected.error != ERROR_BUSY || FixtureNativeCreation::Capture().calls != RetainedRequestLimit || !VerifyQuotaPages(targets[0], helpers, "threads-completed"))
                    return 72;
                std::printf("QUOTA_STILL_FULL requests=%u error=%lu calls=%u\n", RetainedRequestLimit, rejected.error, FixtureNativeCreation::Capture().calls);
                std::fflush(stdout);
                oldReleased = SetEvent(targets[0].completion.get()) != FALSE;
                if(!oldReleased)
                    return 73;
            }
            if(targets[0].terminal && !nextRequested)
            {
                DWORD exit = STILL_ACTIVE;
                if(WaitForSingleObject(targets[0].process.get(), 1000) != WAIT_OBJECT_0 || !GetExitCodeProcess(targets[0].process.get(), &exit) || exit != 7)
                    return 74;
                std::printf("QUOTA_OLD_TERMINAL pid=%lu exit=%lu helpers=%u\n", targets[0].processId, exit, targets[0].exits);
                FixtureNativeCreation::Configure(FixtureNativeCreation::Mode::Normal);
                NativeBreakIn::Result recovered{};
                unsigned attempts = 0;
                const auto recoveryDeadline = GetTickCount64() + 3000;
                do
                {
                    recovered = NativeBreakIn::Create(targets[1].ntdllBase);
                    ++attempts;
                    if(recovered.created)
                        break;
                    if(recovered.error != ERROR_BUSY)
                        return 75;
                    Sleep(1);
                }
                while(GetTickCount64() < recoveryDeadline);
                if(!recovered.created || recovered.status != 0 || recovered.error != 0)
                    return 76;
                std::printf("QUOTA_RECOVERY created=1 status=%08lx error=%lu attempts=%u oldTerminal=1\n", recovered.status, recovered.error, attempts);
                std::fflush(stdout);
                nextRequested = true;
            }
            if(nextRequested && !nextReleased && targets[1].exits == 1)
            {
                DWORD exit = STILL_ACTIVE;
                if(WaitForSingleObject(targets[1].helper.get(), 1000) != WAIT_OBJECT_0 || !GetExitCodeThread(targets[1].helper.get(), &exit) || exit != 0 || !VerifyPages(targets[1], 1, true))
                    return 77;
                std::printf("QUOTA_NEXT_THREAD_TERMINAL pid=%lu thread=%lu exit=%lu\n", targets[1].processId, targets[1].threadId, exit);
                std::fflush(stdout);
                nextReleased = SetEvent(targets[1].completion.get()) != FALSE;
                if(!nextReleased)
                    return 78;
            }
            if(targets[0].terminal && targets[1].terminal)
                break;
        }
        NativeBreakIn::EndTarget();
        NativeBreakIn::Shutdown();
        for(unsigned role = 0; role < targets.size(); ++role)
        {
            auto& target = targets[role];
            DWORD exit = STILL_ACTIVE;
            const auto count = role ? 1u : RetainedRequestLimit;
            if(!target.terminal || target.breaks != 2 || target.helperBreaks != count || target.exits != count ||
                    WaitForSingleObject(target.process.get(), 1000) != WAIT_OBJECT_0 || !GetExitCodeProcess(target.process.get(), &exit) || exit != 7)
                return 79;
            std::printf("QUOTA_TARGET_TERMINAL role=%u pid=%lu exit=%lu breaks=%u helperBreaks=%u helperExits=%u\n", role, target.processId, exit, target.breaks, target.helperBreaks, target.exits);
        }
        std::fflush(stdout);
        return filled && oldReleased && nextRequested && nextReleased ? 0 : 80;
    }

    int RunReplacement(const wchar_t* mode, const wchar_t* kind, unsigned rounds)
    {
        const bool cleanupShutdown = std::wcscmp(kind, L"cleanup-shutdown") == 0;
        if(rounds == 0 || rounds > MaxReplacementRounds || (cleanupShutdown && rounds != 1) ||
                (std::wcscmp(kind, L"normal") && std::wcscmp(kind, L"partial") && std::wcscmp(kind, L"register") && std::wcscmp(kind, L"remove") && std::wcscmp(kind, L"cleanup") && !cleanupShutdown))
            return 31;
        if(std::wcscmp(mode, L"show") && std::wcscmp(mode, L"hide") && std::wcscmp(mode, L"both"))
            return 31;
        wchar_t binary[32768]{};
        if(!GetModuleFileNameW(nullptr, binary, 32768))
            return 32;
        for(unsigned round = 0; round < rounds; ++round)
        {
            const auto result = RunRound(binary, mode, kind, round);
            if(result)
            {
                NativeBreakIn::Shutdown();
                return result;
            }
        }
        NativeBreakIn::Shutdown();
        const auto rejected = NativeBreakIn::Create(0);
        std::printf("SESSION_FINISH rounds=%u createRejected=%u error=%lu\n", rounds, unsigned(!rejected.created), rejected.error);
        std::fflush(stdout);
        return !rejected.created && rejected.error == ERROR_BUSY ? 0 : 33;
    }
}
