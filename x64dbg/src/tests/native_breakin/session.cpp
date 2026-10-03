
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
        std::array<unsigned char, 64> originalCode{};
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
            std::array<unsigned char, 64> observed{};
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
        const DWORD oldExit = registration ? 2u : removal ? 1u : 0u;
        std::array<OwnedSessionTarget, 2> targets;
        for(unsigned role = 0; role < targets.size(); ++role)
            if(!StartTarget(targets[role], binary, mode, role ? L"normal" : kind))
                return 11;
        std::printf("SESSION round=%u old=%lu oldCreation=%llu next=%lu nextCreation=%llu partial=%u registration=%u removal=%u\n", round, targets[0].processId, CreationTime(targets[0].process.get(), false), targets[1].processId, CreationTime(targets[1].process.get(), false), unsigned(partial), unsigned(registration), unsigned(removal));
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
                if(!VerifyPages(targets[0], 0, !partial && !removal) || !VerifyPages(targets[1], 1, true) || ((partial || removal) && !VerifyRetainedPages(targets[0])))
                    return 23;
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

    int RunReplacement(const wchar_t* mode, const wchar_t* kind, unsigned rounds)
    {
        if(rounds == 0 || rounds > MaxReplacementRounds || (std::wcscmp(kind, L"normal") && std::wcscmp(kind, L"partial") && std::wcscmp(kind, L"register") && std::wcscmp(kind, L"remove")))
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
