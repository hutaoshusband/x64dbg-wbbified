#include "native_creator.h"
#include "../../dbg/native_breakin_payload.h"
#include <winternl.h>
#include <tlhelp32.h>
#include <memory>
#include <vector>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <array>

extern "C" LONG NTAPI LdrGetProcedureAddress(void*, const ANSI_STRING*, ULONG, void**);

namespace FixtureNativeCreation
{
    namespace
    {
        constexpr ULONG ThreadQuerySetWin32StartAddress = 9;
        using NativeCreate = LONG(NTAPI*)(HANDLE*, ACCESS_MASK, void*, HANDLE, void*, void*, ULONG, SIZE_T, SIZE_T, SIZE_T, void*);
        std::atomic<Mode> creationMode{Mode::Normal};
        std::atomic<NativeCreate> nativeCreate{nullptr};
        std::atomic<HANDLE> gateReached{nullptr}, gateRelease{nullptr};
        Observation observation;

        bool HoldCreation(const char* phase)
        {
            std::printf("CREATION_GATE phase=%s pid=%lu thread=%lu creation=%llu start=%p calls=%u\n", phase,
                        observation.processId, observation.threadId, observation.creation, observation.start, observation.calls);
            std::fflush(stdout);
            const auto reached = gateReached.load();
            const auto release = gateRelease.load();
            return reached && release && SetEvent(reached) && WaitForSingleObject(release, 10000) == WAIT_OBJECT_0;
        }

        FARPROC Lookup(HMODULE module, LPCSTR name)
        {
            ANSI_STRING string{};
            ULONG ordinal = 0;
            const ANSI_STRING* requested = nullptr;
            if(reinterpret_cast<ULONG_PTR>(name) <= 0xffff)
                ordinal = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(name));
            else
            {
                const auto length = std::strlen(name);
                if(length > 0xfffe)
                {
                    SetLastError(ERROR_INVALID_PARAMETER);
                    return nullptr;
                }
                string.Length = static_cast<USHORT>(length);
                string.MaximumLength = static_cast<USHORT>(length + 1);
                string.Buffer = const_cast<char*>(name);
                requested = &string;
            }
            void* address = nullptr;
            const auto status = LdrGetProcedureAddress(module, requested, ordinal, &address);
            if(status < 0)
            {
                SetLastError(RtlNtStatusToDosError(status));
                return nullptr;
            }
            return reinterpret_cast<FARPROC>(address);
        }

        struct HandleCloser
        {
            void operator()(HANDLE handle) const
            {
                if(handle && handle != INVALID_HANDLE_VALUE)
                    CloseHandle(handle);
            }
        };

        using OwnedHandle = std::unique_ptr<void, HandleCloser>;

        struct ThreadIdentity
        {
            DWORD id;
            unsigned long long creation;
        };

        static unsigned long long CreationTime(const FILETIME& time)
        {
            return (static_cast<unsigned long long>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
        }

        static bool Threads(DWORD processId, std::vector<ThreadIdentity>& threads)
        {
            OwnedHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
            if(snapshot.get() == INVALID_HANDLE_VALUE)
                return false;
            THREADENTRY32 entry{};
            entry.dwSize = sizeof(entry);
            if(!Thread32First(snapshot.get(), &entry))
                return false;
            do
            {
                if(entry.th32OwnerProcessID == processId)
                {
                    OwnedHandle thread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID));
                    FILETIME creation{}, exit{}, kernel{}, user{};
                    if(!thread || GetProcessIdOfThread(thread.get()) != processId || !GetThreadTimes(thread.get(), &creation, &exit, &kernel, &user))
                        return false;
                    threads.push_back({entry.th32ThreadID, CreationTime(creation)});
                }
            }
            while(Thread32Next(snapshot.get(), &entry));
            return GetLastError() == ERROR_NO_MORE_FILES;
        }

        static bool ObserveThread(HANDLE thread, DWORD processId, void* start, unsigned long long creationTime, DWORD& suspended, DWORD& restored)
        {
            using Query = LONG(NTAPI*)(HANDLE, ULONG, void*, ULONG, ULONG*);
            const auto query = reinterpret_cast<Query>(Lookup(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
            void* address = nullptr;
            ULONG length = 0;
            FILETIME creation{}, exit{}, kernel{}, user{};
            if(!query || GetProcessIdOfThread(thread) != processId || !GetThreadTimes(thread, &creation, &exit, &kernel, &user) ||
                    CreationTime(creation) != creationTime || WaitForSingleObject(thread, 0) != WAIT_TIMEOUT ||
                    query(thread, ThreadQuerySetWin32StartAddress, &address, sizeof(address), &length) < 0 || length != sizeof(address) || address != start)
                return false;
            suspended = SuspendThread(thread);
            if(suspended == MAXDWORD)
                return false;
            restored = ResumeThread(thread);
            return restored != MAXDWORD && restored == suspended + 1 && WaitForSingleObject(thread, 0) == WAIT_TIMEOUT;
        }

        static bool ObserveCreatedThread(const std::vector<ThreadIdentity>& before, DWORD processId, void* start)
        {
            std::vector<ThreadIdentity> after;
            if(!Threads(processId, after))
                return false;
            observation.beforeThreads = static_cast<unsigned>(before.size());
            observation.afterThreads = static_cast<unsigned>(after.size());
            unsigned matches = 0;
            for(const auto& identity : after)
            {
                bool existing = false;
                for(const auto& previous : before)
                    existing = existing || (identity.id == previous.id && identity.creation == previous.creation);
                if(existing)
                    continue;
                OwnedHandle thread(OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | SYNCHRONIZE, FALSE, identity.id));
                DWORD suspended = MAXDWORD, restored = MAXDWORD;
                if(thread && ObserveThread(thread.get(), processId, start, identity.creation, suspended, restored))
                {
                    ++matches;
                    observation.threadId = identity.id;
                    observation.creation = identity.creation;
                    observation.suspendBefore = suspended;
                    observation.suspendRestored = restored;
                }
            }
            return matches == 1;
        }

        LONG NTAPI Create(HANDLE* handle, ACCESS_MASK access, void* attributes, HANDLE process, void* start, void* argument, ULONG flags, SIZE_T zero, SIZE_T commit, SIZE_T reserve, void* list)
        {
            const auto calls = observation.calls + 1;
            observation = {};
            observation.calls = calls;
            const auto mode = creationMode.load();
            const auto reduced = mode == Mode::ReducedAccess;
            std::vector<ThreadIdentity> before;
            observation.processId = GetProcessId(process);
            observation.start = start;
            const auto beforeObserved = !reduced || Threads(observation.processId, before);
            const auto actualAccess = reduced ? THREAD_QUERY_INFORMATION | SYNCHRONIZE : access;
            const auto native = nativeCreate.load();
            if(mode == Mode::HeldBeforeCreation && !HoldCreation("before"))
            {
                SetLastError(ERROR_TIMEOUT);
                return static_cast<LONG>(0xc0000102);
            }
            const auto status = native(handle, actualAccess, attributes, process, start, argument, flags, zero, commit, reserve, list);
            const auto error = GetLastError();
            observation.nativeStatus = status;
            observation.start = start;
            DWORD handleFlags = 0;
            observation.nativeHandleValid = *handle && GetHandleInformation(*handle, &handleFlags) != FALSE;
            observation.nativeHandleError = observation.nativeHandleValid ? ERROR_SUCCESS : GetLastError();
            if(reduced)
            {
                observation.threadObserved = beforeObserved && ObserveCreatedThread(before, observation.processId, start);
                observation.nativeCreated = observation.threadObserved;
                std::printf("NATIVE_CREATOR status=%08lx requestedAccess=%08lx actualAccess=%08lx flags=%lu pid=%lu thread=%lu creation=%llu start=%p handleValid=%u handleError=%lu before=%u after=%u observed=%u suspend=%lu restore=%lu calls=%u\n",
                            status, access, actualAccess, flags, observation.processId, observation.threadId, observation.creation, start,
                            unsigned(observation.nativeHandleValid), observation.nativeHandleError, observation.beforeThreads, observation.afterThreads,
                            unsigned(observation.threadObserved), observation.suspendBefore, observation.suspendRestored, observation.calls);
                std::fflush(stdout);
                SetLastError(error);
                return status;
            }
            FILETIME creation{}, exit{}, kernel{}, user{};
            if(status >= 0 && *handle && access == THREAD_ALL_ACCESS && flags == 2 &&
                    GetProcessIdOfThread(*handle) == observation.processId && GetThreadTimes(*handle, &creation, &exit, &kernel, &user))
            {
                observation.threadId = GetThreadId(*handle);
                observation.creation = CreationTime(creation);
                observation.nativeCreated = observation.threadId != 0 && observation.creation != 0;
                if(mode == Mode::HeldBeforeCreation || mode == Mode::HeldAfterCreation)
                {
                    std::printf("INFLIGHT_NATIVE status=%08lx requestedAccess=%08lx actualAccess=%08lx flags=%lu pid=%lu thread=%lu creation=%llu start=%p handleValid=%u calls=%u\n",
                                status, access, actualAccess, flags, observation.processId, observation.threadId, observation.creation, start, unsigned(observation.nativeHandleValid), observation.calls);
                    std::fflush(stdout);
                    if(mode == Mode::HeldAfterCreation && !HoldCreation("after"))
                    {
                        SetLastError(ERROR_TIMEOUT);
                        return static_cast<LONG>(0xc0000102);
                    }
                    SetLastError(error);
                    return status;
                }
                observation.handleClosed = CloseHandle(*handle) != FALSE;
                if(observation.handleClosed)
                    *handle = nullptr;
            }
            const auto returnedStatus = observation.nativeCreated && observation.handleClosed ? static_cast<LONG>(0xc0000022) : status;
            const auto returnedError = observation.nativeCreated && observation.handleClosed ? ERROR_ACCESS_DENIED : error;
            std::printf("CREATOR nativeStatus=%08lx returnedStatus=%08lx error=%lu requestedAccess=%08lx actualAccess=%08lx flags=%lu pid=%lu thread=%lu creation=%llu start=%p nativeCreated=%u handleClosed=%u calls=%u\n",
                        status, returnedStatus, returnedError, access, actualAccess, flags, observation.processId, observation.threadId, observation.creation, start,
                        unsigned(observation.nativeCreated), unsigned(observation.handleClosed), observation.calls);
            std::fflush(stdout);
            SetLastError(returnedError);
            return returnedStatus;
        }
    }

    void Configure(Mode mode)
    {
        creationMode = mode;
    }

    void ConfigureGate(HANDLE reached, HANDLE release)
    {
        gateReached = reached;
        gateRelease = release;
    }

    bool VerifyThread(HANDLE thread, const char* phase)
    {
        DWORD suspended = MAXDWORD, restored = MAXDWORD;
        const auto matched = GetThreadId(thread) == observation.threadId &&
                             ObserveThread(thread, observation.processId, observation.start, observation.creation, suspended, restored);
        std::printf("PARKED_THREAD phase=%s pid=%lu thread=%lu creation=%llu start=%p alive=%u suspend=%lu restore=%lu matches=%u\n",
                    phase, observation.processId, observation.threadId, observation.creation, observation.start,
                    unsigned(WaitForSingleObject(thread, 0) == WAIT_TIMEOUT), suspended, restored, unsigned(matched));
        std::fflush(stdout);
        return matched && suspended == 1 && restored == 2;
    }

    Observation Capture()
    {
        return observation;
    }

    FARPROC Resolve(HMODULE module, LPCSTR name)
    {
        const auto address = Lookup(module, name);
        if(address && creationMode.load() != Mode::Normal && reinterpret_cast<ULONG_PTR>(name) > 0xffff &&
                std::strcmp(name, "NtCreateThreadEx") == 0 && module == GetModuleHandleW(L"ntdll.dll"))
        {
            nativeCreate = reinterpret_cast<NativeCreate>(address);
            return reinterpret_cast<FARPROC>(Create);
        }
        return address;
    }
}

extern "C" FARPROC WINAPI FixtureGetProcAddress(HMODULE module, LPCSTR name)
{
    return FixtureNativeCreation::Resolve(module, name);
}

namespace FixtureNativeCleanup
{
    namespace
    {
        using NativeFree = BOOL(WINAPI*)(HANDLE, void*, SIZE_T, DWORD);
        using OwnedHandle = std::unique_ptr<void, decltype(&CloseHandle)>;
        constexpr DWORD RestrictedProcessAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE;

        struct CleanupSession
        {
            DWORD processId = 0;
            unsigned long long creation = 0;
            OwnedHandle completed{nullptr, CloseHandle};
            OwnedHandle reached{nullptr, CloseHandle}, release{nullptr, CloseHandle}, callbackThread{nullptr, CloseHandle};
            bool after = false;
            std::mutex mutex;
            Observation observation;
        };

        std::mutex registryMutex;
        std::shared_ptr<CleanupSession> current;

        unsigned long long CreationTime(HANDLE process)
        {
            FILETIME creation{}, exit{}, kernel{}, user{};
            if(!GetProcessTimes(process, &creation, &exit, &kernel, &user))
                return 0;
            return (static_cast<unsigned long long>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
        }

        bool Access(HANDLE handle, DWORD& granted)
        {
            using Query = LONG(NTAPI*)(HANDLE, OBJECT_INFORMATION_CLASS, void*, ULONG, ULONG*);
            const auto query = reinterpret_cast<Query>(FixtureNativeCreation::Resolve(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
            PUBLIC_OBJECT_BASIC_INFORMATION information{};
            ULONG length = 0;
            if(!query || query(handle, ObjectBasicInformation, &information, sizeof(information), &length) < 0 || length != sizeof(information))
                return false;
            granted = information.GrantedAccess;
            return true;
        }
    }

    bool ConfigureDeniedTarget(HANDLE process, HANDLE completed)
    {
        auto session = std::make_shared<CleanupSession>();
        session->processId = GetProcessId(process);
        session->creation = CreationTime(process);
        HANDLE duplicate = nullptr;
        if(!session->processId || !session->creation || !DuplicateHandle(GetCurrentProcess(), completed, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
            return false;
        session->completed.reset(duplicate);
        std::lock_guard<std::mutex> guard(registryMutex);
        current = std::move(session);
        return true;
    }

    bool ConfigureGateTarget(HANDLE process, HANDLE reached, HANDLE release, HANDLE completed, bool after)
    {
        if(!ConfigureDeniedTarget(process, completed))
            return false;
        std::lock_guard<std::mutex> guard(registryMutex);
        HANDLE reachedCopy = nullptr, releaseCopy = nullptr;
        if(!DuplicateHandle(GetCurrentProcess(), reached, GetCurrentProcess(), &reachedCopy, 0, FALSE, DUPLICATE_SAME_ACCESS))
            return false;
        current->reached.reset(reachedCopy);
        if(!DuplicateHandle(GetCurrentProcess(), release, GetCurrentProcess(), &releaseCopy, 0, FALSE, DUPLICATE_SAME_ACCESS))
            return false;
        current->release.reset(releaseCopy);
        current->after = after;
        return true;
    }

    void Reset()
    {
        std::lock_guard<std::mutex> guard(registryMutex);
        current.reset();
    }

    Observation Capture()
    {
        std::shared_ptr<CleanupSession> session;
        {
            std::lock_guard<std::mutex> guard(registryMutex);
            session = current;
        }
        if(!session)
            return {};
        std::lock_guard<std::mutex> guard(session->mutex);
        return session->observation;
    }

    HANDLE DuplicateCallbackThread()
    {
        std::shared_ptr<CleanupSession> session;
        {
            std::lock_guard<std::mutex> guard(registryMutex);
            session = current;
        }
        if(!session)
            return nullptr;
        std::lock_guard<std::mutex> guard(session->mutex);
        HANDLE duplicate = nullptr;
        if(!session->callbackThread || !DuplicateHandle(GetCurrentProcess(), session->callbackThread.get(), GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
            return nullptr;
        return duplicate;
    }

    BOOL Free(HANDLE process, void* address, SIZE_T size, DWORD type)
    {
        const auto incomingError = GetLastError();
        const auto native = reinterpret_cast<NativeFree>(FixtureNativeCreation::Resolve(GetModuleHandleW(L"kernel32.dll"), "VirtualFreeEx"));
        if(!native)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }
        std::shared_ptr<CleanupSession> session;
        {
            std::lock_guard<std::mutex> guard(registryMutex);
            session = current;
        }
        if(!session || GetProcessId(process) != session->processId || CreationTime(process) != session->creation)
        {
            SetLastError(incomingError);
            return native(process, address, size, type);
        }
        if(session->reached)
        {
            HANDLE callbackHandle = nullptr;
            if(!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &callbackHandle, 0, FALSE, DUPLICATE_SAME_ACCESS))
                return FALSE;
            {
                std::lock_guard<std::mutex> guard(session->mutex);
                session->callbackThread.reset(callbackHandle);
            }
            DWORD actualAccess = 0;
            FILETIME creation{}, exit{}, kernel{}, user{};
            MEMORY_BASIC_INFORMATION before{}, after{};
            const auto prepared = size == 0 && type == MEM_RELEASE && Access(process, actualAccess) && (actualAccess & PROCESS_VM_OPERATION) &&
                                  VirtualQueryEx(process, address, &before, sizeof(before)) == sizeof(before) && before.AllocationBase == address &&
                                  before.State == MEM_COMMIT && before.Protect == PAGE_EXECUTE_READ && before.Type == MEM_PRIVATE &&
                                  GetThreadTimes(GetCurrentThread(), &creation, &exit, &kernel, &user);
            const auto threadCreation = (static_cast<unsigned long long>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
            BOOL result = FALSE;
            DWORD error = ERROR_SUCCESS;
            if(session->after)
            {
                SetLastError(ERROR_SUCCESS);
                result = native(process, address, size, type);
                error = GetLastError();
            }
            std::printf("CALLBACK_GATE pid=%lu creation=%llu code=%p after=%u controller=%lu thread=%lu threadCreation=%llu access=%08lx prepared=%u releasePending=%u\n",
                        session->processId, session->creation, address, unsigned(session->after), GetCurrentProcessId(), GetCurrentThreadId(), threadCreation,
                        actualAccess, unsigned(prepared), unsigned(WaitForSingleObject(session->release.get(), 0) == WAIT_TIMEOUT));
            std::fflush(stdout);
            if(!prepared || !SetEvent(session->reached.get()) || WaitForSingleObject(session->release.get(), 10000) != WAIT_OBJECT_0)
            {
                SetLastError(ERROR_TIMEOUT);
                return FALSE;
            }
            if(!session->after)
            {
                SetLastError(ERROR_SUCCESS);
                result = native(process, address, size, type);
                error = GetLastError();
            }
            const auto freed = VirtualQueryEx(process, address, &after, sizeof(after)) == sizeof(after) && after.State == MEM_FREE;
            std::printf("CALLBACK_FREE pid=%lu creation=%llu code=%p controller=%lu thread=%lu threadCreation=%llu result=%u error=%lu freed=%u releaseSignaled=%u\n",
                        session->processId, session->creation, address, GetCurrentProcessId(), GetCurrentThreadId(), threadCreation, unsigned(result), error,
                        unsigned(freed), unsigned(WaitForSingleObject(session->release.get(), 0) == WAIT_OBJECT_0));
            std::fflush(stdout);
            if(result && freed)
                SetEvent(session->completed.get());
            SetLastError(error);
            return result;
        }
        HANDLE duplicate = nullptr;
        if(!DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(), &duplicate, RestrictedProcessAccess, FALSE, 0))
            return FALSE;
        OwnedHandle restricted(duplicate, CloseHandle);
        DWORD originalAccess = 0, actualAccess = 0;
        MEMORY_BASIC_INFORMATION before{}, after{};
        std::array<unsigned char, NativeBreakInPayload::CodePageSize> original{}, observed{};
        SIZE_T copied = 0;
        const auto prepared = size == 0 && type == MEM_RELEASE && Access(process, originalAccess) && Access(duplicate, actualAccess) &&
                              (originalAccess & PROCESS_VM_OPERATION) && !(actualAccess & PROCESS_VM_OPERATION) &&
                              (actualAccess & RestrictedProcessAccess) == RestrictedProcessAccess &&
                              GetProcessId(duplicate) == session->processId && CreationTime(duplicate) == session->creation &&
                              VirtualQueryEx(process, address, &before, sizeof(before)) == sizeof(before) && before.AllocationBase == address &&
                              before.State == MEM_COMMIT && before.Protect == PAGE_EXECUTE_READ && before.Type == MEM_PRIVATE &&
                              ReadProcessMemory(duplicate, address, original.data(), original.size(), &copied) && copied == original.size();
        const auto result = native(duplicate, address, size, type);
        const auto error = GetLastError();
        const auto unchanged = VirtualQueryEx(process, address, &after, sizeof(after)) == sizeof(after) &&
                               after.AllocationBase == before.AllocationBase && after.RegionSize == before.RegionSize &&
                               after.State == before.State && after.Protect == before.Protect && after.Type == before.Type &&
                               ReadProcessMemory(duplicate, address, observed.data(), observed.size(), &copied) && copied == observed.size() && observed == original &&
                               WaitForSingleObject(duplicate, 0) == WAIT_TIMEOUT;
        {
            std::lock_guard<std::mutex> guard(session->mutex);
            session->observation = {session->processId, session->creation, address, originalAccess, actualAccess, error, result, session->observation.calls + 1,
                                    prepared && unchanged && result == FALSE && error == ERROR_ACCESS_DENIED};
            std::printf("NATIVE_CLEANUP pid=%lu creation=%llu code=%p size=%zu type=%08lx requestedAccess=%08lx originalAccess=%08lx actualAccess=%08lx result=%u error=%lu prepared=%u unchanged=%u calls=%u\n",
                        session->processId, session->creation, address, size, type, RestrictedProcessAccess, originalAccess, actualAccess, unsigned(result), error,
                        unsigned(prepared), unsigned(unchanged), session->observation.calls);
            std::fflush(stdout);
        }
        SetEvent(session->completed.get());
        restricted.reset();
        SetLastError(error);
        return result;
    }
}

extern "C" BOOL WINAPI FixtureVirtualFreeEx(HANDLE process, void* address, SIZE_T size, DWORD type)
{
    return FixtureNativeCleanup::Free(process, address, size, type);
}
