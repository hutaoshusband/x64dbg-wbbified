#include "native_creator.h"
#include <winternl.h>
#include <atomic>
#include <cstdio>
#include <cstring>

extern "C" LONG NTAPI LdrGetProcedureAddress(void*, const ANSI_STRING*, ULONG, void**);

namespace FixtureNativeCreation
{
    namespace
    {
        using NativeCreate = LONG(NTAPI*)(HANDLE*, ACCESS_MASK, void*, HANDLE, void*, void*, ULONG, SIZE_T, SIZE_T, SIZE_T, void*);
        std::atomic<bool> partialCreation{false};
        std::atomic<NativeCreate> nativeCreate{nullptr};
        Observation observation;

        LONG NTAPI Create(HANDLE* handle, ACCESS_MASK access, void* attributes, HANDLE process, void* start, void* argument, ULONG flags, SIZE_T zero, SIZE_T commit, SIZE_T reserve, void* list)
        {
            const auto native = nativeCreate.load();
            const auto status = native(handle, access, attributes, process, start, argument, flags, zero, commit, reserve, list);
            const auto error = GetLastError();
            observation.nativeStatus = status;
            observation.processId = GetProcessId(process);
            observation.start = start;
            ++observation.calls;
            FILETIME creation{}, exit{}, kernel{}, user{};
            if(status >= 0 && *handle && access == THREAD_ALL_ACCESS && flags == 2 &&
                    GetProcessIdOfThread(*handle) == observation.processId && GetThreadTimes(*handle, &creation, &exit, &kernel, &user))
            {
                observation.threadId = GetThreadId(*handle);
                observation.creation = (static_cast<unsigned long long>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
                observation.nativeCreated = observation.threadId != 0 && observation.creation != 0;
                observation.handleClosed = CloseHandle(*handle) != FALSE;
                if(observation.handleClosed)
                    *handle = nullptr;
            }
            const auto returnedStatus = observation.nativeCreated && observation.handleClosed ? static_cast<LONG>(0xc0000022) : status;
            const auto returnedError = observation.nativeCreated && observation.handleClosed ? ERROR_ACCESS_DENIED : error;
            std::printf("CREATOR nativeStatus=%08lx returnedStatus=%08lx error=%lu requestedAccess=%08lx actualAccess=%08lx flags=%lu pid=%lu thread=%lu creation=%llu start=%p nativeCreated=%u handleClosed=%u calls=%u\n",
                        status, returnedStatus, returnedError, access, access, flags, observation.processId, observation.threadId, observation.creation, start,
                        unsigned(observation.nativeCreated), unsigned(observation.handleClosed), observation.calls);
            std::fflush(stdout);
            SetLastError(returnedError);
            return returnedStatus;
        }
    }

    void Configure(bool partial)
    {
        partialCreation = partial;
    }

    Observation Capture()
    {
        return observation;
    }

    FARPROC Resolve(HMODULE module, LPCSTR name)
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
        if(partialCreation.load() && requested && std::strcmp(name, "NtCreateThreadEx") == 0 && module == GetModuleHandleW(L"ntdll.dll"))
        {
            nativeCreate = reinterpret_cast<NativeCreate>(address);
            return reinterpret_cast<FARPROC>(Create);
        }
        return reinterpret_cast<FARPROC>(address);
    }
}

extern "C" FARPROC WINAPI FixtureGetProcAddress(HMODULE module, LPCSTR name)
{
    return FixtureNativeCreation::Resolve(module, name);
}
