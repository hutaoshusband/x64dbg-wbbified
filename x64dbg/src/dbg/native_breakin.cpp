#include "native_breakin.h"
#include "native_breakin_payload.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <vector>

namespace NativeBreakIn
{
    namespace
    {
#ifdef _WIN64
        constexpr WORD NativeMachine = IMAGE_FILE_MACHINE_AMD64;
#else
        constexpr WORD NativeMachine = IMAGE_FILE_MACHINE_I386;
#endif

        struct HandleCloser
        {
            void operator()(void* handle) const
            {
                if(handle)
                    CloseHandle(handle);
            }
        };

        using OwnedHandle = std::unique_ptr<void, HandleCloser>;

        OwnedHandle Duplicate(HANDLE handle)
        {
            HANDLE duplicate = nullptr;
            if(!handle || !DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
                return {};
            return OwnedHandle(duplicate);
        }

        struct Target
        {
            OwnedHandle process;
            DWORD processId = 0;
        };

        bool Read(HANDLE process, std::uintptr_t address, void* buffer, std::size_t size)
        {
            SIZE_T read = 0;
            return address && size <= std::numeric_limits<std::uintptr_t>::max() - address &&
                   ReadProcessMemory(process, reinterpret_cast<void*>(address), buffer, size, &read) && read == size;
        }

        std::uintptr_t Export(HANDLE process, std::uintptr_t base, const char* name)
        {
            IMAGE_DOS_HEADER dos{};
            IMAGE_NT_HEADERS headers{};
            if(!Read(process, base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
                    dos.e_lfanew < sizeof(dos) || dos.e_lfanew > 0x100000 ||
                    base > std::numeric_limits<std::uintptr_t>::max() - static_cast<unsigned>(dos.e_lfanew) ||
                    !Read(process, base + dos.e_lfanew, &headers, sizeof(headers)) || headers.Signature != IMAGE_NT_SIGNATURE ||
                    headers.FileHeader.Machine != NativeMachine ||
                    headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC ||
                    headers.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
                return 0;
            const auto imageSize = headers.OptionalHeader.SizeOfImage;
            if(!imageSize || imageSize > std::numeric_limits<std::uintptr_t>::max() - base)
                return 0;
            const auto inImage = [imageSize](DWORD offset, std::size_t size)
            {
                return offset < imageSize && size <= imageSize - offset;
            };
            const auto directory = headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            IMAGE_EXPORT_DIRECTORY exports{};
            if(directory.Size < sizeof(exports) || !inImage(directory.VirtualAddress, directory.Size) ||
                    !Read(process, base + directory.VirtualAddress, &exports, sizeof(exports)) ||
                    !exports.NumberOfNames || exports.NumberOfNames > 65536 ||
                    !exports.NumberOfFunctions || exports.NumberOfFunctions > 65536 ||
                    !inImage(exports.AddressOfNames, exports.NumberOfNames * sizeof(DWORD)) ||
                    !inImage(exports.AddressOfNameOrdinals, exports.NumberOfNames * sizeof(WORD)) ||
                    !inImage(exports.AddressOfFunctions, exports.NumberOfFunctions * sizeof(DWORD)))
                return 0;
            std::vector<DWORD> names(exports.NumberOfNames);
            std::vector<WORD> ordinals(exports.NumberOfNames);
            std::vector<DWORD> functions(exports.NumberOfFunctions);
            if(!Read(process, base + exports.AddressOfNames, names.data(), names.size() * sizeof(DWORD)) ||
                    !Read(process, base + exports.AddressOfNameOrdinals, ordinals.data(), ordinals.size() * sizeof(WORD)) ||
                    !Read(process, base + exports.AddressOfFunctions, functions.data(), functions.size() * sizeof(DWORD)))
                return 0;
            const auto length = std::strlen(name) + 1;
            std::array<char, 128> candidate{};
            if(length > candidate.size())
                return 0;
            for(std::size_t index = 0; index < names.size(); ++index)
            {
                if(!inImage(names[index], length) || !Read(process, base + names[index], candidate.data(), length))
                    return 0;
                if(std::memcmp(candidate.data(), name, length) != 0)
                    continue;
                if(ordinals[index] >= functions.size())
                    return 0;
                const auto address = functions[ordinals[index]];
                if(!inImage(address, 1) || (address >= directory.VirtualAddress && address - directory.VirtualAddress < directory.Size))
                    return 0;
                MEMORY_BASIC_INFORMATION memory{};
                if(VirtualQueryEx(process, reinterpret_cast<void*>(base + address), &memory, sizeof(memory)) != sizeof(memory) ||
                        memory.State != MEM_COMMIT || memory.Type != MEM_IMAGE || reinterpret_cast<std::uintptr_t>(memory.AllocationBase) != base ||
                        (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) ||
                        !(memory.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
                    return 0;
                return base + address;
            }
            return 0;
        }

        struct Request
        {
            std::shared_ptr<Target> target;
            std::mutex mutex;
            OwnedHandle thread;
            PTP_WAIT wait = nullptr;
            void* allocation = nullptr;
            std::uintptr_t entry = 0;
            std::uintptr_t trap = 0;
            DWORD threadId = 0;
            bool closing = false;
            bool attempted = false;
            bool consumed = false;
            bool complete = false;
            bool waitingForProcess = false;

            explicit Request(std::shared_ptr<Target> owner) : target(std::move(owner))
            {
            }

            ~Request()
            {
                if(wait)
                {
                    {
                        std::lock_guard<std::mutex> guard(mutex);
                        closing = true;
                    }
                    SetThreadpoolWait(wait, nullptr, nullptr);
                    WaitForThreadpoolWaitCallbacks(wait, TRUE);
                    CloseThreadpoolWait(wait);
                }
                if(allocation && !attempted)
                    VirtualFreeEx(target->process.get(), allocation, 0, MEM_RELEASE);
            }

            static void CALLBACK Terminal(PTP_CALLBACK_INSTANCE, void* context, PTP_WAIT, TP_WAIT_RESULT result)
            {
                auto& request = *static_cast<Request*>(context);
                std::lock_guard<std::mutex> guard(request.mutex);
                if(request.closing || result != WAIT_OBJECT_0)
                    return;
                if(WaitForSingleObject(request.target->process.get(), 0) == WAIT_OBJECT_0)
                {
                    request.allocation = nullptr;
                    request.complete = true;
                    return;
                }
                if(request.waitingForProcess)
                    return;
                DWORD exitCode = STILL_ACTIVE;
                if(request.thread && WaitForSingleObject(request.thread.get(), 0) == WAIT_OBJECT_0 &&
                        GetExitCodeThread(request.thread.get(), &exitCode) &&
                        (exitCode == NativeBreakInPayload::Completed || exitCode == NativeBreakInPayload::RegistrationFailed) &&
                        VirtualFreeEx(request.target->process.get(), request.allocation, 0, MEM_RELEASE))
                {
                    request.allocation = nullptr;
                    request.complete = true;
                    return;
                }
                request.waitingForProcess = true;
                SetThreadpoolWait(request.wait, request.target->process.get(), nullptr);
            }

            bool Prepare(std::uintptr_t ntdllBase)
            {
                SYSTEM_INFO system{};
                GetSystemInfo(&system);
                if(system.dwPageSize != NativeBreakInPayload::CodePageSize)
                    return false;
#ifdef _WIN64
                const auto registration = Export(target->process.get(), ntdllBase, "RtlAddFunctionTable");
                const auto removal = Export(target->process.get(), ntdllBase, "RtlDeleteFunctionTable");
#else
                const auto registration = Export(target->process.get(), ntdllBase, "RtlAddVectoredExceptionHandler");
                const auto removal = Export(target->process.get(), ntdllBase, "RtlRemoveVectoredExceptionHandler");
#endif
                if(!registration || !removal)
                    return false;
                wait = CreateThreadpoolWait(Terminal, this, nullptr);
                if(!wait)
                    return false;
                allocation = VirtualAllocEx(target->process.get(), nullptr, NativeBreakInPayload::AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if(!allocation)
                    return false;
                const auto image = NativeBreakInPayload::Build(reinterpret_cast<std::uintptr_t>(allocation), registration, removal);
                SIZE_T written = 0;
                DWORD protection = 0;
                if(image.bytes.empty() || !WriteProcessMemory(target->process.get(), allocation, image.bytes.data(), image.bytes.size(), &written) ||
                        written != image.bytes.size() || !VirtualProtectEx(target->process.get(), allocation, NativeBreakInPayload::CodePageSize, PAGE_EXECUTE_READ, &protection) ||
                        protection != PAGE_READWRITE || !FlushInstructionCache(target->process.get(), allocation, image.bytes.size()))
                    return false;
                entry = reinterpret_cast<std::uintptr_t>(allocation);
                trap = entry + image.trapOffset;
                return true;
            }

            bool Bind(HANDLE handle, DWORD id)
            {
                if(!id || GetThreadId(handle) != id || GetProcessIdOfThread(handle) != target->processId)
                    return false;
                auto duplicate = Duplicate(handle);
                if(!duplicate)
                    return false;
                std::lock_guard<std::mutex> guard(mutex);
                if(thread)
                    return threadId == id;
                if(complete)
                    return false;
                thread = std::move(duplicate);
                threadId = id;
                waitingForProcess = false;
                SetThreadpoolWait(wait, thread.get(), nullptr);
                return true;
            }

            bool IsComplete()
            {
                std::lock_guard<std::mutex> guard(mutex);
                return complete;
            }
        };

        struct Registry
        {
            std::mutex mutex;
            std::shared_ptr<Target> target;
            std::shared_ptr<Request> current;
            std::vector<std::shared_ptr<Request>> retained;
            bool closing = false;
        };

        Registry registry;

        void Prune()
        {
            std::vector<std::shared_ptr<Request>> retired;
            {
                std::lock_guard<std::mutex> guard(registry.mutex);
                for(auto item = registry.retained.begin(); item != registry.retained.end();)
                {
                    if((*item)->IsComplete())
                    {
                        if(registry.current == *item)
                            registry.current.reset();
                        retired.push_back(std::move(*item));
                        item = registry.retained.erase(item);
                    }
                    else
                        ++item;
                }
            }
        }
    }

    bool BeginTarget(HANDLE process)
    {
        EndTarget();
        auto target = std::make_shared<Target>();
        target->process = Duplicate(process);
        target->processId = target->process ? GetProcessId(target->process.get()) : 0;
        if(!target->processId)
            return false;
        std::lock_guard<std::mutex> guard(registry.mutex);
        if(registry.closing)
            return false;
        registry.target = std::move(target);
        return true;
    }

    void EndTarget()
    {
        {
            std::lock_guard<std::mutex> guard(registry.mutex);
            registry.current.reset();
            registry.target.reset();
        }
        Prune();
    }

    Result Create(std::uintptr_t ntdllBase)
    {
        Prune();
        std::shared_ptr<Target> target;
        {
            std::lock_guard<std::mutex> guard(registry.mutex);
            if(registry.closing || !registry.target || registry.current || registry.retained.size() >= 64)
                return {false, 0, ERROR_BUSY};
            target = registry.target;
        }
        auto request = std::make_shared<Request>(target);
        if(!request->Prepare(ntdllBase))
            return {false, 0, GetLastError()};
        using CreateThread = LONG(NTAPI*)(HANDLE*, ACCESS_MASK, void*, HANDLE, void*, void*, ULONG, SIZE_T, SIZE_T, SIZE_T, void*);
        const auto ntdll = GetModuleHandleW(L"ntdll.dll");
        const auto create = ntdll ? reinterpret_cast<CreateThread>(GetProcAddress(ntdll, "NtCreateThreadEx")) : nullptr;
        if(!create)
            return {false, 0, ERROR_PROC_NOT_FOUND};
        {
            std::lock_guard<std::mutex> guard(registry.mutex);
            if(registry.closing || registry.target != target || registry.current || registry.retained.size() >= 64)
                return {false, 0, ERROR_BUSY};
            registry.current = request;
            registry.retained.push_back(request);
            request->attempted = true;
        }
        HANDLE handle = nullptr;
        constexpr ULONG skipThreadAttach = 2;
        const auto status = create(&handle, THREAD_ALL_ACCESS, nullptr, target->process.get(), request->allocation, nullptr, skipThreadAttach, 0, 0x4000, 0x4000, nullptr);
        OwnedHandle createdThread(handle);
        const auto bound = handle && request->Bind(handle, GetThreadId(handle));
        if(!bound)
        {
            std::lock_guard<std::mutex> guard(request->mutex);
            if(!request->thread && !request->complete)
            {
                request->waitingForProcess = true;
                SetThreadpoolWait(request->wait, target->process.get(), nullptr);
            }
        }
        return {status >= 0 && bound, status, status >= 0 && bound ? 0ul : GetLastError()};
    }

    void BindThread(DWORD processId, DWORD threadId, const CREATE_THREAD_DEBUG_INFO& information)
    {
        std::shared_ptr<Request> request;
        {
            std::lock_guard<std::mutex> guard(registry.mutex);
            request = registry.current;
        }
        if(request && request->target->processId == processId && request->entry == reinterpret_cast<std::uintptr_t>(information.lpStartAddress))
            request->Bind(information.hThread, threadId);
    }

    bool Consume(DWORD processId, DWORD threadId, const EXCEPTION_DEBUG_INFO& information)
    {
        std::shared_ptr<Request> request;
        {
            std::lock_guard<std::mutex> guard(registry.mutex);
            request = registry.current;
        }
        if(!request || request->target->processId != processId || information.dwFirstChance != 1 ||
                information.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT ||
                reinterpret_cast<std::uintptr_t>(information.ExceptionRecord.ExceptionAddress) != request->trap)
            return false;
        std::lock_guard<std::mutex> guard(request->mutex);
        if(!request->thread || request->threadId != threadId || request->consumed || request->complete)
            return false;
        request->consumed = true;
        return true;
    }

    void Shutdown()
    {
        std::vector<std::shared_ptr<Request>> retired;
        {
            std::lock_guard<std::mutex> guard(registry.mutex);
            registry.closing = true;
            registry.current.reset();
            registry.target.reset();
            retired.swap(registry.retained);
        }
    }
}
