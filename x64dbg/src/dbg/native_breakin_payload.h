#pragma once

#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <vector>

namespace NativeBreakInPayload
{
    constexpr std::size_t CodePageSize = 4096;
    constexpr std::size_t AllocationSize = CodePageSize * 2;
    constexpr DWORD Completed = 0;
    constexpr DWORD RemovalFailed = 1;
    constexpr DWORD RegistrationFailed = 2;
    struct Image
    {
        std::vector<unsigned char> bytes;
        std::size_t trapOffset = 0;
        std::size_t continuationOffset = 0;
        std::size_t handlerOffset = 0;
        std::size_t unwindOffset = 0;
        std::size_t tableOffset = 0;
    };

    struct Builder
    {
        Image image;
        bool valid = true;

        void Emit(std::initializer_list<unsigned char> bytes)
        {
            image.bytes.insert(image.bytes.end(), bytes);
        }

        void Value(std::uint64_t value, std::size_t size)
        {
            for(std::size_t index = 0; index < size; ++index)
                image.bytes.push_back(static_cast<unsigned char>(value >> (index * 8)));
        }

        void Patch(std::size_t offset, std::uint64_t value, std::size_t size)
        {
            if(size > sizeof(value) || offset > image.bytes.size() || size > image.bytes.size() - offset)
            {
                valid = false;
                return;
            }
            for(std::size_t index = 0; index < size; ++index)
                image.bytes[offset + index] = static_cast<unsigned char>(value >> (index * 8));
        }

        std::size_t RipAddress(std::initializer_list<unsigned char> instruction)
        {
            Emit(instruction);
            const auto offset = image.bytes.size();
            Value(0, 4);
            return offset;
        }

        void RipTarget(std::size_t offset, std::size_t target)
        {
            Patch(offset, static_cast<std::uint32_t>(static_cast<std::int32_t>(target) - static_cast<std::int32_t>(offset + 4)), 4);
        }

        std::size_t Branch(unsigned char opcode)
        {
            Emit({opcode, 0});
            return image.bytes.size() - 1;
        }

        void BranchTarget(std::size_t offset, std::size_t target)
        {
            const auto displacement = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(offset + 1);
            if(displacement < -128 || displacement > 127)
            {
                valid = false;
                return;
            }
            Patch(offset, static_cast<unsigned char>(displacement), 1);
        }

        void Align(std::size_t alignment)
        {
            while(image.bytes.size() % alignment)
                Emit({0xCC});
        }
    };

    inline Image Build(std::uintptr_t remoteBase, std::uintptr_t registrationFunction, std::uintptr_t removalFunction)
    {
        if(!remoteBase || remoteBase > std::numeric_limits<std::uintptr_t>::max() - AllocationSize ||
                !registrationFunction || !removalFunction)
            return {};
        Builder code;
#ifdef _WIN64
        static_assert(offsetof(CONTEXT, Rip) == 0xF8);
        code.Emit({0x48, 0x83, 0xEC, 0x28});
        const auto registerTable = code.RipAddress({0x48, 0x8D, 0x0D});
        code.Emit({0xBA, 1, 0, 0, 0});
        const auto functionBase = code.RipAddress({0x4C, 0x8D, 0x05});
        code.Emit({0x48, 0xB8});
        code.Value(registrationFunction, 8);
        code.Emit({0xFF, 0xD0, 0x84, 0xC0});
        const auto registrationFailed = code.Branch(0x74);
        code.image.trapOffset = code.image.bytes.size();
        code.Emit({0xCC});
        code.image.continuationOffset = code.image.bytes.size();
        const auto unregisterTable = code.RipAddress({0x48, 0x8D, 0x0D});
        code.Emit({0x48, 0xB8});
        code.Value(removalFunction, 8);
        code.Emit({0xFF, 0xD0, 0x0F, 0xB6, 0xC0, 0x83, 0xF0, 1, 0x48, 0x83, 0xC4, 0x28, 0xC3});
        const auto failureReturn = code.image.bytes.size();
        code.Emit({0xB8, 2, 0, 0, 0, 0x48, 0x83, 0xC4, 0x28, 0xC3});
        const auto functionEnd = code.image.bytes.size();
        code.Align(16);
        code.image.handlerOffset = code.image.bytes.size();
        code.Emit({0x81, 0x39, 3, 0, 0, 0x80});
        const auto differentException = code.Branch(0x75);
        code.Emit({0x48, 0xB8});
        code.Value(remoteBase + code.image.trapOffset, 8);
        code.Emit({0x48, 0x39, 0x41, static_cast<unsigned char>(offsetof(EXCEPTION_RECORD, ExceptionAddress))});
        const auto differentAddress = code.Branch(0x75);
        code.Emit({0x48, 0xB8});
        code.Value(remoteBase + code.image.continuationOffset, 8);
        code.Emit({0x49, 0x89, 0x80});
        code.Value(offsetof(CONTEXT, Rip), 4);
        code.Emit({0x31, 0xC0, 0xC3});
        const auto search = code.image.bytes.size();
        code.Emit({0xB8, 1, 0, 0, 0, 0xC3});
        code.Align(4);
        code.image.unwindOffset = code.image.bytes.size();
        code.Emit({0x09, 4, 1, 0, 4, 0x42, 0, 0});
        code.Value(code.image.handlerOffset, 4);
        code.image.tableOffset = code.image.bytes.size();
        code.Value(0, 4);
        code.Value(functionEnd, 4);
        code.Value(code.image.unwindOffset, 4);
        code.RipTarget(registerTable, code.image.tableOffset);
        code.RipTarget(unregisterTable, code.image.tableOffset);
        code.RipTarget(functionBase, 0);
        code.BranchTarget(registrationFailed, failureReturn);
        code.BranchTarget(differentException, search);
        code.BranchTarget(differentAddress, search);
#else
        static_assert(offsetof(CONTEXT, Eip) == 0xB8);
        struct ThreadIdentityPrefix
        {
            NT_TIB tib;
            void* environment;
            HANDLE processId;
            HANDLE threadId;
        };
        constexpr auto threadIdOffset = offsetof(ThreadIdentityPrefix, threadId);
        static_assert(threadIdOffset == 0x24);
        code.Emit({0x83, 0xEC, 12, 0x64, 0xA1, static_cast<unsigned char>(threadIdOffset), 0, 0, 0, 0xA3});
        code.Value(remoteBase + CodePageSize, 4);
        code.Emit({0x68});
        const auto handlerPointer = code.image.bytes.size();
        code.Value(0, 4);
        code.Emit({0x6A, 1, 0xB8});
        code.Value(registrationFunction, 4);
        code.Emit({0xFF, 0xD0, 0x85, 0xC0});
        const auto registrationFailed = code.Branch(0x74);
        code.Emit({0x89, 0x04, 0x24});
        code.image.trapOffset = code.image.bytes.size();
        code.Emit({0xCC});
        code.image.continuationOffset = code.image.bytes.size();
        code.Emit({0xFF, 0x34, 0x24, 0xB8});
        code.Value(removalFunction, 4);
        code.Emit({0xFF, 0xD0, 0x85, 0xC0, 0x0F, 0x94, 0xC0, 0x0F, 0xB6, 0xC0, 0x83, 0xC4, 12, 0xC2, 4, 0});
        const auto failureReturn = code.image.bytes.size();
        code.Emit({0xB8, 2, 0, 0, 0, 0x83, 0xC4, 12, 0xC2, 4, 0});
        code.Align(16);
        code.image.handlerOffset = code.image.bytes.size();
        code.Emit({0x8B, 0x44, 0x24, 4, 0x8B, 0x10, 0x81, 0x3A, 3, 0, 0, 0x80});
        const auto differentException = code.Branch(0x75);
        code.Emit({0x81, 0x7A, static_cast<unsigned char>(offsetof(EXCEPTION_RECORD, ExceptionAddress))});
        code.Value(remoteBase + code.image.trapOffset, 4);
        const auto differentAddress = code.Branch(0x75);
        code.Emit({0x64, 0x8B, 0x15, static_cast<unsigned char>(threadIdOffset), 0, 0, 0, 0x3B, 0x15});
        code.Value(remoteBase + CodePageSize, 4);
        const auto differentThread = code.Branch(0x75);
        code.Emit({0x8B, 0x40, 4, 0xC7, 0x80});
        code.Value(offsetof(CONTEXT, Eip), 4);
        code.Value(remoteBase + code.image.continuationOffset, 4);
        code.Emit({0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC2, 4, 0});
        const auto search = code.image.bytes.size();
        code.Emit({0x31, 0xC0, 0xC2, 4, 0});
        code.Patch(handlerPointer, remoteBase + code.image.handlerOffset, 4);
        code.BranchTarget(registrationFailed, failureReturn);
        code.BranchTarget(differentException, search);
        code.BranchTarget(differentAddress, search);
        code.BranchTarget(differentThread, search);
#endif
        if(!code.valid || code.image.bytes.size() > CodePageSize || code.image.trapOffset >= code.image.bytes.size())
            return {};
        return code.image;
    }
}
