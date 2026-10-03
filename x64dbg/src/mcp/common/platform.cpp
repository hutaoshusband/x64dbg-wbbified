#include "platform.h"
#include "lifecycle.h"
#include <Windows.h>
#include <bcrypt.h>
#include <sddl.h>
#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>

namespace wininspect::mcp
{
namespace
{
class NativeFailure : public std::runtime_error
{
public:
    explicit NativeFailure(const std::string& message) : std::runtime_error(message) {}
};

class Handle
{
public:
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() { if(value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
private:
    HANDLE value_;
};

struct LocalDeleter { void operator()(void* value) const { LocalFree(value); } };

void require_win32(bool success, const char* operation)
{
    if(!success)
        throw NativeFailure(std::string(operation) + " failed with Win32 error " + std::to_string(GetLastError()));
}

void require_status(NTSTATUS status, const char* operation)
{
    if(status < 0)
        throw NativeFailure(std::string(operation) + " failed with NTSTATUS " + hex64(static_cast<std::uint32_t>(status)));
}

std::string utf8(std::wstring_view text)
{
    auto converted = launch_utf8(text);
    if(const auto* error = std::get_if<ContractError>(&converted))
        throw NativeFailure(error->message);
    return std::get<std::string>(std::move(converted));
}

std::uint64_t file_time(const FILETIME& value)
{
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

std::vector<unsigned char> token_information(HANDLE token, TOKEN_INFORMATION_CLASS information)
{
    DWORD size = 0;
    const auto first = GetTokenInformation(token, information, nullptr, 0, &size);
    const auto error = GetLastError();
    if(first || (error != ERROR_INSUFFICIENT_BUFFER && error != ERROR_BAD_LENGTH) || !size || size > MaximumPayloadBytes)
        throw NativeFailure("Token information size is invalid for class " + std::to_string(information) + " with error " + std::to_string(error));
    std::vector<unsigned char> bytes(size);
    require_win32(GetTokenInformation(token, information, bytes.data(), size, &size), "GetTokenInformation");
    if(size > bytes.size())
        throw NativeFailure("Token information exceeded its allocated size");
    bytes.resize(size);
    return bytes;
}

std::string sid_text(PSID sid)
{
    require_win32(IsValidSid(sid), "IsValidSid");
    wchar_t* raw = nullptr;
    require_win32(ConvertSidToStringSidW(sid, &raw), "ConvertSidToStringSidW");
    const std::unique_ptr<void, LocalDeleter> owner(raw);
    return utf8(raw);
}

class Sha256
{
public:
    Sha256()
    {
        require_status(BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_SHA256_ALGORITHM, nullptr, 0), "BCryptOpenAlgorithmProvider");
        try
        {
            DWORD object_size = 0;
            DWORD returned = 0;
            require_status(BCryptGetProperty(algorithm_, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &returned, 0), "BCryptGetProperty");
            if(returned != sizeof(object_size) || !object_size || object_size > MaximumPayloadBytes)
                throw NativeFailure("SHA-256 object size is invalid");
            object_.resize(object_size);
            require_status(BCryptCreateHash(algorithm_, &hash_, object_.data(), object_size, nullptr, 0, 0), "BCryptCreateHash");
        }
        catch(...)
        {
            BCryptCloseAlgorithmProvider(algorithm_, 0);
            throw;
        }
    }
    ~Sha256()
    {
        if(hash_) BCryptDestroyHash(hash_);
        if(algorithm_) BCryptCloseAlgorithmProvider(algorithm_, 0);
    }
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;
    void add(unsigned char* bytes, ULONG size)
    {
        require_status(BCryptHashData(hash_, bytes, size, 0), "BCryptHashData");
    }
    std::string finish()
    {
        std::array<unsigned char, 32> bytes{};
        require_status(BCryptFinishHash(hash_, bytes.data(), static_cast<ULONG>(bytes.size()), 0), "BCryptFinishHash");
        constexpr char digits[] = "0123456789abcdef";
        std::string value;
        for(const auto byte : bytes)
        {
            value.push_back(digits[byte >> 4]);
            value.push_back(digits[byte & 15]);
        }
        return value;
    }
private:
    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::vector<unsigned char> object_;
};

NativeImageIdentity current_image()
{
    std::vector<wchar_t> path(32768);
    DWORD length = static_cast<DWORD>(path.size());
    require_win32(QueryFullProcessImageNameW(GetCurrentProcess(), 0, path.data(), &length), "QueryFullProcessImageNameW");
    if(!length || length >= path.size())
        throw NativeFailure("Current executable path exceeds its bound");
    const Handle file(CreateFileW(path.data(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    require_win32(file.get() != INVALID_HANDLE_VALUE, "CreateFileW");
    BY_HANDLE_FILE_INFORMATION before{};
    require_win32(GetFileInformationByHandle(file.get(), &before), "GetFileInformationByHandle");
    if(before.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        throw NativeFailure("Current executable resolves to a directory");
    const auto size = (static_cast<std::uint64_t>(before.nFileSizeHigh) << 32) | before.nFileSizeLow;
    constexpr std::uint64_t maximum_image_size = 512ull * 1024 * 1024;
    if(!size || size > maximum_image_size)
        throw NativeFailure("Current executable exceeds the identity hash bound");
    std::array<unsigned char, 65536> block{};
    std::uint64_t observed = 0;
    Sha256 digest;
    while(true)
    {
        DWORD read = 0;
        require_win32(ReadFile(file.get(), block.data(), static_cast<DWORD>(block.size()), &read, nullptr), "ReadFile");
        if(!read)
            break;
        if(read > size - observed)
            throw NativeFailure("Current executable changed size during hashing");
        observed += read;
        digest.add(block.data(), read);
    }
    BY_HANDLE_FILE_INFORMATION after{};
    require_win32(GetFileInformationByHandle(file.get(), &after), "GetFileInformationByHandle");
    if(observed != size || after.nFileSizeHigh != before.nFileSizeHigh || after.nFileSizeLow != before.nFileSizeLow ||
       after.dwVolumeSerialNumber != before.dwVolumeSerialNumber || after.nFileIndexHigh != before.nFileIndexHigh || after.nFileIndexLow != before.nFileIndexLow ||
       file_time(after.ftLastWriteTime) != file_time(before.ftLastWriteTime))
        throw NativeFailure("Current executable identity changed during hashing");
    return {utf8(std::wstring_view(path.data(), length)), digest.finish(), size, before.dwVolumeSerialNumber,
        (static_cast<std::uint64_t>(before.nFileIndexHigh) << 32) | before.nFileIndexLow};
}
}

Checked<std::string> sha256_bytes(std::string_view bytes)
{
    if(bytes.size() > MaximumFrameBytes)
        return ContractError{"payload_limit", "", "Hash input exceeds the frame bound"};
    try
    {
        Sha256 digest;
        std::vector<unsigned char> input(bytes.begin(), bytes.end());
        if(!input.empty())
            digest.add(input.data(), static_cast<ULONG>(input.size()));
        return digest.finish();
    }
    catch(const std::exception& error)
    {
        return ContractError{"native_failure", "", error.what()};
    }
}

Checked<std::string> sha256_file_bytes(std::string_view bytes)
{
    constexpr std::size_t maximum_file_bytes = 512 * 1024 * 1024;
    if(bytes.size() > maximum_file_bytes)
        return ContractError{"resource_limit", "", "File hash exceeds the native artifact bound"};
    try
    {
        Sha256 digest;
        std::array<unsigned char, 65536> block{};
        std::size_t offset = 0;
        while(offset < bytes.size())
        {
            const auto size = (std::min)(block.size(), bytes.size() - offset);
            std::copy_n(bytes.begin() + offset, size, block.begin());
            digest.add(block.data(), static_cast<ULONG>(size));
            offset += size;
        }
        return digest.finish();
    }
    catch(const std::exception& error)
    {
        return ContractError{"native_failure", "", error.what()};
    }
}

Checked<NativeProcessIdentity> capture_current_process()
{
    try
    {
        FILETIME created{}, exited{}, kernel{}, user{};
        require_win32(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user), "GetProcessTimes");
        HANDLE raw_token = nullptr;
        require_win32(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token), "OpenProcessToken");
        const Handle token(raw_token);
        const auto user_data = token_information(token.get(), TokenUser);
        if(user_data.size() < sizeof(TOKEN_USER))
            throw NativeFailure("Token user data size is invalid");
        const auto user_sid = sid_text(reinterpret_cast<const TOKEN_USER*>(user_data.data())->User.Sid);
        const auto group_data = token_information(token.get(), TokenGroups);
        if(group_data.size() < offsetof(TOKEN_GROUPS, Groups))
            throw NativeFailure("Token group data size is invalid");
        const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(group_data.data());
        if(groups->GroupCount > (group_data.size() - offsetof(TOKEN_GROUPS, Groups)) / sizeof(SID_AND_ATTRIBUTES))
            throw NativeFailure("Token group count is invalid");
        std::string logon_sid;
        for(DWORD index = 0; index < groups->GroupCount; ++index)
            if((groups->Groups[index].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
            {
                if(!logon_sid.empty())
                    throw NativeFailure("Process token contains multiple logon identities");
                logon_sid = sid_text(groups->Groups[index].Sid);
            }
        if(logon_sid.empty())
            throw NativeFailure("Process token has no logon identity");
        const auto integrity_data = token_information(token.get(), TokenIntegrityLevel);
        if(integrity_data.size() < sizeof(TOKEN_MANDATORY_LABEL))
            throw NativeFailure("Token integrity data size is invalid");
        const auto integrity_sid = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(integrity_data.data())->Label.Sid;
        require_win32(IsValidSid(integrity_sid), "IsValidSid");
        const auto subauthorities = *GetSidSubAuthorityCount(integrity_sid);
        if(!subauthorities)
            throw NativeFailure("Integrity SID has no level");
        const auto level = *GetSidSubAuthority(integrity_sid, subauthorities - 1);
        const std::string integrity = level < SECURITY_MANDATORY_LOW_RID ? "untrusted" : level < SECURITY_MANDATORY_MEDIUM_RID ? "low" :
            level < SECURITY_MANDATORY_HIGH_RID ? "medium" : level < SECURITY_MANDATORY_SYSTEM_RID ? "high" : level < 0x5000 ? "system" : "protected";
        const auto session_data = token_information(token.get(), TokenSessionId);
        const auto elevation_data = token_information(token.get(), TokenElevation);
        if(session_data.size() != sizeof(DWORD) || elevation_data.size() != sizeof(TOKEN_ELEVATION) || user_data.size() < sizeof(TOKEN_USER) || integrity_data.size() < sizeof(TOKEN_MANDATORY_LABEL))
            throw NativeFailure("Process token data size is invalid");
        return NativeProcessIdentity{GetCurrentProcessId(), file_time(created), *reinterpret_cast<const DWORD*>(session_data.data()), user_sid, logon_sid, integrity,
            reinterpret_cast<const TOKEN_ELEVATION*>(elevation_data.data())->TokenIsElevated != 0,
            sizeof(void*) == 8 ? Architecture::X64 : Architecture::X32, current_image()};
    }
    catch(const NativeFailure& error)
    {
        return ContractError{"process_identity_unavailable", "", error.what()};
    }
}

Json native_process_json(const NativeProcessIdentity& identity)
{
    return {{"pid", identity.pid}, {"creationTime", decimal64(identity.creationTime)}, {"sessionId", identity.sessionId},
        {"userSid", identity.userSid}, {"logonSid", identity.logonSid}, {"integrity", identity.integrity}, {"elevated", identity.elevated},
        {"architecture", identity.architecture == Architecture::X64 ? "x64" : "x32"}, {"image", {
            {"path", identity.image.path}, {"sha256", identity.image.sha256}, {"size", decimal64(identity.image.size)},
            {"volumeSerial", identity.image.volumeSerial}, {"fileIndex", decimal64(identity.image.fileIndex)}}}};
}
}
