#include "broker_profile.h"
#include "lifecycle.h"
#include "new_file_publish.h"
#include <aclapi.h>
#include <sddl.h>
#include <ShlObj.h>
#include <knownfolders.h>
#include <winternl.h>
#include <array>
#include <filesystem>

namespace wininspect::mcp
{
namespace
{
struct CloseHandleOwner { void operator()(void* value) const { if(value && value != INVALID_HANDLE_VALUE) CloseHandle(value); } };
struct FreeLocalOwner { void operator()(void* value) const { LocalFree(value); } };
struct FreeTaskOwner { void operator()(void* value) const { CoTaskMemFree(value); } };
using HandleOwner = std::unique_ptr<void, CloseHandleOwner>;
using LocalOwner = std::unique_ptr<void, FreeLocalOwner>;

template<typename Value>
Value profile_value(Checked<Value> result)
{
    if(const auto* error = std::get_if<ContractError>(&result)) throw *error;
    return std::get<Value>(std::move(result));
}

void require_profile(bool success, const char* operation)
{
    if(!success) throw ContractError{"profile_storage_unavailable", "", std::string(operation) + " failed with Win32 error " + std::to_string(GetLastError())};
}

BY_HANDLE_FILE_INFORMATION information(HANDLE handle)
{
    BY_HANDLE_FILE_INFORMATION value{};
    require_profile(GetFileInformationByHandle(handle, &value) != FALSE, "Inspect profile object");
    if(value.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) throw ContractError{"profile_storage_invalid", "", "Profile objects cannot be reparse points"};
    return value;
}

std::wstring canonical_path(HANDLE handle)
{
    std::array<wchar_t, 32768> path{};
    const auto size = GetFinalPathNameByHandleW(handle, path.data(), static_cast<DWORD>(path.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_GUID);
    require_profile(size && size < path.size(), "Resolve profile object");
    const std::wstring result(path.data(), size);
    if(result.compare(0, 11, L"\\\\?\\Volume{") != 0) throw ContractError{"profile_storage_invalid", "", "Profiles require a local volume path"};
    return result;
}

LocalOwner profile_security(const std::string& user)
{
    const auto sid = profile_value(launch_utf16(user));
    const auto text = L"O:" + sid + L"D:P(A;OICI;FA;;;" + sid + L")";
    PSECURITY_DESCRIPTOR raw = nullptr;
    require_profile(ConvertStringSecurityDescriptorToSecurityDescriptorW(text.c_str(), SDDL_REVISION_1, &raw, nullptr) != FALSE, "Create profile security");
    return LocalOwner(raw);
}

void verify_security(HANDLE handle, const std::string& user, bool directory)
{
    PSID owner = nullptr;
    PACL acl = nullptr;
    PSECURITY_DESCRIPTOR raw = nullptr;
    const auto status = GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &acl, nullptr, &raw);
    const LocalOwner descriptor(raw);
    if(status != ERROR_SUCCESS || !owner || !acl || acl->AceCount != 1) throw ContractError{"profile_security_invalid", "", "Profile ownership or ACL is not private"};
    PSID expected = nullptr;
    const auto user_text = profile_value(launch_utf16(user));
    require_profile(ConvertStringSidToSidW(user_text.c_str(), &expected) != FALSE, "Resolve profile user");
    const LocalOwner sid(expected);
    void* raw_ace = nullptr;
    require_profile(GetAce(acl, 0, &raw_ace) != FALSE, "Read profile ACL");
    const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw_ace);
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    require_profile(GetSecurityDescriptorControl(raw, &control, &revision) != FALSE, "Read profile ACL control");
    if(ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Mask != FILE_ALL_ACCESS || !EqualSid(owner, expected) ||
        !EqualSid(const_cast<DWORD*>(&ace->SidStart), expected) || (directory && (!(control & SE_DACL_PROTECTED) ||
        ace->Header.AceFlags != (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE))))
        throw ContractError{"profile_security_invalid", "", "Profile ACL does not match the owning-user policy"};
}

HandleOwner relative_object(HANDLE parent, const std::wstring& leaf, bool directory, bool create, void* security)
{
    UNICODE_STRING name{static_cast<USHORT>(leaf.size() * sizeof(wchar_t)), static_cast<USHORT>((leaf.size() + 1) * sizeof(wchar_t)), const_cast<wchar_t*>(leaf.data())};
    OBJECT_ATTRIBUTES attributes{sizeof(attributes), parent, &name, OBJ_CASE_INSENSITIVE, security, nullptr};
    IO_STATUS_BLOCK io{};
    HANDLE raw = nullptr;
    const auto function = reinterpret_cast<decltype(&NtCreateFile)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
    if(!function) throw ContractError{"profile_storage_unavailable", "", "Native profile-relative opening is unavailable"};
    const auto rights = READ_CONTROL | SYNCHRONIZE | FILE_READ_ATTRIBUTES | (directory ? FILE_LIST_DIRECTORY | FILE_TRAVERSE : FILE_READ_DATA);
    const auto result = function(&raw, rights, &attributes, &io, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | (directory ? FILE_SHARE_WRITE : 0),
        create ? FILE_OPEN_IF : FILE_OPEN, (directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE) | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT, nullptr, 0);
    HandleOwner handle(raw);
    if(result != 0 || io.Status != 0 || !raw || raw == INVALID_HANDLE_VALUE)
        throw ContractError{static_cast<std::uint32_t>(result) == 0xc0000034 ? "profile_record_missing" : "profile_storage_unavailable", "", "Profile-relative opening failed with NTSTATUS " + hex64(static_cast<std::uint32_t>(result))};
    return handle;
}

std::wstring default_root(const std::string& user)
{
    wchar_t* raw = nullptr;
    const auto result = SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &raw);
    const std::unique_ptr<void, FreeTaskOwner> owner(raw);
    if(FAILED(result) || !raw) throw ContractError{"profile_storage_unavailable", "", "Owning-user local application data is unavailable"};
    std::filesystem::path path(raw);
    const auto security = profile_security(user);
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), security.get(), FALSE};
    for(const auto* leaf : {L"x64dbg-wbbified", L"Mcp", L"profiles"})
    {
        path /= leaf;
        if(!CreateDirectoryW(path.c_str(), &attributes) && GetLastError() != ERROR_ALREADY_EXISTS) require_profile(false, "Create managed profile root");
        const auto flags = GetFileAttributesW(path.c_str());
        if(flags == INVALID_FILE_ATTRIBUTES || !(flags & FILE_ATTRIBUTE_DIRECTORY) || flags & FILE_ATTRIBUTE_REPARSE_POINT)
            throw ContractError{"profile_storage_invalid", "", "Managed profile root must be a directory without a reparse point"};
    }
    return path.wstring();
}
}

BrokerProfile::~BrokerProfile()
{
    if(directory_ != INVALID_HANDLE_VALUE) CloseHandle(directory_);
    if(root_ != INVALID_HANDLE_VALUE) CloseHandle(root_);
}

Checked<std::unique_ptr<BrokerProfile>> BrokerProfile::open(const NativeProcessIdentity& owner, std::string_view profile, std::wstring_view root)
{
    auto store = std::unique_ptr<BrokerProfile>(new BrokerProfile);
    try
    {
        if(profile.size() != 64 || profile.find_first_not_of("0123456789abcdef") != std::string_view::npos)
            throw ContractError{"invalid_argument", "profile", "Profile storage requires a lowercase SHA-256 identifier"};
        store->profile_ = profile;
        store->userSid_ = owner.userSid;
        const auto selected = root.empty() ? default_root(owner.userSid) : std::wstring(root);
        if(selected.empty() || selected.size() > 32000 || selected.find(L'\0') != std::wstring::npos || !std::filesystem::path(selected).is_absolute())
            throw ContractError{"invalid_argument", "profileRoot", "Profile root must be a bounded absolute existing directory"};
        store->root_ = CreateFileW(selected.c_str(), FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        require_profile(store->root_ != INVALID_HANDLE_VALUE, "Open profile root");
        if(!(information(store->root_).dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) throw ContractError{"profile_storage_invalid", "", "Profile root is not a directory"};
        store->rootPath_ = canonical_path(store->root_);
        const auto security = profile_security(owner.userSid);
        auto directory = relative_object(store->root_, profile_value(launch_utf16(profile)), true, true, security.get());
        if(!(information(directory.get()).dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) throw ContractError{"profile_storage_invalid", "", "Profile entry is not a directory"};
        verify_security(directory.get(), owner.userSid, true);
        store->directoryPath_ = canonical_path(directory.get());
        store->directory_ = directory.release();
        return store;
    }
    catch(const ContractError& error) { return error; }
    catch(const std::exception& error) { return ContractError{"profile_storage_unavailable", "", error.what()}; }
}

Checked<Json> BrokerProfile::read(const std::wstring& filename)
{
    try
    {
        auto handle = relative_object(directory_, filename, false, false, nullptr);
        const auto before = information(handle.get());
        if(before.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY || before.nNumberOfLinks != 1 || before.nFileSizeHigh || !before.nFileSizeLow || before.nFileSizeLow > 65536)
            throw ContractError{"profile_record_invalid", "", "Profile record is not a bounded private file"};
        verify_security(handle.get(), userSid_, false);
        std::string bytes(before.nFileSizeLow, '\0');
        DWORD count = 0;
        require_profile(ReadFile(handle.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) && count == bytes.size(), "Read complete profile record");
        const auto after = information(handle.get());
        if(before.nFileIndexHigh != after.nFileIndexHigh || before.nFileIndexLow != after.nFileIndexLow || before.nFileSizeLow != after.nFileSizeLow ||
            CompareFileTime(&before.ftLastWriteTime, &after.ftLastWriteTime) != 0) throw ContractError{"profile_record_invalid", "", "Profile record changed during reading"};
        return parse_bounded_json(bytes);
    }
    catch(const ContractError& error) { return error; }
}

Checked<bool> BrokerProfile::publish(const std::wstring& filename, const Json& value)
{
    const auto bytes = value.dump();
    if(bytes.empty() || bytes.size() > 65536) return ContractError{"profile_record_invalid", "", "Profile publication exceeds the bounded record size"};
    auto prepared = PreparedNewFile::stage(directoryPath_, bytes);
    if(const auto* error = std::get_if<ContractError>(&prepared)) return *error;
    auto file = std::get<std::unique_ptr<PreparedNewFile>>(std::move(prepared));
    const auto published = file->publish(filename);
    if(const auto* error = std::get_if<ContractError>(&published)) return *error;
    return true;
}

Checked<Json> BrokerProfile::configuration(std::string_view installation, bool create)
{
    auto config = read(L"profile.json");
    if(const auto* error = std::get_if<ContractError>(&config); error && create && error->code == "profile_record_missing")
    {
        const auto saved = publish(L"profile.json", {{"schemaVersion", 1}, {"installation", installation}, {"profile", profile_}, {"ownerSid", userSid_}, {"httpPort", 9094}});
        if(const auto* failure = std::get_if<ContractError>(&saved); failure && failure->code != "file_exists") return *failure;
        config = read(L"profile.json");
    }
    if(const auto* error = std::get_if<ContractError>(&config)) return *error;
    const auto& value = std::get<Json>(config);
    const auto schema = closed_object_schema({{"schemaVersion", Json{{"const", 1}}}, {"installation", string_schema("sha256", 64)}, {"profile", string_schema("sha256", 64)},
        {"ownerSid", string_schema("opaque-id", 184)}, {"httpPort", bounded_integer_schema(1, 65535)}}, {"schemaVersion", "installation", "profile", "ownerSid", "httpPort"});
    if(auto error = validate_schema(schema, value)) return *error;
    if(value.at("installation").get<std::string>() != installation || value.at("profile") != profile_ || value.at("ownerSid") != userSid_)
        return ContractError{"profile_identity_mismatch", "", "Profile configuration belongs to another installation, profile or user"};
    return config;
}

std::wstring BrokerProfile::registration_name(std::string_view key, const NativeProcessIdentity& process) const
{
    if(key.size() != 64 || key.find_first_not_of("0123456789abcdef") != std::string_view::npos || !process.pid || !process.creationTime)
        throw ContractError{"invalid_argument", "registration", "Registration requires a namespace digest and a nonzero process generation"};
    return L"registration-" + profile_value(launch_utf16(key)) + L"-" + std::to_wstring(process.pid) + L"-" + std::to_wstring(process.creationTime) + L".json";
}

Checked<bool> BrokerProfile::publish_registration(std::string_view key, const NativeProcessIdentity& process, const Json& value)
{
    return publish(registration_name(key, process), value);
}

Checked<Json> BrokerProfile::registration(std::string_view key, const NativeProcessIdentity& process)
{
    return read(registration_name(key, process));
}
}
