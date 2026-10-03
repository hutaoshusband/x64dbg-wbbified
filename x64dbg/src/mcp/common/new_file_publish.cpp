#include "new_file_publish.h"
#include "platform.h"
#include <bcrypt.h>
#include <winternl.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <cwctype>
#include <stdexcept>

namespace wininspect::mcp
{
namespace
{
struct PublishFailure : std::runtime_error
{
    using std::runtime_error::runtime_error;
};

void require_publish(bool success, const char* operation)
{
    if(!success) throw PublishFailure(std::string(operation) + " failed with Win32 error " + std::to_string(GetLastError()));
}

BY_HANDLE_FILE_INFORMATION publish_information(HANDLE file)
{
    BY_HANDLE_FILE_INFORMATION result{};
    require_publish(GetFileInformationByHandle(file, &result) != FALSE, "GetFileInformationByHandle");
    return result;
}

std::uint64_t publish_index(const BY_HANDLE_FILE_INFORMATION& info)
{
    return (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
}

std::wstring publish_path(HANDLE file)
{
    std::array<wchar_t, 32768> path{};
    const DWORD count = GetFinalPathNameByHandleW(file, path.data(), static_cast<DWORD>(path.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_GUID);
    if(!count || count >= path.size()) throw PublishFailure("Cannot bind a bounded local volume path");
    return std::wstring(path.data(), count);
}

bool publish_leaf(const std::wstring& filename)
{
    if(filename.empty() || filename.size() > 255 || filename.back() == L'.' || filename.back() == L' ') return false;
    for(const auto value : filename)
        if(value < 32 || std::wstring_view(L"\\/:*?\"<>|").find(value) != std::wstring_view::npos) return false;
    auto stem = filename.substr(0, filename.find(L'.'));
    std::transform(stem.begin(), stem.end(), stem.begin(), [](wchar_t value) { return static_cast<wchar_t>(std::towupper(value)); });
    if(stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL" || stem == L"CONIN$" || stem == L"CONOUT$") return false;
    if(stem.size() == 4 && (stem.compare(0, 3, L"COM") == 0 || stem.compare(0, 3, L"LPT") == 0)
            && ((stem[3] >= L'0' && stem[3] <= L'9') || stem[3] == 0xb9 || stem[3] == 0xb2 || stem[3] == 0xb3)) return false;
    return true;
}

void verify_publish_bytes(HANDLE file, std::string_view bytes)
{
    LARGE_INTEGER size{}, start{};
    require_publish(GetFileSizeEx(file, &size) && size.QuadPart >= 0 && static_cast<std::uint64_t>(size.QuadPart) == bytes.size(), "GetFileSizeEx");
    require_publish(SetFilePointerEx(file, start, nullptr, FILE_BEGIN) != FALSE, "SetFilePointerEx");
    std::array<char, 65536> block{};
    std::size_t offset = 0;
    while(offset < bytes.size())
    {
        DWORD count = 0;
        const auto requested = static_cast<DWORD>((std::min)(block.size(), bytes.size() - offset));
        require_publish(ReadFile(file, block.data(), requested, &count, nullptr) && count == requested, "ReadFile");
        if(std::memcmp(block.data(), bytes.data() + offset, count) != 0) throw PublishFailure("Complete temporary file readback differs");
        offset += count;
    }
    DWORD trailing = 0;
    require_publish(ReadFile(file, block.data(), 1, &trailing, nullptr) && trailing == 0, "ReadFile EOF");
}
}

PreparedNewFile::~PreparedNewFile()
{
    if(file_ != INVALID_HANDLE_VALUE)
    {
        if(!published_ && !deletionPending_)
        {
            FILE_DISPOSITION_INFO remove{TRUE};
            SetFileInformationByHandle(file_, FileDispositionInfo, &remove, sizeof(remove));
        }
        CloseHandle(file_);
    }
    if(directoryHandle_ != INVALID_HANDLE_VALUE) CloseHandle(directoryHandle_);
}

Checked<std::unique_ptr<PreparedNewFile>> PreparedNewFile::stage(const std::wstring& directory, std::string_view bytes)
{
    if(directory.empty() || directory.size() > 32700 || directory.find(L'\0') != std::wstring::npos || bytes.size() > 512ull * 1024 * 1024)
        return ContractError{"invalid_argument", "directory", "Publication input exceeds its bound"};
    auto owner = std::unique_ptr<PreparedNewFile>(new PreparedNewFile);
    try
    {
        owner->directoryHandle_ = CreateFileW(directory.c_str(), FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                         FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        require_publish(owner->directoryHandle_ != INVALID_HANDLE_VALUE, "Open destination directory");
        const auto expected = publish_information(owner->directoryHandle_);
        if(!(expected.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (expected.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            throw PublishFailure("Destination must be a directory without a reparse point");
        owner->directory_ = publish_path(owner->directoryHandle_);
        if(owner->directory_.compare(0, 11, L"\\\\?\\Volume{") != 0) throw PublishFailure("Publication requires a local volume GUID path");
        const auto rootEnd = owner->directory_.find(L"}\\", 11);
        if(rootEnd == std::wstring::npos) throw PublishFailure("Volume GUID path is malformed");
        const auto root = owner->directory_.substr(0, rootEnd + 2);
        std::array<wchar_t, 32> filesystem{};
        require_publish(GetVolumeInformationW(root.c_str(), nullptr, 0, nullptr, nullptr, nullptr, filesystem.data(), static_cast<DWORD>(filesystem.size())) != FALSE,
                        "GetVolumeInformationW");
        if(std::wstring_view(filesystem.data()) != L"NTFS") throw PublishFailure("Publication reference currently requires NTFS");
        if(owner->directory_.back() != L'\\') owner->directory_ += L'\\';
        std::array<unsigned char, 16> random{};
        if(BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
            throw PublishFailure("Temporary name generation failed");
        constexpr wchar_t digits[] = L"0123456789abcdef";
        std::wstring leaf = L".x64dbg-mcp-";
        for(const auto value : random) { leaf += digits[value >> 4]; leaf += digits[value & 15]; }
        leaf += L".tmp";
        owner->temporaryPath_ = owner->directory_ + leaf;
        UNICODE_STRING name{static_cast<USHORT>(leaf.size() * sizeof(wchar_t)), static_cast<USHORT>((leaf.size() + 1) * sizeof(wchar_t)), leaf.data()};
        OBJECT_ATTRIBUTES attributes{sizeof(OBJECT_ATTRIBUTES), owner->directoryHandle_, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr};
        IO_STATUS_BLOCK io{};
        const auto create = reinterpret_cast<decltype(&NtCreateFile)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
        if(!create) throw PublishFailure("Native relative file creation is unavailable");
        const auto status = create(&owner->file_, GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE, &attributes, &io, nullptr,
                                   FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT, nullptr, 0);
        if(!owner->file_) owner->file_ = INVALID_HANDLE_VALUE;
        if(status != 0 || io.Status != 0 || io.Information != FILE_CREATED || !owner->file_ || owner->file_ == INVALID_HANDLE_VALUE)
            throw PublishFailure("Exclusive relative file creation failed with NTSTATUS " + hex64(static_cast<std::uint32_t>(status)));
        std::size_t offset = 0;
        while(offset < bytes.size())
        {
            DWORD written = 0;
            const auto count = static_cast<DWORD>((std::min)(bytes.size() - offset, std::size_t(65536)));
            require_publish(WriteFile(owner->file_, bytes.data() + offset, count, &written, nullptr) && written == count, "WriteFile");
            offset += written;
        }
        require_publish(FlushFileBuffers(owner->file_) != FALSE, "FlushFileBuffers");
        HANDLE sealed = INVALID_HANDLE_VALUE;
        require_publish(DuplicateHandle(GetCurrentProcess(), owner->file_, GetCurrentProcess(), &sealed, GENERIC_READ | DELETE | SYNCHRONIZE, FALSE, 0) != FALSE,
                        "Seal temporary file handle");
        const HANDLE writer = owner->file_;
        owner->file_ = sealed;
        require_publish(CloseHandle(writer) != FALSE, "Close temporary writer");
        verify_publish_bytes(owner->file_, bytes);
        const auto information = publish_information(owner->file_);
        if(information.dwVolumeSerialNumber != expected.dwVolumeSerialNumber || information.nNumberOfLinks != 1)
            throw PublishFailure("Temporary identity is not a private same-volume file");
        const auto hash = sha256_file_bytes(bytes);
        if(const auto* error = std::get_if<ContractError>(&hash)) throw PublishFailure(error->message);
        owner->identity_ = {std::get<std::string>(hash), bytes.size(), information.dwVolumeSerialNumber, publish_index(information)};
        return owner;
    }
    catch(const std::exception& error)
    {
        const auto cleanup = owner->discard();
        if(const auto* failure = std::get_if<ContractError>(&cleanup)) return *failure;
        return ContractError{"native_failure", "publication", error.what()};
    }
}

Checked<bool> PreparedNewFile::discard()
{
    if(published_) return ContractError{"invalid_argument", "publication", "A published file requires a separate operation"};
    if(file_ == INVALID_HANDLE_VALUE) return true;
    if(!deletionPending_)
    {
        FILE_DISPOSITION_INFO remove{TRUE};
        if(!SetFileInformationByHandle(file_, FileDispositionInfo, &remove, sizeof(remove)))
            return ContractError{"partial_failure", "temporaryFile", "Owned temporary file deletion failed with Win32 error " + std::to_string(GetLastError())};
        deletionPending_ = true;
    }
    if(!CloseHandle(file_)) return ContractError{"partial_failure", "temporaryFile", "Owned temporary file close failed"};
    file_ = INVALID_HANDLE_VALUE;
    return true;
}

Checked<PublishedFile> PreparedNewFile::publish(const std::wstring& filename)
{
    if(published_ || deletionPending_ || file_ == INVALID_HANDLE_VALUE || !publish_leaf(filename))
        return ContractError{"invalid_argument", "filename", "Publication needs a prepared file and a single ordinary filename"};
    const auto destination = directory_ + filename;
    if(destination.size() > 32766) return ContractError{"invalid_argument", "filename", "Destination exceeds its path bound"};
    if(_wcsicmp(destination.c_str(), temporaryPath_.c_str()) == 0)
        return ContractError{"invalid_argument", "filename", "The temporary filename cannot be the published destination"};
    static_assert(offsetof(FILE_RENAME_INFO, RootDirectory) == sizeof(void*));
    static_assert(offsetof(FILE_RENAME_INFO, FileName) == 2 * sizeof(void*) + sizeof(ULONG));
    const auto count = filename.size() * sizeof(wchar_t);
    std::vector<unsigned char> storage(offsetof(FILE_RENAME_INFO, FileName) + count + sizeof(wchar_t), 0);
    auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
    rename->ReplaceIfExists = FALSE;
    rename->RootDirectory = directoryHandle_;
    rename->FileNameLength = static_cast<DWORD>(count);
    std::memcpy(rename->FileName, filename.data(), count);
    auto result = identity_;
    using NativeRename = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
    const auto set = reinterpret_cast<NativeRename>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile"));
    if(!set) return ContractError{"native_failure", "destination", "Native relative file rename is unavailable"};
    IO_STATUS_BLOCK io{};
    const auto status = set(file_, &io, rename, static_cast<ULONG>(storage.size()), static_cast<FILE_INFORMATION_CLASS>(10));
    if(status != 0)
    {
        return ContractError{static_cast<std::uint32_t>(status) == 0xc0000035 ? "file_exists" : "native_failure", "destination",
                             "Non-replacing relative file rename failed with NTSTATUS " + hex64(static_cast<std::uint32_t>(status))};
    }
    published_ = true;
    if(io.Status != 0) return ContractError{"partial_failure", "destination", "Rename returned success with an inconsistent completion status"};
    BY_HANDLE_FILE_INFORMATION final{};
    if(!GetFileInformationByHandle(file_, &final) || final.dwVolumeSerialNumber != identity_.volumeSerial || publish_index(final) != identity_.fileIndex
            || ((static_cast<std::uint64_t>(final.nFileSizeHigh) << 32) | final.nFileSizeLow) != identity_.size)
        return ContractError{"partial_failure", "destination", "Rename succeeded but published identity verification failed"};
    return result;
}
}
