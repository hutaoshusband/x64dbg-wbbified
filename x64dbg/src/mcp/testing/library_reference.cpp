#include "library_reference.h"
#include "new_file_publish.h"
#include "platform.h"
#include "lifecycle.h"
#include "schema_helpers.h"
#include <Windows.h>
#include <sddl.h>
#include <sqlite3.h>
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <thread>

namespace wininspect::mcp
{
namespace
{
struct StoreFailure : std::runtime_error
{
    std::string code;
    int nativeCode;
    StoreFailure(std::string reason, int value) : std::runtime_error(reason), code(std::move(reason)), nativeCode(value) {}
};

struct HandleCloser
{
    void operator()(void* value) const { if(value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};

struct LocalCloser
{
    void operator()(void* value) const { LocalFree(value); }
};

using Handle = std::unique_ptr<void, HandleCloser>;
using LocalAllocation = std::unique_ptr<void, LocalCloser>;
using Database = std::unique_ptr<sqlite3, decltype(&sqlite3_close)>;
using Statement = std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>;

std::wstring wide_path(const std::string& value)
{
    const auto decoded = launch_utf16(value);
    if(!std::holds_alternative<std::wstring>(decoded)) throw StoreFailure("invalid_path", 0);
    return std::get<std::wstring>(decoded);
}

void execute(sqlite3* database, const char* sql, const char* failure)
{
    const auto result = sqlite3_exec(database, sql, nullptr, nullptr, nullptr);
    if(result != SQLITE_OK) throw StoreFailure(result == SQLITE_BUSY ? "store_busy" : failure, result);
}

Statement prepare(sqlite3* database, const char* sql)
{
    sqlite3_stmt* statement = nullptr;
    const auto result = sqlite3_prepare_v2(database, sql, -1, &statement, nullptr);
    Statement owned(statement, sqlite3_finalize);
    if(result != SQLITE_OK) throw StoreFailure("store_corrupt", result);
    return owned;
}

std::int64_t scalar(sqlite3* database, const char* sql)
{
    const auto statement = prepare(database, sql);
    const auto result = sqlite3_step(statement.get());
    if(result != SQLITE_ROW || sqlite3_column_type(statement.get(), 0) != SQLITE_INTEGER)
        throw StoreFailure("metadata_inconsistent", result);
    return sqlite3_column_int64(statement.get(), 0);
}

class Transaction
{
public:
    explicit Transaction(sqlite3* database) : database_(database) { execute(database_, "BEGIN IMMEDIATE", "transaction_failed"); }
    ~Transaction() { if(active_) sqlite3_exec(database_, "ROLLBACK", nullptr, nullptr, nullptr); }
    void commit() { execute(database_, "COMMIT", "commit_failed"); active_ = false; }
    void rollback() { execute(database_, "ROLLBACK", "rollback_failed"); active_ = false; }
private:
    sqlite3* database_;
    bool active_ = true;
};

std::string encode_hex(std::string_view bytes)
{
    constexpr char digits[] = "0123456789abcdef";
    std::string encoded;
    encoded.reserve(bytes.size() * 2);
    for(const auto character : bytes)
    {
        const auto byte = static_cast<unsigned char>(character);
        encoded.push_back(digits[byte >> 4]);
        encoded.push_back(digits[byte & 15]);
    }
    return encoded;
}

std::string decode_hex(std::string_view encoded)
{
    std::string bytes;
    bytes.reserve(encoded.size() / 2);
    const auto digit = [](char value) { return value <= '9' ? value - '0' : value - 'a' + 10; };
    for(std::size_t offset = 0; offset < encoded.size(); offset += 2)
        bytes.push_back(static_cast<char>((digit(encoded[offset]) << 4) | digit(encoded[offset + 1])));
    return bytes;
}

std::string read_blob(const std::filesystem::path& path)
{
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if(!stream) throw StoreFailure("blob_missing", 0);
    const auto size = stream.tellg();
    if(size < 0 || size > 65536) throw StoreFailure("blob_mismatch", 0);
    std::string bytes(static_cast<std::size_t>(size), '\0');
    stream.seekg(0);
    if(!stream.read(bytes.data(), static_cast<std::streamsize>(bytes.size()))) throw StoreFailure("blob_missing", 0);
    return bytes;
}

std::string hash_bytes(std::string_view bytes)
{
    const auto result = sha256_file_bytes(bytes);
    if(!std::holds_alternative<std::string>(result)) throw StoreFailure("hash_failed", 0);
    return std::get<std::string>(result);
}

void publish_blob(const std::wstring& directory, const std::wstring& leaf, std::string_view bytes)
{
    auto staged = PreparedNewFile::stage(directory, bytes);
    if(!std::holds_alternative<std::unique_ptr<PreparedNewFile>>(staged)) throw StoreFailure("blob_publish_failed", 0);
    const auto result = std::get<std::unique_ptr<PreparedNewFile>>(staged)->publish(leaf);
    if(!std::holds_alternative<PublishedFile>(result)) throw StoreFailure("blob_publish_failed", 0);
}

void create_namespace(const std::wstring& root, const std::string& userSid)
{
    const auto descriptor = L"O:" + wide_path(userSid) + L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + wide_path(userSid) + L")";
    PSECURITY_DESCRIPTOR raw = nullptr;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptor.c_str(), SDDL_REVISION_1, &raw, nullptr))
        throw StoreFailure("acl_failed", GetLastError());
    LocalAllocation owned(raw);
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), raw, FALSE};
    if(!CreateDirectoryW(root.c_str(), &attributes)) throw StoreFailure("namespace_create_failed", GetLastError());
    if(!CreateDirectoryW((root + L"\\blobs").c_str(), nullptr)) throw StoreFailure("namespace_create_failed", GetLastError());
}

Json inspect_store(sqlite3* database, const std::wstring& root)
{
    const auto integrity = prepare(database, "PRAGMA quick_check");
    auto result = sqlite3_step(integrity.get());
    if(result != SQLITE_ROW || std::string(reinterpret_cast<const char*>(sqlite3_column_text(integrity.get(), 0))) != "ok")
        throw StoreFailure("store_corrupt", result);
    if(scalar(database, "PRAGMA user_version") != 1) throw StoreFailure("schema_mismatch", 0);
    const auto foreign = prepare(database, "PRAGMA foreign_key_check");
    if(sqlite3_step(foreign.get()) != SQLITE_DONE) throw StoreFailure("metadata_inconsistent", 0);
    const auto current = scalar(database, "SELECT revision FROM current_revision WHERE singleton=1");
    const auto rows = prepare(database, "SELECT revision, sha256, size, namespace, owner, path FROM revisions ORDER BY revision");
    Json revisions = Json::array();
    bool foundCurrent = false;
    while((result = sqlite3_step(rows.get())) == SQLITE_ROW)
    {
        if(sqlite3_column_type(rows.get(), 0) != SQLITE_INTEGER || sqlite3_column_type(rows.get(), 2) != SQLITE_INTEGER)
            throw StoreFailure("metadata_inconsistent", 0);
        const auto revision = sqlite3_column_int64(rows.get(), 0);
        const auto size = sqlite3_column_int64(rows.get(), 2);
        const auto text = [&](int column)
        {
            if(sqlite3_column_type(rows.get(), column) != SQLITE_TEXT) throw StoreFailure("metadata_inconsistent", 0);
            return std::string(reinterpret_cast<const char*>(sqlite3_column_text(rows.get(), column)), sqlite3_column_bytes(rows.get(), column));
        };
        const auto hash = text(1);
        if(revision < 1 || size < 0 || size > 65536 || hash.size() != 64 || hash.find_first_not_of("0123456789abcdef") != std::string::npos)
            throw StoreFailure("metadata_inconsistent", 0);
        const auto bytes = read_blob(std::filesystem::path(root) / L"blobs" / (wide_path(hash) + L".blob"));
        if(bytes.size() != static_cast<std::size_t>(size) || hash_bytes(bytes) != hash) throw StoreFailure("blob_mismatch", 0);
        revisions.push_back({{"revision", std::to_string(revision)}, {"sha256", hash}, {"size", std::to_string(size)},
                             {"namespace", text(3)}, {"owner", text(4)}, {"path", text(5)}, {"bytesHex", encode_hex(bytes)}});
        foundCurrent |= revision == current;
    }
    if(result != SQLITE_DONE || !foundCurrent) throw StoreFailure("metadata_inconsistent", result);
    return {{"currentRevision", std::to_string(current)}, {"revisions", revisions}};
}

void insert_revision(sqlite3* database, std::int64_t revision, const std::string& hash, std::size_t size)
{
    const auto statement = prepare(database, "INSERT INTO revisions VALUES(?1,?2,?3,'private-fixture','client-fixture','scripts/fixture.bin')");
    if(sqlite3_bind_int64(statement.get(), 1, revision) != SQLITE_OK || sqlite3_bind_text(statement.get(), 2, hash.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
       sqlite3_bind_int64(statement.get(), 3, static_cast<sqlite3_int64>(size)) != SQLITE_OK) throw StoreFailure("metadata_bind_failed", 0);
    const auto result = sqlite3_step(statement.get());
    if(result != SQLITE_DONE) throw StoreFailure("metadata_constraint", result);
    const auto update = prepare(database, "INSERT INTO current_revision VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET revision=excluded.revision");
    if(sqlite3_bind_int64(update.get(), 1, revision) != SQLITE_OK || sqlite3_step(update.get()) != SQLITE_DONE)
        throw StoreFailure("metadata_update_failed", sqlite3_errcode(database));
}

class Impersonation
{
public:
    explicit Impersonation(HANDLE token) { if(!ImpersonateLoggedOnUser(token)) throw StoreFailure("impersonation_failed", GetLastError()); }
    ~Impersonation() { if(!RevertToSelf()) std::terminate(); }
};

Json restricted_access(const std::wstring& path)
{
    Handle normal(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
    if(normal.get() == INVALID_HANDLE_VALUE) throw StoreFailure("normal_access_failed", GetLastError());
    HANDLE rawToken = nullptr;
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &rawToken))
        throw StoreFailure("token_failed", GetLastError());
    Handle token(rawToken);
    PSID rawSid = nullptr;
    if(!ConvertStringSidToSidW(L"S-1-5-7", &rawSid)) throw StoreFailure("sid_failed", GetLastError());
    LocalAllocation sid(rawSid);
    SID_AND_ATTRIBUTES restriction{rawSid, 0};
    HANDLE rawRestricted = nullptr;
    if(!CreateRestrictedToken(token.get(), DISABLE_MAX_PRIVILEGE, 0, nullptr, 0, nullptr, 1, &restriction, &rawRestricted))
        throw StoreFailure("restricted_token_failed", GetLastError());
    Handle restricted(rawRestricted);
    Json attempts = Json::array();
    for(const DWORD desired : std::array<DWORD, 2>{GENERIC_READ, GENERIC_WRITE})
    {
        Impersonation impersonation(restricted.get());
        const auto file = CreateFileW(path.c_str(), desired, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        const auto error = file == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        Handle owned(file);
        attempts.push_back({{"access", desired == GENERIC_READ ? "read" : "write"}, {"opened", file != INVALID_HANDLE_VALUE}, {"error", error}});
    }
    return {{"normalRead", true}, {"restrictedSid", "S-1-5-7"}, {"attempts", attempts}};
}
}

Json library_reference(const Json& input)
{
    const auto identity = capture_current_process();
    if(!std::holds_alternative<NativeProcessIdentity>(identity)) throw StoreFailure("identity_failed", 0);
    Json reply{{"valid", false}, {"identity", native_process_json(std::get<NativeProcessIdentity>(identity))},
               {"sqliteVersion", sqlite3_libversion()}, {"nonce", input.is_object() ? input.value("nonce", Json()) : Json()}};
    try
    {
        const auto schema = closed_object_schema({{"mode", enum_schema({"create", "read", "append", "append_constraint", "hold", "acl"})},
            {"root", string_schema("windows-absolute-path", 16384)}, {"nonce", string_schema("opaque-id", 64)},
            {"bytesHex", {{"oneOf", Json::array({Json{{"const", ""}}, string_schema("hex-bytes", 131072)})}}},
            {"expectedRevision", bounded_integer_schema(0, 1000)}},
            {"mode", "root", "nonce", "bytesHex", "expectedRevision"});
        if(validate_schema(schema, input)) throw StoreFailure("invalid_input", 0);
        const auto mode = input.at("mode").get<std::string>();
        const auto rootText = input.at("root").get<std::string>();
        const auto root = wide_path(rootText);
        const auto nonce = input.at("nonce").get<std::string>();
        if(nonce.empty() || nonce.find_first_not_of("0123456789abcdef") != std::string::npos) throw StoreFailure("invalid_input", 0);
        const auto create = mode == "create";
        if(create && input.at("expectedRevision").get<int>() != 0) throw StoreFailure("invalid_input", 0);
        if(create) create_namespace(root, std::get<NativeProcessIdentity>(identity).userSid);
        sqlite3* raw = nullptr;
        const auto flags = create ? SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE : mode == "read" || mode == "acl" ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE;
        const auto opened = sqlite3_open_v2((rootText + "/library.db").c_str(), &raw, flags, nullptr);
        Database database(raw, sqlite3_close);
        if(opened != SQLITE_OK) throw StoreFailure("store_open_failed", opened);
        execute(raw, "PRAGMA foreign_keys=ON", "store_corrupt");
        if(create)
            execute(raw, "PRAGMA user_version=1; CREATE TABLE revisions(revision INTEGER PRIMARY KEY,sha256 TEXT NOT NULL,size INTEGER NOT NULL,namespace TEXT NOT NULL,owner TEXT NOT NULL,path TEXT NOT NULL); CREATE TABLE current_revision(singleton INTEGER PRIMARY KEY CHECK(singleton=1),revision INTEGER NOT NULL REFERENCES revisions(revision))", "schema_create_failed");
        Json before = create ? Json{{"currentRevision", "0"}, {"revisions", Json::array()}} : inspect_store(raw, root);
        reply["before"] = before;
        if(mode == "read") reply["store"] = before;
        else if(mode == "acl")
        {
            const auto hash = before.at("revisions").at(0).at("sha256").get<std::string>();
            reply["access"] = restricted_access(root + L"\\blobs\\" + wide_path(hash) + L".blob");
            reply["store"] = before;
        }
        else
        {
            if(sqlite3_db_readonly(raw, "main") != 0) throw StoreFailure("store_readonly", 0);
            Transaction transaction(raw);
            const auto current = create ? 0 : scalar(raw, "SELECT revision FROM current_revision WHERE singleton=1");
            if(current != input.at("expectedRevision").get<int>()) throw StoreFailure("stale_revision", 0);
            if(mode == "hold")
            {
                const auto ready = root + L"\\held-" + wide_path(nonce) + L".json";
                const auto release = root + L"\\release-" + wide_path(nonce);
                const auto held = Json{{"identity", reply["identity"]}, {"nonce", nonce}, {"currentRevision", std::to_string(current)}, {"transactionHeld", sqlite3_get_autocommit(raw) == 0}}.dump();
                publish_blob(root, std::filesystem::path(ready).filename().wstring(), held);
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
                while(GetFileAttributesW(release.c_str()) == INVALID_FILE_ATTRIBUTES)
                {
                    if(std::chrono::steady_clock::now() >= deadline) throw StoreFailure("held_deadline", 0);
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
                transaction.rollback();
                if(!DeleteFileW(ready.c_str()) || !DeleteFileW(release.c_str())) throw StoreFailure("held_cleanup_failed", GetLastError());
                reply["rolledBack"] = sqlite3_get_autocommit(raw) == 1;
            }
            else
            {
                const auto bytes = decode_hex(input.at("bytesHex").get<std::string>());
                const auto hash = hash_bytes(bytes);
                const auto leaf = wide_path(hash) + L".blob";
                const auto destination = root + L"\\blobs\\" + leaf;
                const auto fresh = GetFileAttributesW(destination.c_str()) == INVALID_FILE_ATTRIBUTES;
                if(fresh) publish_blob(root + L"\\blobs", leaf, bytes);
                else if(read_blob(destination) != bytes) throw StoreFailure("blob_mismatch", 0);
                try
                {
                    insert_revision(raw, mode == "append_constraint" ? current : current + 1, hash, bytes.size());
                    transaction.commit();
                }
                catch(const StoreFailure&)
                {
                    transaction.rollback();
                    if(fresh && !DeleteFileW(destination.c_str())) throw StoreFailure("blob_cleanup_failed", GetLastError());
                    reply["rolledBack"] = sqlite3_get_autocommit(raw) == 1;
                    reply["publishedBlobRemoved"] = fresh;
                    throw;
                }
            }
            reply["store"] = inspect_store(raw, root);
        }
        reply["valid"] = true;
    }
    catch(const StoreFailure& error)
    {
        reply["error"] = {{"code", error.code}, {"nativeCode", error.nativeCode}};
    }
    return reply;
}
}
