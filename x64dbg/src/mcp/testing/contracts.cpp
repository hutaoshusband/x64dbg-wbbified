#include "contracts.h"
#include "registry.h"
#include "legacy_aliases.h"
#include "parity_catalog.h"
#include "platform.h"
#include "process_peer.h"
#include "pe_file_patch.h"
#include "new_file_publish.h"
#include "lifecycle.h"
#include "ipc.h"
#include "worker.h"
#include "library_reference.h"
#include "pipe_reference.h"
#include <boost/beast/http.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/version.hpp>
#include <quickjs.h>
#include <sqlite3.h>
#include <chrono>
#include <array>
#include <fcntl.h>
#include <io.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>

using namespace wininspect::mcp;

namespace
{
Checked<std::string> read_input()
{
    std::string input;
    char chunk[8192];
    while(std::cin)
    {
        std::cin.read(chunk, sizeof(chunk));
        const auto size = static_cast<std::size_t>(std::cin.gcount());
        if(size > MaximumFrameBytes - input.size())
            return ContractError{"payload_limit", "", "Input exceeds the frame limit"};
        input.append(chunk, size);
    }
    return input;
}

template<typename Value>
Json checked_reply(const Checked<Value>& value)
{
    if(const auto error = std::get_if<ContractError>(&value))
        return {{"valid", false}, {"error", error_json(*error)}};
    return {{"valid", true}};
}

Json process_peer_probe(const Json& input)
{
    const auto schema = closed_object_schema({{"pid", bounded_integer_schema(1, 0xffffffffull)},
        {"handle", enum_schema({"process", "query", "synchronize", "null", "event"})}}, {"pid", "handle"});
    if(const auto error = validate_schema(schema, input))
        return {{"valid", false}, {"error", error_json(*error)}};
    const auto kind = input.at("handle").get<std::string>();
    const auto rights = kind == "query" ? PROCESS_QUERY_LIMITED_INFORMATION : kind == "synchronize" ? SYNCHRONIZE : PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;
    const auto close = [](void* value) { if(value) CloseHandle(value); };
    const std::unique_ptr<void, decltype(close)> process(kind == "null" ? nullptr : kind == "event" ? CreateEventW(nullptr, TRUE, FALSE, nullptr) :
        OpenProcess(rights, FALSE, input.at("pid").get<DWORD>()), close);
    const auto identity = capture_held_process(process.get());
    auto reply = checked_reply(identity);
    if(const auto* value = std::get_if<NativeProcessIdentity>(&identity)) reply["identity"] = native_process_json(*value);
    return reply;
}

Json dependency_probe()
{
    sqlite3* raw_database = nullptr;
    const auto opened = sqlite3_open(":memory:", &raw_database);
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> database(raw_database, sqlite3_close);
    if(opened != SQLITE_OK || sqlite3_exec(database.get(), "CREATE TABLE fixture(value INTEGER UNIQUE); INSERT INTO fixture VALUES(42)", nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("SQLite fixture initialization failed");
    const auto duplicate = sqlite3_exec(database.get(), "INSERT INTO fixture VALUES(42)", nullptr, nullptr, nullptr);
    sqlite3_stmt* raw_statement = nullptr;
    const auto prepared = sqlite3_prepare_v2(database.get(), "SELECT value FROM fixture", -1, &raw_statement, nullptr);
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> statement(raw_statement, sqlite3_finalize);
    if(prepared != SQLITE_OK || sqlite3_step(statement.get()) != SQLITE_ROW)
        throw std::runtime_error("SQLite fixture query failed");
    const auto stored = sqlite3_column_int(statement.get(), 0);
    std::unique_ptr<JSRuntime, decltype(&JS_FreeRuntime)> runtime(JS_NewRuntime(), JS_FreeRuntime);
    if(!runtime)
        throw std::runtime_error("JavaScript runtime allocation failed");
    JS_SetMemoryLimit(runtime.get(), 8 * 1024 * 1024);
    JS_SetMaxStackSize(runtime.get(), 128 * 1024);
    auto expires = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    JS_SetInterruptHandler(runtime.get(), [](JSRuntime*, void* opaque) -> int
    {
        return std::chrono::steady_clock::now() >= *static_cast<std::chrono::steady_clock::time_point*>(opaque);
    }, &expires);
    std::unique_ptr<JSContext, decltype(&JS_FreeContext)> context(JS_NewContext(runtime.get()), JS_FreeContext);
    if(!context)
        throw std::runtime_error("JavaScript context allocation failed");
    const std::string source = "6 * 7";
    const auto result = JS_Eval(context.get(), source.data(), source.size(), "dependency-fixture", JS_EVAL_TYPE_GLOBAL);
    std::int32_t observed = 0;
    const bool evaluated = !JS_IsException(result) && JS_ToInt32(context.get(), &observed, result) == 0;
    JS_FreeValue(context.get(), result);
    if(!evaluated)
        throw std::runtime_error("JavaScript fixture evaluation failed");
    return {{"pointerBits", sizeof(void*) * 8}, {"boostVersion", BOOST_LIB_VERSION}, {"jsonVersion", NLOHMANN_JSON_VERSION_MAJOR * 10000 + NLOHMANN_JSON_VERSION_MINOR * 100 + NLOHMANN_JSON_VERSION_PATCH},
            {"sqliteVersion", sqlite3_libversion()}, {"sqliteSourceId", sqlite3_sourceid()},
            {"sqliteValue", stored}, {"sqliteDuplicateError", duplicate}, {"javascriptValue", observed},
            {"javascriptVersion", std::to_string(QJS_VERSION_MAJOR) + "." + std::to_string(QJS_VERSION_MINOR) + "." + std::to_string(QJS_VERSION_PATCH)}};
}

Json http_probe(std::string_view input)
{
    boost::beast::http::request_parser<boost::beast::http::string_body> parser;
    parser.body_limit(MaximumPayloadBytes);
    parser.header_limit(8192);
    parser.eager(true);
    boost::system::error_code error;
    const auto consumed = parser.put(boost::asio::buffer(input.data(), input.size()), error);
    if(error == boost::beast::http::error::need_more)
        error.clear();
    if(!error && !parser.is_done())
        parser.put_eof(error);
    if(error || !parser.is_done() || consumed != input.size())
        return {{"valid", false}, {"consumed", consumed}, {"error", error ? error.message() : "Trailing or incomplete request"}};
    const auto& request = parser.get();
    return {{"valid", true}, {"method", std::string(request.method_string())},
            {"target", std::string(request.target())}, {"body", request.body()}};
}

std::string read_fixture_file(const std::string& path)
{
    const auto decoded = launch_utf16(path);
    if(const auto* error = std::get_if<ContractError>(&decoded))
        throw std::runtime_error(error->message);
    std::ifstream file(std::filesystem::path(std::get<std::wstring>(decoded)), std::ios::binary);
    if(!file)
        throw std::runtime_error("Cannot open the supplied private fixture file");
    std::string bytes;
    std::array<char, 65536> block{};
    constexpr std::size_t maximum = 512 * 1024 * 1024;
    while(file)
    {
        file.read(block.data(), block.size());
        const auto size = static_cast<std::size_t>(file.gcount());
        if(size > maximum - bytes.size())
            throw std::runtime_error("Private fixture file exceeds the native artifact bound");
        bytes.append(block.data(), size);
    }
    if(!file.eof())
        throw std::runtime_error("Cannot completely read the supplied private fixture file");
    return bytes;
}

PatchBytes fixture_bytes(const std::string& encoded)
{
    PatchBytes bytes;
    for(std::size_t offset = 0; offset < encoded.size(); offset += 2)
        bytes.push_back(static_cast<std::uint8_t>(std::stoul(encoded.substr(offset, 2), nullptr, 16)));
    return bytes;
}

std::string fixture_hex(const PatchBytes& bytes)
{
    constexpr char digits[] = "0123456789abcdef";
    std::string output;
    for(const auto byte : bytes)
    {
        output.push_back(digits[byte >> 4]);
        output.push_back(digits[byte & 15]);
    }
    return output;
}

Json pe_plan_probe(const Json& input)
{
    auto range = closed_object_schema({{"domain", enum_schema({"file_offset", "rva", "loaded_va"})}, {"addressHex", contract_schema("Hex64")},
        {"encoding", enum_schema({"file_bytes", "loaded_bytes"})}, {"expectedHex", string_schema("hex-bytes", MaximumPatchBytes * 2)},
        {"replacementHex", string_schema("hex-bytes", MaximumPatchBytes * 2)}}, {"domain", "addressHex", "encoding", "expectedHex", "replacementHex"});
    auto schema = closed_object_schema({{"sourcePath", string_schema("windows-absolute-path", 32766)}, {"loadedBaseHex", contract_schema("Hex64")},
        {"ranges", bounded_array_schema(range, MaximumPatchRanges, 1)}, {"outputPath", string_schema("windows-absolute-path", 32766)},
        {"renderSourcePath", string_schema("windows-absolute-path", 32766)}}, {"sourcePath", "loadedBaseHex", "ranges"});
    if(const auto error = validate_schema(schema, input))
        return {{"valid", false}, {"error", error_json(*error)}};
    const auto source = read_fixture_file(input.at("sourcePath").get<std::string>());
    std::vector<PePatchRequest> requests;
    for(const auto& item : input.at("ranges"))
    {
        const auto domain = item.at("domain").get<std::string>();
        requests.push_back({domain == "file_offset" ? PePatchAddress::FileOffset : domain == "rva" ? PePatchAddress::Rva : PePatchAddress::LoadedVa,
            std::get<std::uint64_t>(parse_hex64(item.at("addressHex").get<std::string>())),
            item.at("encoding") == "file_bytes" ? PePatchEncoding::FileBytes : PePatchEncoding::LoadedBytes,
            fixture_bytes(item.at("expectedHex").get<std::string>()), fixture_bytes(item.at("replacementHex").get<std::string>())});
    }
    const auto plan = plan_pe_file_patch(source, std::get<std::uint64_t>(parse_hex64(input.at("loadedBaseHex").get<std::string>())), requests);
    auto reply = checked_reply(plan);
    if(const auto* value = std::get_if<PeFilePatchPlan>(&plan))
    {
        Json ranges = Json::array();
        for(const auto& item : value->ranges)
            ranges.push_back({{"fileOffset", decimal64(item.fileOffset)}, {"expectedHex", fixture_hex(item.expected)},
                {"replacementHex", fixture_hex(item.replacement)}, {"normalizedRelocations", item.normalizedRelocations}});
        reply["plan"] = {{"sourceSize", decimal64(value->sourceSize)}, {"sourceSha256", value->sourceSha256}, {"preferredBaseHex", hex64(value->preferredBase)},
            {"imageSize", value->imageSize}, {"pointerBits", value->pointerBits}, {"overlayOffset", decimal64(value->overlayOffset)},
            {"hasCertificate", value->hasCertificate}, {"ranges", std::move(ranges)}};
        const auto renderSource = input.contains("renderSourcePath") ? read_fixture_file(input.at("renderSourcePath").get<std::string>()) : source;
        const auto rendered = render_pe_file_patch(renderSource, *value);
        if(const auto* error = std::get_if<ContractError>(&rendered))
            return {{"valid", false}, {"error", error_json(*error)}, {"plan", reply.at("plan")}};
        const auto& output = std::get<std::string>(rendered);
        const auto hash = sha256_file_bytes(output);
        if(const auto* error = std::get_if<ContractError>(&hash))
            return {{"valid", false}, {"error", error_json(*error)}};
        reply["outputSha256"] = std::get<std::string>(hash);
        if(input.contains("outputPath"))
        {
            const auto path = std::get<std::wstring>(launch_utf16(input.at("outputPath").get<std::string>()));
            std::ofstream file(std::filesystem::path(path), std::ios::binary | std::ios::trunc);
            file.write(output.data(), static_cast<std::streamsize>(output.size()));
            file.flush();
            if(!file)
                throw std::runtime_error("Private fixture materialization failed");
        }
    }
    return reply;
}

Json publication_probe(const Json& input)
{
    const auto schema = closed_object_schema({{"sourcePath", string_schema("windows-absolute-path", 32766)},
        {"directory", string_schema("windows-absolute-path", 32700)}, {"filename", string_schema("utf8-text", 1024)},
        {"guard", enum_schema({"none", "late", "locked", "readonly"})}, {"discard", Json{{"type", "boolean"}}}}, {"sourcePath", "directory", "filename"});
    if(const auto error = validate_schema(schema, input)) return {{"valid", false}, {"error", error_json(*error)}};
    const auto source = read_fixture_file(input.at("sourcePath").get<std::string>());
    const auto directory = std::get<std::wstring>(launch_utf16(input.at("directory").get<std::string>()));
    const auto filename = std::get<std::wstring>(launch_utf16(input.at("filename").get<std::string>()));
    const auto moved = directory + L"-moved";
    const DWORD attributes = GetFileAttributesW(directory.c_str());
    bool renameAllowed = false;
    if(attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        if(!MoveFileExW(directory.c_str(), moved.c_str(), 0) || !MoveFileExW(moved.c_str(), directory.c_str(), 0))
            throw std::runtime_error("Private directory rename positive control failed");
        renameAllowed = true;
    }
    auto staged = PreparedNewFile::stage(directory, source);
    auto* owner = std::get_if<std::unique_ptr<PreparedNewFile>>(&staged);
    if(!owner) return checked_reply(staged);
    const auto temporary = (*owner)->temporaryPath();
    Json reply{{"valid", true}, {"temporaryPath", std::get<std::string>(launch_utf8(temporary))}, {"directoryRenameAllowedBeforeStage", renameAllowed}};
    HANDLE write = CreateFileW(temporary.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    reply["temporaryWriteError"] = write == INVALID_HANDLE_VALUE ? GetLastError() : 0;
    if(write != INVALID_HANDLE_VALUE) CloseHandle(write);
    reply["temporaryDeleteError"] = DeleteFileW(temporary.c_str()) ? 0 : GetLastError();
    reply["directoryRenameError"] = MoveFileExW(directory.c_str(), moved.c_str(), 0) ? 0 : GetLastError();
    reply["selfRename"] = checked_reply((*owner)->publish(temporary.substr(temporary.find_last_of(L'\\') + 1)));
    const auto guard = input.value("guard", std::string("none"));
    struct GuardHandle
    {
        HANDLE value = INVALID_HANDLE_VALUE;
        ~GuardHandle() { if(value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    } lock;
    if(guard != "none")
    {
        const auto path = directory + L"\\" + filename;
        HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if(file == INVALID_HANDLE_VALUE) throw std::runtime_error("Late private guard creation failed");
        constexpr char sentinel[] = "publication-guard";
        DWORD written = 0;
        const bool saved = WriteFile(file, sentinel, sizeof(sentinel) - 1, &written, nullptr) && written == sizeof(sentinel) - 1 && FlushFileBuffers(file);
        CloseHandle(file);
        if(!saved) throw std::runtime_error("Late private guard write failed");
        if(guard == "readonly" && !SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_READONLY)) throw std::runtime_error("Private read-only guard failed");
        if(guard == "locked")
        {
            lock.value = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if(lock.value == INVALID_HANDLE_VALUE) throw std::runtime_error("Private guard lock failed");
        }
    }
    if(input.value("discard", false)) reply["discard"] = checked_reply((*owner)->discard());
    else
    {
        const auto published = (*owner)->publish(filename);
        reply["publication"] = checked_reply(published);
        if(const auto* identity = std::get_if<PublishedFile>(&published))
        {
            reply["publication"]["identity"] = {{"sha256", identity->sha256}, {"size", decimal64(identity->size)},
                {"volumeSerial", identity->volumeSerial}, {"fileIndex", decimal64(identity->fileIndex)}};
            reply["repeat"] = checked_reply((*owner)->publish(filename));
            reply["discardAfterPublication"] = checked_reply((*owner)->discard());
        }
        else reply["discard"] = checked_reply((*owner)->discard());
    }
    owner->reset();
    reply["temporaryAbsent"] = GetFileAttributesW(temporary.c_str()) == INVALID_FILE_ATTRIBUTES;
    return reply;
}

Json normalized_contract(std::string_view name, const Json& input)
{
    if(name == "Page")
    {
        const auto parsed = parse_page(input);
        auto reply = checked_reply(parsed);
        if(const auto page = std::get_if<Page>(&parsed))
        {
            reply["limit"] = page->limit;
            if(page->cursor)
                reply["cursor"] = *page->cursor;
        }
        return reply;
    }
    if(name == "Deadline")
    {
        const auto parsed = parse_deadline(input);
        auto reply = checked_reply(parsed);
        if(const auto deadline = std::get_if<Deadline>(&parsed))
            reply["timeoutMs"] = deadline->timeoutMs;
        return reply;
    }
    if(name == "MutationContext")
    {
        const auto parsed = parse_mutation_context(input);
        auto reply = checked_reply(parsed);
        if(const auto context = std::get_if<MutationContext>(&parsed))
        {
            reply["targetGeneration"] = decimal64(context->paused.target.targetGeneration);
            reply["stopEpoch"] = decimal64(context->paused.stopEpoch);
            reply["leaseId"] = context->leaseId.value;
            if(context->paused.threadId)
                reply["threadId"] = *context->paused.threadId;
        }
        return reply;
    }
    if(name == "Decimal64" || name == "Hex64")
    {
        const auto parsed = name == "Decimal64" ? parse_decimal64(input.get<std::string>()) : parse_hex64(input.get<std::string>());
        auto reply = checked_reply(parsed);
        if(const auto value = std::get_if<std::uint64_t>(&parsed))
        {
            reply["decimal"] = decimal64(*value);
            reply["hex"] = hex64(*value);
        }
        return reply;
    }
    throw std::runtime_error("Unsupported normalization contract");
}

Json result_examples()
{
    const RecoveryRoute recovery{"operation_reconcile", RetryPolicy::AfterReconciliation, "Inspect the retained operation before another attempt"};
    const VerificationEvidence evidence{"fixture_observation", "native_contract_fixture", "Typed serialization fixture", {}, {}};
    ResultHeader header{{"operation-fixture"}, PausedContext{{{"instance-1"}, {"target-1"}, UINT64_MAX}, 9007199254740993ull, 1}, UINT64_MAX,
        {VerificationStatus::Verified, {evidence}, {}}, {}, {9007199254740993ull, UINT64_MAX, 0}};
    const Json data = {{"value", "0xffffffffffffffff"}};
    Json examples = Json::array();
    header.jobId = JobId{"job-fixture"};
    examples.push_back(result_json(OperationResult<Json>{header, CompletedResult<Json>{data, false, ResultPagination{UINT64_MAX, true, {}}}}));
    header.verification = {VerificationStatus::Pending, {}, {}};
    examples.push_back(result_json(OperationResult<Json>{header, AcceptedResult{{"job-fixture"}}}));
    header.verification = {VerificationStatus::Failed, {evidence}, {}};
    examples.push_back(result_json(OperationResult<Json>{header, PartialFailureResult<Json>{data, {DomainErrorCode::PartialFailure, "Observed write could not be completely restored", "/ranges/1", recovery}, {{"range-1", EffectStatus::Applied, "One range remains changed"}}, recovery}}));
    examples.push_back(result_json(OperationResult<Json>{header, FailedResult{{DomainErrorCode::ExpectedBytesMismatch, "Precondition differs before mutation", "/expected", {}}}}));
    header.verification = {VerificationStatus::Verified, {evidence}, {}};
    examples.push_back(result_json(OperationResult<Json>{header, CancelledResult<Json>{{}, {}}}));
    header.verification = {VerificationStatus::Unknown, {}, {}};
    examples.push_back(result_json(OperationResult<Json>{header, UnknownResult<Json>{{}, {DomainErrorCode::TimeoutUnknown, "Completion requires reconciliation", "", recovery}, recovery, {{"range-1", EffectStatus::Applied, "One effect is already observed; completion remains unknown"}}}}));
    header.verification = {VerificationStatus::Unverified, {}, recovery};
    examples.push_back(result_json(OperationResult<Json>{header, CompletedResult<Json>{data, false, {}}}));
    Json errors = Json::array();
    for(std::size_t index = 0; index <= static_cast<std::size_t>(DomainErrorCode::InternalError); ++index)
        errors.push_back(domain_error_json({static_cast<DomainErrorCode>(index), "Typed error serialization", "", {}}));
    return {{"results", examples}, {"errors", errors}, {"schema", result_schema(closed_object_schema({{"value", contract_schema("Hex64")}}, {"value"}))},
            {"unverifiedSchema", result_schema(closed_object_schema({{"value", contract_schema("Hex64")}}, {"value"}), true)}};
}

Json launch_plan_probe(const Json& input)
{
    const auto schema = closed_object_schema({{"request", {{"type", "object"}, {"properties", Json::object()}, {"additionalProperties", true}}},
        {"resolvedImage", string_schema("windows-absolute-path", 32767)},
        {"inherited", bounded_array_schema(closed_object_schema({{"name", string_schema("utf8-text", 32766)},
            {"value", string_schema("utf8-text", 32766, 0)}}, {"name", "value"}), 4096)}}, {"request", "resolvedImage", "inherited"});
    if(auto error = validate_schema(schema, input))
        return {{"valid", false}, {"error", error_json(*error)}};
    const auto request = parse_target_launch(input.at("request"));
    if(const auto* error = std::get_if<ContractError>(&request))
        return {{"valid", false}, {"error", error_json(*error)}};
    std::vector<EnvironmentEntry> inherited;
    for(const auto& entry : input.at("inherited"))
        inherited.push_back({std::get<std::wstring>(launch_utf16(entry.at("name").get<std::string>())), std::get<std::wstring>(launch_utf16(entry.at("value").get<std::string>()))});
    const auto prepared = prepare_windows_launch(std::get<TargetLaunchRequest>(request), input.at("resolvedImage").get<std::string>(), inherited);
    if(const auto* error = std::get_if<ContractError>(&prepared))
        return {{"valid", false}, {"error", error_json(*error)}};
    const auto& plan = std::get<WindowsLaunchPlan>(prepared);
    constexpr const char* hex = "0123456789abcdef";
    std::string environment;
    for(const auto character : plan.environment)
    {
        const auto value = static_cast<std::uint16_t>(character);
        for(const auto byte : {static_cast<unsigned>(value & 0xff), static_cast<unsigned>(value >> 8)})
        {
            environment.push_back(hex[byte >> 4]);
            environment.push_back(hex[byte & 15]);
        }
    }
    return {{"valid", true}, {"application", std::get<std::string>(launch_utf8(plan.application))},
        {"commandLine", std::get<std::string>(launch_utf8(plan.commandLine))}, {"commandLineUnits", plan.commandLine.size()},
        {"cwd", plan.cwd ? Json(std::get<std::string>(launch_utf8(*plan.cwd))) : Json(nullptr)}, {"environmentHex", environment}, {"environmentUnits", plan.environment.size()}};
}
}

int main(int argc, char** argv)
{
    try
    {
        if(_setmode(_fileno(stdin), _O_BINARY) == -1)
            throw std::runtime_error("Cannot read binary fixture input");
        Json reply;
        const std::string mode = argc > 1 ? argv[1] : "";
        if(mode == "catalog" && argc == 2)
            reply = compiled_contracts();
        else if(mode == "registry" && argc == 2)
            reply = compiled_tool_registry();
        else if(mode == "parity-metadata" && argc == 2)
            reply = compiled_parity_metadata();
        else if(mode == "parity-dispatch-check" && argc == 2)
        {
            reply = {{"rejectedActionIds", Json::array()}};
            Json request = {{"limit", MaximumPageLimit}};
            for(;;)
            {
                const auto page = parity_records_page(request);
                if(const auto* error = std::get_if<ContractError>(&page))
                    throw std::runtime_error(error->message);
                const auto& value = std::get<Json>(page);
                for(const auto& item : value.at("items"))
                {
                    const auto actionId = item.at("actionId").get<std::string>();
                    const auto result = call_registry_tool(actionId, Json::object(), {{"operation-fixture"}, 1, 1});
                    const auto* error = std::get_if<ContractError>(&result);
                    if(!error || error->code != "unsupported_capability")
                        throw std::runtime_error("Planned parity declaration was admitted to operational dispatch");
                    reply["rejectedActionIds"].push_back(actionId);
                }
                if(!value.at("hasMore").get<bool>())
                    break;
                request["cursor"] = value.at("nextCursor");
            }
        }
        else if((mode == "parity-describe" || mode == "parity-resolve") && argc == 3)
        {
            const auto value = mode == "parity-describe" ? describe_parity_operation(argv[2]) : resolve_parity_inventory_id(argv[2]);
            reply = checked_reply(value);
            if(const auto* record = std::get_if<Json>(&value))
                reply["record"] = *record;
        }
        else if(mode == "legacy-registry" && argc == 2)
            reply = compiled_legacy_registry();
        else if(mode == "legacy-describe" && argc == 3)
        {
            const auto* alias = find_legacy_alias(argv[2]);
            reply = alias ? Json{{"valid", true}, {"alias", legacy_alias_descriptor(*alias)}} :
                Json{{"valid", false}, {"error", error_json({"unsupported_capability", "", "Legacy alias is not declared in the compiled registry"})}};
        }
        else if(mode == "result-cases" && argc == 2)
            reply = result_examples();
        else if(mode == "dependencies" && argc == 2)
            reply = dependency_probe();
        else if(mode == "worker-build-info" && argc == 2)
        {
            const auto information = worker_build_info();
            reply = checked_reply(information);
            if(const auto* value = std::get_if<Json>(&information))
                reply["information"] = *value;
        }
        else
        {
            const auto bytes = read_input();
            if(const auto error = std::get_if<ContractError>(&bytes))
                reply = {{"valid", false}, {"error", error_json(*error)}};
            else if(mode == "sha256" && argc == 2)
            {
                const auto value = sha256_bytes(std::get<std::string>(bytes));
                reply = checked_reply(value);
                if(const auto* hash = std::get_if<std::string>(&value))
                    reply["sha256"] = *hash;
            }
            else if(mode == "http" && argc == 2)
                reply = http_probe(std::get<std::string>(bytes));
            else if(mode == "ipc-header" && argc == 2)
            {
                const auto header = decode_ipc_header(std::get<std::string>(bytes));
                reply = checked_reply(header);
                if(const auto* value = std::get_if<IpcHeader>(&header))
                    reply["header"] = ipc_header_json(*value);
            }
            else if(mode == "ipc-decode" && argc == 2)
            {
                const auto frame = decode_ipc_frame(std::get<std::string>(bytes));
                reply = checked_reply(frame);
                if(const auto* value = std::get_if<IpcFrame>(&frame))
                {
                    reply["header"] = ipc_header_json(value->header);
                    reply["envelope"] = value->envelope;
                }
            }
            else
            {
                const auto parsed = parse_bounded_json(std::get<std::string>(bytes));
                if(const auto error = std::get_if<ContractError>(&parsed))
                    reply = {{"valid", false}, {"error", error_json(*error)}};
                else
                {
                    const auto& input = std::get<Json>(parsed);
                    if(mode == "process-peer" && argc == 2)
                        reply = process_peer_probe(input);
                    else if(mode == "pe-plan" && argc == 2)
                        reply = pe_plan_probe(input);
                    else if(mode == "publish-new" && argc == 2)
                        reply = publication_probe(input);
                    else if(mode == "library-reference" && argc == 2)
                        reply = library_reference(input);
                    else if(mode == "local-pipe-reference" && argc == 2)
                        reply = local_pipe_reference(input);
                    else if(mode == "parity-resolve-input" && argc == 2)
                    {
                        if(const auto error = validate_schema(string_schema("utf8-text", 16384), input))
                            reply = {{"valid", false}, {"error", error_json(*error)}};
                        else
                        {
                            const auto value = resolve_parity_inventory_id(input.get<std::string>());
                            reply = checked_reply(value);
                            if(const auto* record = std::get_if<Json>(&value))
                                reply["record"] = *record;
                        }
                    }
                    else if(mode == "parity-page" && argc == 2)
                    {
                        const auto page = parity_records_page(input);
                        reply = checked_reply(page);
                        if(const auto* value = std::get_if<Json>(&page))
                            reply["page"] = *value;
                    }
                    else if(mode == "legacy-input" && argc == 3)
                    {
                        const auto arguments = normalize_legacy_alias_input(argv[2], input);
                        reply = checked_reply(arguments);
                        if(const auto* normalized = std::get_if<Json>(&arguments))
                            reply["arguments"] = *normalized;
                    }
                    else if(mode == "launch-plan" && argc == 2)
                        reply = launch_plan_probe(input);
                    else if(mode == "ipc-encode" && argc == 2)
                    {
                        const auto schema = with_contract_definitions(closed_object_schema({{"kind", bounded_integer_schema(1, 7)},
                            {"requestId", reference_schema("Decimal64")}, {"envelope", reference_schema("IpcEnvelope")}}, {"kind", "requestId", "envelope"}));
                        if(auto error = validate_schema(schema, input))
                            reply = {{"valid", false}, {"error", error_json(*error)}};
                        else
                        {
                            const auto frame = encode_ipc_frame(static_cast<IpcMessageKind>(input.at("kind").get<std::uint16_t>()),
                                std::get<std::uint64_t>(parse_decimal64(input.at("requestId").get<std::string>())), input.at("envelope"));
                            reply = checked_reply(frame);
                            if(const auto* bytes = std::get_if<std::string>(&frame))
                            {
                                constexpr char digits[] = "0123456789abcdef";
                                std::string encoded;
                                for(const auto character : *bytes)
                                {
                                    const auto byte = static_cast<unsigned char>(character);
                                    encoded.push_back(digits[byte >> 4]);
                                    encoded.push_back(digits[byte & 15]);
                                }
                                reply["bytesHex"] = std::move(encoded);
                            }
                        }
                    }
                    else if(mode == "effects" && argc == 3)
                    {
                        const auto required = required_tool_effects(argv[2], input);
                        reply = checked_reply(required);
                        if(const auto* effects = std::get_if<std::vector<Effect>>(&required))
                        {
                            constexpr const char* names[] = {"inspect", "execute", "modify", "file_export", "file_replace", "elevate", "configure"};
                            reply["effects"] = Json::array();
                            for(const auto effect : *effects)
                                reply["effects"].push_back(names[static_cast<std::size_t>(effect)]);
                        }
                    }
                    else if(mode == "schema-validate" && argc == 2)
                    {
                        if(!input.is_object() || input.size() != 2 || !input.contains("schema") || !input.contains("value"))
                            reply = {{"valid", false}, {"error", error_json({"invalid_argument", "", "Supply a schema and value to the development fixture"})}};
                        else
                        {
                            const auto error = validate_schema(input.at("schema"), input.at("value"));
                            reply = error ? Json{{"valid", false}, {"error", error_json(*error)}} : Json{{"valid", true}};
                        }
                    }
                    else if((mode == "result-validate" || mode == "result-unverified") && argc == 2)
                    {
                        const auto schema = result_schema(closed_object_schema({{"value", contract_schema("Hex64")}}, {"value"}), mode == "result-unverified");
                        const auto error = validate_schema(schema, input);
                        reply = error ? Json{{"valid", false}, {"error", error_json(*error)}} : Json{{"valid", true}};
                    }
                    else if((mode == "tool-input" || mode == "tool-output" || mode == "call") && argc == 3)
                    {
                        if(mode == "call")
                        {
                            const auto result = call_registry_tool(argv[2], input, {{"operation-fixture"}, 9007199254740993ull, UINT64_MAX});
                            reply = checked_reply(result);
                            if(const auto* output = std::get_if<Json>(&result))
                                reply["result"] = *output;
                        }
                        else
                        {
                            const auto error = mode == "tool-input" ? validate_tool_input(argv[2], input) : validate_tool_output(argv[2], input);
                            reply = error ? Json{{"valid", false}, {"error", error_json(*error)}} : Json{{"valid", true}};
                        }
                    }
                    else if((mode == "validate" || mode == "normalize") && argc == 3)
                    {
                        const auto error = validate_contract(argv[2], input);
                        reply = error ? Json{{"valid", false}, {"error", error_json(*error)}} : mode == "validate" ? Json{{"valid", true}} : normalized_contract(argv[2], input);
                    }
                    else if(mode == "range" && argc == 3)
                    {
                        const auto error = validate_contract("AddressRange", input);
                        if(error)
                            reply = {{"valid", false}, {"error", error_json(*error)}};
                        else
                        {
                            const auto address = parse_address(input.at("address"));
                            const auto absolute = std::get_if<AbsoluteAddress>(&std::get<AddressRef>(address));
                            if(!absolute || (std::string(argv[2]) != "x32" && std::string(argv[2]) != "x64"))
                                throw std::runtime_error("Range fixture requires a resolved address and architecture");
                            const auto end = checked_range_last_address(absolute->value, input.at("size").get<std::uint32_t>(), std::string(argv[2]) == "x32" ? Architecture::X32 : Architecture::X64);
                            reply = checked_reply(end);
                            if(const auto value = std::get_if<std::uint64_t>(&end))
                                reply["lastAddressHex"] = hex64(*value);
                        }
                    }
                    else
                        throw std::runtime_error("Unknown development fixture mode");
                }
            }
        }
        std::cout << reply.dump() << '\n';
        return 0;
    }
    catch(const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
