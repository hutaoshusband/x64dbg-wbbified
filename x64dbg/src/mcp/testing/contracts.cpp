#include "contracts.h"
#include "registry.h"
#include <boost/beast/http.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/version.hpp>
#include <quickjs.h>
#include <sqlite3.h>
#include <chrono>
#include <fcntl.h>
#include <io.h>
#include <iostream>
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
    const RecoveryRoute recovery{"jobs_get", RetryPolicy::AfterReconciliation, "Inspect the retained operation before another attempt"};
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
        else if(mode == "result-cases" && argc == 2)
            reply = result_examples();
        else if(mode == "dependencies" && argc == 2)
            reply = dependency_probe();
        else
        {
            const auto bytes = read_input();
            if(const auto error = std::get_if<ContractError>(&bytes))
                reply = {{"valid", false}, {"error", error_json(*error)}};
            else if(mode == "http" && argc == 2)
                reply = http_probe(std::get<std::string>(bytes));
            else
            {
                const auto parsed = parse_bounded_json(std::get<std::string>(bytes));
                if(const auto error = std::get_if<ContractError>(&parsed))
                    reply = {{"valid", false}, {"error", error_json(*error)}};
                else
                {
                    const auto& input = std::get<Json>(parsed);
                    if((mode == "result-validate" || mode == "result-unverified") && argc == 2)
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
                        throw std::runtime_error("Expected catalog, registry, result-cases, dependencies, http, validate, normalize, range, tool-input, tool-output or call mode");
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
