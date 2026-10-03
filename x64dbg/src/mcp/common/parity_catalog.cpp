#include "parity_catalog.h"
#include "parity_catalog_source.h"
#include "platform.h"
#include "build_identity.h"
#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <stdexcept>

namespace wininspect::mcp
{
namespace
{
constexpr std::array<const char*, 4> RecordKinds = {"operation", "binding", "registration_factory", "excluded_declaration"};
constexpr std::size_t MaximumCatalogBytes = 64 * 1024 * 1024;

struct RecordLocation
{
    std::string key;
    std::size_t offset;
    std::size_t length;
};

struct Catalog
{
    std::string source;
    Json metadata;
    std::array<std::vector<RecordLocation>, 4> records;
    std::map<std::string, std::size_t> inventoryIds;
};

Json parse_record(std::string_view text)
{
    auto parsed = parse_bounded_json(text);
    if(const auto* error = std::get_if<ContractError>(&parsed))
        throw std::logic_error("Compiled parity record failed bounded JSON validation: " + error->message);
    return std::get<Json>(std::move(parsed));
}

Catalog load_catalog()
{
    Catalog result;
    for(const auto part : ParityCatalogParts)
    {
        if(part.size() > MaximumCatalogBytes - result.source.size())
            throw std::logic_error("Compiled parity source exceeds its catalog bound");
        result.source.append(part.data(), part.size());
    }
    std::size_t offset = 0;
    std::set<std::string> operationIds;
    while(offset < result.source.size())
    {
        const auto end = result.source.find('\n', offset);
        if(end == std::string::npos || end == offset)
            throw std::logic_error("Compiled parity source requires nonempty terminated records");
        auto record = parse_record(std::string_view(result.source).substr(offset, end - offset));
        if(!offset)
        {
            if(record.size() != 2 || record.at("kind") != "metadata" || !record.at("data").is_object())
                throw std::logic_error("Compiled parity source requires an initial metadata record");
            result.metadata = record.at("data");
            if(result.metadata.at("schemaVersion") != 1 ||
               validate_schema(string_schema("sha256", 64), result.metadata.at("baselineManifestSha256")))
                throw std::logic_error("Compiled parity metadata has an invalid version or baseline identity");
        }
        else
        {
            if(record.size() != 3 || !record.at("key").is_string() || !record.at("data").is_object())
                throw std::logic_error("Compiled parity record has an invalid shape");
            const auto kind = record.at("kind").get<std::string>();
            const auto found = std::find(RecordKinds.begin(), RecordKinds.end(), kind);
            if(found == RecordKinds.end())
                throw std::logic_error("Compiled parity record has an unknown kind");
            const auto index = static_cast<std::size_t>(found - RecordKinds.begin());
            const auto key = record.at("key").get<std::string>();
            if(!index)
            {
                const auto& row = record.at("data");
                const auto inventoryId = row.at("id").get<std::string>();
                auto digest = sha256_bytes(inventoryId);
                if(const auto* error = std::get_if<ContractError>(&digest))
                    throw std::logic_error(error->message);
                if(key != "parity." + std::get<std::string>(digest) || !operationIds.insert(inventoryId).second ||
                   row.at("agentRoute") != nullptr || row.at("status") != "planned" || row.at("evidence") != nullptr ||
                   !row.at("variants").is_object() || !row.at("source").is_object() || row.at("architectures").empty())
                    throw std::logic_error("Compiled parity action has an invalid identity or declares unsupported operation readiness");
            }
            else if(key != decimal64(result.records[index].size()))
                throw std::logic_error("Compiled parity reference keys must preserve contiguous source indexes");
            result.records[index].push_back({key, offset, end - offset});
        }
        offset = end + 1;
    }
    for(std::size_t index = 0; index < RecordKinds.size(); ++index)
        if(result.metadata.at("recordCounts").at(RecordKinds[index]) != result.records[index].size())
            throw std::logic_error("Compiled parity record count differs from its declared metadata");
    auto& operations = result.records[0];
    std::sort(operations.begin(), operations.end(), [](const auto& left, const auto& right) { return left.key < right.key; });
    for(std::size_t index = 0; index < operations.size(); ++index)
    {
        const auto& location = operations[index];
        const auto row = parse_record(std::string_view(result.source).substr(location.offset, location.length)).at("data");
        result.inventoryIds.emplace(row.at("id").get<std::string>(), index);
        if(row.at("variants").contains("bindingRefs"))
            for(const auto& reference : row.at("variants").at("bindingRefs"))
                if(!reference.is_number_unsigned() || reference.get<std::size_t>() >= result.records[1].size())
                    throw std::logic_error("Compiled parity action refers to a missing native binding");
    }
    return result;
}

const Catalog& catalog()
{
    static const auto value = load_catalog();
    return value;
}

Json record_data(const Catalog& source, const RecordLocation& location, bool operation)
{
    const auto record = parse_record(std::string_view(source.source).substr(location.offset, location.length));
    if(operation)
        return {{"actionId", location.key}, {"inventory", record.at("data")}, {"availability", "planned"}, {"operational", false},
            {"executionAdapterInstalled", false}, {"runtimeRegistrationBound", false}, {"classification", "unknown"}};
    return {{"key", location.key}, {"data", record.at("data")}};
}

std::size_t event_bound(const Json& value)
{
    if(!value.is_structured())
        return 1;
    std::size_t count = 3;
    for(const auto& child : value)
        count += event_bound(child) + (value.is_object() ? 1 : 0);
    return count;
}
}

Json compiled_parity_metadata()
{
    auto metadata = catalog().metadata;
    metadata["buildId"] = BuildId;
    metadata["operationalActionIds"] = Json::array();
    metadata["runtimeValidated"] = false;
    return metadata;
}

Checked<Json> describe_parity_operation(std::string_view actionId)
{
    const auto& source = catalog();
    const auto& operations = source.records[0];
    const auto found = std::lower_bound(operations.begin(), operations.end(), actionId,
        [](const auto& row, const auto& name) { return row.key < name; });
    if(found == operations.end() || found->key != actionId)
        return ContractError{"unsupported_capability", "/actionId", "Action is absent from the compiled parity declarations"};
    return record_data(source, *found, true);
}

Checked<Json> resolve_parity_inventory_id(std::string_view inventoryId)
{
    const auto& source = catalog();
    const auto found = source.inventoryIds.find(std::string(inventoryId));
    if(found == source.inventoryIds.end())
        return ContractError{"unsupported_capability", "/inventoryId", "Inventory identity is absent from the compiled parity declarations"};
    return record_data(source, source.records[0][found->second], true);
}

Checked<Json> parity_records_page(const Json& input)
{
    auto schema = contract_schema("Page");
    schema["properties"]["kind"] = enum_schema({"operation", "binding", "registration_factory", "excluded_declaration"});
    schema["properties"]["category"] = string_schema("utf8-text", 128);
    schema["properties"]["provider"] = string_schema("utf8-text", 128);
    schema["properties"]["architecture"] = enum_schema({"x32", "x64"});
    if(auto error = validate_schema(schema, input))
        return *error;
    const auto kind = input.value("kind", std::string("operation"));
    const auto index = static_cast<std::size_t>(std::find(RecordKinds.begin(), RecordKinds.end(), kind) - RecordKinds.begin());
    if(index && (input.contains("category") || input.contains("provider") || input.contains("architecture")))
        return ContractError{"invalid_argument", "", "Native reference records do not have action filters"};
    auto filter = input;
    filter.erase("cursor");
    filter.erase("limit");
    filter["kind"] = kind;
    const auto prefix = std::string("parity:") + BuildId + ":" + filter.dump() + ":";
    std::uint64_t start = 0;
    if(input.contains("cursor"))
    {
        const auto cursor = input.at("cursor").get<std::string>();
        if(cursor.substr(0, prefix.size()) != prefix)
            return ContractError{"invalid_argument", "/cursor", "Parity cursor belongs to a different build or filter"};
        auto parsed = parse_decimal64(cursor.substr(prefix.size()));
        if(const auto* error = std::get_if<ContractError>(&parsed))
            return *error;
        start = std::get<std::uint64_t>(parsed);
    }
    const auto& source = catalog();
    const auto& records = source.records[index];
    if(start > records.size())
        return ContractError{"invalid_argument", "/cursor", "Parity cursor is outside its compiled snapshot"};
    const auto limit = input.value("limit", DefaultPageLimit);
    Json items = Json::array();
    std::size_t bytes = 8192;
    std::size_t events = 64;
    std::size_t position = static_cast<std::size_t>(start);
    while(position < records.size() && items.size() < limit)
    {
        auto value = record_data(source, records[position], !index);
        if(!index)
        {
            const auto& row = value.at("inventory");
            if((input.contains("category") && input.at("category") != row.at("category")) ||
               (input.contains("provider") && input.at("provider") != row.at("provider")) ||
               (input.contains("architecture") && std::find(row.at("architectures").begin(), row.at("architectures").end(), input.at("architecture")) == row.at("architectures").end()))
            {
                ++position;
                continue;
            }
        }
        const auto value_bytes = value.dump().size();
        const auto value_events = event_bound(value);
        if(value_bytes > MaximumFrameBytes - bytes || value_events > MaximumJsonEvents - events)
        {
            if(items.empty())
                return ContractError{"payload_limit", "", "Parity declaration exceeds a bounded response"};
            break;
        }
        bytes += value_bytes;
        events += value_events;
        items.push_back(std::move(value));
        ++position;
    }
    return Json{{"schemaVersion", ContractVersion}, {"buildId", BuildId}, {"kind", kind}, {"items", std::move(items)},
        {"hasMore", position < records.size()}, {"nextCursor", position < records.size() ? Json(prefix + decimal64(position)) : Json(nullptr)},
        {"snapshotRecordCount", decimal64(records.size())}, {"operational", false}};
}
}
