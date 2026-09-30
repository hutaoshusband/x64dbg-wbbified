#include "contracts.h"
#include "build_identity.h"
#include <algorithm>
#include <charconv>
#include <cmath>
#include <limits>
#include <unordered_set>

namespace wininspect::mcp
{
namespace
{
ContractError invalid(std::string path, std::string message)
{
    return {"invalid_argument", std::move(path), std::move(message)};
}

Json text_schema(std::string format, std::size_t maximum = 128)
{
    Json schema = {{"type", "string"}, {"minLength", 1}, {"maxLength", maximum}, {"format", format}};
    if(format == "opaque-id")
        schema["pattern"] = "^[A-Za-z0-9_.:-]+$";
    else if(format == "uint64-decimal")
        schema["pattern"] = "^(0|[1-9][0-9]{0,19})$";
    else if(format == "uint64-hex")
        schema["pattern"] = "^0x(0|[1-9a-f][0-9a-f]{0,15})$";
    else if(format == "hex-bytes")
        schema["pattern"] = "^([0-9a-f]{2})+$";
    else if(format == "sha256")
    {
        schema["minLength"] = 64;
        schema["maxLength"] = 64;
        schema["pattern"] = "^[0-9a-f]{64}$";
    }
    return schema;
}

Json integer_schema(std::uint32_t minimum, std::uint32_t maximum, std::optional<std::uint32_t> fallback = {})
{
    Json schema = {{"type", "integer"}, {"minimum", minimum}, {"maximum", maximum}};
    if(fallback)
        schema["default"] = *fallback;
    return schema;
}

Json object_schema(Json properties, Json required)
{
    return {{"type", "object"}, {"properties", std::move(properties)},
            {"required", std::move(required)}, {"additionalProperties", false}};
}

std::optional<std::size_t> unicode_length(std::string_view value)
{
    std::size_t count = 0;
    for(std::size_t offset = 0; offset < value.size(); ++count)
    {
        const auto first = static_cast<unsigned char>(value[offset++]);
        if(first == 0)
            return {};
        if(first < 0x80)
            continue;
        const unsigned width = first >= 0xc2 && first <= 0xdf ? 2 : first >= 0xe0 && first <= 0xef ? 3 : first >= 0xf0 && first <= 0xf4 ? 4 : 0;
        if(width == 0 || value.size() - offset < width - 1)
            return {};
        const auto second = static_cast<unsigned char>(value[offset]);
        if((first == 0xe0 && second < 0xa0) || (first == 0xed && second >= 0xa0) ||
           (first == 0xf0 && second < 0x90) || (first == 0xf4 && second >= 0x90))
            return {};
        for(unsigned index = 1; index < width; ++index)
            if((static_cast<unsigned char>(value[offset++]) & 0xc0) != 0x80)
                return {};
    }
    return count;
}

bool lowercase_hex(std::string_view value)
{
    return std::all_of(value.begin(), value.end(), [](unsigned char character)
    {
        return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
    });
}

bool absolute_windows_path(std::string_view value)
{
    if(std::any_of(value.begin(), value.end(), [](unsigned char character) { return character < 32; }))
        return false;
    if(value.substr(0, 4) == "\\\\?\\")
    {
        value.remove_prefix(4);
        if(value.substr(0, 4) == "UNC\\")
        {
            value.remove_prefix(4);
            const auto server_end = value.find('\\');
            return server_end != std::string_view::npos && server_end > 0 && server_end + 1 < value.size() && value[server_end + 1] != '\\';
        }
    }
    if(value.size() >= 3 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) &&
       value[1] == ':' && (value[2] == '\\' || value[2] == '/'))
        return true;
    if(value.substr(0, 2) != "\\\\" || value.substr(0, 4) == "\\\\.\\")
        return false;
    const auto server_end = value.find('\\', 2);
    return server_end != std::string_view::npos && server_end > 2 && server_end + 1 < value.size() && value[server_end + 1] != '\\';
}

bool valid_format(std::string_view format, std::string_view value)
{
    if(format == "uint64-decimal")
        return std::holds_alternative<std::uint64_t>(parse_decimal64(value));
    if(format == "uint64-hex")
        return std::holds_alternative<std::uint64_t>(parse_hex64(value));
    if(format == "hex-bytes")
        return !value.empty() && value.size() % 2 == 0 && lowercase_hex(value);
    if(format == "sha256")
        return value.size() == 64 && lowercase_hex(value);
    if(format == "opaque-id")
        return std::all_of(value.begin(), value.end(), [](unsigned char character)
        {
            return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
                   (character >= '0' && character <= '9') || character == '_' || character == '.' || character == ':' || character == '-';
        });
    if(format == "windows-absolute-path")
        return absolute_windows_path(value);
    return format == "utf8-text";
}

std::string child_path(const std::string& path, const std::string& key)
{
    std::string escaped;
    for(char character : key)
        escaped += character == '~' ? "~0" : character == '/' ? "~1" : std::string(1, character);
    return path + "/" + escaped;
}

std::optional<ContractError> validate_node(const Json& schema, const Json& input, const std::string& path)
{
    if(schema.contains("oneOf"))
    {
        std::size_t matches = 0;
        for(const auto& choice : schema.at("oneOf"))
            matches += !validate_node(choice, input, path).has_value();
        if(matches != 1)
            return invalid(path, "Supply exactly one complete reference form");
        return {};
    }
    const auto type = schema.at("type").get<std::string>();
    if(type == "object")
    {
        if(!input.is_object())
            return invalid(path, "Expected an object");
        const auto& properties = schema.at("properties");
        for(const auto& required : schema.at("required"))
            if(!input.contains(required.get<std::string>()))
                return invalid(child_path(path, required.get<std::string>()), "Required field is missing");
        for(auto item = input.begin(); item != input.end(); ++item)
        {
            if(!properties.contains(item.key()))
                return invalid(child_path(path, item.key()), "Unknown field");
            if(auto error = validate_node(properties.at(item.key()), item.value(), child_path(path, item.key())))
                return error;
        }
        return {};
    }
    if(type == "string")
    {
        if(!input.is_string())
            return invalid(path, "Expected a string");
        const auto& text = input.get_ref<const std::string&>();
        const auto length = unicode_length(text);
        if(!length || *length < schema.at("minLength").get<std::size_t>() || *length > schema.at("maxLength").get<std::size_t>())
            return invalid(path, "String encoding or length is invalid");
        if(!valid_format(schema.at("format").get<std::string>(), text))
            return invalid(path, "String representation is invalid");
        return {};
    }
    if(type == "integer")
    {
        if(!input.is_number())
            return invalid(path, "Expected a bounded integer");
        const double value = input.get<double>();
        if(!std::isfinite(value) || std::floor(value) != value || value < schema.at("minimum").get<double>() || value > schema.at("maximum").get<double>())
            return invalid(path, "Integer is outside its allowed range");
        return {};
    }
    return ContractError{"invalid_contract", path, "Unsupported contract node"};
}

TargetRef target_from_validated(const Json& input)
{
    return {{input.at("instanceId").get<std::string>()}, {input.at("targetId").get<std::string>()},
            std::get<std::uint64_t>(parse_decimal64(input.at("targetGeneration").get<std::string>()))};
}

PausedContext paused_from_validated(const Json& input)
{
    PausedContext context{target_from_validated(input),
        std::get<std::uint64_t>(parse_decimal64(input.at("stopEpoch").get<std::string>())), {}};
    if(input.contains("threadId"))
        context.threadId = input.at("threadId").get<std::uint32_t>();
    return context;
}
}

const std::vector<ContractDefinition>& contract_registry()
{
    static const auto registry = []
    {
        const auto id = text_schema("opaque-id");
        const auto decimal = text_schema("uint64-decimal", MaximumDecimalDigits);
        const auto hexadecimal = text_schema("uint64-hex", MaximumHexDigits + 2);
        const auto target = object_schema({{"instanceId", id}, {"targetId", id}, {"targetGeneration", decimal}},
                                         {"instanceId", "targetId", "targetGeneration"});
        auto paused = target;
        paused["properties"]["stopEpoch"] = decimal;
        paused["properties"]["threadId"] = integer_schema(1, std::numeric_limits<std::uint32_t>::max());
        paused["required"].push_back("stopEpoch");
        auto mutation = paused;
        mutation["properties"]["leaseId"] = id;
        mutation["properties"]["idempotencyKey"] = id;
        mutation["required"].push_back("leaseId");
        const Json address = {{"oneOf", Json::array({
            object_schema({{"addressHex", hexadecimal}}, {"addressHex"}),
            object_schema({{"moduleId", id}, {"rvaHex", hexadecimal}}, {"moduleId", "rvaHex"}),
            object_schema({{"expression", text_schema("utf8-text", 4096)}}, {"expression"})})}};
        std::vector<ContractDefinition> entries = {
            {"InstanceRef", "A debugger instance identity resolved against the current broker and worker generation.", object_schema({{"instanceId", id}}, {"instanceId"})},
            {"TargetRef", "An explicit target identity and exact unsigned 64-bit load generation.", target},
            {"PausedContext", "A target identity and expected stop epoch; thread-sensitive handlers also require threadId.", paused},
            {"MutationContext", "A paused context bound to a mutation lease and optional reconciliation key.", mutation},
            {"AddressRef", "Exactly one absolute, module plus RVA, or target-context expression reference.", address},
            {"AddressRange", "An address reference and positive byte count; resolved ranges also require target-width overflow validation.", object_schema({{"address", address}, {"size", integer_schema(1, MaximumPayloadBytes)}}, {"address", "size"})},
            {"FileRef", "Exactly one managed artifact ID or absolute Windows filesystem path; authorization is checked by the owner executor.", {{"oneOf", Json::array({object_schema({{"artifactId", id}}, {"artifactId"}), object_schema({{"path", text_schema("windows-absolute-path", 32767)}}, {"path"})})}}},
            {"ExpectedBytes", "Exact expected bytes or a bounded range and SHA-256; comparison precedes any mutation.", {{"oneOf", Json::array({object_schema({{"bytesHex", text_schema("hex-bytes", 2 * MaximumPayloadBytes)}}, {"bytesHex"}), object_schema({{"address", address}, {"size", integer_schema(1, MaximumPayloadBytes)}, {"sha256", text_schema("sha256", 64)}}, {"address", "size", "sha256"})})}}},
            {"Page", "A bounded page request with an opaque cursor and a default of 100 rows.", object_schema({{"cursor", text_schema("utf8-text", 4096)}, {"limit", integer_schema(1, MaximumPageLimit, DefaultPageLimit)}}, Json::array())},
            {"Deadline", "A bounded request deadline with a default of 60000 milliseconds.", object_schema({{"timeoutMs", integer_schema(1, MaximumTimeoutMs, DefaultTimeoutMs)}}, Json::array())},
            {"Hex64", "An exact unsigned 64-bit value in canonical lowercase hexadecimal.", hexadecimal},
            {"Decimal64", "An exact unsigned 64-bit count or sequence in canonical decimal.", decimal}
        };
        for(auto& entry : entries)
        {
            entry.schema["$schema"] = "https://json-schema.org/draft/2020-12/schema";
            entry.schema["$id"] = "urn:wininspect:mcp:contract:v1:" + entry.name;
            entry.schema["description"] = entry.description;
        }
        return entries;
    }();
    return registry;
}

Json compiled_contracts()
{
    Json entries = Json::array();
    for(const auto& entry : contract_registry())
        entries.push_back({{"name", entry.name}, {"description", entry.description}, {"schema", entry.schema}});
    return {{"schemaVersion", ContractVersion}, {"buildId", BuildId}, {"contracts", entries}, {"operationalTools", Json::array()},
            {"limits", {{"frameBytes", MaximumFrameBytes}, {"payloadBytes", MaximumPayloadBytes}, {"jsonDepth", MaximumJsonDepth}, {"jsonEvents", MaximumJsonEvents}}}};
}

std::optional<ContractError> validate_contract(std::string_view name, const Json& input)
{
    const auto& registry = contract_registry();
    const auto entry = std::find_if(registry.begin(), registry.end(), [&](const auto& definition) { return definition.name == name; });
    if(entry == registry.end())
        return ContractError{"unknown_contract", "", "The contract name is not registered"};
    return validate_node(entry->schema, input, "");
}

Checked<Json> parse_bounded_json(std::string_view input)
{
    if(input.size() > MaximumFrameBytes)
        return ContractError{"payload_limit", "", "JSON input exceeds the frame limit"};
    std::vector<std::unordered_set<std::string>> object_keys;
    std::size_t events = 0;
    auto callback = [&](int depth, Json::parse_event_t event, Json& parsed)
    {
        if(depth > MaximumJsonDepth || ++events > MaximumJsonEvents)
            throw ContractError{"payload_limit", "", "JSON nesting or event count exceeds its limit"};
        if(event == Json::parse_event_t::object_start)
            object_keys.emplace_back();
        else if(event == Json::parse_event_t::object_end)
            object_keys.pop_back();
        else if(event == Json::parse_event_t::key && !object_keys.back().insert(parsed.get<std::string>()).second)
            throw ContractError{"invalid_json", "", "Duplicate JSON member"};
        return true;
    };
    try
    {
        return Json::parse(input.begin(), input.end(), callback);
    }
    catch(const ContractError& error)
    {
        return error;
    }
    catch(const Json::exception&)
    {
        return ContractError{"invalid_json", "", "Malformed JSON or invalid UTF-8"};
    }
}

Checked<std::uint64_t> parse_hex64(std::string_view input)
{
    if(input.substr(0, 2) != "0x")
        return invalid("", "Expected canonical hexadecimal");
    input.remove_prefix(2);
    if(input.empty() || input.size() > MaximumHexDigits || (input.size() > 1 && input[0] == '0') || !lowercase_hex(input))
        return invalid("", "Expected canonical hexadecimal");
    std::uint64_t value = 0;
    const auto result = std::from_chars(input.data(), input.data() + input.size(), value, 16);
    if(result.ec != std::errc() || result.ptr != input.data() + input.size())
        return invalid("", "Hexadecimal value is outside uint64");
    return value;
}

Checked<std::uint64_t> parse_decimal64(std::string_view input)
{
    if(input.empty() || input.size() > MaximumDecimalDigits || (input.size() > 1 && input[0] == '0') ||
       !std::all_of(input.begin(), input.end(), [](char character) { return character >= '0' && character <= '9'; }))
        return invalid("", "Expected canonical decimal");
    std::uint64_t value = 0;
    const auto result = std::from_chars(input.data(), input.data() + input.size(), value, 10);
    if(result.ec != std::errc() || result.ptr != input.data() + input.size())
        return invalid("", "Decimal value is outside uint64");
    return value;
}

std::string hex64(std::uint64_t value)
{
    char buffer[MaximumHexDigits + 2] = {'0', 'x'};
    const auto result = std::to_chars(buffer + 2, buffer + sizeof(buffer), value, 16);
    return std::string(buffer, result.ptr);
}

std::string decimal64(std::uint64_t value)
{
    char buffer[MaximumDecimalDigits];
    const auto result = std::to_chars(buffer, buffer + sizeof(buffer), value, 10);
    return std::string(buffer, result.ptr);
}

Checked<AddressRef> parse_address(const Json& input)
{
    if(auto error = validate_contract("AddressRef", input))
        return *error;
    if(input.contains("addressHex"))
        return AddressRef{AbsoluteAddress{std::get<std::uint64_t>(parse_hex64(input.at("addressHex").get<std::string>()))}};
    if(input.contains("moduleId"))
        return AddressRef{ModuleAddress{input.at("moduleId").get<std::string>(), std::get<std::uint64_t>(parse_hex64(input.at("rvaHex").get<std::string>()))}};
    return AddressRef{ExpressionAddress{input.at("expression").get<std::string>()}};
}

Checked<TargetRef> parse_target(const Json& input)
{
    if(auto error = validate_contract("TargetRef", input))
        return *error;
    return target_from_validated(input);
}

Checked<PausedContext> parse_paused_context(const Json& input)
{
    if(auto error = validate_contract("PausedContext", input))
        return *error;
    return paused_from_validated(input);
}

Checked<MutationContext> parse_mutation_context(const Json& input)
{
    if(auto error = validate_contract("MutationContext", input))
        return *error;
    MutationContext context{paused_from_validated(input), {input.at("leaseId").get<std::string>()}, {}};
    if(input.contains("idempotencyKey"))
        context.idempotencyKey = input.at("idempotencyKey").get<std::string>();
    return context;
}

Checked<Page> parse_page(const Json& input)
{
    if(auto error = validate_contract("Page", input))
        return *error;
    Page page;
    page.limit = input.value("limit", page.limit);
    if(input.contains("cursor"))
        page.cursor = input.at("cursor").get<std::string>();
    return page;
}

Checked<Deadline> parse_deadline(const Json& input)
{
    if(auto error = validate_contract("Deadline", input))
        return *error;
    return Deadline{input.value("timeoutMs", DefaultTimeoutMs)};
}

Checked<std::uint64_t> checked_range_last_address(std::uint64_t address, std::uint32_t size, Architecture architecture)
{
    const auto maximum = architecture == Architecture::X32 ? std::uint64_t{0xffffffff} : std::numeric_limits<std::uint64_t>::max();
    if(size == 0 || size > MaximumPayloadBytes || address > maximum || size - 1 > maximum - address)
        return ContractError{"range_overflow", "", "Byte range exceeds the payload limit or target pointer width"};
    return address + size - 1;
}

Json error_json(const ContractError& error)
{
    return {{"code", error.code}, {"path", error.path}, {"message", error.message}};
}
}
