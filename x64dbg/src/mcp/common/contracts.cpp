#include "contracts.h"
#include "lifecycle.h"
#include "build_identity.h"
#include "library_script_types.h"
#include <algorithm>
#include <charconv>
#include <cmath>
#include <limits>
#include <stdexcept>
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
    if(format == "library-virtual-path")
        return safe_virtual_path(value);
    if(format == "windows-command-line" || format == "windows-environment-name")
    {
        const auto converted = launch_utf16(value);
        const auto* text = std::get_if<std::wstring>(&converted);
        return text && text->size() <= MaximumWindowsCommandUnits &&
            (format != "windows-environment-name" || (!text->empty() && text->find(L'=') == std::wstring::npos));
    }
    return format == "utf8-text";
}

std::string child_path(const std::string& path, const std::string& key)
{
    std::string escaped;
    for(char character : key)
        escaped += character == '~' ? "~0" : character == '/' ? "~1" : std::string(1, character);
    return path + "/" + escaped;
}

const std::unordered_set<std::string> schema_keywords = {"$schema", "$id", "$defs", "$ref", "description", "type", "properties", "required", "additionalProperties", "oneOf", "not", "format", "pattern", "minLength", "maxLength", "minimum", "maximum", "default", "enum", "const", "items", "minItems", "maxItems", "uniqueItems"};

std::optional<ContractError> validate_schema_dialect(const Json& schema, const Json& root, std::size_t& visits, std::size_t depth)
{
    if(++visits > MaximumValidationVisits || depth > MaximumValidationDepth)
        return ContractError{"resource_limit", "", "Schema declaration exceeds its traversal bound"};
    const auto rejected = [] { return ContractError{"invalid_contract", "", "Schema is outside the declared native dialect"}; };
    if(!schema.is_object())
        return rejected();
    for(auto item = schema.begin(); item != schema.end(); ++item)
        if(!schema_keywords.count(item.key()))
            return rejected();
    const auto type = schema.value("type", std::string{});
    if(!type.empty() && type != "object" && type != "array" && type != "string" && type != "integer" && type != "boolean" && type != "null")
        return rejected();
    for(const auto* keyword : {"properties", "required", "additionalProperties"})
        if(schema.contains(keyword) && type != "object")
            return rejected();
    for(const auto* keyword : {"items", "minItems", "maxItems", "uniqueItems"})
        if(schema.contains(keyword) && type != "array")
            return rejected();
    for(const auto* keyword : {"format", "pattern", "minLength", "maxLength"})
        if(schema.contains(keyword) && type != "string")
            return rejected();
    for(const auto* keyword : {"minimum", "maximum"})
        if(schema.contains(keyword) && type != "integer")
            return rejected();
    for(const auto* keyword : {"$schema", "$id", "description"})
        if(schema.contains(keyword) && !schema.at(keyword).is_string())
            return rejected();
    if(schema.contains("enum") && (!schema.at("enum").is_array() || schema.at("enum").empty()))
        return rejected();
    if(schema.contains("$ref"))
    {
        const auto reference = schema.at("$ref").get<std::string>();
        const std::string prefix = "#/$defs/";
        if(reference.compare(0, prefix.size(), prefix) != 0 || reference.find_first_of("/~", prefix.size()) != std::string::npos ||
           !root.contains("$defs") || !root.at("$defs").contains(reference.substr(prefix.size())))
            return rejected();
    }
    if(type == "string")
    {
        static const std::unordered_set<std::string> formats = {"uint64-decimal", "uint64-hex", "opaque-id", "hex-bytes", "sha256", "utf8-text", "windows-absolute-path", "windows-command-line", "windows-environment-name", "library-virtual-path"};
        const auto format = schema.at("format").get<std::string>();
        if(!formats.count(format) || (schema.contains("pattern") && text_schema(format).value("pattern", "") != schema.at("pattern")))
            return rejected();
    }
    const auto bounds_valid = [&](const char* minimum, const char* maximum)
    {
        return schema.at(minimum).is_number_integer() && schema.at(maximum).is_number_integer() &&
               schema.at(minimum).get<double>() >= 0 && schema.at(minimum).get<double>() <= schema.at(maximum).get<double>();
    };
    if((type == "string" && !bounds_valid("minLength", "maxLength")) || (type == "array" && !bounds_valid("minItems", "maxItems")) ||
       (type == "integer" && !bounds_valid("minimum", "maximum")))
        return rejected();
    if(type == "object")
    {
        if(!schema.at("properties").is_object() || (!schema.at("additionalProperties").is_boolean() && !schema.at("additionalProperties").is_object()) ||
           (schema.contains("required") && !schema.at("required").is_array()))
            return rejected();
        for(const auto& field : schema.value("required", Json::array()))
            if(!field.is_string() || !schema.at("properties").contains(field.get<std::string>()))
                return rejected();
    }
    if(type == "array" && schema.contains("uniqueItems") && !schema.at("uniqueItems").is_boolean())
        return rejected();
    for(const auto* keyword : {"$defs", "properties", "oneOf"})
        if(schema.contains(keyword))
        {
            const auto& children = schema.at(keyword);
            if((std::string_view(keyword) == "oneOf" && (!children.is_array() || children.empty())) ||
               (std::string_view(keyword) != "oneOf" && !children.is_object()))
                return rejected();
            for(const auto& child : children)
                if(auto error = validate_schema_dialect(child, root, visits, depth + 1))
                    return error;
        }
    if(type == "array")
        if(auto error = validate_schema_dialect(schema.at("items"), root, visits, depth + 1))
            return error;
    if(schema.contains("not"))
        if(auto error = validate_schema_dialect(schema.at("not"), root, visits, depth + 1))
            return error;
    if(type == "object" && schema.at("additionalProperties").is_object())
        return validate_schema_dialect(schema.at("additionalProperties"), root, visits, depth + 1);
    return {};
}

std::optional<ContractError> validate_node(const Json& schema, const Json& input, const std::string& path,
                                         const Json& root, std::size_t& visits, std::size_t depth)
{
    if(++visits > MaximumValidationVisits || depth > MaximumValidationDepth)
        return ContractError{"resource_limit", path, "Schema validation exceeds its traversal bound"};
    if(schema.contains("$ref"))
    {
        const auto reference = schema.at("$ref").get<std::string>();
        const std::string prefix = "#/$defs/";
        if(reference.compare(0, prefix.size(), prefix) != 0 || reference.find_first_of("/~", prefix.size()) != std::string::npos ||
           !root.contains("$defs") || !root.at("$defs").contains(reference.substr(prefix.size())))
            return ContractError{"invalid_contract", path, "Schema reference is not a declared local definition"};
        if(auto error = validate_node(root.at("$defs").at(reference.substr(prefix.size())), input, path, root, visits, depth + 1))
            return error;
    }
    if(schema.contains("const") && input != schema.at("const"))
        return invalid(path, "Value differs from the required constant");
    if(schema.contains("not"))
    {
        const auto error = validate_node(schema.at("not"), input, path, root, visits, depth + 1);
        if(!error)
            return invalid(path, "Value matches a prohibited schema");
        if(error->code == "invalid_contract" || error->code == "resource_limit")
            return error;
    }
    if(schema.contains("enum") && std::find(schema.at("enum").begin(), schema.at("enum").end(), input) == schema.at("enum").end())
        return invalid(path, "Value is not in the allowed enumeration");
    if(schema.contains("oneOf"))
    {
        std::size_t matches = 0;
        for(const auto& choice : schema.at("oneOf"))
        {
            const auto error = validate_node(choice, input, path, root, visits, depth + 1);
            if(error && (error->code == "invalid_contract" || error->code == "resource_limit"))
                return error;
            matches += !error.has_value();
        }
        if(matches != 1)
            return invalid(path, "Supply exactly one complete reference form");
    }
    if(!schema.contains("type"))
        return {};
    const auto type = schema.at("type").get<std::string>();
    if(type == "object")
    {
        if(!input.is_object())
            return invalid(path, "Expected an object");
        const auto& properties = schema.at("properties");
        for(const auto& required : schema.value("required", Json::array()))
            if(!input.contains(required.get<std::string>()))
                return invalid(child_path(path, required.get<std::string>()), "Required field is missing");
        for(auto item = input.begin(); item != input.end(); ++item)
        {
            if(!properties.contains(item.key()))
            {
                const auto& additional = schema.at("additionalProperties");
                if(additional == false)
                    return invalid(child_path(path, item.key()), "Unknown field");
                if(additional.is_object())
                    if(auto error = validate_node(additional, item.value(), child_path(path, item.key()), root, visits, depth + 1))
                        return error;
                continue;
            }
            if(auto error = validate_node(properties.at(item.key()), item.value(), child_path(path, item.key()), root, visits, depth + 1))
                return error;
        }
        return {};
    }
    if(type == "array")
    {
        if(!input.is_array() || input.size() < schema.at("minItems").get<std::size_t>() || input.size() > schema.at("maxItems").get<std::size_t>())
            return invalid(path, "Expected an array within its declared item bounds");
        for(std::size_t index = 0; index < input.size(); ++index)
        {
            if(auto error = validate_node(schema.at("items"), input.at(index), child_path(path, std::to_string(index)), root, visits, depth + 1))
                return error;
            if(schema.value("uniqueItems", false))
                for(std::size_t previous = 0; previous < index; ++previous)
                {
                    if(++visits > MaximumValidationVisits)
                        return ContractError{"resource_limit", path, "Array uniqueness check exceeds its traversal bound"};
                    if(input.at(previous) == input.at(index))
                        return invalid(child_path(path, std::to_string(index)), "Array items must be unique");
                }
        }
        return {};
    }
    if(type == "boolean")
        return input.is_boolean() ? std::optional<ContractError>{} : invalid(path, "Expected a boolean");
    if(type == "null")
        return input.is_null() ? std::optional<ContractError>{} : invalid(path, "Expected null");
    if(type == "string")
    {
        if(!input.is_string())
            return invalid(path, "Expected a string");
        const auto& text = input.get_ref<const std::string&>();
        const auto format = schema.at("format").get<std::string>();
        if(schema.contains("pattern") && text_schema(format).value("pattern", "") != schema.at("pattern"))
            return ContractError{"invalid_contract", path, "Pattern is outside the declared native format dialect"};
        const auto length = unicode_length(text);
        if((!length && !text.empty()) || text.size() > MaximumFrameBytes ||
           length.value_or(0) < schema.at("minLength").get<std::size_t>() || length.value_or(0) > schema.at("maxLength").get<std::size_t>())
            return invalid(path, "String encoding or length is invalid");
        if(!valid_format(format, text))
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

Json string_schema(std::string format, std::size_t maximum, std::size_t minimum)
{
    auto schema = text_schema(std::move(format), maximum);
    schema["minLength"] = minimum;
    return schema;
}

Json bounded_integer_schema(std::uint32_t minimum, std::uint32_t maximum, std::optional<std::uint32_t> fallback)
{
    return integer_schema(minimum, maximum, fallback);
}

Json closed_object_schema(Json properties, Json required)
{
    return object_schema(std::move(properties), std::move(required));
}

Json enum_schema(Json values)
{
    return {{"enum", std::move(values)}};
}

Json bounded_array_schema(Json items, std::size_t maximum, std::size_t minimum, bool unique)
{
    return {{"type", "array"}, {"items", std::move(items)}, {"minItems", minimum}, {"maxItems", maximum}, {"uniqueItems", unique}};
}

Json reference_schema(std::string name)
{
    return {{"$ref", "#/$defs/" + name}};
}

Json with_contract_definitions(Json schema)
{
    Json definitions = schema.value("$defs", Json::object());
    for(const auto& contract : contract_registry())
    {
        auto definition = contract.schema;
        definition.erase("$id");
        definition.erase("$schema");
        if(definitions.contains(contract.name) && definitions.at(contract.name) != definition)
            throw std::invalid_argument("Contract definition name conflicts with a schema-local definition");
        definitions[contract.name] = std::move(definition);
    }
    schema.erase("$defs");
    std::unordered_set<std::string> required;
    std::vector<std::string> pending;
    const auto discover = [&](const auto& self, const Json& node) -> void
    {
        if(node.contains("$ref"))
        {
            const auto reference = node.at("$ref").get<std::string>();
            const std::string prefix = "#/$defs/";
            if(reference.compare(0, prefix.size(), prefix) != 0 || !definitions.contains(reference.substr(prefix.size())))
                throw std::invalid_argument("Schema references an undeclared definition");
            auto name = reference.substr(prefix.size());
            if(required.insert(name).second)
                pending.push_back(std::move(name));
        }
        for(const auto& child : node.value("properties", Json::object()))
            self(self, child);
        for(const auto& child : node.value("oneOf", Json::array()))
            self(self, child);
        if(node.contains("items"))
            self(self, node.at("items"));
        if(node.contains("not"))
            self(self, node.at("not"));
        if(node.contains("additionalProperties") && node.at("additionalProperties").is_object())
            self(self, node.at("additionalProperties"));
    };
    discover(discover, schema);
    for(std::size_t index = 0; index < pending.size(); ++index)
        discover(discover, definitions.at(pending[index]));
    if(!required.empty())
    {
        schema["$defs"] = Json::object();
        for(const auto& name : required)
            schema["$defs"][name] = definitions.at(name);
    }
    return schema;
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
        const auto recovery = closed_object_schema({{"capabilityId", id}, {"retry", enum_schema({"never", "after_refresh", "after_reconciliation"})},
            {"reason", text_schema("utf8-text", 4096)}}, {"capabilityId", "retry", "reason"});
        const auto evidence = closed_object_schema({{"kind", id}, {"source", text_schema("utf8-text", 4096)},
            {"summary", text_schema("utf8-text", 4096)}, {"artifactId", id}, {"sha256", text_schema("sha256", 64)}}, {"kind", "source", "summary"});
        const auto verification_properties = Json{{"status", enum_schema({"verified", "unverified", "pending", "failed", "unknown"})},
            {"evidence", bounded_array_schema(evidence, 100)}, {"followUp", recovery}};
        auto verified = closed_object_schema(verification_properties, {"status", "evidence"});
        verified["properties"]["status"] = {{"const", "verified"}};
        verified["properties"]["evidence"]["minItems"] = 1;
        auto unverified = closed_object_schema(verification_properties, {"status", "evidence", "followUp"});
        unverified["properties"]["status"] = {{"const", "unverified"}};
        auto incomplete = closed_object_schema(verification_properties, {"status", "evidence"});
        incomplete["properties"]["status"] = enum_schema({"pending", "failed", "unknown"});
        const auto page_complete = closed_object_schema({{"snapshotVersion", decimal}, {"complete", {{"const", true}}}}, {"snapshotVersion", "complete"});
        const auto page_more = closed_object_schema({{"snapshotVersion", decimal}, {"complete", {{"const", false}}}, {"nextCursor", text_schema("utf8-text", 4096)}}, {"snapshotVersion", "complete", "nextCursor"});
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
            {"Decimal64", "An exact unsigned 64-bit count or sequence in canonical decimal.", decimal},
            {"LibraryRef", "A namespaced library object bound to an explicit immutable revision.", closed_object_schema({{"namespaceId", id}, {"objectId", id}, {"revision", id}}, {"namespaceId", "objectId", "revision"})},
            {"JobRef", "A job identity whose owner and grant are checked independently of possession.", closed_object_schema({{"jobId", id}}, {"jobId"})},
            {"EventRef", "An opaque event cursor; sequence numbers are never inferred from JSON integers.", closed_object_schema({{"cursor", text_schema("utf8-text", 4096)}}, {"cursor"})},
            {"RecoveryRoute", "An explicit capability and retry policy for refresh or reconciliation.", recovery},
            {"DomainError", "A bounded machine-readable execution error with optional recovery; protocol errors use their transport envelope.", closed_object_schema({
                {"code", enum_schema({"debugger_unavailable", "target_required", "target_running", "stale_context", "lease_conflict", "elevation_required", "elevation_denied", "permission_denied", "expected_bytes_mismatch", "file_hash_mismatch", "unsupported_mapping", "partial_failure", "timeout_unknown", "resource_limit", "unsupported_capability", "event_gap", "idempotency_conflict", "invalid_argument", "internal_error"})},
                {"message", text_schema("utf8-text", 4096)}, {"path", string_schema("utf8-text", 4096, 0)}, {"recovery", recovery}}, {"code", "message", "path"})},
            {"ResultContext", "A broker, instance, target or paused identity; each complete reference form is exclusive.", {{"oneOf", Json::array({closed_object_schema({{"brokerGeneration", decimal}}, {"brokerGeneration"}), closed_object_schema({{"instanceId", id}}, {"instanceId"}), target, paused})}}},
            {"VerificationEvidence", "Bounded observed evidence with source and optional hashed artifact.", evidence},
            {"Verification", "Verified requires evidence; unverified requires an explicit follow-up route.", {{"oneOf", Json::array({verified, unverified, incomplete})}}},
            {"ResultWarning", "A bounded nonsecret warning that does not replace an execution error.", closed_object_schema({{"code", id}, {"message", text_schema("utf8-text", 4096)}}, {"code", "message"})},
            {"ResultTimings", "Exact unsigned 64-bit UTC milliseconds and monotonic elapsed/queue microseconds.", closed_object_schema({{"startedUtcMs", decimal}, {"elapsedUs", decimal}, {"queueUs", decimal}}, {"startedUtcMs", "elapsedUs", "queueUs"})},
            {"EffectObservation", "A per-step observation retained when an operation fails, is cancelled or is uncertain.", closed_object_schema({{"stepId", id}, {"status", enum_schema({"applied", "restored", "failed", "unknown"})}, {"summary", text_schema("utf8-text", 4096)}}, {"stepId", "status", "summary"})},
            {"ResultPagination", "A stable snapshot version and either complete coverage or an explicit continuation cursor.", {{"oneOf", Json::array({page_complete, page_more})}}},
            {"IpcEnvelope", "Bounded wire context and payload; identity and authentication claims are revalidated against the actual pipe peer.", closed_object_schema({
                {"context", {{"oneOf", Json::array({closed_object_schema({{"brokerGeneration", decimal}}, {"brokerGeneration"}), closed_object_schema({{"instanceId", id}}, {"instanceId"}), target, paused})}}},
                {"deadlineUtcMs", decimal}, {"authenticationContextId", id},
                {"payload", {{"type", "object"}, {"properties", Json::object()}, {"additionalProperties", true}}}}, {"context", "deadlineUtcMs", "authenticationContextId", "payload"})},
            {"NativeProcessIdentity", "Actual owning-process token, creation identity and handle-read executable hash; a received claim does not authenticate a peer.", closed_object_schema({
                {"pid", integer_schema(1, std::numeric_limits<std::uint32_t>::max())}, {"creationTime", decimal}, {"sessionId", integer_schema(0, std::numeric_limits<std::uint32_t>::max())},
                {"userSid", text_schema("utf8-text", 184)}, {"logonSid", text_schema("utf8-text", 184)}, {"integrity", enum_schema({"untrusted", "low", "medium", "high", "system", "protected"})},
                {"elevated", {{"type", "boolean"}}}, {"architecture", enum_schema({"x32", "x64"})}, {"image", closed_object_schema({
                    {"path", text_schema("windows-absolute-path", 32767)}, {"sha256", text_schema("sha256", 64)}, {"size", decimal},
                    {"volumeSerial", integer_schema(0, std::numeric_limits<std::uint32_t>::max())}, {"fileIndex", decimal}}, {"path", "sha256", "size", "volumeSerial", "fileIndex"})}},
                {"pid", "creationTime", "sessionId", "userSid", "logonSid", "integrity", "elevated", "architecture", "image"})}
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
    return validate_schema(entry->schema, input);
}

Json contract_schema(std::string_view name)
{
    const auto& registry = contract_registry();
    const auto entry = std::find_if(registry.begin(), registry.end(), [&](const auto& definition) { return definition.name == name; });
    if(entry == registry.end())
        throw std::invalid_argument("Unknown contract schema");
    auto schema = entry->schema;
    schema.erase("$id");
    return schema;
}

std::optional<ContractError> validate_schema(const Json& schema, const Json& input)
{
    std::size_t visits = 0;
    try
    {
        if(auto error = validate_schema_dialect(schema, schema, visits, 0))
            return error;
        return validate_node(schema, input, "", schema, visits, 0);
    }
    catch(const Json::exception&)
    {
        return ContractError{"invalid_contract", "", "Declared schema structure is invalid"};
    }
}

Json result_schema(Json data, bool allowUnverified)
{
    Json definitions = data.value("$defs", Json::object());
    data.erase("$defs");
    data.erase("$id");
    data.erase("$schema");
    definitions["ResultData"] = std::move(data);
    definitions["Identifier"] = string_schema("opaque-id");
    const auto id = reference_schema("Identifier");
    const auto verification = contract_schema("Verification").at("oneOf");
    definitions["CompletedVerification"] = verification.at(0);
    definitions["UnverifiedCompletion"] = verification.at(1);
    for(const auto* status : {"pending", "failed", "unknown"})
    {
        auto definition = verification.at(2);
        definition["properties"]["status"] = {{"const", status}};
        definitions[std::string(status) + "_verification"] = std::move(definition);
    }
    for(const auto* outcome : {"failed", "partial_failure", "unknown"})
    {
        auto error = contract_schema("DomainError");
        if(std::string_view(outcome) != "failed")
            error["properties"]["code"] = {{"const", std::string_view(outcome) == "unknown" ? "timeout_unknown" : "partial_failure"}};
        else
        {
            auto& codes = error["properties"]["code"]["enum"];
            codes.erase(std::remove(codes.begin(), codes.end(), "partial_failure"), codes.end());
            codes.erase(std::remove(codes.begin(), codes.end(), "timeout_unknown"), codes.end());
        }
        error.erase("$schema");
        definitions[std::string(outcome) + "_error"] = std::move(error);
    }
    const auto data_reference = reference_schema("ResultData");
    const auto nullable_data = Json{{"oneOf", Json::array({data_reference, {{"type", "null"}}})}};
    Json choices = Json::array();
    for(const auto* outcome : {"completed", "accepted", "partial_failure", "cancelled", "failed", "unknown"})
    {
        const std::string name = outcome;
        Json properties = {{"schemaVersion", {{"const", ContractVersion}}}, {"outcome", {{"const", name}}},
            {"operationId", id}, {"jobId", id}, {"context", reference_schema("ResultContext")}, {"stateVersion", reference_schema("Decimal64")},
            {"data", name == "completed" ? data_reference : name == "accepted" || name == "failed" ? Json{{"type", "null"}} : nullable_data},
            {"warnings", bounded_array_schema(reference_schema("ResultWarning"), 100)}, {"timings", reference_schema("ResultTimings")},
            {"partial", {{"const", name == "partial_failure"}}}};
        Json required = {"schemaVersion", "outcome", "operationId", "context", "stateVersion", "data", "verification", "warnings", "timings", "partial"};
        if(name == "completed" || name == "cancelled")
        {
            properties["verification"] = name == "completed" && allowUnverified ? Json{{"oneOf", Json::array({reference_schema("CompletedVerification"), reference_schema("UnverifiedCompletion")})}} : reference_schema("CompletedVerification");
            if(name == "completed")
            {
                properties["partial"] = {{"type", "boolean"}};
                properties["page"] = reference_schema("ResultPagination");
            }
        }
        else
        {
            properties["verification"] = reference_schema(name == "accepted" ? "pending_verification" : name == "unknown" ? "unknown_verification" : "failed_verification");
        }
        if(name == "accepted")
        {
            properties["jobId"] = id;
            required.push_back("jobId");
        }
        if(name == "failed" || name == "partial_failure" || name == "unknown")
        {
            properties["error"] = reference_schema(name + "_error");
            required.push_back("error");
        }
        if(name == "partial_failure" || name == "cancelled" || name == "unknown")
        {
            properties["effects"] = bounded_array_schema(reference_schema("EffectObservation"), 1000, name == "partial_failure" ? 1 : 0);
            required.push_back("effects");
            if(name == "unknown")
                properties["partial"] = {{"type", "boolean"}};
        }
        if(name == "partial_failure" || name == "unknown")
        {
            const std::string route = name == "unknown" ? "reconciliation" : "recovery";
            properties[route] = reference_schema("RecoveryRoute");
            required.push_back(route);
        }
        choices.push_back(closed_object_schema(std::move(properties), std::move(required)));
    }
    return with_contract_definitions({{"$schema", "https://json-schema.org/draft/2020-12/schema"}, {"$defs", std::move(definitions)}, {"oneOf", std::move(choices)}});
}

Json recovery_json(const RecoveryRoute& recovery)
{
    constexpr const char* policies[] = {"never", "after_refresh", "after_reconciliation"};
    return {{"capabilityId", recovery.capabilityId}, {"retry", policies[static_cast<std::size_t>(recovery.retry)]}, {"reason", recovery.reason}};
}

Json domain_error_json(const DomainError& error)
{
    constexpr const char* codes[] = {"debugger_unavailable", "target_required", "target_running", "stale_context", "lease_conflict", "elevation_required", "elevation_denied", "permission_denied", "expected_bytes_mismatch", "file_hash_mismatch", "unsupported_mapping", "partial_failure", "timeout_unknown", "resource_limit", "unsupported_capability", "event_gap", "idempotency_conflict", "invalid_argument", "internal_error"};
    Json value = {{"code", codes[static_cast<std::size_t>(error.code)]}, {"message", error.message}, {"path", error.path}};
    if(error.recovery)
        value["recovery"] = recovery_json(*error.recovery);
    return value;
}

Json result_header_json(const ResultHeader& header)
{
    constexpr const char* statuses[] = {"verified", "unverified", "pending", "failed", "unknown"};
    Json context = std::visit([](const auto& reference) -> Json
    {
        using Reference = std::decay_t<decltype(reference)>;
        if constexpr(std::is_same_v<Reference, BrokerContext>)
            return {{"brokerGeneration", decimal64(reference.brokerGeneration)}};
        else if constexpr(std::is_same_v<Reference, InstanceId>)
            return {{"instanceId", reference.value}};
        else
        {
            const TargetRef& target = [&]() -> const TargetRef&
            {
                if constexpr(std::is_same_v<Reference, TargetRef>)
                    return reference;
                else
                    return reference.target;
            }();
            Json value = {{"instanceId", target.instanceId.value}, {"targetId", target.targetId.value}, {"targetGeneration", decimal64(target.targetGeneration)}};
            if constexpr(std::is_same_v<Reference, PausedContext>)
            {
                value["stopEpoch"] = decimal64(reference.stopEpoch);
                if(reference.threadId)
                    value["threadId"] = *reference.threadId;
            }
            return value;
        }
    }, header.context);
    Json evidence = Json::array();
    for(const auto& observation : header.verification.evidence)
    {
        Json value = {{"kind", observation.kind}, {"source", observation.source}, {"summary", observation.summary}};
        if(observation.artifactId)
            value["artifactId"] = *observation.artifactId;
        if(observation.sha256)
            value["sha256"] = *observation.sha256;
        evidence.push_back(std::move(value));
    }
    Json verification = {{"status", statuses[static_cast<std::size_t>(header.verification.status)]}, {"evidence", evidence}};
    if(header.verification.followUp)
        verification["followUp"] = recovery_json(*header.verification.followUp);
    Json warnings = Json::array();
    for(const auto& warning : header.warnings)
        warnings.push_back({{"code", warning.code}, {"message", warning.message}});
    Json value = {{"schemaVersion", ContractVersion}, {"operationId", header.operationId.value}, {"context", context},
        {"stateVersion", decimal64(header.stateVersion)}, {"verification", verification}, {"warnings", warnings},
        {"timings", {{"startedUtcMs", decimal64(header.timings.startedUtcMs)}, {"elapsedUs", decimal64(header.timings.elapsedUs)}, {"queueUs", decimal64(header.timings.queueUs)}}}};
    if(header.jobId)
        value["jobId"] = header.jobId->value;
    return value;
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
