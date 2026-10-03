#include "legacy_aliases.h"
#include "legacy_alias_source.h"
#include "build_identity.h"
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <unordered_set>

namespace wininspect::mcp
{
namespace
{
constexpr const char* binding_names[] = {"canonical", "instance_or_target_state", "protocol_echo"};

bool matches_argument_type(std::string_view type, const Json& value)
{
    if(type == "string")
        return value.is_string();
    if(type == "boolean")
        return value.is_boolean();
    if(type != "integer")
        return false;
    if(value.is_number_integer())
        return true;
    if(!value.is_number_float())
        return false;
    const auto number = value.get<double>();
    return std::isfinite(number) && std::trunc(number) == number;
}

bool valid_captured_schema(const Json& schema)
{
    if(!schema.is_object() || schema.size() != 3 || schema.value("type", std::string{}) != "object" ||
       !schema.at("properties").is_object() || !schema.at("required").is_array())
        return false;
    std::unordered_set<std::string> required;
    for(const auto& name : schema.at("required"))
        if(!name.is_string() || !schema.at("properties").contains(name.get<std::string>()) || !required.insert(name.get<std::string>()).second)
            return false;
    for(const auto& property : schema.at("properties"))
    {
        if(!property.is_object() || !property.contains("type") || !property.contains("description") ||
           !property.at("description").is_string() || (property.size() != 2 && (property.size() != 3 || !property.contains("default"))))
            return false;
        const auto type = property.at("type").get<std::string>();
        if(type != "string" && type != "integer" && type != "boolean")
            return false;
        if(property.contains("default") && !matches_argument_type(type, property.at("default")))
            return false;
    }
    return true;
}

struct LegacyContractSet
{
    Json baselineProvider;
    std::string baselineManifestHash;
    std::string capturedCatalogHash;
    std::vector<LegacyAliasDefinition> aliases;
};

LegacyContractSet load_legacy_contracts()
{
    std::string source_text;
    for(const auto part : LegacyAliasSourceParts)
        source_text.append(part.data(), part.size());
    const auto parsed = parse_bounded_json(source_text);
    if(const auto* error = std::get_if<ContractError>(&parsed))
        throw std::logic_error("Compiled legacy alias source is not valid bounded JSON: " + error->message);
    const auto& source = std::get<Json>(parsed);
    if(source.size() != 5 || source.at("schemaVersion") != 1 || !source.at("tools").is_array() || source.at("tools").empty())
        throw std::logic_error("Compiled legacy alias source has an invalid contract version or shape");
    const auto hash_schema = string_schema("sha256", 64);
    if(validate_schema(hash_schema, source.at("baselineManifestSha256")) || validate_schema(hash_schema, source.at("capturedCatalogSha256")))
        throw std::logic_error("Compiled legacy alias source has invalid baseline provenance hashes");
    const auto& provider = source.at("baselineProvider");
    if(provider.size() != 4 || !provider.at("name").is_string() || !provider.at("version").is_string() ||
       provider.at("architecture") != "x64" || validate_schema(hash_schema, provider.at("sha256")))
        throw std::logic_error("Compiled legacy alias source has invalid captured provider provenance");
    LegacyContractSet result{provider, source.at("baselineManifestSha256").get<std::string>(), source.at("capturedCatalogSha256").get<std::string>(), {}};
    std::unordered_set<std::string> names;
    for(const auto& entry : source.at("tools"))
    {
        if(entry.size() != 8 || !valid_captured_schema(entry.at("inputSchema")) || entry.at("nativeStatus") != "planned")
            throw std::logic_error("Compiled legacy alias has an invalid schema or implementation status");
        const auto name = entry.at("legacyName").get<std::string>();
        if(validate_schema(string_schema("opaque-id"), name) || !names.insert(name).second)
            throw std::logic_error("Compiled legacy aliases require unique exact names");
        const auto& annotations = entry.at("annotations");
        if(annotations.size() != 2 || !annotations.at("readOnlyHint").is_boolean() || !annotations.at("openWorldHint").is_boolean())
            throw std::logic_error("Compiled legacy alias has invalid captured annotations");
        const auto& binding = entry.at("binding");
        if(binding.size() != 2 || !binding.at("capabilityIds").is_array())
            throw std::logic_error("Compiled legacy alias has an invalid canonical binding");
        const auto kind_name = binding.at("kind").get<std::string>();
        const auto kind = kind_name == binding_names[0] ? LegacyBindingKind::Canonical :
                          kind_name == binding_names[1] ? LegacyBindingKind::InstanceOrTargetState :
                          kind_name == binding_names[2] ? LegacyBindingKind::ProtocolEcho : throw std::logic_error("Unknown legacy binding kind");
        LegacyAliasDefinition alias{name, entry.at("description").get<std::string>(), entry.at("inputSchema"), annotations,
            entry.at("canonicalRoute").get<std::string>(), entry.at("completionPredicate").get<std::string>(), kind, {}};
        std::unordered_set<std::string> capabilities;
        for(const auto& identifier : binding.at("capabilityIds"))
        {
            const auto capability = identifier.get<std::string>();
            const auto* definition = find_tool(capability);
            if(!definition || !capabilities.insert(capability).second)
                throw std::logic_error("Compiled legacy alias refers to an unknown or repeated canonical definition");
            alias.canonicalBindings.push_back(definition);
        }
        if((kind == LegacyBindingKind::Canonical && (alias.canonicalBindings.size() != 1 || alias.canonicalBindings.front()->name != alias.originalRoute)) ||
           (kind == LegacyBindingKind::ProtocolEcho && (name != "Echo" || !alias.canonicalBindings.empty())) ||
           (kind == LegacyBindingKind::InstanceOrTargetState && (name != "GetDebugState" || capabilities != std::unordered_set<std::string>{"debugger_instances", "target_state"})))
            throw std::logic_error("Compiled legacy alias has an inconsistent compatibility binding");
        result.aliases.push_back(std::move(alias));
    }
    std::sort(result.aliases.begin(), result.aliases.end(), [](const auto& left, const auto& right) { return left.name < right.name; });
    return result;
}

const LegacyContractSet& legacy_contracts()
{
    static const auto source = load_legacy_contracts();
    return source;
}
}

const std::vector<LegacyAliasDefinition>& legacy_alias_registry()
{
    return legacy_contracts().aliases;
}

const LegacyAliasDefinition* find_legacy_alias(std::string_view name)
{
    const auto& aliases = legacy_alias_registry();
    const auto found = std::lower_bound(aliases.begin(), aliases.end(), name,
        [](const auto& alias, const auto& requested) { return alias.name < requested; });
    return found != aliases.end() && found->name == name ? &*found : nullptr;
}

Json legacy_alias_descriptor(const LegacyAliasDefinition& alias)
{
    Json bindings = Json::array();
    for(const auto* definition : alias.canonicalBindings)
    {
        const auto canonical = tool_descriptor(*definition);
        Json binding = {{"capabilityId", canonical.at("capabilityId")}};
        for(const auto* field : {"effects", "effectConditions", "executor", "stateRequirement", "architectureRequirement", "completionPredicate", "recovery", "acceptanceIds"})
            binding[field] = canonical.at(field);
        if(canonical.contains("effectResolution"))
            binding["effectResolution"] = canonical.at("effectResolution");
        bindings.push_back(std::move(binding));
    }
    return {{"name", alias.name}, {"description", alias.description}, {"inputSchema", alias.inputSchema},
        {"capturedAnnotations", alias.capturedAnnotations}, {"originalRoute", alias.originalRoute}, {"compatibilityPredicate", alias.compatibilityPredicate},
        {"bindingKind", binding_names[static_cast<std::size_t>(alias.bindingKind)]}, {"canonicalBindings", std::move(bindings)},
        {"availability", "planned"}, {"operational", false}, {"executionAdapterInstalled", false}};
}

Json compiled_legacy_registry()
{
    const auto& source = legacy_contracts();
    Json aliases = Json::array();
    for(const auto& alias : source.aliases)
        aliases.push_back(legacy_alias_descriptor(alias));
    return {{"schemaVersion", ContractVersion}, {"buildId", BuildId}, {"baselineProvider", source.baselineProvider},
        {"baselineManifestSha256", source.baselineManifestHash}, {"capturedCatalogSha256", source.capturedCatalogHash},
        {"aliases", std::move(aliases)}, {"operationalAliases", Json::array()}};
}

std::optional<ContractError> validate_legacy_alias_input(std::string_view name, const Json& input)
{
    const auto* alias = find_legacy_alias(name);
    if(!alias)
        return ContractError{"unsupported_capability", "", "Legacy alias is not declared in the compiled registry"};
    if(!input.is_object())
        return ContractError{"invalid_argument", "", "Legacy arguments must be a JSON object"};
    for(const auto& required : alias->inputSchema.at("required"))
        if(!input.contains(required.get<std::string>()))
            return ContractError{"invalid_argument", "/" + required.get<std::string>(), "Required legacy argument is missing"};
    for(auto property = alias->inputSchema.at("properties").begin(); property != alias->inputSchema.at("properties").end(); ++property)
        if(input.contains(property.key()) && !matches_argument_type(property.value().at("type").get<std::string>(), input.at(property.key())))
            return ContractError{"invalid_argument", "/" + property.key(), "Legacy argument has a different type from its captured contract"};
    return {};
}

Checked<Json> normalize_legacy_alias_input(std::string_view name, const Json& input)
{
    if(auto error = validate_legacy_alias_input(name, input))
        return *error;
    auto normalized = input;
    const auto& properties = find_legacy_alias(name)->inputSchema.at("properties");
    for(auto property = properties.begin(); property != properties.end(); ++property)
        if(!normalized.contains(property.key()) && property.value().contains("default"))
            normalized[property.key()] = property.value().at("default");
    return normalized;
}
}
