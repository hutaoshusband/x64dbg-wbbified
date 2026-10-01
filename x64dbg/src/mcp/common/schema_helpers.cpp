#include "schema_helpers.h"
#include <algorithm>

namespace wininspect::mcp
{
Json nullable_schema(Json schema)
{
    return {{"oneOf", Json::array({std::move(schema), {{"type", "null"}}})}};
}

Json extend_object_schema(Json base, Json properties, Json required)
{
    base["properties"].update(properties);
    for(const auto& field : required)
        if(std::find(base["required"].begin(), base["required"].end(), field) == base["required"].end())
            base["required"].push_back(field);
    return base;
}

Json context_schema(std::string_view name, Json properties, Json required, bool threadSensitive)
{
    if(threadSensitive)
        required.push_back("threadId");
    return extend_object_schema(contract_schema(name), std::move(properties), std::move(required));
}

Json address_forms(Json base)
{
    const auto address = contract_schema("AddressRef");
    Json choices = Json::array();
    for(const auto& form : address.at("oneOf"))
        choices.push_back(extend_object_schema(base, form.at("properties"), form.at("required")));
    return {{"oneOf", std::move(choices)}};
}

Json instance_or_target_forms(Json properties, Json required)
{
    return {{"oneOf", Json::array({context_schema("InstanceRef", properties, required), context_schema("TargetRef", std::move(properties), std::move(required))})}};
}

Json file_forms(Json base)
{
    const auto file = contract_schema("FileRef");
    Json choices = Json::array();
    for(const auto& form : file.at("oneOf"))
        choices.push_back(extend_object_schema(base, form.at("properties"), form.at("required")));
    return {{"oneOf", std::move(choices)}};
}

Json paged_data_schema(Json item)
{
    return closed_object_schema({{"items", bounded_array_schema(std::move(item), MaximumPageLimit)},
        {"page", reference_schema("ResultPagination")}}, {"items", "page"});
}

Json with_page_schema(Json base)
{
    return extend_object_schema(std::move(base), contract_schema("Page").at("properties"), Json::array());
}

Json with_deadline_schema(Json base)
{
    return extend_object_schema(std::move(base), contract_schema("Deadline").at("properties"), Json::array());
}

Json positive_decimal_schema()
{
    auto schema = contract_schema("Decimal64");
    schema["not"] = {{"const", "0"}};
    return schema;
}

Json typed_setting_value_schema()
{
    Json choices = Json::array();
    for(const auto& entry : std::vector<std::pair<std::string, Json>>{{"boolean", {{"type", "boolean"}}},
        {"uint64", reference_schema("Decimal64")}, {"text", string_schema("utf8-text", 32767, 0)}})
        choices.push_back(closed_object_schema({{"kind", {{"const", entry.first}}}, {"value", entry.second}}, {"kind", "value"}));
    return {{"oneOf", std::move(choices)}};
}

Json effect_list_schema()
{
    return bounded_array_schema(enum_schema({"inspect", "execute", "modify", "file_export", "file_replace", "elevate", "configure"}), 7, 0, true);
}
}
