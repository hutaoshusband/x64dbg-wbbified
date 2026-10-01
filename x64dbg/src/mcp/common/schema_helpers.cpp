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
}
