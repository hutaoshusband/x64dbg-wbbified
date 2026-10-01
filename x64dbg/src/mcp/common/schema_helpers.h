#pragma once

#include "contracts.h"

namespace wininspect::mcp
{
Json nullable_schema(Json schema);
Json extend_object_schema(Json base, Json properties, Json required);
Json context_schema(std::string_view name, Json properties = Json::object(), Json required = Json::array(), bool threadSensitive = false);
Json address_forms(Json base);
Json file_forms(Json base);
Json instance_or_target_forms(Json properties, Json required);
Json paged_data_schema(Json item);
Json with_page_schema(Json base);
Json with_deadline_schema(Json base);
Json positive_decimal_schema();
Json typed_setting_value_schema();
Json effect_list_schema();
}
