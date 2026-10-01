#pragma once

#include "contracts.h"

namespace wininspect::mcp
{
Json schema_document_schema();
Json provider_arguments_schema();
Json ui_value_schema();
Json ui_value_definitions();
Json ui_context_schema();
Json native_action_schema();
Json native_action_outcome_schema();
Json native_command_schema();
Json native_plugin_schema();
Json ui_view_schema();
Json ui_dialog_schema();
}
