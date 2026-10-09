#include "mcp_stdio.h"
#include "build_identity.h"
#include "platform.h"
#include "registry.h"
#include <fcntl.h>
#include <io.h>
#include <iostream>
#include <set>

namespace wininspect::mcp
{
namespace
{
constexpr const char* StdioServerName = "wininspect-mcp";
constexpr const char* StdioFallbackVersion = "2024-11-05";

bool stdio_version_supported(std::string_view version)
{
    return version == "2024-11-05" || version == "2025-03-26" || version == "2025-06-18" || version == "2025-11-25";
}

Json rpc_error(int code, std::string message)
{
    return Json{{"code", code}, {"message", std::move(message)}};
}

struct StdioLine
{
    bool eof = false;
    bool oversized = false;
    std::string text;
};

StdioLine read_stdio_line()
{
    StdioLine line;
    char byte = 0;
    while(std::cin.get(byte))
    {
        if(byte == '\n')
            return line;
        if(line.text.size() >= MaximumPayloadBytes)
        {
            line.oversized = true;
            continue;
        }
        line.text.push_back(byte);
    }
    if(!line.text.empty() || line.oversized)
        return line;
    line.eof = true;
    return line;
}

Json mcp_tool_list()
{
    Json tools = Json::array();
    for(const auto& tool : tool_registry())
    {
        if(!tool.handler)
            continue;
        tools.push_back({{"name", tool.name}, {"description", tool.description},
            {"inputSchema", tool.inputSchema}, {"annotations", tool_descriptor(tool).at("annotations")}});
    }
    return Json{{"tools", std::move(tools)}};
}

Json mcp_tool_result(const Json& envelope)
{
    return Json{{"content", Json::array({Json{{"type", "text"}, {"text", envelope.dump()}}})}};
}

Json mcp_tool_error(const ContractError& error)
{
    Json result = mcp_tool_result(Json{{"code", error.code}, {"path", error.path}, {"message", error.message}});
    result["isError"] = true;
    return result;
}

Json dispatch_stdio(const Json& message, std::uint64_t brokerGeneration, std::uint64_t& operationCounter)
{
    const auto has_id = message.is_object() && message.contains("id");
    const auto invalid = [&](int code, std::string text) -> Json
    {
        if(!has_id)
            return Json(nullptr);
        return Json{{"jsonrpc", "2.0"}, {"id", message.at("id")}, {"error", rpc_error(code, std::move(text))}};
    };
    if(!message.is_object() || !message.contains("jsonrpc") || !message.at("jsonrpc").is_string() ||
        message.at("jsonrpc").get_ref<const std::string&>() != "2.0" || !message.contains("method") || !message.at("method").is_string())
        return invalid(-32600, "Invalid JSON-RPC request");
    const auto& method = message.at("method").get_ref<const std::string&>();
    if(method.rfind("notifications/", 0) == 0)
        return Json(nullptr);
    if(!has_id)
        return Json(nullptr);
    const auto& id = message.at("id");
    const Json params = message.value("params", Json::object());
    if(!params.is_object())
        return Json{{"jsonrpc", "2.0"}, {"id", id}, {"error", rpc_error(-32602, "Request params must be an object")}};
    if(method == "initialize")
    {
        const std::string requested =
            params.contains("protocolVersion") && params.at("protocolVersion").is_string() ? params.at("protocolVersion").get<std::string>() : "";
        const std::string version = stdio_version_supported(requested) ? requested : StdioFallbackVersion;
        return Json{{"jsonrpc", "2.0"}, {"id", id}, {"result", Json{{"protocolVersion", version},
            {"capabilities", Json{{"tools", Json::object()}}},
            {"serverInfo", Json{{"name", StdioServerName}, {"version", BuildId}}}}}};
    }
    if(method == "ping")
        return Json{{"jsonrpc", "2.0"}, {"id", id}, {"result", Json::object()}};
    if(method == "tools/list")
    {
        if(params.contains("cursor"))
            return Json{{"jsonrpc", "2.0"}, {"id", id}, {"error", rpc_error(-32602, "Unknown cursor; the stdio catalog fits one page")}};
        return Json{{"jsonrpc", "2.0"}, {"id", id}, {"result", mcp_tool_list()}};
    }
    if(method == "tools/call")
    {
        if(!params.contains("name") || !params.at("name").is_string())
            return Json{{"jsonrpc", "2.0"}, {"id", id}, {"error", rpc_error(-32602, "tools/call requires a string tool name")}};
        const auto& name = params.at("name").get_ref<const std::string&>();
        if(!find_tool(name) || !find_tool(name)->handler)
            return Json{{"jsonrpc", "2.0"}, {"id", id}, {"error", rpc_error(-32602, "Tool is not implemented in this development build")}};
        const Json arguments = params.value("arguments", Json::object());
        if(!arguments.is_object())
            return Json{{"jsonrpc", "2.0"}, {"id", id}, {"error", rpc_error(-32602, "Tool arguments must be an object")}};
        const RegistryCallContext context{{"stdio-" + std::to_string(++operationCounter)}, brokerGeneration, 1};
        const auto result = call_registry_tool(name, arguments, context);
        if(const auto* error = std::get_if<ContractError>(&result))
            return Json{{"jsonrpc", "2.0"}, {"id", id}, {"result", mcp_tool_error(*error)}};
        return Json{{"jsonrpc", "2.0"}, {"id", id}, {"result", mcp_tool_result(std::get<Json>(result))}};
    }
    return Json{{"jsonrpc", "2.0"}, {"id", id}, {"error", rpc_error(-32601, "Method not found")}};
}
}

int serve_mcp_stdio()
{
    if(_setmode(_fileno(stdin), _O_BINARY) == -1 || _setmode(_fileno(stdout), _O_BINARY) == -1)
        throw ContractError{"ipc_failure", "", "Cannot select UTF-8 stdio byte streams"};
    const auto owner = capture_current_process();
    if(const auto* error = std::get_if<ContractError>(&owner))
        throw *error;
    const std::uint64_t brokerGeneration = std::get<NativeProcessIdentity>(owner).creationTime;
    std::uint64_t operationCounter = 0;
    for(;;)
    {
        const auto line = read_stdio_line();
        if(line.eof)
            return 0;
        Json response(nullptr);
        std::string text = line.text;
        if(!text.empty() && text.back() == '\r')
            text.pop_back();
        if(text.empty() && !line.oversized)
            continue;
        if(line.oversized)
            response = Json{{"jsonrpc", "2.0"}, {"id", nullptr}, {"error", rpc_error(-32600, "Stdio line exceeds its 1048576-byte bound")}};
        else
        {
            const auto parsed = parse_bounded_json(text);
            if(const auto* error = std::get_if<ContractError>(&parsed))
                response = Json{{"jsonrpc", "2.0"}, {"id", nullptr}, {"error", rpc_error(-32700, "Parse error: " + error->code)}};
            else
            {
                try
                {
                    response = dispatch_stdio(std::get<Json>(parsed), brokerGeneration, operationCounter);
                }
                catch(const std::exception& error)
                {
                    response = Json{{"jsonrpc", "2.0"}, {"id", nullptr}, {"error", rpc_error(-32603, std::string("Internal error: ") + error.what())}};
                }
            }
        }
        if(!response.is_null())
            std::cout << response.dump() << '\n' << std::flush;
    }
}
}
