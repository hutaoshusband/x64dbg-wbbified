#include "bootstrap.h"
#include "ipc.h"
#include "registry.h"
#include "legacy_aliases.h"
#include "parity_catalog.h"
#include "build_identity.h"
#include "broker_runtime.h"
#include "mcp_stdio.h"
#include <iostream>

namespace wininspect::mcp
{
Checked<Json> component_build_info(NativeComponent component)
{
    constexpr const char* names[] = {"broker", "connector", "worker_adapter"};
    auto identity = capture_current_process();
    if(const auto* error = std::get_if<ContractError>(&identity))
        return *error;
    auto process = native_process_json(std::get<NativeProcessIdentity>(identity));
    if(auto error = validate_contract("NativeProcessIdentity", process))
        return *error;
    Json transports = component == NativeComponent::Broker ? Json::array({"stdio"}) : Json::array();
    return Json{{"schemaVersion", ContractVersion}, {"component", names[static_cast<std::size_t>(component)]},
        {"buildId", BuildId}, {"wireVersion", IpcWireVersion}, {"process", std::move(process)},
        {"declaredToolCount", tool_registry().size()}, {"declaredLegacyAliasCount", legacy_alias_registry().size()},
        {"declaredParityOperationCount", compiled_parity_metadata().at("recordCounts").at("operation")},
        {"implementedTransports", std::move(transports)}, {"operationalTools", Json::array()}};
}

int native_component_main(NativeComponent component, int argc, wchar_t** argv)
{
    try
    {
        if((argc == 4 || (argc == 6 && std::wstring_view(argv[4]) == L"--profile-root")) && std::wstring_view(argv[2]) == L"--profile")
        {
            const std::wstring_view root = argc == 6 ? argv[5] : L"";
            if(component == NativeComponent::Broker && std::wstring_view(argv[1]) == L"--serve-local") return serve_local_broker(argv[3], root);
            if(component == NativeComponent::Connector && std::wstring_view(argv[1]) == L"--local-control") return connect_local_control(argv[3], root);
        }
        if(argc == 2 && std::wstring_view(argv[1]) == L"--serve-stdio")
        {
            if(component != NativeComponent::Broker)
            {
                std::cerr << Json{{"code", "unsupported_capability"}, {"message", "Only the broker serves MCP stdio"}}.dump() << '\n';
                return 64;
            }
            return serve_mcp_stdio();
        }
        if(argc == 2 && std::wstring_view(argv[1]) == L"--build-info")
        {
            const auto information = component_build_info(component);
            if(const auto* value = std::get_if<Json>(&information))
            {
                std::cout << value->dump() << '\n';
                return 0;
            }
            const auto& error = std::get<ContractError>(information);
            std::cerr << Json{{"code", error.code}, {"message", error.message}}.dump() << '\n';
            return 1;
        }
        if(argc == 2 && std::wstring_view(argv[1]) == L"--help")
        {
            std::cerr << "Usage: --build-info or --help; broker: --serve-local --profile SHA256 or --serve-stdio; connector: --local-control --profile SHA256. Local control accepts status/shutdown JSON lines; stdio serves the five implemented broker inspection tools; other MCP transports remain unavailable.\n";
            return 0;
        }
        std::cerr << Json{{"code", "unsupported_capability"}, {"message", "Native transport startup is not implemented in this development build"}}.dump() << '\n';
        return 64;
    }
    catch(const ContractError& error)
    {
        std::cerr << Json{{"code", error.code}, {"message", error.message}}.dump() << '\n';
        return 1;
    }
    catch(const std::exception& error)
    {
        std::cerr << Json{{"code", "internal_error"}, {"message", error.what()}}.dump() << '\n';
        return 1;
    }
}
}
