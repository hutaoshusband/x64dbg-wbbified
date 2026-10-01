#include "bootstrap.h"
#include "ipc.h"
#include "registry.h"
#include "build_identity.h"
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
    return Json{{"schemaVersion", ContractVersion}, {"component", names[static_cast<std::size_t>(component)]},
        {"buildId", BuildId}, {"wireVersion", IpcWireVersion}, {"process", std::move(process)},
        {"declaredToolCount", tool_registry().size()}, {"implementedTransports", Json::array()}, {"operationalTools", Json::array()}};
}

int native_component_main(NativeComponent component, int argc, wchar_t** argv)
{
    try
    {
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
            std::cerr << "Usage: --build-info or --help. This development build has no implemented transport.\n";
            return 0;
        }
        std::cerr << Json{{"code", "unsupported_capability"}, {"message", "Native transport startup is not implemented in this development build"}}.dump() << '\n';
        return 64;
    }
    catch(const std::exception& error)
    {
        std::cerr << Json{{"code", "internal_error"}, {"message", error.what()}}.dump() << '\n';
        return 1;
    }
}
}
