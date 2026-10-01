#include "lifecycle.h"
#include "registry.h"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <algorithm>
#include <limits>

namespace wininspect::mcp
{
namespace
{
std::wstring quote_crt_argument(std::wstring_view argument)
{
    std::wstring quoted = L"\"";
    std::size_t backslashes = 0;
    for(const auto character : argument)
    {
        if(character == L'\\')
        {
            ++backslashes;
            continue;
        }
        quoted.append(backslashes * (character == L'"' ? 2 : 1), L'\\');
        if(character == L'"')
            quoted.push_back(L'\\');
        backslashes = 0;
        quoted.push_back(character);
    }
    quoted.append(backslashes * 2, L'\\');
    quoted.push_back(L'"');
    return quoted;
}

int compare_environment_name(std::wstring_view left, std::wstring_view right)
{
    return CompareStringOrdinal(left.data(), static_cast<int>(left.size()), right.data(), static_cast<int>(right.size()), TRUE);
}

bool valid_inherited_name(std::wstring_view name)
{
    if(name.empty() || name.size() > MaximumWindowsCommandUnits || name.find(L'\0') != std::wstring_view::npos)
        return false;
    if(name.find(L'=') == std::wstring_view::npos)
        return true;
    return name.size() == 3 && name[0] == L'=' && ((name[1] >= L'A' && name[1] <= L'Z') || (name[1] >= L'a' && name[1] <= L'z')) && name[2] == L':';
}

Checked<std::vector<wchar_t>> environment_block(const LaunchEnvironment& requested, const std::vector<EnvironmentEntry>& inherited)
{
    if(requested.changes.size() > MaximumEnvironmentChanges)
        return ContractError{"resource_limit", "/environment/changes", "Environment change count exceeds its bound"};
    std::vector<EnvironmentEntry> entries = requested.inherit ? inherited : std::vector<EnvironmentEntry>{};
    std::size_t inherited_units = 1;
    for(const auto& entry : entries)
    {
        if(!valid_inherited_name(entry.name) || entry.value.find(L'\0') != std::wstring::npos)
            return ContractError{"invalid_argument", "/environment", "Inherited environment contains an invalid entry"};
        if(entry.name.size() + entry.value.size() + 2 > MaximumEnvironmentUnits - inherited_units)
            return ContractError{"resource_limit", "/environment", "Inherited environment exceeds the byte limit"};
        inherited_units += entry.name.size() + entry.value.size() + 2;
    }
    std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) { return compare_environment_name(left.name, right.name) == CSTR_LESS_THAN; });
    for(std::size_t index = 1; index < entries.size(); ++index)
        if(compare_environment_name(entries[index - 1].name, entries[index].name) == CSTR_EQUAL)
            return ContractError{"invalid_argument", "/environment", "Inherited environment contains duplicate names"};
    std::vector<std::wstring> changed_names;
    for(const auto& change : requested.changes)
    {
        const auto converted_name = launch_utf16(change.name);
        if(const auto* error = std::get_if<ContractError>(&converted_name))
            return *error;
        const auto& name = std::get<std::wstring>(converted_name);
        if(name.empty() || name.size() > MaximumWindowsCommandUnits || name.find(L'=') != std::wstring::npos)
            return ContractError{"invalid_argument", "/environment/changes", "Environment name is invalid"};
        if(std::any_of(changed_names.begin(), changed_names.end(), [&](const auto& previous) { return compare_environment_name(previous, name) == CSTR_EQUAL; }))
            return ContractError{"invalid_argument", "/environment/changes", "Environment change names collide ignoring case"};
        changed_names.push_back(name);
        entries.erase(std::remove_if(entries.begin(), entries.end(), [&](const auto& entry) { return compare_environment_name(entry.name, name) == CSTR_EQUAL; }), entries.end());
        if(change.value)
        {
            auto converted_value = launch_utf16(*change.value);
            if(const auto* error = std::get_if<ContractError>(&converted_value))
                return *error;
            entries.push_back({name, std::get<std::wstring>(std::move(converted_value))});
        }
    }
    std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) { return compare_environment_name(left.name, right.name) == CSTR_LESS_THAN; });
    std::vector<wchar_t> block;
    for(const auto& entry : entries)
    {
        if(entry.name.size() + entry.value.size() + 2 > MaximumEnvironmentUnits - block.size() - 1)
            return ContractError{"resource_limit", "/environment", "Environment block exceeds the byte limit"};
        block.insert(block.end(), entry.name.begin(), entry.name.end());
        block.push_back(L'=');
        block.insert(block.end(), entry.value.begin(), entry.value.end());
        block.push_back(L'\0');
    }
    if(block.empty())
        block.push_back(L'\0');
    block.push_back(L'\0');
    return block;
}
}

Checked<std::wstring> launch_utf16(std::string_view input)
{
    if(input.size() > MaximumFrameBytes || input.find('\0') != std::string_view::npos)
        return ContractError{"invalid_argument", "", "Launch text contains NUL or exceeds its byte bound"};
    if(input.empty())
        return std::wstring{};
    const auto count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), nullptr, 0);
    if(count <= 0)
        return ContractError{"invalid_argument", "", "Launch text is not valid UTF-8"};
    std::wstring output(static_cast<std::size_t>(count), L'\0');
    if(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), output.data(), count) != count)
        return ContractError{"invalid_argument", "", "Launch text conversion failed"};
    return output;
}

Checked<std::string> launch_utf8(std::wstring_view input)
{
    if(input.size() > MaximumFrameBytes || input.find(L'\0') != std::wstring_view::npos)
        return ContractError{"invalid_argument", "", "Launch text contains NUL or exceeds its unit bound"};
    if(input.empty())
        return std::string{};
    const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
    if(count <= 0)
        return ContractError{"invalid_argument", "", "Launch text is not valid UTF-16"};
    std::string output(static_cast<std::size_t>(count), '\0');
    if(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), output.data(), count, nullptr, nullptr) != count)
        return ContractError{"invalid_argument", "", "Launch text conversion failed"};
    return output;
}

Checked<TargetLaunchRequest> parse_target_launch(const Json& input)
{
    if(auto error = validate_tool_input("target_open", input))
        return *error;
    TargetLaunchRequest request;
    request.instanceId = {input.at("instanceId").get<std::string>()};
    request.file = input.contains("path") ? LaunchFile{AbsoluteFile{input.at("path").get<std::string>()}} : LaunchFile{ArtifactFile{input.at("artifactId").get<std::string>()}};
    request.arguments = input.contains("rawCommandLine") ? LaunchArguments{RawCommandLine{input.at("rawCommandLine").get<std::string>()}} : LaunchArguments{input.value("argv", std::vector<std::string>{})};
    if(input.contains("cwd"))
        request.cwd = input.at("cwd").get<std::string>();
    if(input.contains("environment"))
    {
        const auto& environment = input.at("environment");
        request.environment.inherit = environment.value("mode", "inherit") == "inherit";
        for(const auto& change : environment.at("changes"))
            request.environment.changes.push_back({change.at("name").get<std::string>(), change.at("value").is_null() ? std::optional<std::string>{} : change.at("value").get<std::string>()});
    }
    if(input.contains("initialStop"))
    {
        const auto& stop = input.at("initialStop");
        if(stop.is_object())
            request.initialStop = NamedLaunchStop{stop.at("name").get<std::string>()};
        else
            request.initialStop = stop == "system_breakpoint" ? InitialLaunchStop::SystemBreakpoint : stop == "entry_point" ? InitialLaunchStop::EntryPoint : InitialLaunchStop::Configured;
    }
    if(input.contains("initScript"))
    {
        const auto& script = input.at("initScript");
        request.initScript = LibraryRef{{script.at("namespaceId").get<std::string>()}, {script.at("objectId").get<std::string>()}, {script.at("revision").get<std::string>()}};
    }
    if(input.contains("idempotencyKey"))
        request.idempotencyKey = input.at("idempotencyKey").get<std::string>();
    return request;
}

Checked<WindowsLaunchPlan> prepare_windows_launch(const TargetLaunchRequest& request, std::string_view resolvedImage,
                                                const std::vector<EnvironmentEntry>& inheritedEnvironment)
{
    if(auto error = validate_contract("FileRef", {{"path", resolvedImage}}))
        return *error;
    WindowsLaunchPlan plan;
    const auto application = launch_utf16(resolvedImage);
    if(const auto* error = std::get_if<ContractError>(&application))
        return *error;
    plan.application = std::get<std::wstring>(application);
    if(plan.application.find(L'"') != std::wstring::npos || plan.application.size() > MaximumWindowsCommandUnits)
        return ContractError{"invalid_argument", "/path", "Resolved executable path is invalid"};
    if(const auto* argv = std::get_if<std::vector<std::string>>(&request.arguments))
    {
        if(argv->size() > MaximumLaunchArguments)
            return ContractError{"resource_limit", "/argv", "Argument count exceeds its bound"};
        plan.commandLine = quote_crt_argument(plan.application);
        for(const auto& argument : *argv)
        {
            const auto converted = launch_utf16(argument);
            if(const auto* error = std::get_if<ContractError>(&converted))
                return *error;
            plan.commandLine += L" " + quote_crt_argument(std::get<std::wstring>(converted));
            if(plan.commandLine.size() > MaximumWindowsCommandUnits)
                return ContractError{"resource_limit", "/argv", "Encoded command line exceeds the Windows UTF-16 limit"};
        }
    }
    else
    {
        const auto converted = launch_utf16(std::get<RawCommandLine>(request.arguments).value);
        if(const auto* error = std::get_if<ContractError>(&converted))
            return *error;
        plan.commandLine = std::get<std::wstring>(converted);
    }
    if(plan.commandLine.size() > MaximumWindowsCommandUnits)
        return ContractError{"resource_limit", "/rawCommandLine", "Command line exceeds the Windows UTF-16 limit"};
    if(request.cwd)
    {
        if(auto error = validate_contract("FileRef", {{"path", *request.cwd}}))
            return *error;
        auto converted = launch_utf16(*request.cwd);
        if(const auto* error = std::get_if<ContractError>(&converted))
            return *error;
        plan.cwd = std::get<std::wstring>(std::move(converted));
        if(plan.cwd->size() > MaximumWindowsCommandUnits)
            return ContractError{"resource_limit", "/cwd", "Working directory exceeds the Windows UTF-16 limit"};
    }
    auto environment = environment_block(request.environment, inheritedEnvironment);
    if(const auto* error = std::get_if<ContractError>(&environment))
        return *error;
    plan.environment = std::get<std::vector<wchar_t>>(std::move(environment));
    return plan;
}
}
