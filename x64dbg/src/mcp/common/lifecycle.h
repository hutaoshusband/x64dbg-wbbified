#pragma once

#include "contracts.h"

namespace wininspect::mcp
{
constexpr std::size_t MaximumLaunchArguments = 1024;
constexpr std::size_t MaximumWindowsCommandUnits = 32766;
constexpr std::size_t MaximumEnvironmentChanges = 256;
constexpr std::size_t MaximumEnvironmentUnits = MaximumPayloadBytes / sizeof(char16_t);

Json launch_environment_schema();
Json launch_argument_forms(Json base, bool required);
Json target_open_schema();
Json launch_overrides_schema();

struct ArtifactFile { std::string artifactId; };
struct AbsoluteFile { std::string path; };
using LaunchFile = std::variant<ArtifactFile, AbsoluteFile>;
struct RawCommandLine { std::string value; };
using LaunchArguments = std::variant<std::vector<std::string>, RawCommandLine>;
struct EnvironmentChange { std::string name; std::optional<std::string> value; };
struct LaunchEnvironment { bool inherit = true; std::vector<EnvironmentChange> changes; };
enum class InitialLaunchStop { Configured, SystemBreakpoint, EntryPoint };
struct NamedLaunchStop { std::string name; };
using LaunchStop = std::variant<InitialLaunchStop, NamedLaunchStop>;
struct TargetLaunchRequest
{
    InstanceId instanceId;
    LaunchFile file;
    LaunchArguments arguments;
    std::optional<std::string> cwd;
    LaunchEnvironment environment;
    LaunchStop initialStop = InitialLaunchStop::Configured;
    std::optional<LibraryRef> initScript;
    std::optional<std::string> idempotencyKey;
};

struct EnvironmentEntry { std::wstring name; std::wstring value; };
struct WindowsLaunchPlan
{
    std::wstring application;
    std::wstring commandLine;
    std::optional<std::wstring> cwd;
    std::vector<wchar_t> environment;
};

Checked<TargetLaunchRequest> parse_target_launch(const Json& input);
Checked<WindowsLaunchPlan> prepare_windows_launch(const TargetLaunchRequest& request, std::string_view resolvedImage,
                                                const std::vector<EnvironmentEntry>& inheritedEnvironment);
Checked<std::wstring> launch_utf16(std::string_view input);
Checked<std::string> launch_utf8(std::wstring_view input);
}
