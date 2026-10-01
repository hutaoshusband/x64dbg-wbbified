#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
std::string utf8(std::wstring_view value)
{
    if(value.empty())
        return {};
    const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if(count <= 0)
        throw std::runtime_error("Reference UTF-16 conversion failed");
    std::string output(static_cast<std::size_t>(count), '\0');
    if(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), output.data(), count, nullptr, nullptr) != count)
        throw std::runtime_error("Reference UTF-8 conversion failed");
    return output;
}

nlohmann::json environment_value(const wchar_t* name)
{
    SetLastError(ERROR_SUCCESS);
    const auto needed = GetEnvironmentVariableW(name, nullptr, 0);
    if(!needed)
        return GetLastError() == ERROR_ENVVAR_NOT_FOUND ? nlohmann::json(nullptr) : nlohmann::json("");
    std::vector<wchar_t> buffer(needed);
    const auto count = GetEnvironmentVariableW(name, buffer.data(), needed);
    if(count >= needed)
        throw std::runtime_error("Reference environment changed during read");
    return utf8(std::wstring_view(buffer.data(), count));
}
}

int wmain(int argc, wchar_t** argv)
{
    try
    {
        nlohmann::json arguments = nlohmann::json::array();
        for(int index = 0; index < argc; ++index)
            arguments.push_back(utf8(argv[index]));
        const auto needed = GetCurrentDirectoryW(0, nullptr);
        std::vector<wchar_t> directory(needed);
        if(!needed || !GetCurrentDirectoryW(needed, directory.data()))
            throw std::runtime_error("Reference current directory read failed");
        const nlohmann::json result = {{"argv", arguments}, {"rawCommandLine", utf8(GetCommandLineW())}, {"cwd", utf8(directory.data())},
            {"pointerBits", sizeof(void*) * 8}, {"pid", GetCurrentProcessId()}, {"environment", {
                {"WI_KEEP", environment_value(L"WI_KEEP")}, {"WI_DELETE", environment_value(L"WI_DELETE")},
                {"WI_EMPTY", environment_value(L"WI_EMPTY")}, {"WI_UNICODE", environment_value(L"WI_UNICODE")}}}};
        std::cout << result.dump() << '\n';
        return 17;
    }
    catch(const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
