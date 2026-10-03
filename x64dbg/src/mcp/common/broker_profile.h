#pragma once

#include "platform.h"
#include <Windows.h>
#include <memory>

namespace wininspect::mcp
{
class BrokerProfile
{
public:
    static Checked<std::unique_ptr<BrokerProfile>> open(const NativeProcessIdentity& owner, std::string_view profile, std::wstring_view root);
    ~BrokerProfile();
    BrokerProfile(const BrokerProfile&) = delete;
    BrokerProfile& operator=(const BrokerProfile&) = delete;
    Checked<Json> configuration(std::string_view installation, bool create);
    Checked<bool> publish_registration(std::string_view key, const NativeProcessIdentity& process, const Json& value);
    Checked<Json> registration(std::string_view key, const NativeProcessIdentity& process);
    const std::wstring& root() const { return rootPath_; }
    const std::wstring& directory() const { return directoryPath_; }
private:
    BrokerProfile() = default;
    Checked<Json> read(const std::wstring& filename);
    Checked<bool> publish(const std::wstring& filename, const Json& value);
    std::wstring registration_name(std::string_view key, const NativeProcessIdentity& process) const;
    HANDLE root_ = INVALID_HANDLE_VALUE;
    HANDLE directory_ = INVALID_HANDLE_VALUE;
    std::wstring rootPath_, directoryPath_;
    std::string profile_, userSid_;
};
}
