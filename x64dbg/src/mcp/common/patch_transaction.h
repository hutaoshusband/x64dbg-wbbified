#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wininspect::mcp
{
constexpr std::size_t MaximumPatchRanges = 1000;
constexpr std::size_t MaximumPatchBytes = 1024 * 1024;

using PatchBytes = std::vector<std::uint8_t>;

struct PatchTargetStamp
{
    std::uint32_t pid;
    std::uint64_t creationTime;
    std::uint64_t pauseEpoch;
    unsigned pointerBits;
};

struct PatchByteRecord
{
    std::uint8_t original;
    std::uint8_t installed;
    bool operator==(const PatchByteRecord& other) const { return original == other.original && installed == other.installed; }
    bool operator!=(const PatchByteRecord& other) const { return !(*this == other); }
};

struct PatchSnapshot
{
    PatchBytes bytes;
    std::vector<std::optional<PatchByteRecord>> records;
    std::string module;
    bool operator==(const PatchSnapshot& other) const { return bytes == other.bytes && records == other.records && module == other.module; }
    bool operator!=(const PatchSnapshot& other) const { return !(*this == other); }
};

struct RuntimePatchRange
{
    std::uint64_t address;
    PatchBytes expected;
    PatchBytes replacement;
};

enum class PatchTransactionStatus { Rejected, Committed, RolledBack, PartialFailure, Undone, Conflict };
enum class PatchTransactionError { None, InvalidPlan, StaleContext, Mapping, ExpectedBytes, Read, Write, Verify, Flush, Restore };
enum class PatchRangeState { Planned, Applied, Restored, Conflict, Unknown };

struct PatchRangeResult
{
    std::uint64_t address;
    std::size_t size;
    PatchRangeState state = PatchRangeState::Planned;
    std::optional<PatchSnapshot> observed;
    bool writeAttempted = false;
    bool restorationVerified = false;
};

struct PatchTransactionResult
{
    PatchTransactionStatus status = PatchTransactionStatus::Rejected;
    PatchTransactionError error = PatchTransactionError::None;
    std::optional<std::size_t> failureRange;
    bool resumeAllowed = true;
    std::vector<PatchRangeResult> ranges;
};

class PatchBackend
{
public:
    virtual ~PatchBackend() = default;
    virtual bool current(const PatchTargetStamp& target) = 0;
    virtual bool mapping(std::uint64_t address, std::size_t size) = 0;
    virtual bool capture(std::uint64_t address, std::size_t size, PatchSnapshot& snapshot) = 0;
    virtual bool patch(std::uint64_t address, const PatchBytes& bytes) = 0;
    virtual bool restore(std::uint64_t address, const PatchSnapshot& snapshot) = 0;
    virtual bool flush(std::uint64_t address, std::size_t size) = 0;
};

class RuntimePatchTransaction
{
public:
    RuntimePatchTransaction(PatchTargetStamp target, std::vector<RuntimePatchRange> plan, PatchBackend& backend);
    RuntimePatchTransaction(const RuntimePatchTransaction&) = delete;
    RuntimePatchTransaction& operator=(const RuntimePatchTransaction&) = delete;
    const PatchTransactionResult& apply();
    const PatchTransactionResult& undo(PatchTargetStamp target);
    const PatchTransactionResult& result() const { return result_; }

private:
    bool validate_plan();
    bool observe(std::size_t index, PatchSnapshot& snapshot);
    bool restore_ranges(std::size_t count);
    PatchSnapshot expected_installation(std::size_t index) const;
    const PatchTargetStamp target_;
    PatchTargetStamp activeTarget_;
    const std::vector<RuntimePatchRange> plan_;
    PatchBackend& backend_;
    std::vector<PatchSnapshot> originals_;
    std::vector<std::optional<PatchSnapshot>> installed_;
    PatchTransactionResult result_;
    bool attempted_ = false;
    bool committed_ = false;
};
}
