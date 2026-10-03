#include "patch_transaction.h"
#include <algorithm>
#include <limits>
#include <utility>

namespace wininspect::mcp
{
RuntimePatchTransaction::RuntimePatchTransaction(PatchTargetStamp target, std::vector<RuntimePatchRange> plan, PatchBackend& backend)
    : target_(target), activeTarget_(target), plan_(std::move(plan)), backend_(backend)
{
    for(const auto& range : plan_)
        result_.ranges.push_back({range.address, range.expected.size()});
}

bool RuntimePatchTransaction::validate_plan()
{
    if(plan_.empty() || plan_.size() > MaximumPatchRanges || !target_.pid || !target_.creationTime || !target_.pauseEpoch || (target_.pointerBits != 32 && target_.pointerBits != 64))
        return false;
    const auto maximum = target_.pointerBits == 32 ? std::uint64_t(0xffffffff) : std::numeric_limits<std::uint64_t>::max();
    std::size_t total = 0;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> spans;
    for(const auto& range : plan_)
    {
        if(!range.address || range.expected.empty() || range.expected.size() != range.replacement.size() || range.address > maximum
                || range.expected.size() - 1 > maximum - range.address || range.expected.size() > MaximumPatchBytes - total)
            return false;
        total += range.expected.size();
        spans.emplace_back(range.address, range.address + range.expected.size() - 1);
    }
    std::sort(spans.begin(), spans.end());
    for(std::size_t index = 1; index < spans.size(); ++index)
        if(spans[index].first <= spans[index - 1].second)
            return false;
    return true;
}

bool RuntimePatchTransaction::observe(std::size_t index, PatchSnapshot& snapshot)
{
    return backend_.current(activeTarget_) && backend_.capture(plan_[index].address, plan_[index].expected.size(), snapshot)
           && snapshot.bytes.size() == plan_[index].expected.size() && snapshot.records.size() == snapshot.bytes.size();
}

PatchSnapshot RuntimePatchTransaction::expected_installation(std::size_t index) const
{
    auto expected = originals_[index];
    const auto& replacement = plan_[index].replacement;
    for(std::size_t byte = 0; byte < replacement.size(); ++byte)
    {
        if(expected.bytes[byte] == replacement[byte])
            continue;
        if(expected.records[byte])
        {
            if(expected.records[byte]->original == replacement[byte])
                expected.records[byte].reset();
            else
                expected.records[byte]->installed = replacement[byte];
        }
        else
            expected.records[byte] = PatchByteRecord{expected.bytes[byte], replacement[byte]};
    }
    expected.bytes = replacement;
    return expected;
}

bool RuntimePatchTransaction::restore_ranges(std::size_t count)
{
    bool complete = true;
    while(count)
    {
        const auto index = --count;
        auto& range = result_.ranges[index];
        PatchSnapshot current;
        const bool readCurrent = observe(index, current);
        range.observed = readCurrent ? std::optional<PatchSnapshot>(current) : std::nullopt;
        if(!readCurrent || (!installed_[index] && current != originals_[index]))
        {
            range.state = PatchRangeState::Unknown;
            complete = false;
            continue;
        }
        if(installed_[index] && current != *installed_[index])
        {
            range.state = PatchRangeState::Conflict;
            complete = false;
            continue;
        }
        const bool restored = current == originals_[index] || backend_.restore(plan_[index].address, originals_[index]);
        const bool flushed = restored && backend_.flush(plan_[index].address, plan_[index].expected.size());
        PatchSnapshot after;
        const bool read = observe(index, after);
        range.observed = read ? std::optional<PatchSnapshot>(after) : std::nullopt;
        range.restorationVerified = restored && flushed && read && after == originals_[index];
        range.state = range.restorationVerified ? PatchRangeState::Restored : PatchRangeState::Unknown;
        complete = complete && range.restorationVerified;
    }
    result_.resumeAllowed = complete;
    return complete;
}

const PatchTransactionResult& RuntimePatchTransaction::apply()
{
    if(attempted_)
        return result_;
    attempted_ = true;
    if(!validate_plan())
    {
        result_.error = PatchTransactionError::InvalidPlan;
        return result_;
    }
    originals_.resize(plan_.size());
    installed_.resize(plan_.size());
    for(std::size_t index = 0; index < plan_.size(); ++index)
    {
        result_.failureRange = index;
        if(!backend_.current(activeTarget_))
            result_.error = PatchTransactionError::StaleContext;
        else if(!backend_.mapping(plan_[index].address, plan_[index].expected.size()))
            result_.error = PatchTransactionError::Mapping;
        else if(!observe(index, originals_[index]))
            result_.error = PatchTransactionError::Read;
        else
        {
            result_.ranges[index].observed = originals_[index];
            if(originals_[index].bytes != plan_[index].expected)
                result_.error = PatchTransactionError::ExpectedBytes;
            for(std::size_t byte = 0; byte < originals_[index].bytes.size(); ++byte)
                if(originals_[index].records[byte] && originals_[index].records[byte]->installed != originals_[index].bytes[byte])
                    result_.error = PatchTransactionError::ExpectedBytes;
            if(result_.error == PatchTransactionError::ExpectedBytes)
                result_.ranges[index].state = PatchRangeState::Conflict;
        }
        if(result_.error != PatchTransactionError::None)
            return result_;
    }
    for(std::size_t index = 0; index < plan_.size(); ++index)
    {
        result_.failureRange = index;
        PatchSnapshot before;
        if(!observe(index, before))
            result_.error = PatchTransactionError::StaleContext;
        else if(before != originals_[index])
            result_.error = PatchTransactionError::ExpectedBytes;
        if(result_.error != PatchTransactionError::None)
        {
            result_.status = restore_ranges(index) ? PatchTransactionStatus::RolledBack : PatchTransactionStatus::PartialFailure;
            return result_;
        }
        result_.ranges[index].writeAttempted = true;
        const bool written = backend_.patch(plan_[index].address, plan_[index].replacement);
        PatchSnapshot after;
        const bool read = observe(index, after);
        installed_[index] = read ? std::optional<PatchSnapshot>(after) : std::nullopt;
        result_.ranges[index].observed = installed_[index];
        const bool verified = read && after == expected_installation(index);
        const bool flushed = written && verified && backend_.flush(plan_[index].address, plan_[index].replacement.size());
        if(!written || !verified || !flushed)
        {
            result_.error = !written ? PatchTransactionError::Write : !verified ? PatchTransactionError::Verify : PatchTransactionError::Flush;
            result_.status = restore_ranges(index + 1) ? PatchTransactionStatus::RolledBack : PatchTransactionStatus::PartialFailure;
            return result_;
        }
        result_.ranges[index].state = PatchRangeState::Applied;
    }
    result_.failureRange.reset();
    result_.status = PatchTransactionStatus::Committed;
    committed_ = true;
    return result_;
}

const PatchTransactionResult& RuntimePatchTransaction::undo(PatchTargetStamp target)
{
    if(!committed_)
        return result_;
    if(target.pid != target_.pid || target.creationTime != target_.creationTime || target.pointerBits != target_.pointerBits
            || target.pauseEpoch < target_.pauseEpoch || !backend_.current(target))
    {
        result_.error = PatchTransactionError::StaleContext;
        result_.status = PatchTransactionStatus::Conflict;
        result_.resumeAllowed = false;
        return result_;
    }
    activeTarget_ = target;
    result_.error = PatchTransactionError::None;
    result_.failureRange.reset();
    for(std::size_t index = 0; index < plan_.size(); ++index)
    {
        PatchSnapshot current;
        const bool read = observe(index, current);
        result_.ranges[index].observed = read ? std::optional<PatchSnapshot>(current) : std::nullopt;
        if(!read || !installed_[index] || current != *installed_[index])
        {
            result_.failureRange = index;
            result_.error = backend_.current(activeTarget_) ? PatchTransactionError::ExpectedBytes : PatchTransactionError::StaleContext;
            result_.status = PatchTransactionStatus::Conflict;
            result_.ranges[index].state = PatchRangeState::Conflict;
            result_.resumeAllowed = false;
            return result_;
        }
    }
    const bool restored = restore_ranges(plan_.size());
    result_.status = restored ? PatchTransactionStatus::Undone : PatchTransactionStatus::PartialFailure;
    result_.error = restored ? PatchTransactionError::None : PatchTransactionError::Restore;
    committed_ = false;
    return result_;
}
}
