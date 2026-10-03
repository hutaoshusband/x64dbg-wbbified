using wininspect::mcp::PatchBackend;
using wininspect::mcp::PatchByteRecord;
using wininspect::mcp::PatchBytes;
using wininspect::mcp::PatchSnapshot;
using wininspect::mcp::PatchTargetStamp;
using wininspect::mcp::PatchTransactionError;
using wininspect::mcp::PatchTransactionResult;
using wininspect::mcp::PatchTransactionStatus;
using wininspect::mcp::RuntimePatchRange;
using wininspect::mcp::RuntimePatchTransaction;

enum class TransactionFault { None, Permission, Unavailable, Conflict };

struct NativePatchBackend : PatchBackend
{
    ScopedProcess process;
    PatchTargetStamp target{};
    TransactionFault fault = TransactionFault::None;
    duint allocation = 0;
    unsigned patchCalls = 0, restoreCalls = 0, flushCalls = 0;
    DWORD nativeError = 0;
    SIZE_T nativeWritten = 0;
    explicit NativePatchBackend(duint ownedAllocation = 0) : process(DbgGetProcessId(), PROCESS_VM_OPERATION | PROCESS_VM_WRITE | SYNCHRONIZE), allocation(ownedAllocation)
    {
        FILETIME creation{}, exit{}, kernel{}, user{};
        if(process.value && GetProcessTimes(process.value, &creation, &exit, &kernel, &user))
            target = {DbgGetProcessId(), (std::uint64_t(creation.dwHighDateTime) << 32) | creation.dwLowDateTime,
                      gPauseEpoch.load(std::memory_order_acquire), unsigned(sizeof(duint) * 8)};
    }
    bool current(const PatchTargetStamp& stamp) override
    {
        FILETIME creation{}, exit{}, kernel{}, user{};
        return process.value && DbgIsDebugging() && !DbgIsRunning() && stamp.pid == DbgGetProcessId()
               && stamp.pauseEpoch == gPauseEpoch.load(std::memory_order_acquire) && stamp.pointerBits == sizeof(duint) * 8
               && GetProcessId(process.value) == stamp.pid && GetProcessTimes(process.value, &creation, &exit, &kernel, &user)
               && stamp.creationTime == ((std::uint64_t(creation.dwHighDateTime) << 32) | creation.dwLowDateTime)
               && WaitForSingleObject(process.value, 0) == WAIT_TIMEOUT;
    }
    bool mapping(std::uint64_t address, std::size_t size) override
    {
        if(!current(target) || !size || address > std::numeric_limits<duint>::max() || size - 1 > std::numeric_limits<duint>::max() - address) return false;
        const auto end = address + size - 1;
        for(auto cursor = address; cursor <= end;)
        {
            MEMORY_BASIC_INFORMATION region{};
            if(VirtualQueryEx(process.value, reinterpret_cast<void*>(duint(cursor)), &region, sizeof(region)) != sizeof(region)
                    || region.State != MEM_COMMIT || !region.RegionSize || (region.Protect & (PAGE_NOACCESS | PAGE_GUARD))) return false;
            const auto base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
            if(base > cursor || region.RegionSize - 1 > std::numeric_limits<duint>::max() - base) return false;
            const auto last = base + region.RegionSize - 1;
            if(last >= end) return true;
            cursor = last + 1;
        }
        return false;
    }
    bool capture(std::uint64_t address, std::size_t size, PatchSnapshot& snapshot) override
    {
        if(!current(target)) return false;
        snapshot.bytes.resize(size);
        snapshot.records.resize(size);
        char module[MAX_MODULE_SIZE]{}, last[MAX_MODULE_SIZE]{};
        DbgFunctions()->ModNameFromAddr(duint(address), module, true);
        DbgFunctions()->ModNameFromAddr(duint(address + size - 1), last, true);
        if(strcmp(module, last) != 0 || !DbgMemRead(duint(address), snapshot.bytes.data(), size)) return false;
        snapshot.module = module;
        for(std::size_t index = 0; index < size; ++index)
        {
            DBGPATCHINFO record{};
            const bool present = DbgFunctions()->PatchGetEx(duint(address + index), &record);
            if(present && (record.addr != address + index || strcmp(record.mod, module) != 0)) return false;
            snapshot.records[index] = present ? std::optional<PatchByteRecord>({record.oldbyte, record.newbyte}) : std::nullopt;
        }
        return true;
    }
    bool patch(std::uint64_t address, const PatchBytes& bytes) override
    {
        ++patchCalls;
        if(!current(target)) return false;
        if(patchCalls == 2 && fault != TransactionFault::None)
        {
            if(fault == TransactionFault::Unavailable && !VirtualFreeEx(process.value, reinterpret_cast<void*>(allocation), 0x1000, MEM_DECOMMIT)) return false;
            const unsigned char changed = 0x5f;
            if(fault == TransactionFault::Conflict && !DbgMemWrite(allocation + 0x80, &changed, 1)) return false;
            const ScopedProcess restricted(target.pid);
            SetLastError(ERROR_SUCCESS);
            const bool success = restricted.value && WriteProcessMemory(restricted.value, reinterpret_cast<void*>(duint(address)), bytes.data(), bytes.size(), &nativeWritten);
            nativeError = GetLastError();
            _plugin_logprintf("PATCH_TX_NATIVE fault=%u pid=%lu address=%llx requested=%llu written=%llu success=%u error=%lu paused=%u\n", unsigned(fault), target.pid,
                              static_cast<unsigned long long>(address), static_cast<unsigned long long>(bytes.size()), static_cast<unsigned long long>(nativeWritten),
                              unsigned(success), nativeError, unsigned(!DbgIsRunning()));
            return success;
        }
        return DbgFunctions()->MemPatch(duint(address), bytes.data(), duint(bytes.size()));
    }
    bool restore(std::uint64_t address, const PatchSnapshot& original) override
    {
        ++restoreCalls;
        for(std::size_t index = 0; index < original.bytes.size(); ++index)
        {
            PatchSnapshot currentByte;
            if(!capture(address + index, 1, currentByte) || currentByte.module != original.module) return false;
            const auto& prior = original.records[index];
            const auto& now = currentByte.records[0];
            const auto byte = original.bytes[index];
            if(now == prior)
            {
                if(currentByte.bytes[0] != byte && !DbgMemWrite(duint(address + index), &byte, 1)) return false;
            }
            else if(prior)
            {
                if(!now || now->original != prior->original || !DbgFunctions()->MemPatch(duint(address + index), &byte, 1)) return false;
            }
            else if(!now || now->original != byte || !DbgFunctions()->PatchRestore(duint(address + index))) return false;
        }
        return true;
    }
    bool flush(std::uint64_t address, std::size_t size) override
    {
        ++flushCalls;
        return current(target) && FlushInstructionCache(process.value, reinterpret_cast<void*>(duint(address)), size);
    }
};

std::unique_ptr<NativePatchBackend> gTransactionBackend;
std::unique_ptr<RuntimePatchTransaction> gRuntimeTransaction;
bool gTransactionsEnabled = false;

std::string TransactionHex(const PatchBytes& bytes)
{
    std::string result;
    const char digits[] = "0123456789abcdef";
    for(const auto byte : bytes) { result.push_back(digits[byte >> 4]); result.push_back(digits[byte & 15]); }
    return result;
}

void PrintTransaction(const char* name, const char* operation, NativePatchBackend& backend, const PatchTransactionResult& result)
{
    _plugin_logprintf("PATCH_TX_RESULT name=%s operation=%s status=%u error=%u failure=%lld resume=%u ranges=%llu patches=%u restores=%u flushes=%u pid=%lu creation=%llu epoch=%llu paused=%u\n",
                      name, operation, unsigned(result.status), unsigned(result.error), result.failureRange ? static_cast<long long>(*result.failureRange) : -1,
                      unsigned(result.resumeAllowed), static_cast<unsigned long long>(result.ranges.size()), backend.patchCalls, backend.restoreCalls, backend.flushCalls,
                      backend.target.pid, static_cast<unsigned long long>(backend.target.creationTime), static_cast<unsigned long long>(backend.target.pauseEpoch), unsigned(!DbgIsRunning()));
    for(unsigned index = 0; index < result.ranges.size(); ++index)
    {
        const auto& range = result.ranges[index];
        std::string records;
        if(range.observed)
            for(const auto& record : range.observed->records)
                records += record ? TransactionHex({record->original, record->installed}) : "----";
        _plugin_logprintf("PATCH_TX_RANGE name=%s operation=%s index=%u address=%llx size=%llu state=%u attempted=%u restored=%u observed=%s records=%s\n", name, operation, index,
                          static_cast<unsigned long long>(range.address), static_cast<unsigned long long>(range.size), unsigned(range.state), unsigned(range.writeAttempted), unsigned(range.restorationVerified),
                          range.observed ? TransactionHex(range.observed->bytes).c_str() : "unknown", range.observed ? records.c_str() : "unknown");
    }
}

bool ObserveTransactionPrivate(const char* name, NativePatchBackend& backend, duint address, const PatchBytes& expected, unsigned trackedMask, const PatchBytes& installed, unsigned otherTracked = 0)
{
    PatchBytes raw(expected.size()), logical(expected.size());
    SIZE_T read = 0;
    MEMORY_BASIC_INFORMATION region{};
    size_t count = 0;
    if(!_plugin_testassert(backend.current(backend.target) && ReadProcessMemory(backend.process.value, reinterpret_cast<void*>(address), raw.data(), raw.size(), &read)
                          && read == raw.size() && raw == expected && DbgMemRead(address, logical.data(), logical.size()) && logical == expected
                          && VirtualQueryEx(backend.process.value, reinterpret_cast<void*>(address), &region, sizeof(region)) == sizeof(region)
                          && region.State == MEM_COMMIT && region.Type == MEM_PRIVATE && region.Protect == PAGE_EXECUTE_READ && DbgFunctions()->PatchEnum(nullptr, &count),
                          "transaction private outcome has actual logical/native bytes and unchanged RX protection")) return false;
    unsigned total = 0;
    std::string records;
    for(unsigned index = 0; index < expected.size(); ++index)
    {
        DBGPATCHINFO record{};
        const bool tracked = DbgFunctions()->PatchGetEx(address + index, &record);
        total += unsigned(tracked);
        if(!_plugin_testassert(tracked == bool(trackedMask & (1u << index)) && (!tracked || (record.oldbyte == 0x5a && record.newbyte == installed[index] && record.addr == address + index)),
                              "transaction retains only declared native original/installed records")) return false;
        records += tracked ? TransactionHex({record.oldbyte, record.newbyte}) : "----";
    }
    _plugin_logprintf("PATCH_TX_BYTES name=%s address=%llx logical=%s raw=%s records=%s total=%llu state=%lx protection=%lx paused=%u\n", name,
                      static_cast<unsigned long long>(address), TransactionHex(logical).c_str(), TransactionHex(raw).c_str(), records.c_str(),
                      static_cast<unsigned long long>(count / sizeof(DBGPATCHINFO)), region.State, region.Protect, unsigned(!DbgIsRunning()));
    if(!_plugin_testassert(count == (total + otherTracked) * sizeof(DBGPATCHINFO), "transaction has no unexpected native patch records")) return false;
    const auto otherAddress = backend.allocation + 0x100;
    const PatchBytes otherExpected = otherTracked ? PatchBytes{0x5d, 0x5e} : PatchBytes{0x5a, 0x5a};
    raw.resize(2); logical.resize(2); read = 0;
    if(!_plugin_testassert(ReadProcessMemory(backend.process.value, reinterpret_cast<void*>(otherAddress), raw.data(), raw.size(), &read)
                          && read == raw.size() && raw == otherExpected && DbgMemRead(otherAddress, logical.data(), logical.size()) && logical == otherExpected,
                          "second transaction range has independent unchanged or installed native bytes")) return false;
    records.clear();
    for(unsigned index = 0; index < 2; ++index)
    {
        DBGPATCHINFO record{};
        const bool tracked = DbgFunctions()->PatchGetEx(otherAddress + index, &record);
        if(!_plugin_testassert(tracked == bool(otherTracked) && (!tracked || (record.oldbyte == 0x5a && record.newbyte == otherExpected[index] && record.addr == otherAddress + index)),
                              "second range keeps exact native tracking independently of transaction result")) return false;
        records += tracked ? TransactionHex({record.oldbyte, record.newbyte}) : "----";
    }
    _plugin_logprintf("PATCH_TX_OTHER name=%s address=%llx logical=%s raw=%s records=%s paused=%u\n", name, static_cast<unsigned long long>(otherAddress),
                      TransactionHex(logical).c_str(), TransactionHex(raw).c_str(), records.c_str(), unsigned(!DbgIsRunning()));
    return true;
}

bool cbTransactionChecks(int, char**)
{
    if(!CheckPhase(1, {0, 0, 0}) || !CheckTracking(false)) return false;
    uintptr_t allocation = 0;
    if(!ReadTarget("gPatchWriteFailureRegion", allocation)) return false;
    const auto privatePlan = [&]() { return std::vector<RuntimePatchRange>{{allocation + 0x80, {0x5a, 0x5a}, {0x5b, 0x5c}}, {allocation + 0x100, {0x5a, 0x5a}, {0x5d, 0x5e}}}; };
    for(unsigned scenario = 0; scenario < 4; ++scenario)
    {
        NativePatchBackend backend(allocation);
        auto plan = privatePlan();
        auto stamp = backend.target;
        const char* name = scenario == 0 ? "preflight" : scenario == 1 ? "overlap" : scenario == 2 ? "overflow" : "stale";
        if(scenario == 0) plan[1].expected[0] = 0x59;
        else if(scenario == 1) plan[1].address = plan[0].address + 1;
        else if(scenario == 2) plan[1].address = std::numeric_limits<std::uint64_t>::max();
        else ++stamp.creationTime;
        RuntimePatchTransaction transaction(stamp, plan, backend);
        const auto& result = transaction.apply();
        PrintTransaction(name, "apply", backend, result);
        if(!_plugin_testassert(result.status == PatchTransactionStatus::Rejected && result.resumeAllowed && !backend.patchCalls && !backend.restoreCalls,
                              "all-range invalid/conflicting/stale admission has no native write effect")) return false;
        if(!ObserveTransactionPrivate(name, backend, allocation + 0x80, {0x5a, 0x5a}, 0, {})) return false;
    }
    for(const auto fault : {TransactionFault::Permission, TransactionFault::Conflict, TransactionFault::Unavailable})
    {
        NativePatchBackend backend(allocation);
        backend.fault = fault;
        RuntimePatchTransaction transaction(backend.target, privatePlan(), backend);
        const auto& result = transaction.apply();
        const char* name = fault == TransactionFault::Permission ? "rollback" : fault == TransactionFault::Conflict ? "rollback_conflict" : "partial";
        PrintTransaction(name, "apply", backend, result);
        if(!_plugin_testassert(backend.patchCalls == 2 && backend.nativeError == DWORD(fault == TransactionFault::Unavailable ? ERROR_NOACCESS : ERROR_ACCESS_DENIED) && backend.nativeWritten == 0
                              && result.status == (fault == TransactionFault::Permission ? PatchTransactionStatus::RolledBack : PatchTransactionStatus::PartialFailure)
                              && result.resumeAllowed == (fault == TransactionFault::Permission), "real native write denial has verified rollback or explicit blocked partial effects")) return false;
        if(fault == TransactionFault::Unavailable)
        {
            MEMORY_BASIC_INFORMATION region{};
            unsigned char byte = 0;
            SIZE_T read = 0;
            SetLastError(ERROR_SUCCESS);
            const bool readable = ReadProcessMemory(backend.process.value, reinterpret_cast<void*>(allocation + 0x80), &byte, 1, &read) != FALSE;
            const DWORD error = GetLastError();
            DBGPATCHINFO record{};
            if(!_plugin_testassert(!readable && read == 0 && error == ERROR_PARTIAL_COPY
                                  && VirtualQueryEx(backend.process.value, reinterpret_cast<void*>(allocation), &region, sizeof(region)) == sizeof(region)
                                  && region.State == MEM_RESERVE && DbgFunctions()->PatchGetEx(allocation + 0x80, &record) && record.oldbyte == 0x5a && record.newbyte == 0x5b,
                                  "failed rollback retains real inaccessible effects and their native provenance while paused")) return false;
            _plugin_logprintf("PATCH_TX_PARTIAL allocation=%llx address=%llx state=%lx read=%u count=%llu error=%lu old=%02x new=%02x paused=%u\n",
                              static_cast<unsigned long long>(allocation), static_cast<unsigned long long>(allocation + 0x80), region.State, unsigned(readable),
                              static_cast<unsigned long long>(read), error, record.oldbyte, record.newbyte, unsigned(!DbgIsRunning()));
            std::array<unsigned char, 0x1000> repaired{};
            repaired.fill(0x5a); repaired[0x80] = 0x5b; repaired[0x81] = 0x5c;
            SIZE_T written = 0;
            DWORD previous = 0;
            if(!_plugin_testassert(VirtualAllocEx(backend.process.value, reinterpret_cast<void*>(allocation), repaired.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE) == reinterpret_cast<void*>(allocation)
                                  && WriteProcessMemory(backend.process.value, reinterpret_cast<void*>(allocation), repaired.data(), repaired.size(), &written) && written == repaired.size()
                                  && VirtualProtectEx(backend.process.value, reinterpret_cast<void*>(allocation), repaired.size(), PAGE_EXECUTE_READ, &previous),
                                  "explicit fixture recovery restores accessibility with installed bytes intact")) return false;
        }
        else if(!ObserveTransactionPrivate(name, backend, allocation + 0x80, fault == TransactionFault::Conflict ? PatchBytes{0x5f, 0x5c} : PatchBytes{0x5a, 0x5a},
                                          fault == TransactionFault::Conflict ? 3 : 0, {0x5b, 0x5c})) return false;
        if(fault != TransactionFault::Permission && !_plugin_testassert(DbgFunctions()->PatchRestore(allocation + 0x80) && DbgFunctions()->PatchRestore(allocation + 0x81),
                                                                      "explicit fixture recovery is separate from transaction automatic rollback")) return false;
        if(!ObserveTransactionPrivate("recovered", backend, allocation + 0x80, {0x5a, 0x5a}, 0, {})) return false;
    }
    for(unsigned amended = 0; amended < 2; ++amended)
    {
        NativePatchBackend backend(allocation);
        auto plan = privatePlan();
        if(amended)
        {
            const PatchBytes earlier{0x59, 0x58};
            if(!_plugin_testassert(DbgFunctions()->MemPatch(allocation + 0x80, earlier.data(), duint(earlier.size())), "amendment begins with actual earlier native patches")) return false;
            plan[0].expected = earlier;
        }
        RuntimePatchTransaction transaction(backend.target, plan, backend);
        const char* name = amended ? "amendment" : "undo_conflict";
        const auto& applied = transaction.apply();
        PrintTransaction(name, "apply", backend, applied);
        if(!_plugin_testassert(applied.status == PatchTransactionStatus::Committed, "native private transaction commits both independently verified ranges")) return false;
        if(!ObserveTransactionPrivate(name, backend, allocation + 0x80, {0x5b, 0x5c}, 3, {0x5b, 0x5c}, 2)) return false;
        if(!amended)
        {
            const unsigned char changed = 0x5f;
            if(!_plugin_testassert(DbgMemWrite(allocation + 0x80, &changed, 1), "undo conflict creates a real later untracked native change")) return false;
            const auto& conflict = transaction.undo(backend.target);
            PrintTransaction(name, "conflict", backend, conflict);
            if(!_plugin_testassert(conflict.status == PatchTransactionStatus::Conflict && !conflict.resumeAllowed && backend.restoreCalls == 0,
                                  "undo checks every installed range before restoring any byte")) return false;
            if(!ObserveTransactionPrivate(name, backend, allocation + 0x80, {0x5f, 0x5c}, 3, {0x5b, 0x5c}, 2)) return false;
            const unsigned char installed = 0x5b;
            if(!_plugin_testassert(DbgMemWrite(allocation + 0x80, &installed, 1), "explicit conflict resolution reinstates the independently known installed byte")) return false;
        }
        const auto& undone = transaction.undo(backend.target);
        PrintTransaction(name, "undo", backend, undone);
        if(!_plugin_testassert(undone.status == PatchTransactionStatus::Undone && undone.resumeAllowed, "transaction compare-undo restores its exact prior byte/tracking snapshot")) return false;
        if(!ObserveTransactionPrivate(name, backend, allocation + 0x80, amended ? PatchBytes{0x59, 0x58} : PatchBytes{0x5a, 0x5a}, amended ? 3 : 0, {0x59, 0x58})) return false;
        if(amended && !_plugin_testassert(DbgFunctions()->PatchRestore(allocation + 0x80) && DbgFunctions()->PatchRestore(allocation + 0x81), "earlier native patches keep their oldest originals after transaction undo")) return false;
    }
    NativePatchBackend completed(allocation);
    if(!ObserveTransactionPrivate("done", completed, allocation + 0x80, {0x5a, 0x5a}, 0, {})) return false;
    std::array<unsigned char, 0x1000> page{};
    SIZE_T read = 0;
    MEMORY_BASIC_INFORMATION reserved{};
    if(!_plugin_testassert(ReadProcessMemory(completed.process.value, reinterpret_cast<void*>(allocation), page.data(), page.size(), &read) && read == page.size()
                          && std::all_of(page.begin(), page.end(), [](unsigned char byte) { return byte == 0x5a; })
                          && VirtualQueryEx(completed.process.value, reinterpret_cast<void*>(allocation + page.size()), &reserved, sizeof(reserved)) == sizeof(reserved)
                          && reserved.State == MEM_RESERVE, "complete transaction page and original reserved tail are restored before code execution")) return false;
    _plugin_logprintf("PATCH_TX_PAGE allocation=%llx read=%llu content=5a reserved=%lx paused=%u\n", static_cast<unsigned long long>(allocation),
                      static_cast<unsigned long long>(read), reserved.State, unsigned(!DbgIsRunning()));
    gTransactionsEnabled = true;
    _plugin_logprintf("PATCH_TX_DONE allocation=%llx scenarios=9 paused=%u epoch=%llu\n", static_cast<unsigned long long>(allocation), unsigned(!DbgIsRunning()),
                      static_cast<unsigned long long>(gPauseEpoch.load(std::memory_order_acquire)));
    return true;
}

bool ApplyCodeTransaction(duint address)
{
    gRuntimeTransaction.reset();
    gTransactionBackend = std::make_unique<NativePatchBackend>();
    const std::vector<RuntimePatchRange> plan{{address, {0xb8, 7, 0, 0}, {0x66, 0xb8, 0x2a, 0}}, {address + 4, {0, 0xc3}, {0x90, 0xc3}}};
    gRuntimeTransaction = std::make_unique<RuntimePatchTransaction>(gTransactionBackend->target, plan, *gTransactionBackend);
    const auto& result = gRuntimeTransaction->apply();
    PrintTransaction("code", "apply", *gTransactionBackend, result);
    return _plugin_testassert(result.status == PatchTransactionStatus::Committed && result.resumeAllowed, "shared transaction installs both actual code ranges and native tracking");
}

bool UndoCodeTransaction()
{
    if(!gRuntimeTransaction || !gTransactionBackend) return false;
    gTransactionBackend->target.pauseEpoch = gPauseEpoch.load(std::memory_order_acquire);
    const auto& result = gRuntimeTransaction->undo(gTransactionBackend->target);
    PrintTransaction("code", "undo", *gTransactionBackend, result);
    return _plugin_testassert(result.status == PatchTransactionStatus::Undone && result.resumeAllowed, "shared transaction restores actual executed code with compare-undo");
}

void ResetTransactions()
{
    gRuntimeTransaction.reset();
    gTransactionBackend.reset();
    gTransactionsEnabled = false;
}
