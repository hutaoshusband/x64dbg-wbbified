bool PeReadWhole(HANDLE file, std::string& source)
{
    LARGE_INTEGER size{}, start{};
    if(file == INVALID_HANDLE_VALUE || !GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 512ll * 1024 * 1024
            || !SetFilePointerEx(file, start, nullptr, FILE_BEGIN)) return false;
    source.clear();
    std::array<char, 65536> block{};
    while(source.size() < static_cast<std::uint64_t>(size.QuadPart))
    {
        DWORD read = 0;
        if(!ReadFile(file, block.data(), static_cast<DWORD>(block.size()), &read, nullptr) || !read
                || read > static_cast<std::uint64_t>(size.QuadPart) - source.size()) return false;
        source.append(block.data(), read);
    }
    DWORD trailing = 0;
    return ReadFile(file, block.data(), 1, &trailing, nullptr) && !trailing;
}

bool PePublishPrivate(const std::wstring& directory, unsigned kind, const std::string& bytes)
{
    using namespace wininspect::mcp;
    auto staged = PreparedNewFile::stage(directory, bytes);
    auto* prepared = std::get_if<std::unique_ptr<PreparedNewFile>>(&staged);
    if(!_plugin_testassert(prepared && *prepared, "strict PE publication stages and verifies a sealed sibling file")) return false;
    const auto temporary = (*prepared)->temporaryPath();
    const auto name = L"strict-" + std::to_wstring(kind) + L".exe";
    const auto destination = directory + L"\\" + name;
    const ScopedFile write(temporary.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING);
    const DWORD writeError = GetLastError();
    const BOOL deleted = DeleteFileW(temporary.c_str());
    const DWORD deleteError = GetLastError();
    if(!_plugin_testassert(GetFileAttributesW(destination.c_str()) == INVALID_FILE_ATTRIBUTES && write.value == INVALID_HANDLE_VALUE
                          && writeError == ERROR_SHARING_VIOLATION && !deleted && deleteError == ERROR_SHARING_VIOLATION,
                          "sealed temporary file denies independent write and deletion before publication")) return false;
    const auto published = (*prepared)->publish(name);
    const auto* result = std::get_if<PublishedFile>(&published);
    if(!_plugin_testassert(result && result->size == bytes.size() && result->volumeSerial && result->fileIndex,
                          "strict PE publication uses the non-replacing same-volume rename")) return false;
    const PublishedFile identity = *result;
    const auto repeat = (*prepared)->publish(name);
    const auto* rejected = std::get_if<ContractError>(&repeat);
    if(!_plugin_testassert(rejected && rejected->code == "invalid_argument", "a committed prepared file cannot publish twice")) return false;
    prepared->reset();
    const ScopedFile read(destination.c_str(), GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING);
    std::string observed;
    BY_HANDLE_FILE_INFORMATION information{};
    if(!_plugin_testassert(GetFileAttributesW(temporary.c_str()) == INVALID_FILE_ATTRIBUTES && PeReadWhole(read.value, observed) && observed == bytes
                          && GetFileInformationByHandle(read.value, &information) && information.dwVolumeSerialNumber == identity.volumeSerial
                          && ((static_cast<std::uint64_t>(information.nFileIndexHigh) << 32) | information.nFileIndexLow) == identity.fileIndex,
                          "published path retains the exact staged file object and complete verified bytes")) return false;
    _plugin_logprintf("PE_PUBLISH kind=%u volume=%lu fileId=%llu size=%llu source=sealed rename=nonreplace writeDenied=%lu deleteDenied=%lu tempAbsent=1\n",
                      kind, static_cast<unsigned long>(identity.volumeSerial), static_cast<unsigned long long>(identity.fileIndex),
                      static_cast<unsigned long long>(identity.size), writeError, deleteError);
    return true;
}

bool PeCollisionPrivate(const std::wstring& directory, const std::string& bytes)
{
    using namespace wininspect::mcp;
    for(const unsigned kind : {4u, 8u})
    {
        const auto name = L"file-" + std::to_wstring(kind) + L".exe";
        const ScopedFile guard((directory + L"\\" + name).c_str(), GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING);
        BY_HANDLE_FILE_INFORMATION before{}, after{};
        std::string original, observed;
        if(!_plugin_testassert(GetFileInformationByHandle(guard.value, &before) && PeReadWhole(guard.value, original)
                              && original == std::string("WBB_FILE_GUARD\0\x5a", 16), "publication retains the native destination guard")) return false;
        auto staged = PreparedNewFile::stage(directory, bytes);
        auto* prepared = std::get_if<std::unique_ptr<PreparedNewFile>>(&staged);
        if(!_plugin_testassert(prepared && *prepared, "collision reference seals its complete temporary file")) return false;
        const auto temporary = (*prepared)->temporaryPath();
        const auto published = (*prepared)->publish(name);
        const auto* error = std::get_if<ContractError>(&published);
        if(!_plugin_testassert(error && (error->code == "file_exists" || error->code == "native_failure"),
                              "publication refuses an existing held destination")) return false;
        const auto discarded = (*prepared)->discard();
        if(!_plugin_testassert(std::holds_alternative<bool>(discarded) && std::get<bool>(discarded), "collision reference explicitly removes its owned temporary file")) return false;
        prepared->reset();
        if(!_plugin_testassert(GetFileAttributesW(temporary.c_str()) == INVALID_FILE_ATTRIBUTES && GetFileInformationByHandle(guard.value, &after)
                              && PeReadWhole(guard.value, observed) && observed == original && before.dwVolumeSerialNumber == after.dwVolumeSerialNumber
                              && before.nFileIndexHigh == after.nFileIndexHigh && before.nFileIndexLow == after.nFileIndexLow
                              && before.dwFileAttributes == after.dwFileAttributes && CompareFileTime(&before.ftLastWriteTime, &after.ftLastWriteTime) == 0,
                              "refused publication preserves complete destination content, identity and attributes")) return false;
        _plugin_logprintf("PE_COLLISION kind=%u code=%s volume=%lu fileId=%llu attributes=%lu unchanged=1 tempAbsent=1\n", kind, error->code.c_str(),
                          before.dwVolumeSerialNumber, (static_cast<unsigned long long>(before.nFileIndexHigh) << 32) | before.nFileIndexLow,
                          before.dwFileAttributes);
    }
    return true;
}

bool cbStrictFiles(int argc, char** argv)
{
    using namespace wininspect::mcp;
    if(!_plugin_testassert(argc == 2 && CheckPhase(2, {7, 0, 0}) && CheckBytes(true, true) && CheckTracking(true),
                          "strict PE fixture starts at the source-bound paused patched call")) return false;
    const auto epoch = gPauseEpoch.load(std::memory_order_acquire);
    const DWORD pid = DbgGetProcessId(), thread = DbgGetThreadId();
    const ScopedProcess process(pid);
    std::array<wchar_t, 32768> image{};
    DWORD characters = static_cast<DWORD>(image.size());
    if(!_plugin_testassert(process.value && QueryFullProcessImageNameW(process.value, 0, image.data(), &characters),
                          "strict PE fixture opens the actual selected OS process image")) return false;
    const ScopedFile file(image.data(), GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING);
    BY_HANDLE_FILE_INFORMATION identity{};
    std::string source;
    if(!_plugin_testassert(file.value != INVALID_HANDLE_VALUE && GetFileInformationByHandle(file.value, &identity) && PeReadWhole(file.value, source),
                          "strict PE fixture holds and reads the complete actual source file")) return false;
    const duint base = DbgModBaseFromName("patch_canary"), address = FieldAddress("PatchRelocation");
    duint pointer = 0;
    if(!_plugin_testassert(base && DbgMemRead(address, &pointer, sizeof(pointer)) && pointer == FieldAddress("PatchValue"),
                          "strict PE fixture selects the actual relocated pointer")) return false;
    PatchBytes pointerBytes(sizeof(pointer));
    std::memcpy(pointerBytes.data(), &pointer, sizeof(pointer));
    const PePatchRequest pointerRequest{PePatchAddress::LoadedVa, address, PePatchEncoding::LoadedBytes, pointerBytes, pointerBytes};
    const PePatchRequest codeRequest{PePatchAddress::LoadedVa, FieldAddress("PatchValue"), PePatchEncoding::FileBytes,
                                    PatchBytes(Original.begin(), Original.end()), PatchBytes(Patched.begin(), Patched.end())};
    const auto directory = DecodePath(argv[1]);
    if(!_plugin_testassert(!directory.empty() && GetFileAttributesW(directory.c_str()) != INVALID_FILE_ATTRIBUTES,
                          "strict PE fixture uses the previously created private directory")) return false;
    for(unsigned kind = 0; kind < 3; ++kind)
    {
        std::vector<PePatchRequest> requests{pointerRequest};
        if(kind == 1) requests.push_back(codeRequest);
        if(kind == 2) requests.push_back({PePatchAddress::FileOffset, 0x1c, PePatchEncoding::FileBytes, {0}, {0x5b}});
        const auto planned = plan_pe_file_patch(source, base, requests);
        const auto* plan = std::get_if<PeFilePatchPlan>(&planned);
        if(!_plugin_testassert(plan && plan->pointerBits == sizeof(duint) * 8 && plan->preferredBase != base && !plan->hasCertificate
                              && plan->ranges.size() == requests.size() && plan->ranges[0].normalizedRelocations == 1,
                              "strict PE fixture admits the actual rebase and complete pointer field")) return false;
        const auto rendered = render_pe_file_patch(source, *plan);
        const auto* bytes = std::get_if<std::string>(&rendered);
        if(!_plugin_testassert(bytes && (kind || *bytes == source), "normalized unmodified loaded pointer reproduces the complete original file")) return false;
        const auto outputHash = sha256_file_bytes(*bytes);
        const auto* hash = std::get_if<std::string>(&outputHash);
        if(!_plugin_testassert(hash && PePublishPrivate(directory, kind, *bytes),
                              "strict PE fixture publishes a verified new file and independently reads every byte back")) return false;
        _plugin_logprintf("PE_FILE kind=%u sourceSha=%s outputSha=%s preferred=%llx actual=%llx width=%u pointerOffset=%llu normalized=%u ranges=%u size=%llu\n",
                          kind, plan->sourceSha256.c_str(), hash->c_str(), static_cast<unsigned long long>(plan->preferredBase),
                          static_cast<unsigned long long>(base), plan->pointerBits, static_cast<unsigned long long>(plan->ranges[0].fileOffset),
                          static_cast<unsigned>(plan->ranges[0].normalizedRelocations), static_cast<unsigned>(plan->ranges.size()),
                          static_cast<unsigned long long>(bytes->size()));
    }
    if(!PeCollisionPrivate(directory, source)) return false;
    auto reject = [&](const char* name, const char* code, const Checked<PeFilePatchPlan>& result)
    {
        const auto* error = std::get_if<ContractError>(&result);
        if(!_plugin_testassert(error && error->code == code, "strict PE fixture rejects %s before any destination effects", name)) return false;
        _plugin_logprintf("PE_REJECT name=%s code=%s\n", name, error->code.c_str());
        return true;
    };
    auto conflict = codeRequest;
    conflict.expected[0] ^= 1;
    auto partial = pointerRequest;
    ++partial.address;
    partial.expected.erase(partial.expected.begin());
    partial.replacement.erase(partial.replacement.begin());
    auto underflow = codeRequest;
    underflow.address = base - 1;
    if(!reject("virtual_tail", "unsupported_mapping", plan_pe_file_patch(source, base, {{PePatchAddress::LoadedVa, FieldAddress("PatchVirtualTail"), PePatchEncoding::LoadedBytes, {0}, {0x5b}}}))
            || !reject("partial_relocation", "unsupported_mapping", plan_pe_file_patch(source, base, {partial}))
            || !reject("expected_conflict", "expected_bytes_mismatch", plan_pe_file_patch(source, base, {conflict}))
            || !reject("address_underflow", "unsupported_mapping", plan_pe_file_patch(source, base, {underflow}))
            || !reject("range_overlap", "invalid_argument", plan_pe_file_patch(source, base, {pointerRequest, pointerRequest}))) return false;
    const auto admitted = plan_pe_file_patch(source, base, {pointerRequest});
    auto changed = source;
    changed.back() ^= 1;
    const auto rendered = render_pe_file_patch(changed, std::get<PeFilePatchPlan>(admitted));
    const auto* error = std::get_if<ContractError>(&rendered);
    if(!_plugin_testassert(error && error->code == "file_hash_mismatch", "strict PE fixture detects a change outside every selected span")) return false;
    _plugin_logprintf("PE_REJECT name=outside_source_change code=%s\n", error->code.c_str());
    std::string after;
    BY_HANDLE_FILE_INFORMATION finalIdentity{};
    if(!_plugin_testassert(PeReadWhole(file.value, after) && after == source && GetFileInformationByHandle(file.value, &finalIdentity)
                          && finalIdentity.dwVolumeSerialNumber == identity.dwVolumeSerialNumber && finalIdentity.nFileIndexHigh == identity.nFileIndexHigh
                          && finalIdentity.nFileIndexLow == identity.nFileIndexLow && finalIdentity.nFileSizeHigh == identity.nFileSizeHigh
                          && finalIdentity.nFileSizeLow == identity.nFileSizeLow && CompareFileTime(&finalIdentity.ftLastWriteTime, &identity.ftLastWriteTime) == 0
                          && DbgGetProcessId() == pid && DbgGetThreadId() == thread && gPauseEpoch.load(std::memory_order_acquire) == epoch,
                          "strict PE fixture preserves the held source identity and selected paused process epoch")) return false;
    _plugin_logprintf("PE_SOURCE pid=%lu thread=%lu epoch=%llu volume=%lu fileId=%llu unchanged=1\n", pid, thread,
                      static_cast<unsigned long long>(epoch), identity.dwVolumeSerialNumber,
                      (static_cast<unsigned long long>(identity.nFileIndexHigh) << 32) | identity.nFileIndexLow);
    return CheckPhase(2, {7, 0, 0}) && CheckBytes(true, true) && CheckTracking(true);
}
