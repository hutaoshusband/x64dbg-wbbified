#include <Windows.h>

#include <atomic>
#include <array>
#include <charconv>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>

#include "_plugins.h"
#include "bridgemain.h"
#include "_scriptapi_module.h"
#include "bridgelist.h"


namespace
{
    int gPluginHandle = 0;
    std::atomic<unsigned int> gNormalBreakpointHits{ 0 };
    std::atomic<unsigned int> gDllBreakpointHits{ 0 };
    std::atomic<unsigned int> gDllMainHits{ 0 };

    void cbPlugin(CBTYPE cbType, void* callbackInfo)
    {
        if(cbType == CB_INITDEBUG)
        {
            gNormalBreakpointHits = 0;
            gDllBreakpointHits = 0;
            gDllMainHits = 0;
            return;
        }

        if(cbType != CB_BREAKPOINT)
            return;

        auto info = static_cast<PLUG_CB_BREAKPOINT*>(callbackInfo);
        if(info == nullptr || info->breakpoint == nullptr)
            return;

        if(info->breakpoint->type == bp_dll)
            gDllBreakpointHits.fetch_add(1);
        else if(info->breakpoint->type == bp_normal)
        {
            gNormalBreakpointHits.fetch_add(1);
            if(strstr(info->breakpoint->name, "DllMain (") == info->breakpoint->name)
                gDllMainHits.fetch_add(1);
        }
    }

    bool cbRandomDllAssert(int, char**)
    {
        const auto callbackCount = (unsigned int)DbgValFromString("$callback_count");
        const auto normalBreakpointHits = gNormalBreakpointHits.load();
        const auto dllBreakpointHits = gDllBreakpointHits.load();
        const auto dllMainHits = gDllMainHits.load();

        if(!_plugin_testassert(normalBreakpointHits >= 2, "expected at least 2 normal breakpoint callbacks, got %u", normalBreakpointHits))
            return false;
        if(!_plugin_testassert(callbackCount == 2, "expected script callback count 2, got %u", callbackCount))
            return false;
        if(!_plugin_testassert(dllBreakpointHits == 2, "expected dynamic DLL breakpoint hits 2, got %u", dllBreakpointHits))
            return false;
        return _plugin_testassert(dllMainHits == 2, "expected DllMain breakpoint hits 2, got %u", dllMainHits);
    }

    struct ModuleEvent { bool loaded; unsigned index; duint base; };
    std::array<ModuleEvent, 4> gModuleEvents{};
    std::array<duint, 2> gActiveModules{};
    std::atomic<unsigned> gModuleEventCount{0};
    std::atomic<bool> gModuleOverflow{false};
    std::atomic<DWORD> gModuleExitCode{0};
    std::atomic<bool> gModuleExitObserved{false};
    std::wstring gDirectory;
    std::array<std::wstring, 2> gPaths;
    bool gPrepared = false;

    class FileHandle
    {
    public:
        explicit FileHandle(const wchar_t* path) : handle(CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)) {}
        ~FileHandle() { if(handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
        FileHandle(const FileHandle&) = delete;
        FileHandle& operator=(const FileHandle&) = delete;
        HANDLE Get() const { return handle; }
    private:
        HANDLE handle;
    };

    bool ReadFileBytes(const std::wstring& path, std::vector<unsigned char>& bytes)
    {
        FileHandle file(path.c_str());
        LARGE_INTEGER length{};
        if(file.Get() == INVALID_HANDLE_VALUE || !GetFileSizeEx(file.Get(), &length) || length.QuadPart < 64 || length.QuadPart > 16 * 1024 * 1024)
            return false;
        bytes.resize(static_cast<size_t>(length.QuadPart));
        DWORD read = 0;
        return ReadFile(file.Get(), bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) && read == bytes.size();
    }

    std::wstring FilePath(const std::wstring& path)
    {
        FileHandle file(path.c_str());
        if(file.Get() == INVALID_HANDLE_VALUE)
            return {};
        std::array<wchar_t, MAX_PATH * 2> normalized{};
        const auto length = GetFinalPathNameByHandleW(file.Get(), normalized.data(), DWORD(normalized.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if(length == 0 || length >= normalized.size())
            return {};
        return std::wstring(normalized.data(), length);
    }

    std::wstring Wide(const char* value)
    {
        const auto length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, nullptr, 0);
        if(length <= 0)
            return {};
        std::wstring result(size_t(length), L'\0');
        if(!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, result.data(), length))
            return {};
        result.pop_back();
        return result;
    }

    struct ImageFacts
    {
        std::vector<unsigned char> bytes;
        IMAGE_NT_HEADERS header{};
        std::vector<IMAGE_SECTION_HEADER> sections;
        DWORD valueRva = 0;
        DWORD processIatRva = 0;

        template<typename Value> bool Read(size_t offset, Value& value) const
        {
            if(offset > bytes.size() || sizeof(value) > bytes.size() - offset)
                return false;
            memcpy(&value, bytes.data() + offset, sizeof(value));
            return true;
        }
        bool Rva(DWORD rva, size_t length, size_t& offset) const
        {
            if(rva < header.OptionalHeader.SizeOfHeaders)
                offset = rva;
            else
            {
                bool found = false;
                for(const auto& section : sections)
                    if(rva >= section.VirtualAddress && rva - section.VirtualAddress <= section.SizeOfRawData && length <= section.SizeOfRawData - (rva - section.VirtualAddress))
                    {
                        offset = size_t(section.PointerToRawData) + rva - section.VirtualAddress;
                        found = true;
                        break;
                    }
                if(!found)
                    return false;
            }
            return offset <= bytes.size() && length <= bytes.size() - offset;
        }
        template<typename Value> bool ReadRva(DWORD rva, Value& value) const
        {
            size_t offset = 0;
            return Rva(rva, sizeof(value), offset) && Read(offset, value);
        }
        bool Name(DWORD rva, std::string& name) const
        {
            size_t offset = 0;
            if(!Rva(rva, 1, offset))
                return false;
            const auto limit = bytes.begin() + (std::min)(bytes.size(), offset + size_t(256));
            const auto end = std::find(bytes.begin() + offset, limit, 0);
            if(end == limit)
                return false;
            name.assign(reinterpret_cast<const char*>(bytes.data() + offset), size_t(end - bytes.begin()) - offset);
            return true;
        }
        bool Initialize(const std::wstring& source)
        {
            IMAGE_DOS_HEADER dos{};
            if(!ReadFileBytes(source, bytes) || !Read(0, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 || !Read(size_t(dos.e_lfanew), header))
                return false;
            if(header.Signature != IMAGE_NT_SIGNATURE || header.FileHeader.Machine != (sizeof(duint) == 8 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386)
                    || header.OptionalHeader.Magic != (sizeof(duint) == 8 ? IMAGE_NT_OPTIONAL_HDR64_MAGIC : IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                    || header.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER) || header.FileHeader.NumberOfSections == 0 || header.FileHeader.NumberOfSections > 96)
                return false;
            sections.resize(header.FileHeader.NumberOfSections);
            for(size_t index = 0; index < sections.size(); ++index)
                if(!Read(size_t(dos.e_lfanew) + sizeof(header) + index * sizeof(IMAGE_SECTION_HEADER), sections[index]))
                    return false;
            IMAGE_EXPORT_DIRECTORY exports{};
            if(!ReadRva(header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, exports) || exports.NumberOfNames > 4096 || exports.NumberOfFunctions > 4096)
                return false;
            for(DWORD index = 0; index < exports.NumberOfNames; ++index)
            {
                DWORD nameRva = 0;
                WORD ordinal = 0;
                std::string name;
                if(!ReadRva(exports.AddressOfNames + index * 4, nameRva) || !Name(nameRva, name) || !ReadRva(exports.AddressOfNameOrdinals + index * 2, ordinal) || ordinal >= exports.NumberOfFunctions)
                    return false;
                if(name == "ModuleValue" && !ReadRva(exports.AddressOfFunctions + DWORD(ordinal) * 4, valueRva))
                    return false;
            }
            const auto importDirectory = header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            for(DWORD index = 0; index < importDirectory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR) && index < 256; ++index)
            {
                IMAGE_IMPORT_DESCRIPTOR imported{};
                if(!ReadRva(importDirectory.VirtualAddress + index * sizeof(imported), imported))
                    return false;
                if(imported.Name == 0)
                    break;
                if(imported.OriginalFirstThunk == 0)
                    return false;
                for(DWORD thunkIndex = 0; thunkIndex < 4096; ++thunkIndex)
                {
                    IMAGE_THUNK_DATA thunk{};
                    if(!ReadRva(imported.OriginalFirstThunk + thunkIndex * sizeof(thunk), thunk))
                        return false;
                    if(thunk.u1.AddressOfData == 0)
                        break;
                    if(!IMAGE_SNAP_BY_ORDINAL(thunk.u1.Ordinal))
                    {
                        std::string name;
                        if(thunk.u1.AddressOfData > MAXDWORD - 2 || !Name(DWORD(thunk.u1.AddressOfData) + 2, name))
                            return false;
                        if(name == "GetCurrentProcessId")
                            processIatRva = imported.FirstThunk + thunkIndex * sizeof(thunk);
                    }
                }
            }
            size_t offset = 0;
            const auto exportDirectory = header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            return valueRva != 0 && Rva(valueRva, 1, offset) && !(valueRva >= exportDirectory.VirtualAddress && valueRva - exportDirectory.VirtualAddress < exportDirectory.Size)
                   && processIatRva != 0 && Rva(processIatRva, sizeof(duint), offset);
        }
    };
    ImageFacts gImage;

    std::string Utf8(const std::wstring& value)
    {
        const auto length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if(length <= 0)
            return {};
        std::string result(size_t(length), '\0');
        if(!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.c_str(), -1, result.data(), length, nullptr, nullptr))
            return {};
        result.pop_back();
        return result;
    }

    template<typename Value> bool ReadTarget(const char* name, Value& value)
    {
        const auto expression = std::string("random_dll:") + name;
        const auto address = DbgValFromString(expression.c_str());
        return _plugin_testassert(address != 0 && DbgMemRead(address, &value, sizeof(value)), "read module fixture field %s", name);
    }
    bool ReadPath(const char* name, std::wstring& value)
    {
        std::array<wchar_t, MAX_PATH> path{};
        if(!ReadTarget(name, path))
            return false;
        const auto end = std::find(path.begin(), path.end(), L'\0');
        if(!_plugin_testassert(end != path.end() && end != path.begin(), "module path is bounded and nonempty"))
            return false;
        value.assign(path.begin(), end);
        return true;
    }

    void RecordEvent(bool loaded, unsigned index, duint base)
    {
        const auto count = gModuleEventCount.load(std::memory_order_relaxed);
        if(count >= gModuleEvents.size())
        {
            gModuleOverflow.store(true, std::memory_order_release);
            return;
        }
        gModuleEvents[count] = {loaded, index, base};
        gModuleEventCount.store(count + 1, std::memory_order_release);
    }
    void cbModuleEvent(CBTYPE type, void* callbackInfo)
    {
        cbPlugin(type, callbackInfo);
        if(type == CB_INITDEBUG)
        {
            gActiveModules = {};
            gModuleEventCount = 0;
            gModuleOverflow = false;
            gModuleExitObserved = false;
            gModuleExitCode = 0;
            gPrepared = false;
        }
        else if(type == CB_LOADDLL)
        {
            const auto info = static_cast<PLUG_CB_LOADDLL*>(callbackInfo);
            if(!info || !info->LoadDll || !info->modname)
                return;
            const unsigned index = _stricmp(info->modname, "first.xxl") == 0 ? 0 : _stricmp(info->modname, "second.xxl") == 0 ? 1 : 2;
            if(index < 2)
            {
                const auto base = reinterpret_cast<duint>(info->LoadDll->lpBaseOfDll);
                gActiveModules[index] = base;
                RecordEvent(true, index, base);
            }
        }
        else if(type == CB_UNLOADDLL)
        {
            const auto info = static_cast<PLUG_CB_UNLOADDLL*>(callbackInfo);
            if(!info || !info->UnloadDll)
                return;
            const auto base = reinterpret_cast<duint>(info->UnloadDll->lpBaseOfDll);
            for(unsigned index = 0; index < 2; ++index)
                if(base != 0 && gActiveModules[index] == base)
                {
                    gActiveModules[index] = 0;
                    RecordEvent(false, index, base);
                    break;
                }
        }
        else if(type == CB_EXITPROCESS)
        {
            const auto info = static_cast<PLUG_CB_EXITPROCESS*>(callbackInfo);
            if(info && info->ExitProcess)
            {
                gModuleExitCode.store(info->ExitProcess->dwExitCode, std::memory_order_relaxed);
                gModuleExitObserved.store(true, std::memory_order_release);
            }
        }
    }

    bool Prepare()
    {
        std::wstring source;
        std::array<std::array<wchar_t, MAX_PATH>, 2> paths{};
        unsigned phase = 0;
        if(!ReadTarget("gModulePhase", phase) || !ReadPath("gModuleSource", source) || !ReadPath("gModuleDirectory", gDirectory) || !ReadTarget("gModulePaths", paths))
            return false;
        if(!_plugin_testassert(phase == 1 && gModuleEventCount.load(std::memory_order_acquire) == 0, "module preparation precedes both DLL loads"))
            return false;
        for(unsigned index = 0; index < 2; ++index)
        {
            const auto end = std::find(paths[index].begin(), paths[index].end(), L'\0');
            if(!_plugin_testassert(end != paths[index].end(), "prepared module path is bounded"))
                return false;
            gPaths[index].assign(paths[index].begin(), end);
            const auto expected = gDirectory + (index == 0 ? L"\\first.xxl" : L"\\second.xxl");
            if(!_plugin_testassert(gPaths[index] == expected, "prepared module path is the declared owned copy"))
                return false;
        }
        Script::Module::ModuleInfo main{};
        if(!_plugin_testassert(Script::Module::GetMainModuleInfo(&main), "native target module identity is available"))
            return false;
        const auto mainPath = Wide(main.path);
        const auto separator = mainPath.find_last_of(L'\\');
        const auto expectedSource = separator == std::wstring::npos ? std::wstring{} : mainPath.substr(0, separator + 1) + L"random.dll";
        if(!_plugin_testassert(!FilePath(source).empty() && FilePath(source) == FilePath(expectedSource), "DLL source belongs to the actual target directory"))
            return false;
        gImage = {};
        if(!_plugin_testassert(gImage.Initialize(source), "source DLL has the expected PE architecture, entry, sections, export and process-ID import"))
            return false;
        for(const auto& path : gPaths)
        {
            std::vector<unsigned char> bytes;
            if(!_plugin_testassert(ReadFileBytes(path, bytes) && bytes == gImage.bytes, "prepared DLL copy is byte-identical to its source"))
                return false;
        }
        gPrepared = true;
        _plugin_logprintf("MODULE_SOURCE path=%s valueRva=%X processIatRva=%X entryRva=%X size=%X\n", Utf8(source).c_str(), gImage.valueRva, gImage.processIatRva, gImage.header.OptionalHeader.AddressOfEntryPoint, gImage.header.OptionalHeader.SizeOfImage);
        _plugin_logprintf("MODULE_DIRECTORY path=%s\n", Utf8(gDirectory).c_str());
        return true;
    }

    bool CheckEvents(unsigned expectedCount, const std::array<duint, 2>& bases)
    {
        const auto count = gModuleEventCount.load(std::memory_order_acquire);
        if(!_plugin_testassert(!gModuleOverflow.load(std::memory_order_acquire) && count == expectedCount, "DLL event count matches the exact expected stage"))
            return false;
        for(unsigned index = 0; index < count; ++index)
        {
            const auto& event = gModuleEvents[index];
            if(!_plugin_testassert(event.loaded == (index % 2 == 0) && event.index == index / 2 && event.base == bases[index / 2] && event.base != 0, "DLL event %u has the expected load/unload, fixture index and actual base", index))
                return false;
        }
        return true;
    }

    bool CheckModule(unsigned index, bool loaded, const std::array<duint, 2>& bases, const std::array<duint, 2>& functions, const std::array<duint, 2>& entries, const std::array<unsigned, 2>& sizes)
    {
        Script::Module::ModuleInfo info{};
        const auto name = index == 0 ? "first.xxl" : "second.xxl";
        BridgeList<Script::Module::ModuleInfo> list;
        if(!_plugin_testassert(Script::Module::GetList(&list), "native module list is available"))
            return false;
        unsigned matches = 0;
        for(int item = 0; item < list.Count(); ++item)
            if(_stricmp(list[item].name, name) == 0)
                ++matches;
        if(!_plugin_testassert(matches == (loaded ? 1u : 0u), "native module list agrees with the completed load or unload"))
            return false;
        if(!loaded)
            return _plugin_testassert(!Script::Module::InfoFromName(name, &info), "unloaded module name no longer resolves");
        std::vector<unsigned char> currentBytes;
        if(!_plugin_testassert(ReadFileBytes(gPaths[index], currentBytes) && currentBytes == gImage.bytes, "loaded DLL copy still equals the frozen source bytes"))
            return false;
        if(!_plugin_testassert(Script::Module::InfoFromName(name, &info) && info.base == bases[index] && info.size == gImage.header.OptionalHeader.SizeOfImage
                              && info.entry == bases[index] + gImage.header.OptionalHeader.AddressOfEntryPoint && info.sectionCount == int(gImage.sections.size())
                              && !FilePath(gPaths[index]).empty() && FilePath(Wide(info.path)) == FilePath(gPaths[index])
                              && sizes[index] == info.size && entries[index] == info.entry && functions[index] == bases[index] + gImage.valueRva,
                              "native module identity agrees with source PE facts, Unicode path and target OS observations"))
            return false;
        BridgeList<Script::Module::ModuleExport> exports;
        if(!_plugin_testassert(Script::Module::GetExports(&info, &exports), "native export list is available"))
            return false;
        matches = 0;
        for(int item = 0; item < exports.Count(); ++item)
            if(strcmp(exports[item].name, "ModuleValue") == 0)
            {
                ++matches;
                if(!_plugin_testassert(!exports[item].forwarded && exports[item].rva == gImage.valueRva && exports[item].va == functions[index], "ModuleValue export agrees with source PE and the executed target function"))
                    return false;
            }
        if(!_plugin_testassert(matches == 1, "exactly one known ModuleValue export is present"))
            return false;
        BridgeList<Script::Module::ModuleImport> imports;
        if(!_plugin_testassert(Script::Module::GetImports(&info, &imports), "native import list is available"))
            return false;
        matches = 0;
        for(int item = 0; item < imports.Count(); ++item)
            if(strcmp(imports[item].name, "GetCurrentProcessId") == 0)
            {
                ++matches;
                if(!_plugin_testassert(imports[item].iatRva == gImage.processIatRva && imports[item].iatVa == bases[index] + gImage.processIatRva, "executed process-ID import agrees with source PE IAT mapping"))
                    return false;
            }
        if(!_plugin_testassert(matches == 1, "exactly one known process-ID import is present"))
            return false;
        BridgeList<Script::Module::ModuleSectionInfo> sections;
        if(!_plugin_testassert(Script::Module::SectionListFromAddr(bases[index], &sections) && sections.Count() == int(gImage.sections.size()), "native section list matches the source PE section count"))
            return false;
        for(int item = 0; item < sections.Count(); ++item)
        {
            const auto& expected = gImage.sections[item];
            char expectedName[9]{};
            memcpy(expectedName, expected.Name, 8);
            if(!_plugin_testassert(sections[item].addr == bases[index] + expected.VirtualAddress && sections[item].size == expected.Misc.VirtualSize && strcmp(sections[item].name, expectedName) == 0, "native section %u agrees with source PE name, address and size", item))
                return false;
        }
        _plugin_logprintf("MODULE_LOADED index=%u base=%p path=%s value=%p\n", index, reinterpret_cast<void*>(bases[index]), info.path, reinterpret_cast<void*>(functions[index]));
        return true;
    }

    bool CheckStage(const char* stage)
    {
        const bool loaded0 = strcmp(stage, "loaded0") == 0;
        const bool reference = strcmp(stage, "reference") == 0;
        const bool unloaded0 = strcmp(stage, "unloaded0") == 0;
        const bool loaded1 = strcmp(stage, "loaded1") == 0;
        const bool unloaded1 = strcmp(stage, "unloaded1") == 0;
        const bool finish = strcmp(stage, "finish") == 0;
        if(!_plugin_testassert(gPrepared && (loaded0 || reference || unloaded0 || loaded1 || unloaded1 || finish), "module check has a prepared, recognized stage"))
            return false;
        const unsigned activeIndex = loaded1 || unloaded1 || finish ? 1 : 0;
        const unsigned expectedCount = loaded0 || reference ? 1 : unloaded0 ? 2 : loaded1 ? 3 : 4;
        const unsigned expectedPhase = loaded0 ? 10 : reference ? 20 : unloaded0 ? 30 : loaded1 ? 11 : unloaded1 ? 31 : 2;
        unsigned phase = 0, loads = 0, unloads = 0, released = 0, alive = 0, result = 0;
        std::array<duint, 2> bases{}, functions{}, entries{};
        std::array<unsigned, 2> sizes{}, values{}, calls{}, arguments{}, attaches{}, processIds{}, present{};
        std::array<LONG, 2> detaches{};
        if(!ReadTarget("gModulePhase", phase) || !ReadTarget("gModuleLoads", loads) || !ReadTarget("gModuleUnloads", unloads)
                || !ReadTarget("gModuleReferenceReleased", released) || !ReadTarget("gModuleReferenceAlive", alive) || !ReadTarget("gModuleResult", result)
                || !ReadTarget("gModuleBases", bases) || !ReadTarget("gModuleFunctions", functions) || !ReadTarget("gModuleEntries", entries) || !ReadTarget("gModuleSizes", sizes)
                || !ReadTarget("gModuleValues", values) || !ReadTarget("gModuleCalls", calls) || !ReadTarget("gModuleArguments", arguments) || !ReadTarget("gModuleAttachCounts", attaches)
                || !ReadTarget("gModuleProcessIds", processIds) || !ReadTarget("gModulePresent", present) || !ReadTarget("gModuleDetaches", detaches))
            return false;
        if(!_plugin_testassert(phase == expectedPhase && loads == activeIndex + 1 && unloads == expectedCount / 2 && result == (activeIndex == 0 ? 20u : 43u)
                              && released == (loaded0 ? 0u : 1u) && alive == released, "target load, reference, unload and result counters match the executed stage") || !CheckEvents(expectedCount, bases))
            return false;
        for(unsigned index = 0; index <= activeIndex; ++index)
        {
            const bool loaded = index == activeIndex && (loaded0 || reference || loaded1);
            if(!_plugin_testassert(values[index] == 20 + index * 3 && calls[index] == 1 && arguments[index] == index + 1 && attaches[index] == 1
                                  && processIds[index] == DbgGetProcessId() && detaches[index] == (loaded ? 0 : 1) && present[index] == 0,
                                  "module %u has the known executed return, call, argument, attach/detach and target PID", index)
                    || !CheckModule(index, loaded, bases, functions, entries, sizes))
                return false;
        }
        _plugin_logprintf("MODULE_STAGE stage=%s events=%u phase=%u result=%u\n", stage, expectedCount, phase, result);
        if(finish)
            for(unsigned index = 0; index < expectedCount; ++index)
                _plugin_logprintf("MODULE_EVENT sequence=%u loaded=%u index=%u base=%p\n", index, gModuleEvents[index].loaded ? 1u : 0u, gModuleEvents[index].index, reinterpret_cast<void*>(gModuleEvents[index].base));
        return true;
    }
    bool cbModuleCheck(int argc, char** argv)
    {
        if(!_plugin_testassert(argc == 2, "modulecheck requires one declared stage"))
            return false;
        return strcmp(argv[1], "ready") == 0 ? Prepare() : CheckStage(argv[1]);
    }
    bool cbModuleExit(int argc, char** argv)
    {
        unsigned expected = 0;
        if(!_plugin_testassert(argc == 2, "moduleexit requires the expected decimal exit"))
            return false;
        const auto end = argv[1] + strlen(argv[1]);
        const auto parsed = std::from_chars(argv[1], end, expected);
        if(!_plugin_testassert(parsed.ec == std::errc{} && parsed.ptr == end && gModuleExitObserved.load(std::memory_order_acquire), "actual target exit was captured"))
            return false;
        if(!_plugin_testassert(gModuleExitCode.load(std::memory_order_relaxed) == expected, "actual module target exit matches the known canary"))
            return false;
        SetLastError(ERROR_SUCCESS);
        const auto attributes = GetFileAttributesW(gDirectory.c_str());
        const auto error = GetLastError();
        if(!_plugin_testassert(gPrepared && attributes == INVALID_FILE_ATTRIBUTES && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND), "actual target removed its owned DLL copies and directory"))
            return false;
        _plugin_logprintf("MODULE_EXIT actual=%u expected=%u cleanup=1\n", gModuleExitCode.load(std::memory_order_relaxed), expected);
        return true;
    }
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = 1;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, sizeof(initStruct->pluginName), X64DBG_TEST_NAME, _TRUNCATE);
    gPluginHandle = initStruct->pluginHandle;
    _plugin_registercallback(gPluginHandle, CB_INITDEBUG, cbModuleEvent);
    _plugin_registercallback(gPluginHandle, CB_BREAKPOINT, cbModuleEvent);
    _plugin_registercommand(gPluginHandle, "randomdllassert", cbRandomDllAssert, true);
    _plugin_registercallback(gPluginHandle, CB_LOADDLL, cbModuleEvent);
    _plugin_registercallback(gPluginHandle, CB_UNLOADDLL, cbModuleEvent);
    _plugin_registercallback(gPluginHandle, CB_EXITPROCESS, cbModuleEvent);
    _plugin_registercommand(gPluginHandle, "modulecheck", cbModuleCheck, true);
    _plugin_registercommand(gPluginHandle, "moduleexit", cbModuleExit, false);
    return true;
}

extern "C" __declspec(dllexport) bool plugstop()
{
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT*)
{
}
