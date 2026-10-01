#include <windows.h>
#include <psapi.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

using TestFunction = void (*)(const char* message);

static void generateRandomString(wchar_t* buffer, int length)
{
    const wchar_t charset[] = L"abcdefghijklmnopqrstuvwxyz0123456789";
    const int charsetSize = (int)(_countof(charset) - 1);
    for(int i = 0; i < length; i++)
        buffer[i] = charset[rand() % charsetSize];
    buffer[length] = L'\0';
}

static bool copyDllWithRandomName(const wchar_t* sourceDll, wchar_t* finalPath, size_t finalPathCount)
{
    wchar_t tempPath[MAX_PATH] = L"";
    wchar_t randomName[16] = L"";
    if(GetTempPathW(_countof(tempPath), tempPath) == 0)
        return false;

    generateRandomString(randomName, 8);
    if(swprintf_s(finalPath, finalPathCount, L"%s%s.xxl", tempPath, randomName) < 0)
        return false;

    return CopyFileW(sourceDll, finalPath, FALSE) != FALSE;
}

int RunOriginalRandomDll()
{
    srand(1337);

    wchar_t sourceDll[MAX_PATH] = L"";
    GetModuleFileNameW(nullptr, sourceDll, _countof(sourceDll));
    if(auto slashIdx = wcsrchr(sourceDll, L'\\'))
        slashIdx[1] = L'\0';
    wcscat_s(sourceDll, L"random.dll");

    if(GetFileAttributesW(sourceDll) == INVALID_FILE_ATTRIBUTES)
        return 1;

    wchar_t dllPath1[MAX_PATH] = L"";
    wchar_t dllPath2[MAX_PATH] = L"";

    if(!copyDllWithRandomName(sourceDll, dllPath1, _countof(dllPath1)))
        return 1;
    auto hDll1 = LoadLibraryExW(dllPath1, nullptr, 0);
    if(hDll1 == nullptr)
    {
        DeleteFileW(dllPath1);
        return 1;
    }
    if(auto testFunc = (TestFunction)GetProcAddress(hDll1, "TestFunction"))
        testFunc("Hello from first random DLL!");
    else
        return 1;
    FreeLibrary(hDll1);
    DeleteFileW(dllPath1);

    if(!copyDllWithRandomName(sourceDll, dllPath2, _countof(dllPath2)))
        return 1;
    auto hDll2 = LoadLibraryExW(dllPath2, nullptr, 0);
    if(hDll2 == nullptr)
    {
        DeleteFileW(dllPath2);
        return 1;
    }
    if(auto testFunc = (TestFunction)GetProcAddress(hDll2, "TestFunction"))
        testFunc("Hello from second random DLL!");
    else
        return 1;
    FreeLibrary(hDll2);
    DeleteFileW(dllPath2);

    __debugbreak();
    return 0;
}

using ModuleValueFunction = unsigned (*)(unsigned);
using ModuleDetachFunction = void (*)(volatile LONG*);

extern "C" __declspec(dllexport) volatile unsigned gModuleMode = 0;
extern "C" __declspec(dllexport) volatile unsigned gModulePhase = 0;
extern "C" __declspec(dllexport) volatile unsigned gModuleLoads = 0;
extern "C" __declspec(dllexport) volatile unsigned gModuleUnloads = 0;
extern "C" __declspec(dllexport) volatile unsigned gModuleReferenceReleased = 0;
extern "C" __declspec(dllexport) volatile unsigned gModuleReferenceAlive = 0;
extern "C" __declspec(dllexport) volatile unsigned gModuleCleanup = 0;
extern "C" __declspec(dllexport) volatile unsigned gModuleResult = 0;
extern "C" __declspec(dllexport) volatile LONG gModuleDetaches[2] = {};
extern "C" __declspec(dllexport) volatile ULONG_PTR gModuleBases[2] = {};
extern "C" __declspec(dllexport) volatile ULONG_PTR gModuleFunctions[2] = {};
extern "C" __declspec(dllexport) volatile ULONG_PTR gModuleEntries[2] = {};
extern "C" __declspec(dllexport) volatile unsigned gModuleSizes[2] = {};
extern "C" __declspec(dllexport) volatile unsigned gModuleValues[2] = {};
extern "C" __declspec(dllexport) volatile unsigned gModuleCalls[2] = {};
extern "C" __declspec(dllexport) volatile unsigned gModuleArguments[2] = {};
extern "C" __declspec(dllexport) volatile unsigned gModuleAttachCounts[2] = {};
extern "C" __declspec(dllexport) volatile unsigned gModuleProcessIds[2] = {};
extern "C" __declspec(dllexport) volatile unsigned gModulePresent[2] = {};
extern "C" __declspec(dllexport) wchar_t gModuleDirectory[MAX_PATH] = {};
extern "C" __declspec(dllexport) wchar_t gModuleSource[MAX_PATH] = {};
extern "C" __declspec(dllexport) wchar_t gModulePaths[2][MAX_PATH] = {};
extern "C" __declspec(dllexport) wchar_t gModuleActualPaths[2][MAX_PATH] = {};

extern "C" __declspec(dllexport) __declspec(noinline) void ModuleReady()
{
    gModulePhase = 1;
}

extern "C" __declspec(dllexport) __declspec(noinline) void ModuleLoaded(unsigned index)
{
    gModulePhase = 10 + index;
}

extern "C" __declspec(dllexport) __declspec(noinline) void ModuleReferenceReleased()
{
    gModulePhase = 20;
}

extern "C" __declspec(dllexport) __declspec(noinline) void ModuleUnloaded(unsigned index)
{
    gModulePhase = 30 + index;
}

extern "C" __declspec(dllexport) __declspec(noinline) void ModuleFinish()
{
    gModulePhase = 2;
}

class ModuleHandle
{
public:
    explicit ModuleHandle(HMODULE value) : handle(value) {}
    ~ModuleHandle()
    {
        if(handle)
            FreeLibrary(handle);
    }
    ModuleHandle(const ModuleHandle&) = delete;
    ModuleHandle& operator=(const ModuleHandle&) = delete;
    HMODULE Get() const { return handle; }
    bool Release()
    {
        if(!handle || !FreeLibrary(handle))
            return false;
        handle = nullptr;
        return true;
    }
private:
    HMODULE handle;
};

class ModuleDirectory
{
public:
    bool Initialize(bool normal)
    {
        const auto length = GetModuleFileNameW(nullptr, gModuleSource, MAX_PATH);
        if(length == 0 || length >= MAX_PATH)
            return false;
        auto separator = wcsrchr(gModuleSource, L'\\');
        if(!separator || size_t(separator - gModuleSource) + 12 >= MAX_PATH)
            return false;
        wcscpy_s(separator + 1, MAX_PATH - size_t(separator + 1 - gModuleSource), L"random.dll");
        if(normal)
        {
            const auto length = GetEnvironmentVariableW(L"WININSPECT_TEST_MODULE_DIRECTORY", gModuleDirectory, MAX_PATH);
            if(length == 0 || length >= MAX_PATH)
                return false;
        }
        else
        {
            wchar_t temporary[MAX_PATH] = {};
            wchar_t unique[MAX_PATH] = {};
            const auto length = GetTempPathW(MAX_PATH, temporary);
            if(length == 0 || length >= MAX_PATH || !GetTempFileNameW(temporary, L"xmd", 0, unique))
                return false;
            if(!DeleteFileW(unique))
                return false;
            if(wcslen(unique) + 8 >= MAX_PATH || swprintf_s(gModuleDirectory, MAX_PATH, L"%s-\x6a21\x5757-\x03b1", unique) < 0)
                return false;
            if(!CreateDirectoryW(gModuleDirectory, nullptr))
                return false;
            owned = true;
        }
        if(wcslen(gModuleDirectory) + 12 >= MAX_PATH)
            return false;
        for(unsigned index = 0; index < 2; ++index)
        {
            if(swprintf_s(gModulePaths[index], MAX_PATH, L"%s\\%s", gModuleDirectory, index == 0 ? L"first.xxl" : L"second.xxl") < 0)
                return false;
            if(owned && !CopyFileW(gModuleSource, gModulePaths[index], TRUE))
                return false;
            if(GetFileAttributesW(gModulePaths[index]) == INVALID_FILE_ATTRIBUTES)
                return false;
        }
        return true;
    }
    bool Cleanup()
    {
        if(!owned)
        {
            gModuleCleanup = 2;
            return true;
        }
        bool removed = true;
        for(const auto& path : gModulePaths)
            if(path[0] && GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES && !DeleteFileW(path))
                removed = false;
        if(!RemoveDirectoryW(gModuleDirectory))
            removed = false;
        if(removed)
        {
            owned = false;
            gModuleCleanup = 1;
        }
        return removed;
    }
    ~ModuleDirectory()
    {
        if(owned)
            Cleanup();
    }
private:
    bool owned = false;
};

bool RunModule(unsigned index)
{
    ModuleHandle module(LoadLibraryExW(gModulePaths[index], nullptr, 0));
    if(!module.Get())
        return false;
    ++gModuleLoads;
    gModuleBases[index] = reinterpret_cast<ULONG_PTR>(module.Get());
    const auto value = reinterpret_cast<ModuleValueFunction>(GetProcAddress(module.Get(), "ModuleValue"));
    const auto observe = reinterpret_cast<ModuleDetachFunction>(GetProcAddress(module.Get(), "ModuleObserveDetach"));
    const auto calls = reinterpret_cast<const volatile unsigned*>(GetProcAddress(module.Get(), "gModuleCallCount"));
    const auto argument = reinterpret_cast<const volatile unsigned*>(GetProcAddress(module.Get(), "gModuleLastArgument"));
    const auto attached = reinterpret_cast<const volatile unsigned*>(GetProcAddress(module.Get(), "gModuleAttachCount"));
    const auto processId = reinterpret_cast<const volatile unsigned*>(GetProcAddress(module.Get(), "gModuleCallerProcessId"));
    if(!value || !observe || !calls || !argument || !attached || !processId)
        return false;
    gModuleFunctions[index] = reinterpret_cast<ULONG_PTR>(value);
    MODULEINFO info{};
    if(!GetModuleInformation(GetCurrentProcess(), module.Get(), &info, sizeof(info)))
        return false;
    gModuleSizes[index] = info.SizeOfImage;
    gModuleEntries[index] = reinterpret_cast<ULONG_PTR>(info.EntryPoint);
    const auto length = GetModuleFileNameW(module.Get(), gModuleActualPaths[index], MAX_PATH);
    if(length == 0 || length >= MAX_PATH || wcscmp(gModulePaths[index], gModuleActualPaths[index]) != 0)
        return false;
    observe(&gModuleDetaches[index]);
    gModuleValues[index] = value(index + 1);
    gModuleCalls[index] = *calls;
    gModuleArguments[index] = *argument;
    gModuleAttachCounts[index] = *attached;
    gModuleProcessIds[index] = *processId;
    gModuleResult += gModuleValues[index];
    ModuleLoaded(index);
    if(index == 0)
    {
        ModuleHandle reference(LoadLibraryExW(gModulePaths[index], nullptr, 0));
        if(reference.Get() != module.Get() || !reference.Release())
            return false;
        gModuleReferenceReleased = 1;
        gModuleReferenceAlive = GetModuleHandleW(gModulePaths[index]) == module.Get() && gModuleDetaches[index] == 0 ? 1 : 0;
        ModuleReferenceReleased();
    }
    if(!module.Release())
        return false;
    ++gModuleUnloads;
    gModulePresent[index] = GetModuleHandleW(gModulePaths[index]) ? 1 : 0;
    ModuleUnloaded(index);
    return gModuleValues[index] == 20 + index * 3 && gModuleCalls[index] == 1 && gModuleArguments[index] == index + 1
           && gModuleAttachCounts[index] == 1 && gModuleProcessIds[index] == GetCurrentProcessId() && gModuleDetaches[index] == 1
           && gModulePresent[index] == 0;
}

void PrintModulePath(const char* name, const wchar_t* path)
{
    char utf8[MAX_PATH * 4] = {};
    if(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, -1, utf8, sizeof(utf8), nullptr, nullptr) > 0)
        printf("%s=%s\n", name, utf8);
}

int wmain()
{
    wchar_t normalMode[2] = {};
    const bool normal = GetEnvironmentVariableW(L"WININSPECT_TEST_NORMAL", normalMode, 2) == 1 && normalMode[0] == L'1';
    if(normal)
        gModuleMode = 1;
    if(gModuleMode == 0)
        return RunOriginalRandomDll();
    if(gModuleMode != 1)
        return 104;
    ModuleDirectory directory;
    if(!directory.Initialize(normal))
        return 105;
    ModuleReady();
    if(!RunModule(0) || !RunModule(1))
        return 106;
    ModuleFinish();
    if(!directory.Cleanup())
        return 107;
    gModulePhase = 3;
    const bool valid = gModuleLoads == 2 && gModuleUnloads == 2 && gModuleReferenceReleased == 1 && gModuleReferenceAlive == 1 && gModuleResult == 43;
    if(normal)
    {
        printf("phase=%u\nloads=%u\nunloads=%u\nreferenceReleased=%u\nreferenceAlive=%u\ncleanup=%u\nresult=%u\nprocessId=%lu\n",
               gModulePhase, gModuleLoads, gModuleUnloads, gModuleReferenceReleased, gModuleReferenceAlive, gModuleCleanup, gModuleResult, GetCurrentProcessId());
        PrintModulePath("source", gModuleSource);
        PrintModulePath("directory", gModuleDirectory);
        for(unsigned index = 0; index < 2; ++index)
        {
            printf("module%u.base=%llx\nmodule%u.function=%llx\nmodule%u.entry=%llx\nmodule%u.size=%u\nmodule%u.value=%u\nmodule%u.calls=%u\nmodule%u.argument=%u\nmodule%u.attach=%u\nmodule%u.detach=%ld\nmodule%u.processId=%u\nmodule%u.present=%u\n",
                   index, static_cast<unsigned long long>(gModuleBases[index]), index, static_cast<unsigned long long>(gModuleFunctions[index]),
                   index, static_cast<unsigned long long>(gModuleEntries[index]), index, gModuleSizes[index], index, gModuleValues[index], index, gModuleCalls[index],
                   index, gModuleArguments[index], index, gModuleAttachCounts[index], index, gModuleDetaches[index], index, gModuleProcessIds[index], index, gModulePresent[index]);
            char field[32] = {};
            sprintf_s(field, "module%u.path", index);
            PrintModulePath(field, gModuleActualPaths[index]);
        }
    }
    return valid ? 43 : 108;
}
