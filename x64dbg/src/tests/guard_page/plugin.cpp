#include <Windows.h>

#include <atomic>
#include <cstring>

#include "_plugins.h"


namespace
{
    int gPluginHandle = 0;
    std::atomic<unsigned int> gGuardPageFirstChanceCount{ 0 };
    std::atomic<unsigned int> gGuardPageSecondChanceCount{ 0 };
    std::atomic<duint> gFirstExceptionAddress{ 0 };
    std::atomic<duint> gSecondExceptionAddress{ 0 };
    std::atomic<unsigned long> gExitCode{ 0xFFFFFFFFu };

    void cbPlugin(CBTYPE cbType, void* callbackInfo)
    {
        if(cbType == CB_EXCEPTION)
        {
            auto info = static_cast<PLUG_CB_EXCEPTION*>(callbackInfo);
            if(info && info->Exception && info->Exception->ExceptionRecord.ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
            {
                if(info->Exception->dwFirstChance)
                {
                    gGuardPageFirstChanceCount.fetch_add(1);
                    gFirstExceptionAddress = reinterpret_cast<duint>(info->Exception->ExceptionRecord.ExceptionAddress);
                }
                else
                {
                    gGuardPageSecondChanceCount.fetch_add(1);
                    gSecondExceptionAddress = reinterpret_cast<duint>(info->Exception->ExceptionRecord.ExceptionAddress);
                }
            }
        }
        else if(cbType == CB_EXITPROCESS)
        {
            auto info = static_cast<PLUG_CB_EXITPROCESS*>(callbackInfo);
            if(info && info->ExitProcess)
                gExitCode = info->ExitProcess->dwExitCode;
        }
        else if(cbType == CB_INITDEBUG)
        {
            gGuardPageFirstChanceCount = 0;
            gGuardPageSecondChanceCount = 0;
            gFirstExceptionAddress = 0;
            gSecondExceptionAddress = 0;
            gExitCode = 0xFFFFFFFFu;
        }
    }

    bool cbGuardPageAssert(int, char**)
    {
        const auto first = gGuardPageFirstChanceCount.load();
        const auto second = gGuardPageSecondChanceCount.load();
        const auto exitCode = gExitCode.load();
        if(!_plugin_testassert(first == 1, "expected exactly 1 first-chance guard page exception, got %u", first))
            return false;
        if(!_plugin_testassert(second == 1, "expected exactly 1 second-chance guard page exception, got %u", second))
            return false;
        return _plugin_testassert(exitCode == 0, "expected actual exit code zero after continuing the guard fault, got %08lx", exitCode);
    }

    bool cbGuardPageStopAssert(int argc, char** argv)
    {
        if(!_plugin_testassert(argc == 2, "guardpagestopassert requires first or second"))
            return false;
        const bool first = strcmp(argv[1], "first") == 0;
        if(!_plugin_testassert(first || strcmp(argv[1], "second") == 0, "unknown guard-page stop phase"))
            return false;
        duint page = 0;
        if(!_plugin_testassert(DbgMemRead(DbgValFromString("guard_page:GuardedPage"), &page, sizeof(page)) && page,
                              "guarded page pointer must be readable"))
            return false;
        const auto exceptionAddress = first ? gFirstExceptionAddress.load() : gSecondExceptionAddress.load();
        if(!_plugin_testassert(exceptionAddress == page, "guard exception must originate at the allocated code page"))
            return false;
        if(!_plugin_testassert(gGuardPageFirstChanceCount.load() == 1 && gGuardPageSecondChanceCount.load() == (first ? 0u : 1u),
                              "guard exception counts must match the current phase"))
            return false;
        unsigned char bytes[4] = {};
        const unsigned char expected[4] = { 0x6a, 0x01, 0x58, 0xc3 };
        return _plugin_testassert(DbgMemRead(page, bytes, sizeof(bytes)) && memcmp(bytes, expected, sizeof(bytes)) == 0,
                                  "guarded code bytes must retain push 1, pop accumulator, ret");
    }
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = 1;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, sizeof(initStruct->pluginName), X64DBG_TEST_NAME, _TRUNCATE);
    gPluginHandle = initStruct->pluginHandle;
    _plugin_registercallback(gPluginHandle, CB_INITDEBUG, cbPlugin);
    _plugin_registercallback(gPluginHandle, CB_EXCEPTION, cbPlugin);
    _plugin_registercallback(gPluginHandle, CB_EXITPROCESS, cbPlugin);
    _plugin_registercommand(gPluginHandle, "guardpageassert", cbGuardPageAssert, false);
    _plugin_registercommand(gPluginHandle, "guardpagestopassert", cbGuardPageStopAssert, true);
    return true;
}

extern "C" __declspec(dllexport) void plugstop()
{
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT*)
{
}
