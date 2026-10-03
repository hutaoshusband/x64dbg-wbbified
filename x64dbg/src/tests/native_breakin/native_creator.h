#pragma once
#include <windows.h>

namespace FixtureNativeCreation
{
    enum class Mode
    {
        Normal,
        ControlledFailure,
        ReducedAccess,
        HeldBeforeCreation,
        HeldAfterCreation
    };

    struct Observation
    {
        LONG nativeStatus = 0;
        DWORD processId = 0;
        DWORD threadId = 0;
        unsigned long long creation = 0;
        void* start = nullptr;
        bool nativeCreated = false;
        bool handleClosed = false;
        bool nativeHandleValid = false;
        bool threadObserved = false;
        DWORD nativeHandleError = 0;
        DWORD suspendBefore = MAXDWORD;
        DWORD suspendRestored = MAXDWORD;
        unsigned beforeThreads = 0;
        unsigned afterThreads = 0;
        unsigned calls = 0;
    };

    void Configure(Mode mode);
    void ConfigureGate(HANDLE reached, HANDLE release);
    bool VerifyThread(HANDLE thread, const char* phase);
    Observation Capture();
}

namespace FixtureNativeCleanup
{
    struct Observation
    {
        DWORD processId = 0;
        unsigned long long creation = 0;
        void* address = nullptr;
        DWORD originalAccess = 0, actualAccess = 0;
        DWORD error = 0;
        BOOL result = FALSE;
        unsigned calls = 0;
        bool verified = false;
    };

    bool ConfigureDeniedTarget(HANDLE process, HANDLE completed);
    bool ConfigureGateTarget(HANDLE process, HANDLE reached, HANDLE release, HANDLE completed, bool after);
    HANDLE DuplicateCallbackThread();
    void Reset();
    Observation Capture();
}
