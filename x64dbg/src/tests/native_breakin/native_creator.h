#pragma once
#include <windows.h>

namespace FixtureNativeCreation
{
    enum class Mode
    {
        Normal,
        ControlledFailure,
        ReducedAccess
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
    bool VerifyThread(HANDLE thread, const char* phase);
    Observation Capture();
}
