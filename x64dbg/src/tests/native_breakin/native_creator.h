#pragma once
#include <windows.h>

namespace FixtureNativeCreation
{
    struct Observation
    {
        LONG nativeStatus = 0;
        DWORD processId = 0;
        DWORD threadId = 0;
        unsigned long long creation = 0;
        void* start = nullptr;
        bool nativeCreated = false;
        bool handleClosed = false;
        unsigned calls = 0;
    };

    void Configure(bool partial);
    Observation Capture();
}
