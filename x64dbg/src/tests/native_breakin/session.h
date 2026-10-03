#pragma once

namespace BreakInSessions
{
    inline constexpr unsigned MaxReplacementRounds = 16;

    int RunReplacement(const wchar_t* mode, const wchar_t* kind, unsigned rounds);
    int RunInFlight(const wchar_t* mode, const wchar_t* phase, const wchar_t* action);
}
