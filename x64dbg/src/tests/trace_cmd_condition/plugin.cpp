#include <windows.h>
#include <array>
#include <atomic>
#include <algorithm>
#include <string>
#include <vector>
#include "_plugins.h"
#include "bridgemain.h"

namespace
{
    int gPluginHandle = 0;
    struct TraceEvent { duint ip; DWORD pid, thread; bool stop; };
    std::array<TraceEvent, 256> gEvents{};
    std::atomic<unsigned> gCount{0};
    std::atomic<bool> gOverflow{false}, gArmed{false}, gExited{false};
    std::atomic<DWORD> gPid{0}, gThread{0}, gExit{0};
    struct ScopedProcess
    {
        HANDLE value;
        explicit ScopedProcess(DWORD pid) : value(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)) {}
        ScopedProcess(const ScopedProcess&) = delete;
        ScopedProcess& operator=(const ScopedProcess&) = delete;
        ~ScopedProcess()
        {
            if(value)
                CloseHandle(value);
        }
    };
    duint gStack = 0;
    std::vector<duint> gExpected;
    REGDUMP gInitial{};
    void cbTraceEvent(CBTYPE type, void* callbackInfo)
    {
        if(type == CB_INITDEBUG)
        {
            gCount = 0; gOverflow = false; gArmed = false; gExited = false;
            gPid = 0; gThread = 0; gExit = 0; gStack = 0;
        }
        else if(type == CB_DEBUGEVENT)
        {
            const auto info = static_cast<PLUG_CB_DEBUGEVENT*>(callbackInfo);
            if(info && info->DebugEvent)
            {
                gPid.store(info->DebugEvent->dwProcessId, std::memory_order_relaxed);
                gThread.store(info->DebugEvent->dwThreadId, std::memory_order_release);
            }
        }
        else if(type == CB_TRACEEXECUTE && gArmed.load(std::memory_order_acquire))
        {
            const auto info = static_cast<PLUG_CB_TRACEEXECUTE*>(callbackInfo);
            const auto count = gCount.load(std::memory_order_relaxed);
            if(!info || count >= gEvents.size())
            {
                gOverflow.store(true, std::memory_order_release);
                return;
            }
            gEvents[count] = {info->cip, gPid.load(std::memory_order_relaxed), gThread.load(std::memory_order_acquire), info->stop};
            gCount.store(count + 1, std::memory_order_release);
        }
        else if(type == CB_EXITPROCESS)
        {
            const auto info = static_cast<PLUG_CB_EXITPROCESS*>(callbackInfo);
            if(info && info->ExitProcess)
            {
                gExit.store(info->ExitProcess->dwExitCode, std::memory_order_relaxed);
                gExited.store(true, std::memory_order_release);
            }
        }
    }
    template<typename Value> bool ReadTarget(const char* name, Value& value)
    {
        const auto expression = std::string("trace_cmd_condition:") + name;
        const auto address = DbgValFromString(expression.c_str());
        return _plugin_testassert(address != 0 && DbgMemRead(address, &value, sizeof(value)), "read trace fixture field %s", name);
    }
    duint FieldAddress(const char* name)
    {
        return DbgValFromString((std::string("trace_cmd_condition:") + name).c_str());
    }
    bool InstructionRange(duint start, duint limit, std::vector<duint>& addresses)
    {
        for(unsigned count = 0; start < limit && count < 32; ++count)
        {
            BASIC_INSTRUCTION_INFO instruction{};
            DbgDisasmFastAt(start, &instruction);
            if(instruction.size <= 0 || instruction.size > 15 || duint(instruction.size) > limit - start)
                return _plugin_testassert(false, "trace instruction range has invalid native boundaries");
            addresses.push_back(start);
            start += instruction.size;
        }
        return _plugin_testassert(start == limit, "trace instruction range reaches its exact boundary");
    }
    struct ExpectedNode
    {
        duint start, limit, branchTrue, branchFalse;
        bool terminal, split;
        std::vector<duint> exits;
    };
    bool CheckGraph(const char* name, const std::array<ExpectedNode, 3>& expected)
    {
        const auto entry = FieldAddress(name);
        BridgeCFGraphList list{};
        if(!_plugin_testassert(entry != 0 && DbgAnalyzeFunction(entry, &list), "native graph analysis completes for %s", name))
            return false;
        BridgeCFGraph graph(&list, true);
        if(!_plugin_testassert(graph.entryPoint == entry && graph.nodes.size() == expected.size(), "native graph has its exact entry and three source blocks for %s", name))
            return false;
        _plugin_logprintf("TRACE_GRAPH name=%s entry=%llx nodes=%llu\n", name, static_cast<unsigned long long>(graph.entryPoint), static_cast<unsigned long long>(graph.nodes.size()));
        for(const auto& wanted : expected)
        {
            std::vector<duint> addresses;
            if(!InstructionRange(wanted.start, wanted.limit, addresses) || addresses.empty())
                return false;
            const auto found = graph.nodes.find(wanted.start);
            if(!_plugin_testassert(found != graph.nodes.end(), "native graph contains its exact source block for %s", name))
                return false;
            const auto& node = found->second;
            if(!_plugin_testassert(node.parentGraph == entry && node.end == addresses.back() && node.brtrue == wanted.branchTrue && node.brfalse == wanted.branchFalse
                                   && node.icount == addresses.size() && node.terminal == wanted.terminal && node.split == wanted.split && !node.indirectcall
                                   && node.exits == wanted.exits && node.instrs.size() == addresses.size(), "native graph block, edges, loop and terminal facts agree for %s", name))
                return false;
            _plugin_logprintf("TRACE_NODE name=%s start=%llx end=%llx true=%llx false=%llx count=%llu terminal=%u split=%u indirect=%u\n", name,
                              static_cast<unsigned long long>(node.start), static_cast<unsigned long long>(node.end), static_cast<unsigned long long>(node.brtrue),
                              static_cast<unsigned long long>(node.brfalse), static_cast<unsigned long long>(node.icount), node.terminal ? 1 : 0, node.split ? 1 : 0, node.indirectcall ? 1 : 0);
            for(unsigned index = 0; index < node.exits.size(); ++index)
                _plugin_logprintf("TRACE_EDGE name=%s node=%llx index=%u destination=%llx\n", name, static_cast<unsigned long long>(node.start), index, static_cast<unsigned long long>(node.exits[index]));
            for(unsigned index = 0; index < addresses.size(); ++index)
            {
                BASIC_INSTRUCTION_INFO decoded{};
                DbgDisasmFastAt(addresses[index], &decoded);
                const auto& instruction = node.instrs[index];
                std::array<unsigned char, 15> actual{};
                if(!_plugin_testassert(instruction.addr == addresses[index] && decoded.size > 0 && decoded.size <= int(actual.size())
                                       && DbgMemRead(instruction.addr, actual.data(), decoded.size) && memcmp(actual.data(), instruction.data, decoded.size) == 0,
                                       "native graph instruction address and exact decoded bytes agree for %s", name))
                    return false;
                std::string bytes;
                const char digits[] = "0123456789abcdef";
                for(int byte = 0; byte < decoded.size; ++byte)
                {
                    bytes.push_back(digits[instruction.data[byte] >> 4]);
                    bytes.push_back(digits[instruction.data[byte] & 15]);
                }
                _plugin_logprintf("TRACE_GRAPH_INSTRUCTION name=%s node=%llx ip=%llx bytes=%s\n", name, static_cast<unsigned long long>(node.start),
                                  static_cast<unsigned long long>(instruction.addr), bytes.c_str());
            }
        }
        return true;
    }
    bool PrepareReference(bool over)
    {
        const auto run = FieldAddress("TraceRun"), body = FieldAddress("TraceBody"), loop = FieldAddress("TraceLoop"), after = FieldAddress("TraceAfterCall");
        const auto tail = FieldAddress("TraceAfterLoop"), done = FieldAddress("TraceDone"), leaf = FieldAddress("TraceLeaf"), odd = FieldAddress("TraceOdd");
        const auto even = odd - 10;
        if(!_plugin_testassert(run <= body && body < loop && loop < after && after < tail && tail < done && done < leaf && leaf < even && even < odd,
                               "trace exports have the declared source ordering"))
            return false;
        const std::array<ExpectedNode, 3> main{{{run, loop, 0, 0, false, true, {loop}}, {loop, tail, loop, tail, false, false, {loop, tail}},
                                              {tail, leaf, 0, 0, true, false, {}}}};
        const std::array<ExpectedNode, 3> helper{{{leaf, even, odd, even, false, false, {odd, even}}, {even, odd, 0, 0, true, false, {}},
                                                {odd, odd + 10, 0, 0, true, false, {}}}};
        if(!CheckGraph("TraceRun", main) || !CheckGraph("TraceLeaf", helper))
            return false;
        gExpected.clear();
        if(!InstructionRange(body, loop, gExpected))
            return false;
        for(unsigned index = 0; index < 4; ++index)
        {
            if(!InstructionRange(loop, after, gExpected))
                return false;
            if(!over)
            {
                if(!InstructionRange(leaf, even, gExpected) || !InstructionRange(index & 1 ? odd : even, index & 1 ? odd + 10 : odd, gExpected))
                    return false;
            }
            if(!InstructionRange(after, tail, gExpected))
                return false;
        }
        if(!InstructionRange(tail, done, gExpected))
            return false;
        const auto expectedCount = over ? (sizeof(duint) == 8 ? 34u : 33u) : (sizeof(duint) == 8 ? 58u : 57u);
        if(!_plugin_testassert(gExpected.size() == expectedCount, "source reference has its independently known executed instruction count"))
            return false;
        gExpected.erase(gExpected.begin());
        gExpected.push_back(done);
        return true;
    }
    bool cbPrepare(int argc, char** argv)
    {
        if(!_plugin_testassert(argc == 2 && (strcmp(argv[1], "0") == 0 || strcmp(argv[1], "1") == 0), "trace preparation declares into or over semantics"))
            return false;
        unsigned phase = 0;
        DWORD pid = 0, thread = 0;
        REGDUMP dump{};
        if(!ReadTarget("gTracePhase", phase) || !ReadTarget("gTracePid", pid) || !ReadTarget("gTraceThread", thread))
            return false;
        if(!_plugin_testassert(phase == 2 && DbgGetProcessId() == pid && DbgGetThreadId() == thread
                              && DbgGetRegDumpEx(reinterpret_cast<REGDUMP_AVX512*>(&dump), sizeof(dump))
                              && dump.regcontext.cip == DbgValFromString("trace_cmd_condition:TraceBody"), "trace reference starts at its exact body and target identity"))
            return false;
        gStack = dump.regcontext.csp;
        gInitial = dump;
        if(!PrepareReference(argv[1][0] == '1'))
            return false;
        const ScopedProcess process(pid);
        FILETIME creation{}, exit{}, kernel{}, user{};
        const bool identified = process.value && GetProcessTimes(process.value, &creation, &exit, &kernel, &user);
        if(!_plugin_testassert(identified, "trace target has an actual OS process creation identity"))
            return false;
        uintptr_t base = 0;
        if(!ReadTarget("gTraceImageBase", base))
            return false;
        const auto creationTime = (static_cast<unsigned long long>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
        gArmed.store(true, std::memory_order_release);
        _plugin_logprintf("TRACE_LAYOUT words=%llu ipIndex=%llu pointerSize=%llu stack=%llx pid=%lu thread=%lu base=%llx creation=%llu\n",
                          static_cast<unsigned long long>((offsetof(REGDUMP, lastError) + sizeof(DWORD)) / sizeof(duint)),
                          static_cast<unsigned long long>(offsetof(REGISTERCONTEXT, cip) / sizeof(duint)), static_cast<unsigned long long>(sizeof(duint)),
                          static_cast<unsigned long long>(gStack), pid, thread, static_cast<unsigned long long>(base), creationTime);
        _plugin_logprintf("TRACE_START ax=%llx cx=%llx dx=%llx r8=%llx\n", static_cast<unsigned long long>(gInitial.regcontext.cax),
                          static_cast<unsigned long long>(gInitial.regcontext.ccx), static_cast<unsigned long long>(gInitial.regcontext.cdx),
#ifdef _WIN64
                          static_cast<unsigned long long>(gInitial.regcontext.r8)
#else
                          0ull
#endif
                         );
        return true;
    }
    bool cbInspect(int, char**)
    {
        gArmed.store(false, std::memory_order_release);
        std::array<DWORD, 4> values{};
        DWORD sum = 0, calls = 0, even = 0, odd = 0, completed = 0;
        REGDUMP dump{};
        if(!ReadTarget("gTraceValues", values) || !ReadTarget("gTraceSum", sum) || !ReadTarget("gTraceCalls", calls)
                || !ReadTarget("gTraceEven", even) || !ReadTarget("gTraceOdd", odd) || !ReadTarget("gTraceCompleted", completed))
            return false;
        if(!_plugin_testassert(values == std::array<DWORD, 4>{9, 12, 14, 17} && sum == 52 && calls == 4 && even == 2 && odd == 2 && completed == 1
                              && DbgGetRegDumpEx(reinterpret_cast<REGDUMP_AVX512*>(&dump), sizeof(dump))
                              && dump.regcontext.cip == DbgValFromString("trace_cmd_condition:TraceDone") && dump.regcontext.cax == 17 && dump.regcontext.ccx == 4
                              && dump.regcontext.cdx == 52 && dump.regcontext.csp == gStack, "trace stops only after the actual branch, call, register and memory effects"))
            return false;
        const auto count = gCount.load(std::memory_order_acquire);
        if(!_plugin_testassert(count == gExpected.size() && count <= gEvents.size() && !gOverflow.load(std::memory_order_acquire), "trace callback observation is bounded and complete"))
            return false;
        for(unsigned index = 0; index < count; ++index)
        {
            const auto& event = gEvents[index];
            if(!_plugin_testassert(event.ip == gExpected[index] && event.pid == DbgGetProcessId() && event.thread == DbgGetThreadId()
                                   && event.stop == (index + 1 == count), "trace callback has the exact source instruction, OS identity and final stop"))
                return false;
            _plugin_logprintf("TRACE_CALLBACK index=%u ip=%llx pid=%lu thread=%lu stop=%u\n", index, static_cast<unsigned long long>(event.ip), event.pid, event.thread, event.stop ? 1 : 0);
        }
        _plugin_logprintf("TRACE_RESULT values=%lu/%lu/%lu/%lu sum=%lu calls=%lu even=%lu odd=%lu steps=%llu\n", values[0], values[1], values[2], values[3], sum, calls, even, odd,
                          static_cast<unsigned long long>(DbgValFromString("$tracecounter")));
        return true;
    }
    bool cbExit(int, char**)
    {
        return _plugin_testassert(gExited.load(std::memory_order_acquire) && gExit.load(std::memory_order_relaxed) == 52 && !DbgIsDebugging(), "trace target actually exits with its independently known sum");
    }
}
extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* init)
{
    init->pluginVersion = 1;
    init->sdkVersion = PLUG_SDKVERSION;
    strcpy_s(init->pluginName, "trace-graph-reference");
    gPluginHandle = init->pluginHandle;
    for(const auto type : {CB_INITDEBUG, CB_DEBUGEVENT, CB_TRACEEXECUTE, CB_EXITPROCESS})
        _plugin_registercallback(gPluginHandle, type, cbTraceEvent);
    return _plugin_registercommand(gPluginHandle, "traceprepare", cbPrepare, true)
           && _plugin_registercommand(gPluginHandle, "traceinspect", cbInspect, true)
           && _plugin_registercommand(gPluginHandle, "traceexit", cbExit, false);
}
extern "C" __declspec(dllexport) bool plugstop() { return true; }
