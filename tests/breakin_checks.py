import os
import re

from wi_driver import file_identity, write_json


def fields(line):
    pairs = re.findall(r"([A-Za-z][A-Za-z0-9_]*)=([^ ]+)", line)
    assert pairs and len(dict(pairs)) == len(pairs), "Native observation fields repeat"
    return dict(pairs)


def one_line(lines, prefix):
    selected = [line for line in lines if line.startswith(prefix)]
    assert len(selected) == 1, f"Native observation {prefix} is missing or repeated"
    return fields(selected[0])


def check_breakin_receipt(receipt, architecture, mode, detached, failure=None):
    assert failure in (None, "register", "remove", "partial", "reduced")
    partial = failure == "partial"
    reduced = failure == "reduced"
    parked = reduced and architecture == "x32"
    handler_failure = failure in ("register", "remove")
    assert receipt["exitCode"] == 0 and not receipt["timedOut"] and receipt["terminalObserved"] and receipt["jobClosed"], "Native controller did not complete normally"
    lines = receipt["stdout"].splitlines()
    identities = [fields(line) for line in lines if line.startswith("IDENTITY ")]
    assert len(identities) == 3 and {item["role"] for item in identities} == {"controller", "created", "target"}
    identities = {item["role"]: item for item in identities}
    assert identities["controller"]["pid"] == str(receipt["processIdentity"]["pid"])
    assert identities["controller"]["creation"] == receipt["processIdentity"]["creationTime"]
    assert identities["created"]["pid"] == identities["target"]["pid"] and identities["created"]["creation"] == identities["target"]["creation"]
    assert identities["target"]["pid"] != identities["controller"]["pid"] and int(identities["target"]["creation"]) >= int(identities["controller"]["creation"])
    reference = one_line(lines, "REFERENCE ")
    strings = 0 if mode == "both" or architecture == "x64" and mode == "hide" else 1
    breaks = int(failure != "register" and not detached and not parked)
    thread_exit = "7" if parked else "2" if failure == "register" else "1" if failure == "remove" else "0"
    freed = failure != "remove" and not parked
    allocation_state = "00010000" if freed else "00001000"
    assert reference == {"hidden": str(int(mode != "show")), "strings": str(strings), "breakpoints": str(2 + breaks), "target_exit": "7", "exited": "1", "terminal": "1"}
    final = one_line(lines, "TARGET final_peb=")
    assert final == {"final_peb": str(int(mode == "show" and not detached)), "final_port": str(int(not detached)), "detached": str(int(detached)), "port_read": "1"}
    assert one_line(lines, "READONLY ") == {"rejected": "1", "error": "5"}
    assert one_line(lines, "INVALID_BASE ") == {"rejected": "1"}
    assert one_line(lines, "DUPLICATE ") == {"rejected": "1", "error": "170"}
    assert one_line(lines, "STUB ") == {"status": "c0000022" if partial or parked else "00000000", "error": "6" if parked else "5" if partial else "0", "created": str(int(not partial and not parked))}
    remote = one_line(lines, "REMOTE ")
    assert remote["created"] == str(int(not parked)) and remote["result"] == str(int(not partial and not parked)) and int(remote["tid"]) > 0
    assert remote["exited"] == str(int(not detached)) and remote["broken"] == str(breaks)
    if parked:
        cleanup = one_line(lines, "PROCESS_CLEANUP ")
        assert cleanup == {"processTerminal": "1", "targetExit": "7", "threadTerminal": "1", "threadExit": "7"}
        assert not any(line.startswith(("MATCH ", "CREATE_THREAD ", "THREAD_IDENTITY ", "DETACHED ", "STUB_CLEANUP ")) for line in lines)
    elif detached:
        cleanup = one_line(lines, "DETACHED ")
        assert cleanup == {"thread": remote["tid"], "exit": thread_exit, "freed": str(int(freed)), "state": allocation_state}
        assert not any(line.startswith("MATCH ") for line in lines)
    else:
        if failure == "register":
            assert not any(line.startswith("MATCH ") for line in lines)
        else:
            assert one_line(lines, "MATCH ") == {"actual": "1", "wrongAddress": "0", "wrongChance": "0", "wrongCode": "0", "wrongProcess": "0", "wrongThread": "0", "repeated": "0"}
        assert one_line(lines, "STUB_CLEANUP ") == {"terminal": "1", "exit": thread_exit, "freed": str(int(freed)), "state": allocation_state}
    provider = one_line(lines, "HANDLER_PROVIDER ")
    assert provider["controlled"] == str(int(handler_failure)) and int(provider["base"], 16) > 0
    if handler_failure:
        handler = one_line(lines, "HANDLER ")
        created = one_line(lines, "CREATE_THREAD ")
        assert handler["code"] == created["start"] and created["thread"] == remote["tid"] and created["pid"] == identities["target"]["pid"]
        assert set(handler) == {"registrationCalls", "removalCalls", "nativeRegistration", "removalMatches", "active", "lateRemoved", "code", "queried", "state", "protection"}
        assert {key: value for key, value in handler.items() if key != "protection"} == {"registrationCalls": "1", "removalCalls": str(int(failure == "remove")), "nativeRegistration": str(int(failure == "remove")),
                           "removalMatches": str(int(failure == "remove")), "active": str(int(failure == "remove")), "lateRemoved": str(int(failure == "remove")),
                           "code": created["start"], "queried": "1", "state": allocation_state}
        if not freed:
            assert handler["protection"] == "00000020"
        if failure == "remove":
            retention = []
            for phase in ("retired", "shutdown"):
                observation = one_line(lines, f"RETENTION phase={phase} ")
                assert 0 < int(observation["samples"]) and 250 <= int(observation["elapsed"]) < 10000
                assert {key: observation[key] for key in ("phase", "alive", "code", "executable", "data", "unchanged")} == {
                    "phase": phase, "alive": "1", "code": created["start"], "executable": "00000020", "data": "00000004", "unchanged": "1"}
                retention.append(observation)
            assert len([line for line in lines if line.startswith("RETENTION ")]) == 2
            shutdown = one_line(lines, "SHUTDOWN ")
            assert int(shutdown["before"]) >= int(shutdown["after"]) + 2
            assert {key: shutdown[key] for key in ("createRejected", "error", "beginRejected")} == {"createRejected": "1", "error": "170", "beginRejected": "1"}
        else:
            assert not any(line.startswith("RETENTION ") for line in lines)
    else:
        assert not any(line.startswith("HANDLER ") for line in lines)
        if not partial and not reduced:
            assert not any(line.startswith("RETENTION ") for line in lines)
    creator = None
    if partial:
        creator = one_line(lines, "CREATOR ")
        created = one_line(lines, "CREATE_THREAD ")
        assert set(creator) == {"nativeStatus", "returnedStatus", "error", "requestedAccess", "actualAccess", "flags", "pid", "thread", "creation", "start", "nativeCreated", "handleClosed", "calls"}
        assert {key: creator[key] for key in ("nativeStatus", "returnedStatus", "error", "requestedAccess", "actualAccess", "flags", "nativeCreated", "handleClosed", "calls")} == {
            "nativeStatus": "00000000", "returnedStatus": "c0000022", "error": "5", "requestedAccess": "001fffff", "actualAccess": "001fffff", "flags": "2", "nativeCreated": "1", "handleClosed": "1", "calls": "1"}
        assert creator["pid"] == created["pid"] == identities["target"]["pid"] and creator["thread"] == created["thread"] == remote["tid"]
        assert creator["start"] == created["start"] and int(creator["start"], 16) > 0 and int(creator["creation"]) > int(identities["target"]["creation"])
        assert one_line(lines, "THREAD_IDENTITY ") == {key: creator[key] for key in ("pid", "thread", "creation", "start")}
        retention = []
        for phase in ("pending", "created"):
            observation = one_line(lines, f"RETENTION phase={phase} ")
            assert 0 < int(observation["samples"]) and 250 <= int(observation["elapsed"]) < 10000
            assert {key: observation[key] for key in ("phase", "alive", "code", "executable", "data", "unchanged")} == {
                "phase": phase, "alive": "1", "code": created["start"], "executable": "00000020", "data": "00000004", "unchanged": "1"}
            retention.append(observation)
        prefixes = ("CREATOR ", "RETENTION phase=pending ", "STUB ", "THREAD_IDENTITY ", "RETENTION phase=created ", "CREATE_THREAD ", "DETACHED " if detached else "STUB_CLEANUP ", "REFERENCE ")
        positions = [next(index for index, line in enumerate(lines) if line.startswith(prefix)) for prefix in prefixes]
        assert positions == sorted(set(positions)), "Partial creation observations are out of order"
        assert len([line for line in lines if line.startswith("RETENTION ")]) == 2 and not any(line.startswith("SHUTDOWN ") for line in lines)
    elif not reduced:
        assert not any(line.startswith(("CREATOR ", "THREAD_IDENTITY ")) for line in lines)
    if reduced:
        creator = one_line(lines, "NATIVE_CREATOR ")
        assert set(creator) == {"status", "requestedAccess", "actualAccess", "flags", "pid", "thread", "creation", "start", "handleValid", "handleError", "before", "after", "observed", "suspend", "restore", "calls"}
        assert {key: creator[key] for key in ("status", "requestedAccess", "actualAccess", "flags", "handleValid", "handleError", "observed", "suspend", "restore", "calls")} == {
            "status": "c0000022" if parked else "00000000", "requestedAccess": "001fffff", "actualAccess": "00100040", "flags": "2",
            "handleValid": str(int(not parked)), "handleError": "6" if parked else "0", "observed": "1", "suspend": "1" if parked else "0", "restore": "2" if parked else "1", "calls": "1"}
        assert creator["pid"] == identities["target"]["pid"] and creator["thread"] == remote["tid"] and int(creator["thread"]) > 0
        assert int(creator["creation"]) > int(identities["target"]["creation"]) and int(creator["start"], 16) > 0
        assert 0 < int(creator["before"]) and int(creator["after"]) == int(creator["before"]) + 1
        assert not any(line.startswith("CREATOR ") for line in lines)
        retention = []
        if parked:
            phases = ("pending", "retired", "shutdown")
            if detached:
                phases += ("detached",)
        else:
            phases = ("created",)
        for phase in phases:
            observation = one_line(lines, f"RETENTION phase={phase} ")
            assert 0 < int(observation["samples"]) and 250 <= int(observation["elapsed"]) < 10000
            assert {key: observation[key] for key in ("phase", "alive", "code", "executable", "data", "unchanged")} == {
                "phase": phase, "alive": "1", "code": creator["start"], "executable": "00000020", "data": "00000004", "unchanged": "1"}
            retention.append(observation)
        assert len([line for line in lines if line.startswith("RETENTION ")]) == len(phases)
        if parked:
            thread_phases = ("pending", "shutdown") + (("detached",) if detached else ())
            for phase in thread_phases:
                state = one_line(lines, f"PARKED_THREAD phase={phase} ")
                assert state == {"phase": phase, **{key: creator[key] for key in ("pid", "thread", "creation", "start")}, "alive": "1", "suspend": "1", "restore": "2", "matches": "1"}
            assert len([line for line in lines if line.startswith("PARKED_THREAD ")]) == len(thread_phases)
            assert one_line(lines, "PENDING_EVENT ") == {"missing": "1", "error": "121"}
            shutdown = one_line(lines, "SHUTDOWN ")
            assert int(shutdown["before"]) >= int(shutdown["after"]) + 1
            assert {key: shutdown[key] for key in ("createRejected", "error", "beginRejected")} == {"createRejected": "1", "error": "170", "beginRejected": "1"}
            prefixes = ("NATIVE_CREATOR ", "PARKED_THREAD phase=pending ", "RETENTION phase=pending ", "STUB ", "PENDING_EVENT ", "RETENTION phase=retired ", "SHUTDOWN ", "RETENTION phase=shutdown ", "PARKED_THREAD phase=shutdown ")
            if detached:
                prefixes += ("PARKED_THREAD phase=detached ", "RETENTION phase=detached ")
            prefixes += ("TARGET breakpoint_returned=", "PROCESS_CLEANUP ", "REFERENCE ")
        else:
            assert one_line(lines, "THREAD_IDENTITY ") == {key: creator[key] for key in ("pid", "thread", "creation", "start")}
            assert one_line(lines, "CREATE_THREAD ") == {key: creator[key] for key in ("pid", "thread", "start")}
            assert not any(line.startswith(("PARKED_THREAD ", "PENDING_EVENT ", "PROCESS_CLEANUP ", "SHUTDOWN ")) for line in lines)
            prefixes = ("NATIVE_CREATOR ", "STUB ", "THREAD_IDENTITY ", "RETENTION phase=created ", "CREATE_THREAD ", "DETACHED " if detached else "STUB_CLEANUP ", "REFERENCE ")
        positions = [next(index for index, line in enumerate(lines) if line.startswith(prefix)) for prefix in prefixes]
        assert positions == sorted(set(positions)), "Native reduced-access observations are out of order"
    else:
        assert not any(line.startswith(("NATIVE_CREATOR ", "PARKED_THREAD ", "PENDING_EVENT ", "PROCESS_CLEANUP ")) for line in lines)
    if architecture == "x32":
        native = one_line(lines, "NATIVE_PEB ")
        assert native["original"] == "1" and native["observed"] == str(int(mode != "both")) and int(native["address"], 16) > 0
    return {"identities": identities, "reference": reference, "final": final, "remote": remote, "cleanup": cleanup if detached or parked else one_line(lines, "STUB_CLEANUP "),
            "failure": failure, "handler": handler if handler_failure else None, "retention": retention if failure in ("remove", "partial", "reduced") else None, "creator": creator, "provider": provider}


def check_replacement_receipt(receipt, architecture, mode, kind, rounds=8):
    assert kind in ("normal", "register", "remove", "partial") and mode in ("show", "hide", "both")
    assert receipt["exitCode"] == 0 and not receipt["timedOut"] and receipt["terminalObserved"] and receipt["jobClosed"]
    lines = receipt["stdout"].splitlines()
    headers = [index for index, line in enumerate(lines) if line.startswith("SESSION ")]
    assert len(headers) == rounds
    assert one_line(lines, "SESSION_FINISH ") == {"rounds": str(rounds), "createRejected": "1", "error": "170"}
    observed = []
    generations = set()
    partial = kind == "partial"
    registration = kind == "register"
    removal = kind == "remove"
    retained = partial or removal
    for round_index, begin in enumerate(headers):
        block = lines[begin:headers[round_index + 1] if round_index + 1 < rounds else len(lines)]
        session = one_line(block, "SESSION ")
        assert set(session) == {"round", "old", "oldCreation", "next", "nextCreation", "partial", "registration", "removal"}
        assert {key: session[key] for key in ("round", "partial", "registration", "removal")} == {
            "round": str(round_index), "partial": str(int(partial)), "registration": str(int(registration)), "removal": str(int(removal))}
        assert int(session["old"]) > 0 and int(session["next"]) > 0 and session["old"] != session["next"]
        assert int(session["oldCreation"]) > int(receipt["processIdentity"]["creationTime"]) and int(session["nextCreation"]) >= int(session["oldCreation"])
        identities = [fields(line) for line in block if line.startswith("IDENTITY ")]
        assert len(identities) == 2 and {item["role"] for item in identities} == {"target"}
        expected_identities = {(session["old"], session["oldCreation"]), (session["next"], session["nextCreation"])}
        assert {(item["pid"], item["creation"]) for item in identities} == expected_identities and not generations.intersection(expected_identities)
        generations.update(expected_identities)
        assert one_line(block, "SESSION_REQUEST ") == {"oldStatus": "c0000022" if partial else "00000000", "oldCreated": str(int(not partial)), "nextStatus": "00000000", "nextCreated": "1"}
        assert one_line(block, "SESSION_DUPLICATE ") == {"rejected": "1", "error": "170"}
        helpers = [one_line(block, f"SESSION_HELPER role={role} ") for role in range(2)]
        for role, helper in enumerate(helpers):
            target_role = "old" if role == 0 else "next"
            assert set(helper) == {"role", "pid", "thread", "creation", "code"} and helper["role"] == str(role) and helper["pid"] == session[target_role]
            assert int(helper["thread"]) > 0 and int(helper["creation"]) > int(session[target_role + "Creation"]) and int(helper["code"], 16) > 0
            expected_breaks = int(role == 1 or not registration)
            if expected_breaks:
                assert one_line(block, f"SESSION_CONSUME role={role} ") == {"role": str(role), "pid": helper["pid"], "thread": helper["thread"], "consumed": str(role), "repeated": "0"}
            else:
                assert not any(line.startswith(f"SESSION_CONSUME role={role} ") for line in block)
            exit_code = "2" if role == 0 and registration else "1" if role == 0 and removal else "0"
            assert one_line(block, f"SESSION_THREAD_TERMINAL role={role} ") == {"role": str(role), "pid": helper["pid"], "thread": helper["thread"], "exit": exit_code}
            freed = role == 1 or not retained
            assert one_line(block, f"SESSION_PAGE role={role} ") == {"role": str(role), "pid": helper["pid"], "code": helper["code"], "freed": str(int(freed)), "state": "00010000" if freed else "00001000"}
            assert one_line(block, f"SESSION_TARGET_TERMINAL role={role} ") == {"role": str(role), "pid": helper["pid"], "exit": "7", "breaks": "2", "helperBreaks": str(expected_breaks), "helperExits": "1"}
        assert helpers[0]["thread"] != helpers[1]["thread"]
        for prefix in ("SESSION_HELPER ", "SESSION_THREAD_TERMINAL ", "SESSION_PAGE ", "SESSION_TARGET_TERMINAL "):
            assert len([line for line in block if line.startswith(prefix)]) == 2
        assert len([line for line in block if line.startswith("SESSION_CONSUME ")]) == (1 if registration else 2)
        if retained:
            retention = one_line(block, "SESSION_RETAIN ")
            assert {key: retention[key] for key in ("pid", "code", "alive", "executable", "data", "unchanged")} == {
                "pid": helpers[0]["pid"], "code": helpers[0]["code"], "alive": "1", "executable": "00000020", "data": "00000004", "unchanged": "1"}
            assert int(retention["samples"]) > 0 and 250 <= int(retention["elapsed"]) < 10000
        else:
            assert not any(line.startswith("SESSION_RETAIN ") for line in block)
        if partial:
            creator = one_line(block, "CREATOR ")
            assert {key: creator[key] for key in ("nativeStatus", "returnedStatus", "error", "requestedAccess", "actualAccess", "flags", "nativeCreated", "handleClosed", "calls")} == {
                "nativeStatus": "00000000", "returnedStatus": "c0000022", "error": "5", "requestedAccess": "001fffff", "actualAccess": "001fffff", "flags": "2", "nativeCreated": "1", "handleClosed": "1", "calls": str(round_index + 1)}
            assert {key: creator[key] for key in ("pid", "thread", "creation")} == {key: helpers[0][key] for key in ("pid", "thread", "creation")} and creator["start"] == helpers[0]["code"]
        else:
            assert not any(line.startswith("CREATOR ") for line in block)
        if registration or removal:
            handler = one_line(block, "HANDLER ")
            assert {key: handler[key] for key in ("registrationCalls", "removalCalls", "nativeRegistration", "removalMatches", "active", "lateRemoved", "code", "queried", "state")} == {
                "registrationCalls": "1", "removalCalls": str(int(removal)), "nativeRegistration": str(int(removal)), "removalMatches": str(int(removal)), "active": str(int(removal)), "lateRemoved": str(int(removal)),
                "code": helpers[0]["code"], "queried": "1", "state": "00001000" if removal else "00010000"}
            if removal:
                assert handler["protection"] == "00000020"
        else:
            assert not any(line.startswith("HANDLER ") for line in block)
        final = [fields(line) for line in block if line.startswith("TARGET final_peb=")]
        assert len(final) == 2 and all(item == {"final_peb": str(int(mode == "show")), "final_port": "1", "detached": "0", "port_read": "1"} for item in final)
        if architecture == "x32":
            native = [fields(line) for line in block if line.startswith("NATIVE_PEB ")]
            assert len(native) == 2 and all(item["original"] == "1" and item["observed"] == str(int(mode != "both")) and int(item["address"], 16) > 0 for item in native)
        assert one_line(block, "SESSION_ROUND ") == {"round": str(round_index), "completed": "1"}
        request = next(index for index, line in enumerate(block) if line.startswith("SESSION_REQUEST "))
        for role in range(2):
            helper_position = next(index for index, line in enumerate(block) if line.startswith(f"SESSION_HELPER role={role} "))
            thread_position = next(index for index, line in enumerate(block) if line.startswith(f"SESSION_THREAD_TERMINAL role={role} "))
            page_position = next(index for index, line in enumerate(block) if line.startswith(f"SESSION_PAGE role={role} "))
            target_position = next(index for index, line in enumerate(block) if line.startswith(f"SESSION_TARGET_TERMINAL role={role} "))
            assert request < helper_position < thread_position < page_position < target_position
        if retained:
            held = next(index for index, line in enumerate(block) if line.startswith("SESSION_RETAIN "))
            released = next(index for index, line in enumerate(block) if line.startswith("TARGET breakpoint_returned="))
            assert page_position < held < released
        observed.append({"session": session, "helpers": helpers, "retained": retained, "sameVirtualAddress": helpers[0]["code"] == helpers[1]["code"]})
    assert len(generations) == rounds * 2
    return {"rounds": observed, "targetGenerations": len(generations)}


def check_inflight_receipt(receipt, architecture, mode, phase, action):
    assert architecture in ("x64", "x32") and mode in ("show", "hide", "both") and phase in ("before", "after") and action in ("end", "shutdown")
    assert receipt["exitCode"] == 0 and not receipt["timedOut"] and receipt["terminalObserved"] and receipt["jobClosed"]
    lines = receipt["stdout"].splitlines()
    controller = receipt["processIdentity"]
    header = one_line(lines, "INFLIGHT phase=")
    assert set(header) == {"phase", "action", "pid", "creation", "controllerCreation"} and header["phase"] == phase and header["action"] == action and header["controllerCreation"] == controller["creationTime"]
    assert int(header["pid"]) > 0 and header["pid"] != str(controller["pid"]) and int(header["creation"]) >= int(controller["creationTime"])
    assert one_line(lines, "IDENTITY ") == {"role": "target", "pid": header["pid"], "creation": header["creation"]}
    worker = one_line(lines, "INFLIGHT_WORKER ")
    assert set(worker) == {"pid", "thread", "creation", "alive", "releasePending"}
    assert worker["pid"] == str(controller["pid"]) and int(worker["thread"]) > 0 and int(worker["creation"]) > int(controller["creationTime"])
    assert worker["alive"] == worker["releasePending"] == "1"
    assert one_line(lines, "INFLIGHT_WORKER_TERMINAL ") == {key: worker[key] for key in ("pid", "thread", "creation")} | {"exit": "0"}
    helper = one_line(lines, "INFLIGHT_HELPER ")
    assert set(helper) == {"pid", "thread", "creation", "code"} and helper["pid"] == header["pid"]
    assert int(helper["thread"]) > 0 and helper["thread"] != worker["thread"] and int(helper["creation"]) > int(header["creation"]) and int(helper["code"], 16) > 0
    native = one_line(lines, "INFLIGHT_NATIVE ")
    assert native == {"status": "00000000", "requestedAccess": "001fffff", "actualAccess": "001fffff", "flags": "2", "pid": helper["pid"], "thread": helper["thread"], "creation": helper["creation"], "start": helper["code"], "handleValid": "1", "calls": "1"}
    gate = one_line(lines, "CREATION_GATE ")
    assert gate == {"phase": phase, "pid": helper["pid"], "thread": "0" if phase == "before" else helper["thread"], "creation": "0" if phase == "before" else helper["creation"], "start": helper["code"], "calls": "1"}
    assert one_line(lines, "INFLIGHT_RETIRE ") == {"action": action, "createRejected": "1", "error": "170", "workerPending": "1"}
    assert one_line(lines, "INFLIGHT_RETURN ") == {"created": "1", "status": "00000000", "error": "0", **helper}
    assert one_line(lines, "INFLIGHT_CONSUME ") == {"pid": helper["pid"], "thread": helper["thread"], "consumed": "0", "repeated": "0"}
    assert one_line(lines, "INFLIGHT_THREAD_TERMINAL ") == {"pid": helper["pid"], "thread": helper["thread"], "exit": "0"}
    retained = action == "shutdown"
    assert one_line(lines, "SESSION_PAGE ") == {"role": "0", "pid": helper["pid"], "code": helper["code"], "freed": str(int(not retained)), "state": "00001000" if retained else "00010000"}
    assert one_line(lines, "INFLIGHT_TARGET_TERMINAL ") == {"pid": helper["pid"], "exit": "7", "breaks": "2", "helperBreaks": "1", "helperExits": "1"}
    assert one_line(lines, "TARGET final_peb=") == {"final_peb": str(int(mode == "show")), "final_port": "1", "detached": "0", "port_read": "1"}
    assert one_line(lines, "TARGET breakpoint_returned=") == {"breakpoint_returned": "1"}
    if architecture == "x32":
        peb = one_line(lines, "NATIVE_PEB ")
        assert set(peb) == {"address", "original", "observed"} and int(peb["address"], 16) > 0 and peb["original"] == "1" and peb["observed"] == str(int(mode != "both"))
    phases = ("held", "retired", "completed") if retained else ("held", "retired")
    stages = [fields(line) for line in lines if line.startswith("INFLIGHT_RETENTION ")]
    assert stages == [{"phase": item} for item in phases]
    retentions = [(index, fields(line)) for index, line in enumerate(lines) if line.startswith("SESSION_RETAIN ")]
    assert len(retentions) == len(phases)
    retention_positions = []
    for stage, (index, sample) in zip(phases, retentions):
        assert set(sample) == {"pid", "code", "alive", "executable", "data", "unchanged", "samples", "elapsed"}
        assert {key: sample[key] for key in ("pid", "code", "alive", "executable", "data", "unchanged")} == {
            "pid": helper["pid"], "code": helper["code"], "alive": "1", "executable": "00000020", "data": "00000004", "unchanged": "1"}
        assert int(sample["samples"]) > 0 and 250 <= int(sample["elapsed"]) < 10000
        assert lines[index - 1] == f"INFLIGHT_RETENTION phase={stage}"
        retention_positions.append(index)
    def position(prefix):
        return next(index for index, line in enumerate(lines) if line.startswith(prefix))
    assert position("CREATION_GATE ") < position("INFLIGHT_WORKER ") < retention_positions[0] < position("INFLIGHT_RETIRE ") < retention_positions[1] < position("INFLIGHT_WORKER_TERMINAL ") < position("INFLIGHT_RETURN ") < position("INFLIGHT_HELPER ") < position("INFLIGHT_CONSUME ") < position("INFLIGHT_THREAD_TERMINAL ") < position("SESSION_PAGE ") < position("TARGET breakpoint_returned=") < position("INFLIGHT_TARGET_TERMINAL ")
    if phase == "before":
        assert retention_positions[1] < position("INFLIGHT_NATIVE ") < position("INFLIGHT_WORKER_TERMINAL ")
    else:
        assert position("INFLIGHT_NATIVE ") < position("CREATION_GATE ")
    if retained:
        assert position("SESSION_PAGE ") < retention_positions[2] < position("TARGET breakpoint_returned=")
    return {"target": header, "worker": worker, "helper": helper, "gate": gate, "retentions": [sample for index, sample in retentions], "retainedThroughProcessLifetime": retained}


def run_breakin_oracles(environment, results, fixture_identity, run_owned):
    binary, identity, machine = fixture_identity(environment, "native_breakin")
    observations = []
    for failure in (None, "register", "remove", "partial", "reduced"):
        for mode in ("show", "hide", "both"):
            for detached in (False, True):
                command = [str(binary), mode, "controller", "detach" if detached else "stub"]
                if failure:
                    command.append(failure)
                receipt = run_owned(command, os.environ, 35)
                path = environment.root / f"breakin-{mode}-{'detach' if detached else 'attached'}-{failure or 'normal'}.json"
                write_json(path, receipt)
                observed = check_breakin_receipt(receipt, environment.architecture, mode, detached, failure)
                assert file_identity(binary) == identity, "Native break-in fixture changed"
                observations.append({"mode": mode, "detached": detached, "failure": failure, "receipt": file_identity(path), "observed": observed})
    replacements = []
    for kind in ("normal", "register", "remove", "partial"):
        for mode in ("show", "hide", "both"):
            receipt = run_owned([str(binary), mode, "replacement", kind, "8"], os.environ, 35)
            path = environment.root / f"breakin-replacement-{mode}-{kind}.json"
            write_json(path, receipt)
            observed = check_replacement_receipt(receipt, environment.architecture, mode, kind)
            assert file_identity(binary) == identity, "Native replacement fixture changed"
            replacements.append({"mode": mode, "kind": kind, "receipt": file_identity(path), "observed": observed})
    inflight = []
    for phase in ("before", "after"):
        for action in ("end", "shutdown"):
            for mode in ("show", "hide", "both"):
                receipt = run_owned([str(binary), mode, "inflight", phase, action], os.environ, 35)
                path = environment.root / f"breakin-inflight-{mode}-{phase}-{action}.json"
                write_json(path, receipt)
                observed = check_inflight_receipt(receipt, environment.architecture, mode, phase, action)
                assert file_identity(binary) == identity, "Native in-flight fixture changed"
                inflight.append({"mode": mode, "phase": phase, "action": action, "receipt": file_identity(path), "observed": observed})
    results.append({"name": "test_native_breakin_oracles", "status": "verified", "oracle": {
        "binary": identity, "machine": machine, "observations": observations, "replacements": replacements, "inflight": inflight, "debuggerUsed": "owned Windows native controller"}})
    print(f"[VERIFIED] Native {environment.architecture} hidden/unhidden break-in, identity rejection, detach, thread exit, page release, failed-handler retention, late-thread binding, actual reduced-access creation, repeated replacement and held in-flight creation retirement/shutdown", flush=True)
