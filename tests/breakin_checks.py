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
    assert failure in (None, "register", "remove", "partial")
    partial = failure == "partial"
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
    breaks = int(failure != "register" and not detached)
    thread_exit = "2" if failure == "register" else "1" if failure == "remove" else "0"
    freed = failure != "remove"
    allocation_state = "00010000" if freed else "00001000"
    assert reference == {"hidden": str(int(mode != "show")), "strings": str(strings), "breakpoints": str(2 + breaks), "target_exit": "7", "exited": "1", "terminal": "1"}
    final = one_line(lines, "TARGET final_peb=")
    assert final == {"final_peb": str(int(mode == "show" and not detached)), "final_port": str(int(not detached)), "detached": str(int(detached)), "port_read": "1"}
    assert one_line(lines, "READONLY ") == {"rejected": "1", "error": "5"}
    assert one_line(lines, "INVALID_BASE ") == {"rejected": "1"}
    assert one_line(lines, "DUPLICATE ") == {"rejected": "1", "error": "170"}
    assert one_line(lines, "STUB ") == {"status": "c0000022" if partial else "00000000", "error": "5" if partial else "0", "created": str(int(not partial))}
    remote = one_line(lines, "REMOTE ")
    assert remote["created"] == "1" and remote["result"] == str(int(not partial)) and int(remote["tid"]) > 0
    assert remote["exited"] == str(int(not detached)) and remote["broken"] == str(breaks)
    if detached:
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
        if not partial:
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
    else:
        assert not any(line.startswith(("CREATOR ", "THREAD_IDENTITY ")) for line in lines)
    if architecture == "x32":
        native = one_line(lines, "NATIVE_PEB ")
        assert native["original"] == "1" and native["observed"] == str(int(mode != "both")) and int(native["address"], 16) > 0
    return {"identities": identities, "reference": reference, "final": final, "remote": remote, "cleanup": cleanup if detached else one_line(lines, "STUB_CLEANUP "),
            "failure": failure, "handler": handler if handler_failure else None, "retention": retention if failure in ("remove", "partial") else None, "creator": creator, "provider": provider}


def run_breakin_oracles(environment, results, fixture_identity, run_owned):
    binary, identity, machine = fixture_identity(environment, "native_breakin")
    observations = []
    for failure in (None, "register", "remove", "partial"):
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
    results.append({"name": "test_native_breakin_oracles", "status": "verified", "oracle": {
        "binary": identity, "machine": machine, "observations": observations, "debuggerUsed": "owned Windows native controller"}})
    print(f"[VERIFIED] Native {environment.architecture} hidden/unhidden break-in, identity rejection, detach, thread exit, page release, failed-handler retention and late-thread partial creation", flush=True)
