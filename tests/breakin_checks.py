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


def check_breakin_receipt(receipt, architecture, mode, detached):
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
    assert reference == {"hidden": str(int(mode != "show")), "strings": str(strings), "breakpoints": "2" if detached else "3", "target_exit": "7", "exited": "1", "terminal": "1"}
    final = one_line(lines, "TARGET final_peb=")
    assert final == {"final_peb": str(int(mode == "show" and not detached)), "final_port": str(int(not detached)), "detached": str(int(detached)), "port_read": "1"}
    assert one_line(lines, "READONLY ") == {"rejected": "1", "error": "5"}
    assert one_line(lines, "INVALID_BASE ") == {"rejected": "1"}
    assert one_line(lines, "DUPLICATE ") == {"rejected": "1", "error": "170"}
    assert one_line(lines, "STUB ") == {"status": "00000000", "error": "0", "created": "1"}
    remote = one_line(lines, "REMOTE ")
    assert remote["created"] == remote["result"] == "1" and int(remote["tid"]) > 0
    assert remote["exited"] == remote["broken"] == str(int(not detached))
    if detached:
        cleanup = one_line(lines, "DETACHED ")
        assert cleanup == {"thread": remote["tid"], "exit": "0", "freed": "1", "state": "00010000"}
        assert not any(line.startswith("MATCH ") for line in lines)
    else:
        assert one_line(lines, "MATCH ") == {"actual": "1", "wrongAddress": "0", "wrongChance": "0", "wrongCode": "0", "wrongProcess": "0", "wrongThread": "0", "repeated": "0"}
        assert one_line(lines, "STUB_CLEANUP ") == {"terminal": "1", "exit": "0", "freed": "1", "state": "00010000"}
    if architecture == "x32":
        native = one_line(lines, "NATIVE_PEB ")
        assert native["original"] == "1" and native["observed"] == str(int(mode != "both")) and int(native["address"], 16) > 0
    return {"identities": identities, "reference": reference, "final": final, "remote": remote, "cleanup": cleanup if detached else one_line(lines, "STUB_CLEANUP ")}


def run_breakin_oracles(environment, results, fixture_identity, run_owned):
    binary, identity, machine = fixture_identity(environment, "native_breakin")
    observations = []
    for mode in ("show", "hide", "both"):
        for detached in (False, True):
            receipt = run_owned([str(binary), mode, "controller", "detach" if detached else "stub"], os.environ, 35)
            path = environment.root / f"breakin-{mode}-{'detach' if detached else 'attached'}.json"
            write_json(path, receipt)
            observed = check_breakin_receipt(receipt, environment.architecture, mode, detached)
            assert file_identity(binary) == identity, "Native break-in fixture changed"
            observations.append({"mode": mode, "detached": detached, "receipt": file_identity(path), "observed": observed})
    results.append({"name": "test_native_breakin_oracles", "status": "verified", "oracle": {
        "binary": identity, "machine": machine, "observations": observations, "debuggerUsed": "owned Windows native controller"}})
    print(f"[VERIFIED] Native {environment.architecture} hidden/unhidden break-in, identity rejection, detach, thread exit and page release", flush=True)
