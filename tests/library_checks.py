from contextlib import closing
import copy
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time
import uuid

from wi_driver import CREATE_SUSPENDED, KERNEL, OwnedJob, file_identity, loaded_modules, process_identity, resume_suspended_process, tree_identity, write_json


def directory_security(path, user_sid, protected):
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
                                            ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                            ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                            ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.USHORT), ctypes.POINTER(wintypes.DWORD)]
    advapi.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
    advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    KERNEL.LocalFree.argtypes = [ctypes.c_void_p]
    KERNEL.LocalFree.restype = ctypes.c_void_p
    descriptor, dacl, owner = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    status = advapi.GetNamedSecurityInfoW(str(path), 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
    assert status == 0 and dacl.value, (path, status)
    try:
        control, revision = wintypes.USHORT(), wintypes.DWORD()
        assert advapi.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision))
        assert bool(control.value & 0x1000) == protected, "Fixture namespace DACL protection differs"
        information = (wintypes.DWORD * 3)()
        assert advapi.GetAclInformation(dacl, information, ctypes.sizeof(information), 2)
        assert information[0] == 2, "Fixture namespace admits an unexpected access entry"

        def sid_text(address):
            value = wintypes.LPWSTR()
            assert advapi.ConvertSidToStringSidW(address, ctypes.byref(value))
            try:
                return value.value
            finally:
                KERNEL.LocalFree(ctypes.cast(value, ctypes.c_void_p))

        entries = []
        for index in range(information[0]):
            ace = ctypes.c_void_p()
            assert advapi.GetAce(dacl, index, ctypes.byref(ace))
            header = (ctypes.c_ubyte * 4).from_address(ace.value)
            assert header[0] == 0 and header[1] == (3 if protected else 16), "Fixture namespace has another ACE type/inheritance"
            mask = wintypes.DWORD.from_address(ace.value + 4).value
            assert mask == 0x1f01ff, "Fixture namespace does not have exact full-access entries"
            entries.append({"sid": sid_text(ace.value + 8), "mask": mask, "flags": header[1]})
        assert {entry["sid"] for entry in entries} == {user_sid, "S-1-5-18"}
        assert sid_text(owner) == user_sid, "Private fixture namespace/file has another owner"
        return {"path": str(path), "ownerSid": sid_text(owner), "control": control.value, "entries": entries}
    finally:
        KERNEL.LocalFree(descriptor)


def expected_store(contents):
    return {"currentRevision": str(len(contents)), "revisions": [
        {"revision": str(index), "sha256": hashlib.sha256(data).hexdigest(), "size": str(len(data)),
         "namespace": "private-fixture", "owner": "client-fixture", "path": "scripts/fixture.bin", "bytesHex": data.hex()}
        for index, data in enumerate(contents, 1)]}


def check_store_files(root, contents):
    expected = expected_store(contents)
    with closing(sqlite3.connect((root / "library.db").as_uri() + "?mode=ro", uri=True)) as database:
        assert database.execute("PRAGMA quick_check").fetchall() == [("ok",)]
        assert database.execute("PRAGMA user_version").fetchone() == (1,)
        assert database.execute("PRAGMA foreign_key_check").fetchall() == []
        assert database.execute("SELECT revision FROM current_revision").fetchall() == [(len(contents),)]
        rows = database.execute("SELECT revision,sha256,size,namespace,owner,path FROM revisions ORDER BY revision").fetchall()
        wanted = [(index, hashlib.sha256(data).hexdigest(), len(data), "private-fixture", "client-fixture", "scripts/fixture.bin") for index, data in enumerate(contents, 1)]
        assert rows == wanted, "Independent SQLite reader found another immutable revision"
    blobs = {hashlib.sha256(data).hexdigest() + ".blob": data for data in contents}
    assert {path.name for path in (root / "blobs").iterdir()} == set(blobs), "Missing or unreferenced fixture blob"
    for name, data in blobs.items():
        assert (root / "blobs" / name).read_bytes() == data, "Independent complete blob bytes differ"
    assert {path.name for path in root.iterdir()} == {"library.db", "blobs"}, "Private fixture left a transient file"
    return {"store": expected, "files": tree_identity(root)}


def check_normal_reply(reply, wanted):
    assert reply["valid"] and "error" not in reply and reply["store"] == wanted, "Native revision/blob content differs from independent input"


def check_library_oracles(probe, architecture, token_oracle, file_oracle):
    directory = probe.output / "library-reference"
    directory.mkdir()
    root = directory / "private 源 🌸"
    parent, token_queries = token_oracle()
    binary = file_identity(probe.binary)
    image = {**file_oracle(probe.binary), "path": str(probe.binary.resolve()), "sha256": binary["sha256"]}
    observations = []

    def verify_identity(reply, identity):
        native = reply["identity"]
        assert native["pid"] == identity["pid"] and native["creationTime"] == identity["creationTime"]
        assert native["architecture"] == architecture and native["image"] == image
        assert {name: native[name] for name in parent} == parent

    def request(mode, destination=root, data=b"", expected=0):
        return {"mode": mode, "root": str(destination), "nonce": uuid.uuid4().hex, "bytesHex": data.hex(), "expectedRevision": expected}

    def call(fields):
        reply = probe.call("library-reference", fields)
        receipt = probe.observations[-1]
        verify_identity(reply, receipt["processIdentity"])
        assert reply["nonce"] == fields.get("nonce") and reply["sqliteVersion"] == "3.53.4"
        observations.append({"request": fields, "response": reply, "process": receipt["processIdentity"]})
        write_json(directory / "observations.json", observations)
        return reply

    original = 'script\0源 "quote", {field}\\tail 🌸'.encode("utf-8")
    second = bytes(range(256)) * 16 + "\r\nFurina 💙".encode("utf-8")
    contents = [original]
    check_normal_reply(call(request("create", data=original)), expected_store(contents))
    checks = [check_store_files(root, contents)]
    security = [directory_security(root, parent["userSid"], True),
                directory_security(root / "library.db", parent["userSid"], False),
                directory_security(next((root / "blobs").iterdir()), parent["userSid"], False)]
    for data in (second, b"", original, bytes(range(256)) * 256):
        before = tree_identity(root)
        reply = call(request("append", data=data, expected=len(contents)))
        assert reply["before"] == expected_store(contents)
        contents.append(data)
        check_normal_reply(reply, expected_store(contents))
        current = check_store_files(root, contents)
        assert all(item in current["files"] for item in before if item["path"] != str(root / "library.db")), "Append changed a prior blob"
        checks.append(current)
        check_normal_reply(call(request("read")), expected_store(contents))
    before = tree_identity(root)
    conflict = call(request("append", data=b"must not publish stale data", expected=len(contents) - 1))
    assert conflict["valid"] is False and conflict["error"] == {"code": "stale_revision", "nativeCode": 0}
    assert tree_identity(root) == before
    constraint = call(request("append_constraint", data=b"must roll back metadata and private blob", expected=len(contents)))
    assert constraint["valid"] is False and constraint["error"] == {"code": "metadata_constraint", "nativeCode": 19}
    assert constraint["rolledBack"] and constraint["publishedBlobRemoved"] and tree_identity(root) == before
    check_normal_reply(call(request("read")), expected_store(contents))
    duplicate = call(request("create", data=b"duplicate namespace"))
    assert duplicate["valid"] is False and duplicate["error"] == {"code": "namespace_create_failed", "nativeCode": 183}
    assert tree_identity(root) == before
    access = call(request("acl"))
    check_normal_reply(access, expected_store(contents))
    assert access["access"] == {"normalRead": True, "restrictedSid": "S-1-5-7", "attempts": [
        {"access": "read", "opened": False, "error": 5}, {"access": "write", "opened": False, "error": 5}]}
    assert tree_identity(root) == before
    holder_request = request("hold", expected=len(contents))
    encoded = json.dumps(holder_request, ensure_ascii=False).encode("utf-8")
    with OwnedJob() as job:
        holder = subprocess.Popen([str(probe.binary), "library-reference"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  creationflags=subprocess.CREATE_NO_WINDOW | CREATE_SUSPENDED)
        assigned = False
        holder_record = {"request": holder_request, "state": "created-suspended"}
        try:
            holder_identity = process_identity(holder)
            holder_record["process"] = holder_identity
            observations.append(holder_record)
            write_json(directory / "observations.json", observations)
            job.assign(holder)
            assigned = True
            startup_thread = resume_suspended_process(holder)
            holder.stdin.write(encoded)
            holder.stdin.close()
            holder.stdin = None
            ready = root / ("held-" + holder_request["nonce"] + ".json")
            deadline = time.monotonic() + min(probe.timeout, 20)
            while not ready.is_file():
                assert holder.poll() is None and time.monotonic() < deadline, "Native writer did not acquire its real transaction"
                time.sleep(0.02)
            held_bytes = ready.read_bytes()
            held = json.loads(held_bytes)
            verify_identity(held, holder_identity)
            assert held["nonce"] == holder_request["nonce"] and held["transactionHeld"] and held["currentRevision"] == str(len(contents))
            write_json(directory / "held-writer.json", held)
            modules = loaded_modules(holder)
            assert not any(Path(item["path"]).name.lower().startswith("x64dbg-mcp-server") for item in modules)
            assert next(item for item in modules if Path(item["path"]).resolve() == probe.binary.resolve()) == binary
            held_before = tree_identity(root)
            check_normal_reply(call(request("read")), expected_store(contents))
            busy = call(request("append", data=b"competing writer must not publish", expected=len(contents)))
            assert busy["valid"] is False and busy["error"] == {"code": "store_busy", "nativeCode": 5}
            assert tree_identity(root) == held_before and holder.poll() is None, "Competing writer changed the held store"
            release = root / ("release-" + holder_request["nonce"])
            release.write_bytes(b"release")
            stdout, stderr = holder.communicate(timeout=probe.timeout)
            assert holder.returncode == 0 and not stderr, (holder.returncode, stderr)
            released = json.loads(stdout)
            verify_identity(released, holder_identity)
            assert released["nonce"] == holder_request["nonce"] and released["rolledBack"]
            check_normal_reply(released, expected_store(contents))
            assert tree_identity(root) == before
            holder_record.update(response=released, startupThread=startup_thread, loadedModules=modules,
                                 heldReceipt=file_identity(directory / "held-writer.json"), exitCode=holder.returncode, state="completed")
        finally:
            if holder.poll() is None:
                if assigned:
                    job.close()
                else:
                    holder.kill()
                holder.communicate(timeout=10)
            holder_record["exitCode"] = holder.returncode
            write_json(directory / "observations.json", observations)
    check_normal_reply(call(request("append", data=b"writer after actual release", expected=len(contents))), expected_store([*contents, b"writer after actual release"]))
    contents.append(b"writer after actual release")
    checks.append(check_store_files(root, contents))
    first_blob = hashlib.sha256(original).hexdigest() + ".blob"
    controls = []
    for name, wanted in [("database_header", "store_corrupt"), ("schema_version", "schema_mismatch"),
                         ("missing_database", "store_open_failed"), ("missing_blob", "blob_missing"),
                         ("changed_blob", "blob_mismatch"), ("extra_blob_byte", "blob_mismatch"),
                         ("metadata_size", "blob_mismatch"), ("metadata_hash", "blob_missing"),
                         ("missing_revision", "metadata_inconsistent"), ("current_foreign_key", "metadata_inconsistent")]:
        damaged = directory / name
        shutil.copytree(root, damaged)
        database = damaged / "library.db"
        blob = damaged / "blobs" / first_blob
        if name == "database_header":
            with database.open("r+b") as stream:
                stream.write(b"Not SQLite data!")
        elif name == "schema_version":
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("PRAGMA user_version=2")
        elif name == "missing_database":
            database.unlink()
        elif name == "missing_blob":
            blob.unlink()
        elif name == "changed_blob":
            data = blob.read_bytes()
            blob.write_bytes(bytes([data[0] ^ 128]) + data[1:])
        elif name == "extra_blob_byte":
            blob.write_bytes(blob.read_bytes() + b"x")
        else:
            sql = {"metadata_size": "UPDATE revisions SET size=size+1 WHERE revision=1", "metadata_hash": "UPDATE revisions SET sha256='" + "0" * 64 + "' WHERE revision=1",
                   "missing_revision": "DELETE FROM revisions WHERE revision=" + str(len(contents)), "current_foreign_key": "UPDATE current_revision SET revision=999"}[name]
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(sql)
                connection.commit()
        previous = tree_identity(damaged)
        refused = call(request("read", damaged))
        assert refused["valid"] is False and refused["error"]["code"] == wanted, (name, refused)
        assert tree_identity(damaged) == previous, "Corrupt store was silently recreated or changed"
        controls.append({"name": name, "error": refused["error"], "unchangedFiles": previous, "nativeFault": True})
    absent = directory / "absent"
    missing = call(request("read", absent))
    assert missing["valid"] is False and missing["error"] == {"code": "store_open_failed", "nativeCode": 14} and not absent.exists()
    invalid = [("extra_field", {"extra": True}), ("wrong_mode", {"mode": "unknown"}), ("odd_hex", {"bytesHex": "0"}),
               ("uppercase_hex", {"bytesHex": "FF"}), ("excess_blob", {"bytesHex": "00" * 65537}),
               ("fractional_revision", {"expectedRevision": 1.5}), ("negative_revision", {"expectedRevision": -1}),
               ("relative_path", {"root": "relative"}), ("invalid_nonce", {"nonce": "non-hex"}),
               ("nonzero_initial_revision", {"expectedRevision": 1})]
    for name, changes in invalid:
        destination = directory / ("invalid-" + name)
        fields = {**request("create", destination, original), **changes}
        rejected = call(fields)
        assert rejected["valid"] is False and rejected["error"] == {"code": "invalid_input", "nativeCode": 0}
        assert not destination.exists()
    valid = call(request("read"))
    check_normal_reply(valid, expected_store(contents))
    checker_controls = []
    for name, changed in [("missing_revision", {**valid["store"], "revisions": valid["store"]["revisions"][:-1]}),
                          ("wrong_current", {**valid["store"], "currentRevision": "999"}),
                          ("wrong_bytes", {**valid["store"], "revisions": [{**valid["store"]["revisions"][0], "bytesHex": "00"}, *valid["store"]["revisions"][1:]]})]:
        altered = copy.deepcopy(valid)
        altered["store"] = changed
        try:
            check_normal_reply(altered, expected_store(contents))
        except AssertionError:
            checker_controls.append({"name": name, "status": "rejected", "nativeFault": False})
        else:
            raise AssertionError(f"Library checker admitted altered evidence: {name}")
    final = check_store_files(root, contents)
    write_json(directory / "observations.json", observations)
    return {"scope": "native SQLite/immutable blob/private ACL/transaction reference fixture", "observations": file_identity(directory / "observations.json"),
            "sourceBuiltSqliteVersion": "3.53.4", "independentPythonSqliteVersion": sqlite3.sqlite_version, "storeChecks": checks,
            "nativeFaultControls": controls, "rejectedInputs": len(invalid), "checkerControls": checker_controls,
            "namespaceSecurity": security, "parentTokenQueries": token_queries, "finalStore": final,
            "openGates": ["operational broker-managed library", "namespace authentication and grants", "durable publication journal and crash reconciliation", "migration/backup/trash/quota and reparse races"]}
