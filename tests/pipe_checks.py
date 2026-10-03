import copy
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess
import time
from types import SimpleNamespace

from wi_driver import KERNEL, OwnedJob, file_identity, process_identity, write_json


def pipe_process_identity(process, binary, token_oracle, file_oracle):
    token, queries = token_oracle(process._handle)
    image = file_identity(binary)
    path = ctypes.create_unicode_buffer(32768)
    length = wintypes.DWORD(len(path))
    KERNEL.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    if not KERNEL.QueryFullProcessImageNameW(process._handle, 0, path, ctypes.byref(length)):
        raise ctypes.WinError(ctypes.get_last_error())
    image_bytes = Path(binary).read_bytes()
    pe = struct.unpack_from("<I", image_bytes, 0x3c)[0]
    machine = struct.unpack_from("<H", image_bytes, pe + 4)[0]
    assert machine in (0x8664, 0x14c)
    return {**process_identity(process), **token, "architecture": "x64" if machine == 0x8664 else "x32",
            "image": {"path": path.value, "sha256": image["sha256"], **file_oracle(binary)}}, queries


def pipe_namespace(request, owner):
    value = {key: request[key] for key in ("installation", "profile", "channel")}
    value.update(userSid=owner["userSid"], logonSid=owner["logonSid"], sessionId=owner["sessionId"], wireVersion=1)
    digest = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return "\\\\.\\pipe\\wininspect-mcp-" + digest


def write_process_input(process, request):
    process.stdin.write(json.dumps(request, ensure_ascii=False).encode())
    process.stdin.close()
    process.stdin = None


def wait_pipe_receipt(process, path):
    expires = time.monotonic() + 10
    while time.monotonic() < expires:
        if path.exists():
            try:
                return json.loads(path.read_bytes())
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        if process.poll() is not None:
            raise AssertionError(f"Pipe server ended before ready: {process.communicate()}")
        time.sleep(0.01)
    raise AssertionError("Owned pipe server did not publish readiness")


def collect_pipe_process(process):
    output, errors = process.communicate(timeout=12)
    assert process.returncode == 0, (process.returncode, errors, output)
    return json.loads(output)


def independent_pipe_dacl(handle, object_type=6, include_owner=False):
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)]
    advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    acl, descriptor, owner = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    error = advapi.GetSecurityInfo(handle, object_type, 5 if include_owner else 4, ctypes.byref(owner) if include_owner else None, None, ctypes.byref(acl), None, ctypes.byref(descriptor))
    assert error == 0 and acl.value
    try:
        control, revision = wintypes.WORD(), wintypes.DWORD()
        assert advapi.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision))
        header = ctypes.string_at(acl, 8)
        count = struct.unpack_from("<H", header, 4)[0]
        rows = []
        for index in range(count):
            address = ctypes.c_void_p()
            assert advapi.GetAce(acl, index, ctypes.byref(address))
            data = ctypes.string_at(address, 8)
            text = wintypes.LPWSTR()
            assert advapi.ConvertSidToStringSidW(address.value + 8, ctypes.byref(text))
            try:
                rows.append({"type": data[0], "flags": data[1], "mask": struct.unpack_from("<I", data, 4)[0], "sid": text.value})
            finally:
                KERNEL.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        result = {"protected": bool(control.value & 0x1000), "aces": rows}
        if include_owner:
            text = wintypes.LPWSTR()
            assert advapi.ConvertSidToStringSidW(owner, ctypes.byref(text))
            try:
                result["ownerSid"] = text.value
            finally:
                KERNEL.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        return result
    finally:
        KERNEL.LocalFree(descriptor)


class OraclePipe:
    def __init__(self, name):
        KERNEL.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        KERNEL.WaitForSingleObject.restype = wintypes.DWORD
        KERNEL.ResetEvent.argtypes = [wintypes.HANDLE]
        KERNEL.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        KERNEL.CreateFileW.restype = wintypes.HANDLE
        self.handle = KERNEL.CreateFileW(name, 0x120083, 0, None, 3, 0x40110000, None)
        if self.handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        if self.handle:
            KERNEL.CloseHandle(self.handle)
            self.handle = None

    def transfer(self, data=None, size=0):
        class Overlapped(ctypes.Structure):
            _fields_ = [("internal", ctypes.c_size_t), ("internalHigh", ctypes.c_size_t), ("offset", wintypes.DWORD), ("offsetHigh", wintypes.DWORD), ("event", wintypes.HANDLE)]
        KERNEL.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        KERNEL.CreateEventW.restype = wintypes.HANDLE
        KERNEL.ReadFile.argtypes = KERNEL.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(Overlapped)]
        KERNEL.GetOverlappedResult.argtypes = [wintypes.HANDLE, ctypes.POINTER(Overlapped), ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
        KERNEL.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(Overlapped)]
        writing = data is not None
        count = len(data) if writing else size
        result = bytearray()
        event = KERNEL.CreateEventW(None, True, False, None)
        assert event
        try:
            while len(result) < count:
                remaining = count - len(result)
                buffer = ctypes.create_string_buffer(data[len(result):] if writing else remaining)
                operation = Overlapped(event=event)
                completed = wintypes.DWORD()
                KERNEL.ResetEvent(event)
                method = KERNEL.WriteFile if writing else KERNEL.ReadFile
                if not method(self.handle, buffer, remaining, ctypes.byref(completed), ctypes.byref(operation)):
                    error = ctypes.get_last_error()
                    if error != 997:
                        raise ctypes.WinError(error)
                    if KERNEL.WaitForSingleObject(event, 4000) != 0:
                        KERNEL.CancelIoEx(self.handle, ctypes.byref(operation))
                        KERNEL.GetOverlappedResult(self.handle, ctypes.byref(operation), ctypes.byref(completed), True)
                        raise AssertionError("Independent pipe transfer timed out after cancellation/drain")
                    if not KERNEL.GetOverlappedResult(self.handle, ctypes.byref(operation), ctypes.byref(completed), False):
                        raise ctypes.WinError(ctypes.get_last_error())
                assert 0 < completed.value <= remaining
                result.extend(buffer.raw[:completed.value])
            return bytes(result)
        finally:
            KERNEL.CloseHandle(event)

    def send(self, kind, request_id, envelope):
        body = json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode()
        self.transfer(struct.pack("<4sHHIIQ", b"WIMC", 1, kind, len(body) + 24, 0, request_id) + body)

    def receive(self):
        header = self.transfer(size=24)
        magic, version, kind, size, flags, request_id = struct.unpack("<4sHHIIQ", header)
        assert magic == b"WIMC" and version == 1 and flags == 0 and 26 <= size <= 8 * 1024 * 1024
        return kind, request_id, json.loads(self.transfer(size=size - 24))


def wire_handshake(pipe, request, own_identity, server_identity, server_build, variant):
    nonce = secrets.token_hex(32)
    generation = server_identity["creationTime"]
    context = {"brokerGeneration": generation}
    payload = {key: request[key] for key in ("installation", "profile", "channel")}
    payload.update(phase="hello", buildId=request["expectedBuildId"], identity=own_identity, nonce=nonce, peerNonce="0" * 64)
    envelope = {"context": context, "deadlineUtcMs": "0", "authenticationContextId": "pipe-" + nonce, "payload": payload}
    if variant == "wrong-build":
        payload["buildId"] = "0" * 64
    if variant == "wrong-profile-claim":
        payload["profile"] = "0" * 64
    if variant == "wrong-identity-claim":
        payload["identity"] = {**own_identity, "creationTime": str(int(own_identity["creationTime"]) + 1)}
    pipe.send(1, 1, envelope)
    if variant in ("wrong-build", "wrong-profile-claim", "wrong-identity-claim"):
        return {"sentHello": copy.deepcopy(envelope)}
    kind, correlation, reply = pipe.receive()
    assert kind == 2 and correlation == 1 and reply["context"] == context
    received = reply["payload"]
    assert received["identity"] == server_identity and received["buildId"] == server_build
    assert received["phase"] == "reply" and received["peerNonce"] == nonce
    assert reply["authenticationContextId"] == "pipe-" + nonce and len(received["nonce"]) == 64
    payload.update(phase="ack", peerNonce="0" * 64 if variant == "wrong-ack" else received["nonce"])
    pipe.send(1, 2 if variant == "bad-ack-correlation" else 1, envelope)
    return {"helloNonce": nonce, "reply": reply, "ack": copy.deepcopy(envelope)}


def check_local_pipes(probe, architecture, token_oracle, file_oracle):
    output = probe.output / "native-pipes"
    output.mkdir()
    binary = probe.binary
    catalog = json.loads((probe.output / "compiled-contracts.json").read_text())
    import sys
    controller = SimpleNamespace(pid=os.getpid(), _handle=KERNEL.GetCurrentProcess())
    controller_identity, controller_queries = pipe_process_identity(controller, Path(sys.executable), token_oracle, file_oracle)
    installation = hashlib.sha256(str(binary.parent.parent).encode()).hexdigest()
    profile = hashlib.sha256(b"owned native pipe profile").hexdigest()
    oracle_build = hashlib.sha256(b"independent Windows pipe wire oracle v1").hexdigest()
    payload = {"left": 6, "right": 7, "text": "Hu Tao ❤ Furina 💙 Columbina 💙\n" * 3000}
    expected = {"value": 42, "textSha256": hashlib.sha256(payload["text"].encode()).hexdigest()}
    variants = ["native-pair", "wire-pair", "early-request", "wrong-build", "wrong-profile-claim", "wrong-identity-claim", "wrong-ack", "bad-ack-correlation", "wrong-user", "wrong-session", "stale-generation", "wrong-image", "bad-magic", "bad-version", "oversized-header", "truncated-header", "stall-header", "stall-body"]
    pair_binaries = [("native-pair", binary, catalog["buildId"])]
    if architecture == "x32":
        other = binary.parent.parent / "build-x64/wininspect-mcp-contract-fixture.exe"
        other_catalog_path = probe.output.parent / "x64/compiled-contracts.json"
        if other.is_file() and other_catalog_path.is_file():
            other_catalog = json.loads(other_catalog_path.read_text())
            pair_binaries.append(("native-cross-architecture", other, other_catalog["buildId"]))
            pair_binaries.append(("native-cross-architecture-reverse", binary, catalog["buildId"]))
            variants.extend(("native-cross-architecture", "native-cross-architecture-reverse"))
    results = []
    for index, variant in enumerate(variants):
        directory = output / f"{index:02d}-{variant}"
        directory.mkdir()
        witness = directory / "witness.json"
        write_json(witness, {"value": 7})
        original = file_identity(witness)
        channel = secrets.token_hex(32)
        request = {"role": "server", "installation": installation, "profile": profile, "channel": channel, "timeoutMs": 1500,
                   "readyPath": str(directory / "ready.json"), "witnessPath": str(witness), "releasePath": str(directory / "release.json")}
        server_binary = other if variant == "native-cross-architecture-reverse" else binary
        server_build = other_catalog["buildId"] if variant == "native-cross-architecture-reverse" else catalog["buildId"]
        server = subprocess.Popen([str(server_binary), "local-pipe-reference"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
        client = None
        pipe = None
        job = OwnedJob()
        try:
            job.assign(server)
            server_identity, server_queries = pipe_process_identity(server, server_binary, token_oracle, file_oracle)
            native_pair = variant.startswith("native-")
            if native_pair:
                selected_binary, selected_build = next((b, build) for name, b, build in pair_binaries if name == variant)
                client = subprocess.Popen([str(selected_binary), "local-pipe-reference"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
                job.assign(client)
                client_identity, client_queries = pipe_process_identity(client, selected_binary, token_oracle, file_oracle)
            else:
                client_identity, client_queries = controller_identity, controller_queries
                selected_build = oracle_build
            request.update(expectedPeer=copy.deepcopy(client_identity), expectedBuildId=selected_build)
            if variant == "wrong-user": request["expectedPeer"]["userSid"] = "S-1-5-18"
            if variant == "wrong-session": request["expectedPeer"]["sessionId"] += 1
            if variant == "stale-generation": request["expectedPeer"]["creationTime"] = str(int(client_identity["creationTime"]) + 1)
            if variant == "wrong-image": request["expectedPeer"]["image"]["sha256"] = "0" * 64
            write_process_input(server, request)
            ready = wait_pipe_receipt(server, Path(request["readyPath"]))
            assert ready["identity"] == server_identity and ready["buildId"] == server_build
            assert ready["name"] == pipe_namespace(request, server_identity)
            protocol = {}
            if native_pair:
                collision = probe.call("local-pipe-reference", {**request, "role": "first"})
                assert not collision["valid"] and collision["error"]["code"] == "ipc_failure" and "error 5" in collision["error"]["message"], collision
                write_process_input(client, {**request, "role": "client", "expectedPeer": server_identity, "expectedBuildId": server_build, "payload": payload})
                client_result = collect_pipe_process(client)
                assert client_result["valid"] and client_result["observed"] == expected and client_result["peer"] == server_identity
                protocol.update(client=client_result, collision=collision)
            else:
                if variant == "wire-pair":
                    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
                    advapi.ImpersonateAnonymousToken.argtypes = [wintypes.HANDLE]
                    assert advapi.ImpersonateAnonymousToken(ctypes.c_void_p(-2))
                    try:
                        KERNEL.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
                        KERNEL.CreateFileW.restype = wintypes.HANDLE
                        denied = KERNEL.CreateFileW(ready["name"], 0x100083, 0, None, 3, 0x40110000, None)
                        access_error = ctypes.get_last_error()
                        assert denied == ctypes.c_void_p(-1).value and access_error == 5
                        protocol["anonymousAccessError"] = access_error
                    finally:
                        assert advapi.RevertToSelf()
                pipe = OraclePipe(ready["name"])
                if variant == "wire-pair":
                    dacl = independent_pipe_dacl(pipe.handle)
                    assert dacl == {"protected": True, "aces": [{"type": 0, "flags": 0, "mask": 0x120083, "sid": controller_identity["logonSid"]}]}, dacl
                    protocol["dacl"] = dacl
                if variant == "early-request":
                    pipe.send(3, 42, {"context": {"brokerGeneration": server_identity["creationTime"]}, "deadlineUtcMs": "0", "authenticationContextId": "fixture-channel", "payload": payload})
                    protocol["requestBeforeHandshake"] = True
                elif variant not in ("wrong-user", "wrong-session", "stale-generation", "wrong-image"):
                    protocol.update(wire_handshake(pipe, request, client_identity, server_identity, catalog["buildId"], variant))
                    if variant == "wire-pair":
                        envelope = {"context": {"brokerGeneration": server_identity["creationTime"]}, "deadlineUtcMs": "0", "authenticationContextId": "fixture-channel", "payload": payload}
                        pipe.send(3, 42, envelope)
                        kind, correlation, response = pipe.receive()
                        assert kind == 4 and correlation == 42 and response["payload"] == expected
                        protocol["response"] = response
                    elif variant in ("bad-magic", "bad-version", "oversized-header", "truncated-header", "stall-header", "stall-body"):
                        header = struct.pack("<4sHHIIQ", b"BAD!" if variant == "bad-magic" else b"WIMC", 2 if variant == "bad-version" else 1, 3, 8 * 1024 * 1024 + 1 if variant == "oversized-header" else 128, 0, 42)
                        sent = header[:9] if variant in ("truncated-header", "stall-header") else header
                        pipe.transfer(sent)
                        protocol["rawBytesHex"] = sent.hex()
                        if variant == "truncated-header": pipe.close()
            write_json(Path(request["releasePath"]), {"released": True})
            observed = collect_pipe_process(server)
            if variant in ("native-pair", "wire-pair", "native-cross-architecture", "native-cross-architecture-reverse"):
                assert observed["valid"] and observed["peer"] == client_identity and observed["observed"] == expected, observed
                assert json.loads(witness.read_bytes()) == expected
                assert file_identity(witness)["sha256"] != original["sha256"]
            else:
                assert not observed["valid"] and file_identity(witness) == original, observed
                if variant in ("wrong-user", "wrong-session", "stale-generation", "wrong-image"):
                    assert observed["error"]["code"] == "ipc_peer_mismatch"
                elif variant.startswith("wrong-"):
                    assert observed["error"]["code"] == "ipc_handshake_mismatch"
                elif variant.startswith("stall-"):
                    assert observed["error"]["code"] == "ipc_timeout"
            results.append({"variant": variant, "serverBinary": file_identity(server_binary), "serverBuildId": server_build, "serverIdentity": server_identity, "clientIdentity": client_identity, "serverTokenQueries": server_queries,
                            "clientTokenQueries": client_queries, "ready": ready, "request": request, "protocol": protocol, "observed": observed,
                            "witness": file_identity(witness), "originalWitness": original, "serverExitCode": server.returncode,
                            "clientExitCode": client.returncode if client else None})
            write_json(directory / "record.json", results[-1])
        finally:
            if pipe: pipe.close()
            job.close()
            for process in (server, client):
                if process and process.poll() is None:
                    process.wait(timeout=5)
    write_json(output / "observations.json", results)
    return {"nativePipeCases": results, "actualPipeCaseCount": len(results), "originalWitnessValue": 7, "completedWitnessValue": 42,
            "protectedDacl": True, "anonymousAccessRefused": True, "firstInstanceCollisionRefused": True,
            "crossArchitectureChannels": sum(v["variant"].startswith("native-cross-architecture") for v in results), "ordinaryLocalHandshakeOnly": True}


def check_broker_lifetime(probe, architecture, token_oracle, file_oracle):
    output = probe.output / "broker-lifetime"
    output.mkdir()
    profile_root = output / "Hu Tao ❤ profiles with spaces"
    profile_root.mkdir()
    connector = probe.binary.parent / "wininspect-mcp-connect.exe"
    broker = probe.binary.parent / "wininspect-mcp.exe"
    profile = secrets.token_hex(32)
    other_profile = secrets.token_hex(32)
    job = OwnedJob()
    processes, broker_handles, observations = [], [], []
    KERNEL.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    KERNEL.OpenProcess.restype = wintypes.HANDLE
    KERNEL.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    KERNEL.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    KERNEL.CreateFileW.restype = wintypes.HANDLE

    def canonical_directory(path, volume):
        opened = KERNEL.CreateFileW(str(path), 0x120080, 3, None, 3, 0x02200000, None)
        assert opened and opened != ctypes.c_void_p(-1).value
        try:
            KERNEL.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
            buffer = ctypes.create_unicode_buffer(32768)
            count = KERNEL.GetFinalPathNameByHandleW(opened, buffer, len(buffer), volume)
            assert 0 < count < len(buffer)
            return buffer.value
        finally:
            KERNEL.CloseHandle(opened)

    def process_snapshot(stage):
        class ProcessEntry(ctypes.Structure):
            _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD), ("pid", wintypes.DWORD), ("heap", ctypes.c_size_t),
                        ("module", wintypes.DWORD), ("threads", wintypes.DWORD), ("parent", wintypes.DWORD),
                        ("priority", wintypes.LONG), ("flags", wintypes.DWORD), ("image", wintypes.WCHAR * 260)]
        KERNEL.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        KERNEL.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        KERNEL.Process32FirstW.argtypes = KERNEL.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
        handle = KERNEL.CreateToolhelp32Snapshot(2, 0)
        assert handle and handle != ctypes.c_void_p(-1).value
        rows = []
        try:
            entry = ProcessEntry(size=ctypes.sizeof(ProcessEntry))
            assert KERNEL.Process32FirstW(handle, ctypes.byref(entry))
            while True:
                rows.append({"pid": entry.pid, "parentPid": entry.parent, "image": entry.image})
                if not KERNEL.Process32NextW(handle, ctypes.byref(entry)):
                    assert ctypes.get_last_error() == 18
                    break
        finally:
            KERNEL.CloseHandle(handle)
        assert any(v["pid"] == os.getpid() for v in rows)
        debuggers = [v for v in rows if v["image"].casefold() in ("x64dbg.exe", "x32dbg.exe")]
        assert not debuggers, debuggers
        observations.append({"kind": "process-snapshot", "stage": stage, "debuggerProcesses": debuggers, "positiveControllerPid": os.getpid(), "nativeComponents": [v for v in rows if v["image"].casefold().startswith("wininspect-mcp")]})
        return rows

    def start(name, profile_id, root=profile_root):
        stream = (output / f"{name}.jsonl").open("wb")
        errors = (output / f"{name}.stderr").open("wb")
        try:
            process = subprocess.Popen([str(connector), "--local-control", "--profile", profile_id, "--profile-root", str(root)], stdin=subprocess.PIPE, stdout=stream, stderr=errors, creationflags=subprocess.CREATE_NO_WINDOW)
            process.native_profile_id = profile_id
            processes.append(process)
            try:
                job.assign(process)
            except BaseException:
                process.kill()
                process.wait(timeout=5)
                raise
        finally:
            stream.close()
            errors.close()
        identity, queries = pipe_process_identity(process, connector, token_oracle, file_oracle)
        observations.append({"kind": "connector", "name": name, "identity": identity, "tokenQueries": queries})
        return process, output / f"{name}.jsonl"

    def request(client, operation):
        process, path = client
        previous = path.stat().st_size
        process.stdin.write(json.dumps({"operation": operation}).encode() + b"\n")
        process.stdin.flush()
        expires = time.monotonic() + 15
        while time.monotonic() < expires:
            raw = path.read_bytes()[previous:]
            if raw.endswith(b"\n"):
                value = json.loads(raw)
                assert value["operation"] == operation and value["debuggerInstances"] == value["operationalTools"] == []
                assert value["profile"] == process.native_profile_id
                observations.append({"kind": "response", "value": value, "output": file_identity(path)})
                return value
            assert process.poll() is None, (process.returncode, path.with_suffix(".stderr").read_bytes())
            time.sleep(0.01)
        raise AssertionError("Actual native connector did not return a local-control response")

    def observe_broker(response, root=profile_root):
        expected = response["broker"]
        handle = KERNEL.OpenProcess(0x100000 | 0x1000, False, expected["pid"])
        assert handle
        broker_handles.append(handle)
        process = SimpleNamespace(pid=expected["pid"], _handle=handle)
        actual, queries = pipe_process_identity(process, broker, token_oracle, file_oracle)
        assert actual == expected and actual["architecture"] == architecture and actual["integrity"] == "medium" and not actual["elevated"]
        rows = process_snapshot("actual-broker-observation")
        assert any(v["pid"] == actual["pid"] and v["image"].casefold() == "wininspect-mcp.exe" for v in rows)
        observations.append({"kind": "broker", "identity": actual, "tokenQueries": queries, "binary": file_identity(broker), "processSnapshot": next(v for v in rows if v["pid"] == actual["pid"])})
        directory = root / response["profile"]
        config_path = directory / "profile.json"
        config = json.loads(config_path.read_bytes())
        installation = hashlib.sha256(canonical_directory(broker.parent, 0).encode()).hexdigest()
        assert response["installation"] == installation
        expected_config = {"schemaVersion": 1, "installation": installation, "profile": response["profile"], "ownerSid": actual["userSid"], "httpPort": 9094}
        assert config == response["configuration"] == expected_config
        records = [path for path in directory.glob("registration-*.json") if path.name.endswith(f"-{actual['pid']}-{actual['creationTime']}.json")]
        assert len(records) == 1
        record_path = records[0]
        endpoint_profile = hashlib.sha256(json.dumps({"profile": response["profile"], "root": canonical_directory(root, 1)}, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        namespace = {"installation": installation, "profile": endpoint_profile, "userSid": actual["userSid"], "logonSid": actual["logonSid"], "sessionId": actual["sessionId"], "wireVersion": 1}
        key = hashlib.sha256(json.dumps(namespace, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        assert record_path.name == f"registration-{key}-{actual['pid']}-{actual['creationTime']}.json"
        expected_record = {"schemaVersion": 1, "installation": response["installation"], "profile": response["profile"], "buildId": response["buildId"], "wireVersion": 1,
                           "process": actual, "configuredHttpPort": 9094, "port": None}
        assert json.loads(record_path.read_bytes()) == response["registration"] == expected_record
        security = []
        for path in (directory, config_path, record_path):
            object_handle = KERNEL.CreateFileW(str(path), 0x120080, 3, None, 3, 0x02200000, None)
            assert object_handle and object_handle != ctypes.c_void_p(-1).value
            try:
                descriptor = independent_pipe_dacl(object_handle, 1, True)
                assert descriptor["ownerSid"] == actual["userSid"] and len(descriptor["aces"]) == 1
                ace = descriptor["aces"][0]
                assert ace["type"] == 0 and ace["mask"] == 0x1f01ff and ace["sid"] == actual["userSid"]
                if path == directory:
                    assert descriptor["protected"] and ace["flags"] == 3
                security.append({"path": str(path), "actualSecurity": descriptor})
            finally:
                KERNEL.CloseHandle(object_handle)
        observations.append({"kind": "profile-storage", "configuration": file_identity(config_path), "registration": file_identity(record_path), "actualSecurity": security,
                             "configurationValue": config, "registrationValue": expected_record})
        return handle, actual

    def finish(client):
        process, path = client
        if process.stdin and not process.stdin.closed:
            process.stdin.close()
        assert process.wait(timeout=10) == 0
        observations.append({"kind": "connector-exit", "identity": process_identity(process), "exitCode": process.returncode, "output": file_identity(path)})

    def terminal(handle, identity):
        assert KERNEL.WaitForSingleObject(handle, 10000) == 0
        code = wintypes.DWORD()
        assert KERNEL.GetExitCodeProcess(handle, ctypes.byref(code)) and code.value == 0
        observations.append({"kind": "broker-exit", "identity": identity, "exitCode": code.value})

    def still_live(handle, identity, stage):
        waited = KERNEL.WaitForSingleObject(handle, 0)
        assert waited == 258
        observations.append({"kind": "broker-live", "stage": stage, "identity": identity, "waitResult": waited})

    def profile_faults(handle, identity):
        original = next(v for v in observations if v["kind"] == "profile-storage")
        config_path = Path(original["configuration"]["path"])
        record_path = Path(original["registration"]["path"])
        controls = []
        changed_install = {**original["configurationValue"], "installation": "0" * 64}
        changed_version = {**original["configurationValue"], "schemaVersion": 2}
        changed_generation = copy.deepcopy(original["registrationValue"])
        changed_generation["process"]["creationTime"] = str(int(identity["creationTime"]) + 1)
        changed_image = copy.deepcopy(original["registrationValue"])
        changed_image["process"]["image"]["sha256"] = "0" * 64
        cases = [("invalid-configuration-json", config_path, b'{"schemaVersion":', "invalid_json"),
                 ("wrong-configuration-installation", config_path, json.dumps(changed_install).encode(), "profile_identity_mismatch"),
                 ("unsupported-configuration-version", config_path, json.dumps(changed_version).encode(), "invalid_argument"),
                 ("stale-registration-generation", record_path, json.dumps(changed_generation).encode(), "profile_registration_mismatch"),
                 ("wrong-registration-image", record_path, json.dumps(changed_image).encode(), "profile_registration_mismatch"),
                 ("extra-registration-field", record_path, json.dumps({**original["registrationValue"], "unexpected": True}).encode(), "profile_registration_mismatch")]
        command = [str(connector), "--local-control", "--profile", profile, "--profile-root", str(profile_root)]
        for name, path, changed, code in cases:
            retained = path.read_bytes()
            retained_identity = file_identity(path)
            try:
                path.write_bytes(changed)
                before = file_identity(path)
                stdout, stderr, receipt = probe.execute(command, b'{"operation":"status"}\n', expected_exit=1)
                assert not stdout and json.loads(stderr)["code"] == code
                assert file_identity(path) == before
                still_live(handle, identity, name)
                controls.append({"case": name, "nativeRefusal": receipt, "before": before, "after": file_identity(path)})
            finally:
                path.write_bytes(retained)
            assert file_identity(path) == retained_identity
            controls[-1]["restored"] = retained_identity
        link = output / "controlled-profile-hardlink.json"
        os.link(config_path, link)
        try:
            before = file_identity(config_path)
            stdout, stderr, receipt = probe.execute(command, b'{"operation":"status"}\n', expected_exit=1)
            assert not stdout and json.loads(stderr)["code"] == "profile_record_invalid"
            assert file_identity(config_path) == before
            still_live(handle, identity, "hardlinked-configuration")
            controls.append({"case": "hardlinked-configuration", "nativeRefusal": receipt, "before": before, "after": file_identity(config_path), "actualLinkCount": config_path.stat().st_nlink})
            assert controls[-1]["actualLinkCount"] == 2
        finally:
            link.unlink()
        foreign_profile = secrets.token_hex(32)
        foreign = profile_root / foreign_profile
        foreign.mkdir()
        sentinel = foreign / "profile.json"
        sentinel.write_bytes(b'{"sentinel":7}')
        before = file_identity(sentinel)
        stdout, stderr, receipt = probe.execute([str(broker), "--serve-local", "--profile", foreign_profile, "--profile-root", str(profile_root)], expected_exit=1)
        assert not stdout and json.loads(stderr)["code"] == "profile_security_invalid"
        assert file_identity(sentinel) == before
        still_live(handle, identity, "foreign-profile-security")
        controls.append({"case": "foreign-profile-security", "nativeRefusal": receipt, "before": before, "after": file_identity(sentinel)})
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        advapi.ImpersonateAnonymousToken.argtypes = [wintypes.HANDLE]
        assert advapi.ImpersonateAnonymousToken(ctypes.c_void_p(-2))
        try:
            denied = KERNEL.CreateFileW(str(config_path), 1, 3, None, 3, 0, None)
            error = ctypes.get_last_error()
            if denied and denied != ctypes.c_void_p(-1).value:
                KERNEL.CloseHandle(denied)
            assert denied == ctypes.c_void_p(-1).value and error == 5
        finally:
            assert advapi.RevertToSelf()
        observations.append({"kind": "profile-faults", "actualNativeRefusals": controls, "anonymousReadError": error})

    try:
        process_snapshot("before-cold-start")
        first, second = start("first", profile), start("second", profile)
        before = request(first, "status")
        handle, identity = observe_broker(before)
        assert request(second, "status")["broker"] == identity
        stdout, stderr, duplicate = probe.execute([str(broker), "--serve-local", "--profile", profile, "--profile-root", str(profile_root)], expected_exit=1)
        assert not stdout and json.loads(stderr)["code"] == "broker_already_running"
        refusals = []
        for label, arguments, payload in (
                ("invalid-profile", ["--profile", "A" * 64], b'{"operation":"status"}\n'),
                ("debugger-operation", ["--profile", profile], b'{"operation":"target_open"}\n'),
                ("extra-property", ["--profile", profile], b'{"operation":"status","targetId":"absent"}\n'),
                ("bounded-input", ["--profile", profile], b"x" * 4097)):
            stdout, stderr, refusal = probe.execute([str(connector), "--local-control", *arguments, "--profile-root", str(profile_root)], payload, expected_exit=1)
            assert not stdout and json.loads(stderr)["code"] == ("payload_limit" if label == "bounded-input" else "invalid_argument")
            refusals.append({"case": label, "observation": refusal})
            still_live(handle, identity, label)
        finish(first)
        still_live(handle, identity, "first-connector-EOF")
        assert request(second, "status")["broker"] == identity
        finish(second)
        still_live(handle, identity, "second-connector-EOF")
        profile_faults(handle, identity)
        isolated = start("isolated", other_profile)
        isolated_response = request(isolated, "status")
        other_handle, other_identity = observe_broker(isolated_response)
        assert other_identity["pid"] != identity["pid"] and isolated_response["installation"] == before["installation"] and isolated_response["profile"] != before["profile"]
        alternate_root = output / "Furina 💙 second root"
        alternate_root.mkdir()
        root_twin = start("separate-root", profile, alternate_root)
        root_response = request(root_twin, "status")
        root_handle, root_identity = observe_broker(root_response, alternate_root)
        assert root_identity["pid"] not in (identity["pid"], other_identity["pid"]) and root_response["profile"] == before["profile"]
        assert request(root_twin, "shutdown")["broker"] == root_identity
        finish(root_twin)
        terminal(root_handle, root_identity)
        still_live(handle, identity, "separate-root-shutdown")
        closer = start("closer", profile)
        assert request(closer, "shutdown")["broker"] == identity
        finish(closer)
        terminal(handle, identity)
        still_live(other_handle, other_identity, "other-profile-shutdown")
        original_store = next(v for v in observations if v["kind"] == "profile-storage")
        config_path = Path(original_store["configuration"]["path"])
        original_bytes = config_path.read_bytes()
        registrations_before = [file_identity(path) for path in sorted(config_path.parent.glob("registration-*.json"))]
        try:
            config_path.write_bytes(json.dumps({**json.loads(original_bytes), "schemaVersion": 2}).encode())
            bad_identity = file_identity(config_path)
            stdout, stderr, cold_refusal = probe.execute([str(connector), "--local-control", "--profile", profile, "--profile-root", str(profile_root)], b'{"operation":"status"}\n', expected_exit=1)
            assert not stdout and json.loads(stderr)["code"] == "invalid_argument"
            assert file_identity(config_path) == bad_identity
            assert [file_identity(path) for path in sorted(config_path.parent.glob("registration-*.json"))] == registrations_before
            observations.append({"kind": "cold-profile-refusal", "nativeRefusal": cold_refusal, "before": bad_identity, "after": file_identity(config_path), "registrationsUnchanged": registrations_before})
        finally:
            config_path.write_bytes(original_bytes)
        assert request(isolated, "shutdown")["broker"] == other_identity
        finish(isolated)
        terminal(other_handle, other_identity)
        restarted = start("restarted", profile)
        restarted_response = request(restarted, "status")
        restarted_handle, restarted_identity = observe_broker(restarted_response)
        assert restarted_identity["creationTime"] != identity["creationTime"]
        stored = [v for v in observations if v["kind"] == "profile-storage"]
        assert stored[0]["configuration"] == stored[-1]["configuration"]
        assert file_identity(stored[0]["registration"]["path"]) == stored[0]["registration"]
        assert stored[0]["registration"]["path"] != stored[-1]["registration"]["path"]
        assert request(restarted, "shutdown")["broker"] == restarted_identity
        finish(restarted)
        terminal(restarted_handle, restarted_identity)
        write_json(output / "observations.json", observations)
        return {"nativeBrokerLifetime": observations, "normalConnectorExits": 6, "normalBrokerExits": 4,
                "sharedGeneration": identity, "isolatedGeneration": other_identity, "separateRootGeneration": root_identity, "restartedGeneration": restarted_identity,
                "duplicateBrokerRefused": duplicate, "localControlRefusals": refusals, "profilePersistenceVerified": True,
                "profileRoot": str(profile_root), "operationalMcpTransport": False, "workerRegistrationVerified": False}
    finally:
        job.close()
        for process in processes:
            if process.poll() is None:
                process.wait(timeout=5)
        for handle in broker_handles:
            KERNEL.CloseHandle(handle)
        write_json(output / "observations.json", observations)
