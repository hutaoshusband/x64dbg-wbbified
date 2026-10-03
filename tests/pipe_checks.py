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


def independent_pipe_dacl(handle):
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)]
    advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    acl, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
    error = advapi.GetSecurityInfo(handle, 6, 4, None, None, ctypes.byref(acl), None, ctypes.byref(descriptor))
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
        return {"protected": bool(control.value & 0x1000), "aces": rows}
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
