from datetime import datetime, timezone
import fnmatch
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import time

from wi_driver import McpError, ROOT, compiler_environment, file_identity, process_identity, write_json


CASE_NAMES = ("test_compiled_schema_catalog", "test_contract_boundaries", "test_context_roundtrip",
              "test_bounded_json", "test_target_pointer_ranges", "test_source_dependencies", "test_http_parser",
              "test_result_contracts", "test_registry_contracts", "test_registry_dispatch")


def build_contract_fixture(output, architecture):
    build = Path(output) / f"build-{architecture}"
    build.mkdir()
    source = ROOT / "x64dbg"
    environment = compiler_environment(architecture)
    qt = source / ("build64" if architecture == "x64" else "build32") / "_deps/qt5-src/lib/cmake/Qt5"
    configure = ["cmake", "-S", str(source), "-B", str(build), "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
                 "-DX64DBG_BUILD_IN_TREE=OFF", "-DX64DBG_BUILD_MCP=ON", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"]
    if qt.is_dir():
        configure.append(f"-DQt5_DIR={qt}")
    commands = []
    source_paths = [source / "cmake.toml", source / "CMakeLists.txt", *sorted((source / "src/mcp").rglob("*"))]
    source_inputs = [file_identity(path) for path in source_paths if path.is_file()]
    with (build / "build.log").open("w", encoding="utf-8") as log:
        for command in (configure, ["cmake", "--build", str(build), "--target", "mcp_contract_fixture", "--parallel", "6"]):
            print(f"Building MCP contracts {architecture}: {command[1]}", flush=True)
            process = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
            log.flush()
            commands.append({"command": command, "exitCode": process.returncode})
            write_json(build / "commands.json", commands)
            if process.returncode:
                raise McpError(f"Contract fixture build failed: {(build / 'build.log').read_text(encoding='utf-8')[-6000:]}")
    binary = build / "wininspect-mcp-contract-fixture.exe"
    image = binary.read_bytes()
    pe_offset = struct.unpack_from("<I", image, 0x3c)[0]
    assert image[:2] == b"MZ" and image[pe_offset:pe_offset + 4] == b"PE\0\0"
    assert struct.unpack_from("<H", image, pe_offset + 4)[0] == (0x8664 if architecture == "x64" else 0x14c)
    manifest = {"architecture": architecture, "sourceHead": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "sourceStatus": subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True),
                "sourceInputs": source_inputs, "commands": commands, "binary": file_identity(binary),
                "buildInputs": file_identity(build / "CMakeCache.txt"),
                "compiledDependencies": [file_identity(path) for path in sorted(build.glob("mcp_*.lib"))],
                "compileCommands": json.loads((build / "compile_commands.json").read_text(encoding="utf-8")),
                "notices": [file_identity(path) for path in sorted((build / "mcp-notices").glob("*.txt"))]}
    for input_file in source_inputs:
        assert file_identity(input_file["path"])["sha256"] == input_file["sha256"], "Build source changed during compilation"
    write_json(build / "build-manifest.json", manifest)
    return binary


class ContractProbe:
    def __init__(self, binary, output, timeout):
        self.binary = binary
        self.output = Path(output)
        self.output.mkdir()
        self.timeout = timeout
        self.observations = []

    def call(self, mode, value=None, argument=None, raw=None):
        command = [str(self.binary), mode]
        if argument is not None:
            command.append(argument)
        payload = raw if raw is not None else b"" if value is None else json.dumps(value, ensure_ascii=False).encode("utf-8")
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        timed_out = False
        try:
            identity = process_identity(process)
            stdout, stderr = process.communicate(payload, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            stdout, stderr = process.communicate()
        except BaseException:
            if process.poll() is None:
                process.kill()
            process.communicate()
            raise
        observation = {"command": command, "inputSha256": hashlib.sha256(payload).hexdigest(), "inputSize": len(payload),
                       "processIdentity": identity, "exitCode": process.returncode, "timedOut": timed_out, "stderr": stderr.decode("utf-8", "replace")}
        self.observations.append(observation)
        assert not timed_out, f"Owned contract fixture timed out: {identity}"
        assert process.returncode == 0, observation
        response = json.loads(stdout)
        observation["response"] = response
        return response


def independent_validators(catalog):
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError as error:
        raise McpError("The mcp-contracts phase requires the test-only requirements in tests/requirements.txt") from error
    formats = FormatChecker()
    checks = {
        "uint64-decimal": lambda value: bool(re.fullmatch(r"0|[1-9][0-9]{0,19}", value)) and int(value) <= 2**64 - 1,
        "uint64-hex": lambda value: bool(re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]{0,15})", value)),
        "opaque-id": lambda value: bool(re.fullmatch(r"[A-Za-z0-9_.:-]+", value)),
        "hex-bytes": lambda value: bool(re.fullmatch(r"(?:[0-9a-f]{2})+", value)),
        "sha256": lambda value: bool(re.fullmatch(r"[0-9a-f]{64}", value)),
        "utf8-text": lambda value: "\0" not in value,
        "windows-absolute-path": lambda value: bool(re.fullmatch(r"(?:[A-Za-z]:[\\/].*|\\\\(?!\.\\|\?\\)[^\\]+\\[^\\]+(?:\\.*)?|\\\\\?\\[A-Za-z]:[\\/].*|\\\\\?\\UNC\\[^\\]+\\[^\\]+(?:\\.*)?)", value)) and not any(ord(character) < 32 for character in value)
    }
    for name, check in checks.items():
        formats.checks(name)(lambda value, check=check: not isinstance(value, str) or check(value))
    validators = {}
    for entry in catalog["contracts"]:
        Draft202012Validator.check_schema(entry["schema"])
        assert entry["name"] not in validators
        assert entry["schema"]["$id"] == f"urn:wininspect:mcp:contract:v1:{entry['name']}"
        validators[entry["name"]] = Draft202012Validator(entry["schema"], format_checker=formats)
    return validators


def contract_examples():
    target = {"instanceId": "instance-1", "targetId": "target-1", "targetGeneration": "18446744073709551615"}
    paused = {**target, "stopEpoch": "9007199254740993", "threadId": 4294967295}
    mutation = {**paused, "leaseId": "lease-1", "idempotencyKey": "request-1"}
    examples = {
        "InstanceRef": [(True, {"instanceId": "instance-1"}), (False, {}), (False, {"instanceId": 1})],
        "TargetRef": [(True, target), (False, {**target, "targetGeneration": 9007199254740993}), (False, {**target, "targetGeneration": "18446744073709551616"})],
        "PausedContext": [(True, paused), (False, target), (False, {**paused, "threadId": 0}), (False, {**paused, "threadId": 4294967296})],
        "MutationContext": [(True, mutation), (False, paused), (False, {**mutation, "leaseId": ""})],
        "AddressRef": [(True, {"addressHex": "0xffffffffffffffff"}), (True, {"moduleId": "module-1", "rvaHex": "0x123"}), (True, {"expression": "Hu Tao ❤ + rax"}),
                       (False, {}), (False, {"moduleId": "module-1"}), (False, {"addressHex": "0x1", "expression": "rax"})],
        "AddressRange": [(True, {"address": {"addressHex": "0x0"}, "size": 1048576}), (False, {"address": {"addressHex": "0x0"}, "size": 0}), (False, {"address": {"expression": "rax"}, "size": 1048577})],
        "FileRef": [(True, {"artifactId": "artifact-1"}), (True, {"path": "C:\\Hu Tao ❤\\target.exe"}), (True, {"path": "\\\\server\\share\\file.exe"}),
                    (True, {"path": "\\\\?\\C:\\target.exe"}), (True, {"path": "\\\\?\\UNC\\server\\share\\file.exe"}),
                    (False, {"path": "relative.exe"}), (False, {"path": "C:relative.exe"}), (False, {"path": "\\\\.\\pipe\\debug"}), (False, {"path": "C:\\file\0.exe"}),
                    (False, {"path": "C:\\target.exe", "artifactId": "artifact-1"})],
        "ExpectedBytes": [(True, {"bytesHex": "0001ff"}), (True, {"bytesHex": "00" * 1048576}), (False, {"bytesHex": "00" * 1048577}),
                          (True, {"address": {"addressHex": "0x1"}, "size": 1, "sha256": "0" * 64}),
                          (False, {"bytesHex": "0"}), (False, {"bytesHex": "GG"}), (False, {"bytesHex": "00", "size": 1})],
        "Page": [(True, {}), (True, {"limit": 1000}), (True, {"limit": 100.0}), (False, {"limit": 0}), (False, {"limit": 1001}), (False, {"limit": True}), (False, {"limit": 1.5})],
        "Deadline": [(True, {}), (True, {"timeoutMs": 1}), (True, {"timeoutMs": 60000}), (False, {"timeoutMs": 0}), (False, {"timeoutMs": 60001}), (False, {"timeoutMs": "60000"})],
        "Hex64": [(True, "0x0"), (True, "0xffffffffffffffff"), (False, 18446744073709551615), (False, "0x10000000000000000"), (False, "0x00"), (False, "0xFF")],
        "Decimal64": [(True, "0"), (True, "18446744073709551615"), (False, "18446744073709551616"), (False, "01"), (False, "-1"), (False, 9007199254740993)]
    }
    recovery = {"capabilityId": "operation_reconcile", "retry": "after_reconciliation", "reason": "Inspect the operation"}
    evidence = {"kind": "readback", "source": "native_fixture", "summary": "Observed exact bytes"}
    examples.update({
        "LibraryRef": [(True, {"namespaceId": "private-1", "objectId": "script-1", "revision": "rev-2"}), (False, {"namespaceId": "private-1", "objectId": "script-1"})],
        "JobRef": [(True, {"jobId": "job-1"}), (False, {"jobId": None})],
        "EventRef": [(True, {"cursor": "opaque:9007199254740993"}), (False, {"cursor": 9007199254740993})],
        "RecoveryRoute": [(True, recovery), (False, {**recovery, "retry": "automatically"})],
        "DomainError": [(True, {"code": "timeout_unknown", "message": "Reconcile", "path": "", "recovery": recovery}), (False, {"code": "success", "message": "Incorrect", "path": ""})],
        "ResultContext": [(True, {"brokerGeneration": "18446744073709551615"}), (True, target), (True, paused), (False, {**target, "brokerGeneration": "1"})],
        "VerificationEvidence": [(True, evidence), (True, {**evidence, "artifactId": "artifact-1", "sha256": "0" * 64}), (False, {**evidence, "sha256": "0" * 63})],
        "Verification": [(True, {"status": "verified", "evidence": [evidence]}), (True, {"status": "unverified", "evidence": [], "followUp": recovery}),
                         (True, {"status": "pending", "evidence": []}), (False, {"status": "verified", "evidence": []}), (False, {"status": "unverified", "evidence": []}), (False, {"status": "passed", "evidence": [evidence]})],
        "ResultWarning": [(True, {"code": "scan_holes", "message": "Some ranges are unreadable"}), (False, {"code": "", "message": "Missing warning code"})],
        "ResultTimings": [(True, {"startedUtcMs": "9007199254740993", "elapsedUs": "18446744073709551615", "queueUs": "0"}), (False, {"startedUtcMs": 9007199254740993, "elapsedUs": "1", "queueUs": "0"})],
        "EffectObservation": [(True, {"stepId": "write-1", "status": "restored", "summary": "Original bytes observed"}), (False, {"stepId": "write-1", "status": "successful", "summary": "Unknown status"})],
        "ResultPagination": [(True, {"snapshotVersion": "9007199254740993", "complete": True}), (True, {"snapshotVersion": "1", "complete": False, "nextCursor": "next"}),
                             (False, {"snapshotVersion": "1", "complete": False}), (False, {"snapshotVersion": "1", "complete": True, "nextCursor": "contradiction"}), (False, {"snapshotVersion": "1", "complete": 1})]
    })
    return examples, mutation


def check_results(probe, formats):
    from jsonschema import Draft202012Validator
    fixture = probe.call("result-cases")
    for schema in (fixture["schema"], fixture["unverifiedSchema"]):
        Draft202012Validator.check_schema(schema)
    strict = Draft202012Validator(fixture["schema"], format_checker=formats)
    relaxed = Draft202012Validator(fixture["unverifiedSchema"], format_checker=formats)
    results = fixture["results"]
    assert [result["outcome"] for result in results] == ["completed", "accepted", "partial_failure", "failed", "cancelled", "unknown", "completed"]
    for index, result in enumerate(results):
        expected = index != 6
        assert strict.is_valid(result) == expected
        assert probe.call("result-validate", result)["valid"] == expected
        assert relaxed.is_valid(result) and probe.call("result-unverified", result)["valid"]
        assert result["stateVersion"] == "18446744073709551615" and result["context"]["stopEpoch"] == "9007199254740993"
        assert result["timings"]["elapsedUs"] == "18446744073709551615"
    mutations = []
    assert results[0]["jobId"] == "job-fixture" and results[5]["effects"][0]["status"] == "applied" and results[5]["partial"] is True
    assert results[2]["recovery"]["capabilityId"] == results[5]["reconciliation"]["capabilityId"] == results[6]["verification"]["followUp"]["capabilityId"] == "operation_reconcile"
    for index, field in ((0, "operationId"), (1, "jobId"), (2, "effects"), (2, "recovery"), (5, "reconciliation"), (5, "effects")):
        changed = copy.deepcopy(results[index])
        del changed[field]
        mutations.append(changed)
    for index, field, value in ((0, "error", results[3]["error"]), (0, "jobId", ""), (1, "data", {"value": "0x1"}),
                               (1, "verification", results[0]["verification"]), (2, "effects", []), (2, "partial", False),
                               (3, "error", results[2]["error"]), (5, "outcome", "completed"), (0, "data", {"value": 9007199254740993}),
                               (0, "data", {"value": "0x1", "unknown": "reject"}), (0, "warnings", [{"code": "warning", "message": "Bounded"}] * 101),
                               (0, "page", {"snapshotVersion": "1", "complete": False}), (0, "page", {"snapshotVersion": "1", "complete": True, "nextCursor": "contradiction"})):
        changed = copy.deepcopy(results[index])
        changed[field] = value
        mutations.append(changed)
    changed = copy.deepcopy(results[0])
    changed["verification"]["evidence"] = []
    mutations.append(changed)
    changed = copy.deepcopy(results[0])
    changed["timings"]["queueUs"] = "18446744073709551616"
    mutations.append(changed)
    changed = copy.deepcopy(results[6])
    del changed["verification"]["followUp"]
    assert not relaxed.is_valid(changed) and not probe.call("result-unverified", changed)["valid"]
    for index, changed in enumerate(mutations):
        assert not strict.is_valid(changed), f"Independent result validator accepted contradiction {index}"
        assert not probe.call("result-validate", changed)["valid"], f"Native result validator accepted contradiction {index}"
    expected_codes = {"debugger_unavailable", "target_required", "target_running", "stale_context", "lease_conflict", "elevation_required", "elevation_denied", "permission_denied", "expected_bytes_mismatch", "file_hash_mismatch", "unsupported_mapping", "partial_failure", "timeout_unknown", "resource_limit", "unsupported_capability", "event_gap", "idempotency_conflict", "invalid_argument", "internal_error"}
    assert {error["code"] for error in fixture["errors"]} == expected_codes
    return {"typedOutcomes": 6, "rejectedContradictions": len(mutations) + 1, "typedErrorCodes": sorted(expected_codes)}


def registry_validators(registry, formats):
    from jsonschema import Draft202012Validator
    validators = {}
    expected = {"server_info", "server_health", "capabilities_list", "capabilities_describe", "capabilities_search", "client_context_get", "client_context_set", "control_acquire", "control_renew", "control_release"}
    assert registry["operationalTools"] == [] and {tool["name"] for tool in registry["tools"]} == expected
    assert [tool["name"] for tool in registry["tools"]] == sorted(expected)
    for tool in registry["tools"]:
        assert tool["schemaVersion"] == 1 and tool["operational"] is False
        assert tool["completionPredicate"] and tool["nativeSource"] and tool["recovery"] and tool["acceptanceIds"]
        assert tool["annotations"]["readOnlyHint"] == (tool["effects"] == ["inspect"])
        assert tool["executor"] == "broker" and tool["architectureRequirement"] == "any"
        for direction in ("input", "output"):
            schema = tool[f"{direction}Schema"]
            Draft202012Validator.check_schema(schema)
            assert schema["$id"] == f"urn:wininspect:mcp:tool:v1:{tool['name']}:{direction}"
            validators[(tool["name"], direction)] = Draft202012Validator(schema, format_checker=formats)
    return validators


def check_registry_contracts(probe, registry, validators):
    target = {"instanceId": "instance-1", "targetId": "target-1", "targetGeneration": "18446744073709551615"}
    examples = {
        "server_info": {}, "server_health": {}, "capabilities_list": {"limit": 2, "availability": "planned"},
        "capabilities_describe": {"capabilityId": "server_info"}, "capabilities_search": {"query": "capabilities", "limit": 2},
        "client_context_get": {}, "client_context_set": {"defaultTarget": target},
        "control_acquire": {**target, "purpose": "Controlled fixture", "durationMs": 30000, "idempotencyKey": "request-1"},
        "control_renew": {**target, "leaseId": "lease-1", "durationMs": 60000}, "control_release": {**target, "leaseId": "lease-1"}}
    comparisons = 0
    for name, value in examples.items():
        validator = validators[(name, "input")]
        assert validator.is_valid(value) and probe.call("tool-input", value, name)["valid"]
        unknown = {**value, "unregisteredField": "reject"}
        assert not validator.is_valid(unknown) and not probe.call("tool-input", unknown, name)["valid"]
        comparisons += 2
    for name, value in (("control_acquire", {**examples["control_acquire"], "durationMs": 0}),
                        ("control_renew", {**examples["control_renew"], "durationMs": 60001}),
                        ("control_release", {**examples["control_release"], "targetGeneration": 9007199254740993}),
                        ("capabilities_list", {"availability": "ready"}), ("capabilities_search", {"query": "x" * 257}),
                        ("client_context_set", {"defaultTarget": {**target, "targetGeneration": "18446744073709551616"}})):
        assert not validators[(name, "input")].is_valid(value) and not probe.call("tool-input", value, name)["valid"]
        comparisons += 1
    for tool in registry["tools"]:
        assert tool["availability"] == ("implemented" if tool["name"] in ("capabilities_list", "capabilities_describe", "capabilities_search") else "planned")
    return {"declaredTools": len(registry["tools"]), "independentComparisons": comparisons, "operationalTools": 0}


def check_registry_dispatch(probe, registry, validators):
    def call(name, value):
        response = probe.call("call", value, name)
        assert response["valid"], response
        result = response["result"]
        assert validators[(name, "output")].is_valid(result), f"Independent output rejection for {name}"
        assert probe.call("tool-output", result, name)["valid"]
        assert result["outcome"] == "completed" and result["verification"]["status"] == "verified"
        assert result["context"] == {"brokerGeneration": "9007199254740993"} and result["stateVersion"] == "18446744073709551615"
        return result["data"]
    actual = []
    request = {"limit": 2}
    cursors = []
    while True:
        page = call("capabilities_list", request)
        assert page["snapshotId"] == registry["buildId"] and len(page["items"]) <= 2
        actual.extend(page["items"])
        if page["complete"]:
            assert "nextCursor" not in page
            break
        cursors.append(page["nextCursor"])
        request = {"limit": 2, "cursor": page["nextCursor"]}
    assert actual == registry["tools"] and len({item["name"] for item in actual}) == len(actual)
    assert not probe.call("call", {"limit": 2, "cursor": cursors[0], "domain": "capabilities"}, "capabilities_list")["valid"]
    assert not probe.call("call", {"cursor": "registry:wrong-build:capabilities_list"}, "capabilities_list")["valid"]
    implemented = call("capabilities_list", {"availability": "implemented"})
    assert [item["name"] for item in implemented["items"]] == ["capabilities_describe", "capabilities_list", "capabilities_search"]
    assert call("capabilities_list", {"provider": "missing.provider"})["items"] == []
    for tool in actual:
        assert call("capabilities_describe", {"capabilityId": tool["name"]})["capability"] == tool
    search = call("capabilities_search", {"query": "CAPABILITIES_LIST", "limit": 1})
    assert search["items"][0] == {"capabilityId": "capabilities_list", "description": next(item["description"] for item in actual if item["name"] == "capabilities_list"), "score": 3}
    ranked = call("capabilities_search", {"query": "capabilities"})
    assert [item["capabilityId"] for item in ranked["items"] if item["score"] == 2] == ["capabilities_describe", "capabilities_list", "capabilities_search"]
    for name, value in (("server_info", {}), ("control_release", {"instanceId": "instance-1", "targetId": "target-1", "targetGeneration": "1", "leaseId": "lease-1"}),
                        ("missing_tool", {}), ("capabilities_describe", {"capabilityId": "missing_tool"})):
        rejected = probe.call("call", value, name)
        assert not rejected["valid"] and rejected["error"]["code"] == "unsupported_capability"
    return {"exactDescriptors": len(actual), "paginationPages": len(cursors) + 1, "implementedNativeMetadataHandlers": 3, "publicOperationalTools": 0}


def run_contract_checks(binary, output, architecture, selected, timeout):
    probe = ContractProbe(binary, output, timeout)
    catalog = probe.call("catalog")
    write_json(Path(output) / "compiled-contracts.json", catalog)
    validators = independent_validators(catalog)
    registry = probe.call("registry")
    write_json(Path(output) / "compiled-registry.json", registry)
    catalog["tools"] = registry["tools"]
    formats = validators["Hex64"].format_checker
    tool_validators = registry_validators(registry, formats)
    examples, mutation = contract_examples()
    results = []
    for name in CASE_NAMES:
        if selected and not any(fnmatch.fnmatchcase(name, pattern) for pattern in selected):
            continue
        result = {"name": name, "architecture": architecture, "status": "verified"}
        started = time.monotonic()
        try:
            if name == "test_compiled_schema_catalog":
                assert catalog["schemaVersion"] == 1 and re.fullmatch(r"[0-9a-f]{64}", catalog["buildId"])
                assert catalog["operationalTools"] == [] and set(validators) == set(examples)
                result["contracts"] = len(validators)
            elif name == "test_contract_boundaries":
                checked = 0
                for contract, values in examples.items():
                    for expected, value in values:
                        assert validators[contract].is_valid(value) == expected, f"{contract} example {checked}: independent acceptance differs from {expected}"
                        assert probe.call("validate", value, contract)["valid"] == expected, f"{contract} example {checked}: native acceptance differs from {expected}"
                        checked += 1
                    if values[0][1].__class__ is dict:
                        unknown = {**values[0][1], "unregisteredField": "reject"}
                        assert not validators[contract].is_valid(unknown) and not probe.call("validate", unknown, contract)["valid"]
                        checked += 1
                result["independentComparisons"] = checked
                missing = probe.call("validate", {}, "UnregisteredContract")
                assert not missing["valid"] and missing["error"]["code"] == "unknown_contract"
            elif name == "test_context_roundtrip":
                assert probe.call("normalize", {}, "Page") == {"valid": True, "limit": 100}
                assert probe.call("normalize", {}, "Deadline") == {"valid": True, "timeoutMs": 60000}
                context = probe.call("normalize", mutation, "MutationContext")
                assert context == {"valid": True, "targetGeneration": "18446744073709551615", "stopEpoch": "9007199254740993", "leaseId": "lease-1", "threadId": 4294967295}
                for value in (0, 2**32 - 1, 2**53 + 1, 2**64 - 1):
                    for contract, input_value in (("Decimal64", str(value)), ("Hex64", hex(value))):
                        assert probe.call("normalize", input_value, contract) == {"valid": True, "decimal": str(value), "hex": hex(value)}
                result["actualContext"] = context
            elif name == "test_bounded_json":
                malformed = [b'{"limit":1,"limit":2}', b'{"a":{"x":1,"x":2}}', b'{"limit":', b'{"cursor":"\xff"}', b'{"cursor":"\\ud800"}', b'[' * 66 + b'0' + b']' * 66,
                             b'{"cursor":"' + b'x' * (8 * 1024 * 1024) + b'"}', b'[' + b','.join([b'0'] * 100001) + b']']
                for raw in malformed:
                    response = probe.call("validate", argument="Page", raw=raw)
                    assert not response["valid"] and response["error"]["code"] in ("invalid_json", "payload_limit"), response
                assert probe.call("validate", {"cursor": "Hu Tao ❤"}, "Page")["valid"]
                result["rejectedMalformedInputs"] = len(malformed)
            elif name == "test_target_pointer_ranges":
                for width in (32, 64):
                    last = 2**width - 1
                    reference = {"address": {"addressHex": hex(last)}, "size": 1}
                    assert probe.call("range", reference, f"x{width}") == {"valid": True, "lastAddressHex": hex(last)}
                    assert not probe.call("range", {**reference, "size": 2}, f"x{width}")["valid"]
                    assert not probe.call("range", {"address": {"addressHex": "0x100000000"}, "size": 1}, "x32")["valid"]
                result["targetWidths"] = [32, 64]
            elif name == "test_source_dependencies":
                observed = probe.call("dependencies")
                assert observed["pointerBits"] == (64 if architecture == "x64" else 32)
                assert observed["boostVersion"] == "1_92" and observed["jsonVersion"] == 31200
                assert observed["sqliteVersion"] == "3.53.4" and observed["sqliteValue"] == 42 and observed["sqliteDuplicateError"] == 19
                assert observed["javascriptVersion"] == "0.17.0" and observed["javascriptValue"] == 42
                result["observed"] = observed
            elif name == "test_http_parser":
                requests = [(True, b'POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}'),
                            (True, b'POST /mcp HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n'),
                            (False, b'POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}'),
                            (False, b'POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n'),
                            (False, b'POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1048577\r\n\r\n'),
                            (False, b'POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n{}'),
                            (False, b'GET /mcp HTTP/1.1\r\nHost: localhost\r\nX-Test: ' + b'x' * 8192 + b'\r\n\r\n')]
                for expected, request in requests:
                    observed = probe.call("http", raw=request)
                    assert observed["valid"] == expected, observed
                    if expected:
                        assert observed["method"] == "POST" and observed["target"] == "/mcp" and observed["body"] == "{}"
                result["requestCases"] = len(requests)
            elif name == "test_result_contracts":
                result.update(check_results(probe, formats))
                fixture = probe.call("result-cases")
                assert len(set(result["typedErrorCodes"])) == 19
                for error in fixture["errors"]:
                    assert validators["DomainError"].is_valid(error) and probe.call("validate", error, "DomainError")["valid"]
            elif name == "test_registry_contracts":
                result.update(check_registry_contracts(probe, registry, tool_validators))
            elif name == "test_registry_dispatch":
                result.update(check_registry_dispatch(probe, registry, tool_validators))
        except Exception as error:
            result.update(status="failed", error=str(error))
        result["seconds"] = round(time.monotonic() - started, 3)
        results.append(result)
        print(f"[{result['status'].upper()}] {architecture} {name}", flush=True)
        if result.get("error"):
            print(result["error"], flush=True)
    write_json(Path(output) / "observations.json", probe.observations)
    write_json(Path(output) / "summary.json", {"observedAtUtc": datetime.now(timezone.utc).isoformat(), "binary": file_identity(binary),
               "compiledBuildId": catalog["buildId"], "results": results})
    return results, catalog
