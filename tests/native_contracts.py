from datetime import datetime, timezone
import fnmatch
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import time

from wi_driver import McpError, ROOT, compiler_environment, file_identity, write_json


CASE_NAMES = ("test_compiled_schema_catalog", "test_contract_boundaries", "test_context_roundtrip",
              "test_bounded_json", "test_target_pointer_ranges", "test_source_dependencies", "test_http_parser")


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
        process = subprocess.run(command, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 timeout=self.timeout, creationflags=subprocess.CREATE_NO_WINDOW)
        observation = {"command": command, "inputSha256": hashlib.sha256(payload).hexdigest(), "inputSize": len(payload),
                       "exitCode": process.returncode, "stderr": process.stderr.decode("utf-8", "replace")}
        self.observations.append(observation)
        assert process.returncode == 0, observation
        response = json.loads(process.stdout)
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
    return examples, mutation


def run_contract_checks(binary, output, architecture, selected, timeout):
    probe = ContractProbe(binary, output, timeout)
    catalog = probe.call("catalog")
    write_json(Path(output) / "compiled-contracts.json", catalog)
    validators = independent_validators(catalog)
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
