from collections import Counter
import configparser
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import time
import xml.etree.ElementTree as Xml

from wi_driver import McpError, ROOT, compiler_environment, file_identity, loaded_modules, write_json


TOKEN_PATTERN = re.compile(
    r'(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)'
    r'|(?P<string>(?:u8|u|U|L)?R"[^\(]*\([\s\S]*?\)[^"]*"|(?:u8|u|U|L)?"(?:\\.|[^"\\])*")'
    r"|(?P<character>'(?:\\.|[^'\\])*')"
    r'|(?P<identifier>[A-Za-z_]\w*)|(?P<symbol>[^\s])')
ACTION_FUNCTIONS = {"makeAction", "makeShortcutAction", "makeActionColor", "addAction", "QAction", "QShortcut"}
SETTING_FUNCTIONS = {"BridgeSettingGet", "BridgeSettingGetUint", "BridgeSettingSet", "BridgeSettingSetUint"}
SCRIPT_FUNCTIONS = {"GuiRegisterScriptLanguage", "_plugin_registerscript", "_plugin_registerexprfunction",
                    "_plugin_registerexprfunctionex", "_plugin_registerformatfunction"}
REGISTRATION_FUNCTIONS = {"dbgcmdnew", "Register", "RegisterEasy", "_plugin_registercommand",
                          "_plugin_menuaddentry", "_plugin_menuadd", "setDefault", "insert"}
REGISTRY_DIRECTORY = ROOT / "tests" / "native_mcp"
RESOURCE_CALLBACK = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HMODULE, ctypes.c_void_p, ctypes.c_void_p, wintypes.LPARAM)
LANGUAGE_CALLBACK = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HMODULE, ctypes.c_void_p, ctypes.c_void_p, wintypes.WORD, wintypes.LPARAM)
RESOURCE_API = ctypes.WinDLL("kernel32", use_last_error=True)
RESOURCE_API.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
RESOURCE_API.LoadLibraryExW.restype = wintypes.HMODULE
RESOURCE_API.FreeLibrary.argtypes = [wintypes.HMODULE]
RESOURCE_API.EnumResourceNamesW.argtypes = [wintypes.HMODULE, ctypes.c_void_p, RESOURCE_CALLBACK, wintypes.LPARAM]
RESOURCE_API.EnumResourceLanguagesW.argtypes = [wintypes.HMODULE, ctypes.c_void_p, ctypes.c_void_p, LANGUAGE_CALLBACK, wintypes.LPARAM]
RESOURCE_API.FindResourceExW.argtypes = [wintypes.HMODULE, ctypes.c_void_p, ctypes.c_void_p, wintypes.WORD]
RESOURCE_API.FindResourceExW.restype = ctypes.c_void_p
RESOURCE_API.SizeofResource.argtypes = [wintypes.HMODULE, ctypes.c_void_p]
RESOURCE_API.SizeofResource.restype = wintypes.DWORD
RESOURCE_API.LoadResource.argtypes = [wintypes.HMODULE, ctypes.c_void_p]
RESOURCE_API.LoadResource.restype = ctypes.c_void_p
RESOURCE_API.LockResource.argtypes = [ctypes.c_void_p]
RESOURCE_API.LockResource.restype = ctypes.c_void_p


class ResourceReader:
    def __init__(self, content):
        self.content = content
        self.position = 0

    def take(self, format):
        length = struct.calcsize("<" + format)
        if self.position + length > len(self.content):
            raise ValueError("Truncated Windows resource template")
        values = struct.unpack_from("<" + format, self.content, self.position)
        self.position += length
        return values[0] if len(values) == 1 else values

    def align(self, boundary):
        self.skip((-self.position) % boundary)

    def skip(self, length):
        if length < 0 or self.position + length > len(self.content):
            raise ValueError("Invalid Windows resource length")
        self.position += length

    def string_or_ordinal(self):
        first = self.take("H")
        if first == 0xFFFF:
            return self.take("H")
        values = []
        while first:
            values.append(first)
            first = self.take("H")
        return struct.pack("<" + "H" * len(values), *values).decode("utf-16-le")


def parse_dialog_resource(content):
    reader = ResourceReader(content)
    extended = content[:4] == b"\x01\x00\xff\xff"
    if extended:
        version, signature, help_id, extended_style, style, count, x, y, width, height = reader.take("HHIIIHhhhh")
    else:
        style, extended_style, count, x, y, width, height = reader.take("IIHhhhh")
        help_id = 0
    menu = reader.string_or_ordinal()
    window_class = reader.string_or_ordinal()
    title = reader.string_or_ordinal()
    font = None
    if style & 0x40:
        font = {"pointSize": reader.take("H")}
        if extended:
            weight, italic, charset = reader.take("HBB")
            font.update(weight=weight, italic=italic, charset=charset)
        font["typeface"] = reader.string_or_ordinal()
    controls = []
    for index in range(count):
        reader.align(4)
        if extended:
            control_help, control_extended_style, control_style, cx, cy, cw, ch, identifier = reader.take("IIIhhhhI")
        else:
            control_style, control_extended_style, cx, cy, cw, ch, identifier = reader.take("IIhhhhH")
            control_help = 0
        control_class = reader.string_or_ordinal()
        control_title = reader.string_or_ordinal()
        extra_count = reader.take("H")
        reader.skip(extra_count if extended else max(0, extra_count - 2))
        controls.append({"index": index, "id": identifier, "class": control_class, "text": control_title,
                         "style": control_style, "extendedStyle": control_extended_style,
                         "helpId": control_help, "bounds": [cx, cy, cw, ch], "creationDataLength": extra_count})
    return {"extended": extended, "title": title, "class": window_class, "menu": menu, "font": font,
            "style": style, "extendedStyle": extended_style, "helpId": help_id,
            "bounds": [x, y, width, height], "controls": controls, "decodedBytes": reader.position}


def parse_menu_resource(content):
    reader = ResourceReader(content)
    version, offset = reader.take("HH")
    if version not in (0, 1):
        raise ValueError(f"Unknown Windows menu template version: {version}")
    reader.skip(offset)

    def read_items(depth):
        if depth > 32:
            raise ValueError("Windows menu nesting exceeds inventory bound")
        items = []
        while True:
            if version == 1:
                reader.align(4)
                item_type, state, identifier, flags = reader.take("IIIH")
                popup = bool(flags & 1)
            else:
                flags = reader.take("H")
                popup = bool(flags & 0x10)
                identifier = 0 if popup else reader.take("H")
                item_type = flags
                state = 0
            title = reader.string_or_ordinal()
            item = {"id": identifier, "text": title, "type": item_type, "state": state, "flags": flags}
            if popup:
                if version == 1:
                    reader.align(4)
                    item["helpId"] = reader.take("I")
                item["children"] = read_items(depth + 1)
            items.append(item)
            if flags & 0x80:
                return items

    return {"version": version, "items": read_items(0), "decodedBytes": reader.position}


def collect_binary_resources(path):
    handle = RESOURCE_API.LoadLibraryExW(str(path), None, 0x22)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    resources = []
    errors = []

    def collect_language(module, resource_type, name, language, parameter):
        try:
            identifier = name if name <= 0xFFFF else ctypes.wstring_at(name)
            resource = RESOURCE_API.FindResourceExW(module, resource_type, name, language)
            length = RESOURCE_API.SizeofResource(module, resource)
            memory = RESOURCE_API.LockResource(RESOURCE_API.LoadResource(module, resource))
            if not resource or not memory or not 0 < length <= 16 * 1024 * 1024:
                raise ValueError("Invalid Windows resource size or handle")
            content = ctypes.string_at(memory, length)
            parsed = parse_dialog_resource(content) if resource_type == 5 else parse_menu_resource(content)
            resources.append({"type": resource_type, "id": identifier, "language": language,
                              "size": length, "sha256": hashlib.sha256(content).hexdigest(), "template": parsed})
        except Exception as error:
            errors.append(str(error))
        return True

    language_callback = LANGUAGE_CALLBACK(collect_language)

    def collect_name(module, resource_type, name, parameter):
        if not RESOURCE_API.EnumResourceLanguagesW(module, resource_type, name, language_callback, 0):
            errors.append(f"Cannot enumerate Windows resource languages: {ctypes.get_last_error()}")
        return True

    name_callback = RESOURCE_CALLBACK(collect_name)
    try:
        for resource_type in (4, 5):
            if not RESOURCE_API.EnumResourceNamesW(handle, resource_type, name_callback, 0):
                error = ctypes.get_last_error()
                if error not in (1812, 1813):
                    errors.append(f"Cannot enumerate Windows resource names: {error}")
        if errors:
            raise ValueError(f"Resource inventory failed for {path.name}: {errors}")
    finally:
        RESOURCE_API.FreeLibrary(handle)
    return {"binary": file_identity(path), "resources": resources}


def collect_plugin_resources(directory):
    binaries = [collect_binary_resources(path) for path in sorted(Path(directory).iterdir())
                if path.suffix.lower() in (".dp64", ".dp32", ".dll") and path.stem != "baseline_inventory"]
    settings = []
    for path in sorted(Path(directory).glob("*.ini")):
        if path.stem == "x64dbg-MCP-Server":
            continue
        parser = configparser.RawConfigParser(strict=False)
        parser.optionxform = str
        parser.read(path, encoding="utf-8-sig")
        settings.append({"provider": path.stem, "source": file_identity(path),
                         "sections": {section: sorted(parser[section].keys()) for section in parser.sections()}})
    return {"schemaVersion": 1, "scope": "shipped plugin dialog/menu resources and configuration keys",
            "binaries": binaries, "settings": settings}


def tokenize_cpp(source):
    return [(match.lastgroup, match.group(), match.start(), match.end())
            for match in TOKEN_PATTERN.finditer(source) if match.lastgroup != "comment"]


def call_arguments(tokens, opening):
    arguments = []
    argument = []
    nesting = 1
    for token in tokens[opening + 1:]:
        kind, value, start, end = token
        if kind == "symbol" and value in "([{":
            nesting += 1
        elif kind == "symbol" and value in ")]}":
            nesting -= 1
        if nesting == 0:
            arguments.append(argument)
            return arguments, end
        if value == "," and nesting == 1 and kind == "symbol":
            arguments.append(argument)
            argument = []
        else:
            argument.append(token)
    raise ValueError("Unterminated source registration")


def literal_string(tokens):
    if not tokens or any(token[0] != "string" for token in tokens):
        return None
    values = []
    for kind, value, start, end in tokens:
        first_quote = value.find('"')
        literal = value[first_quote:]
        if value[:first_quote].endswith("R"):
            return None
        try:
            values.append(json.loads(literal))
        except json.JSONDecodeError:
            return None
    return "".join(values)


def source_calls(path):
    source = path.read_text(encoding="utf-8-sig")
    tokens = tokenize_cpp(source)
    relevant = ACTION_FUNCTIONS | SETTING_FUNCTIONS | SCRIPT_FUNCTIONS | REGISTRATION_FUNCTIONS
    for index, token in enumerate(tokens[:-1]):
        kind, name, start, end = token
        if kind != "identifier" or name not in relevant or tokens[index + 1][1] != "(":
            continue
        arguments, ending = call_arguments(tokens, index + 1)
        owner = None
        if index >= 2 and tokens[index - 1][1] == ".":
            owner = tokens[index - 2][1]
        elif index >= 3 and tokens[index - 2][1] == "-" and tokens[index - 1][1] == ">":
            owner = tokens[index - 3][1]
        yield {"function": name, "owner": owner, "line": source.count("\n", 0, start) + 1,
               "expression": source[start:ending], "arguments": [literal_string(value) for value in arguments]}


def classify_call(call, relative):
    function = call["function"]
    if function == "dbgcmdnew":
        return "command"
    if function in ACTION_FUNCTIONS and "/gui/" in relative:
        return "gui_action"
    if function in SETTING_FUNCTIONS:
        return "setting"
    if function in SCRIPT_FUNCTIONS:
        return "script_provider"
    if function in ("Register", "RegisterEasy") and relative.endswith("expressionfunctions.cpp"):
        return "expression"
    if function in ("Register", "RegisterEasy") and relative.endswith("formatfunctions.cpp"):
        return "format_function"
    if function == "insert" and call["owner"] and call["owner"].startswith("default"):
        return "shortcut" if call["owner"] == "defaultShortcuts" else "setting"
    if function.startswith("_plugin_"):
        return "plugin_registration"
    return None


def make_row(identifier, category, source, variants, aliases=None):
    return {"id": identifier, "category": category, "source": source, "aliases": aliases or [],
            "provider": "debugger-source", "variants": variants, "architectures": ["x64", "x32"],
            "stateRequirement": "inventory_pending_classification", "agentRoute": None,
            "acceptanceIds": ["A-51"] if category.startswith("gui") else ["A-52"],
            "completionPredicate": "Equivalent native and agent outcomes with the same supplied inputs",
            "status": "planned", "evidence": None}


def collect_source_inventory():
    rows = []
    inputs = []
    occurrences = Counter()
    categories = Counter()
    source_root = ROOT / "x64dbg" / "src"
    for directory in (source_root / "dbg", source_root / "gui", source_root / "bridge"):
        for path in sorted(directory.rglob("*")):
            if path.suffix not in (".cpp", ".h", ".ui") or any(part in ("btparser", "ThirdPartyLibs") for part in path.parts):
                continue
            identity = file_identity(path)
            relative = path.relative_to(ROOT).as_posix()
            inputs.append({"path": relative, "sha256": identity["sha256"]})
            if path.suffix == ".ui":
                tree = Xml.parse(path)
                form = tree.findtext("class")
                for widget in tree.iter():
                    if widget.tag not in ("widget", "action"):
                        continue
                    name = widget.get("name")
                    category = "gui_action" if widget.tag == "action" else "gui_field"
                    identifier = f"ui.{form}.{name}"
                    variants = {"class": widget.get("class"), "form": form,
                                "properties": {value.get("name"): "".join(value.itertext()).strip()
                                               for value in widget.findall("property")},
                                "items": ["".join(item.itertext()).strip() for item in widget.findall("item")]}
                    rows.append(make_row(identifier, category, {"path": relative, "objectName": name}, variants))
                    categories[category] += 1
                continue
            for call in source_calls(path):
                category = classify_call(call, relative)
                if category is None:
                    continue
                digest = hashlib.sha256(call["expression"].encode()).hexdigest()[:16]
                base = f"source.{relative}.{category}.{digest}"
                occurrences[base] += 1
                identifier = f"{base}.{occurrences[base]}"
                aliases = []
                if category == "command" and call["arguments"] and call["arguments"][0] is not None:
                    aliases = call["arguments"][0].split(",")
                rows.append(make_row(identifier, category, {"path": relative, "line": call["line"]}, call, aliases))
                categories[category] += 1
    identifiers = [row["id"] for row in rows]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Duplicate inventory identity")
    return {"schemaVersion": 1, "scope": "source-registration-and-form-inventory", "inputs": inputs,
            "categories": dict(categories), "operations": rows,
            "coverageGaps": ["Dynamic menu instances and shipped opaque plugin operations require runtime reconciliation",
                             "Source registration candidates still require semantic deduplication and state classification"]}


def reconcile_legacy_catalog(catalog_path):
    expected = json.loads((REGISTRY_DIRECTORY / "legacy-manifest.json").read_text(encoding="utf-8"))
    actual = json.loads(Path(catalog_path).read_text(encoding="utf-8"))
    expected_names = {tool["legacyName"] for tool in expected["tools"]}
    names = [tool["name"] for tool in actual]
    if len(names) != len(set(names)):
        raise ValueError("Legacy catalog contains duplicate names")
    missing = sorted(expected_names - set(names))
    added = sorted(set(names) - expected_names)
    if missing or added:
        raise ValueError(f"Legacy candidates differ: missing={missing}, added={added}")
    for tool in actual:
        schema = tool.get("inputSchema", {})
        if schema.get("type") != "object" or not set(schema.get("required", [])).issubset(schema.get("properties", {})):
            raise ValueError(f"Invalid legacy schema: {tool['name']}")
        baseline = next(candidate for candidate in expected["tools"] if candidate["legacyName"] == tool["name"])
        for field in ("inputSchema", "description", "annotations"):
            if tool.get(field) != baseline.get(field):
                raise ValueError(f"Legacy contract changed: {tool['name']}.{field}")
    return {"status": "verified", "count": len(names), "missing": missing, "added": added,
            "catalog": file_identity(catalog_path)}


def build_inventory_fixture(environment):
    compiler_variables = compiler_environment(environment.architecture)
    search_path = next(value for key, value in compiler_variables.items() if key.lower() == "path")
    compiler = shutil.which("cl.exe", path=search_path)
    if not compiler:
        raise McpError("Visual Studio compiler is unavailable")
    qt_build = "build64" if environment.architecture == "x64" else "build32"
    qt = ROOT / "x64dbg" / qt_build / "_deps" / "qt5-src"
    source = REGISTRY_DIRECTORY / "fixtures" / "inventory_plugin.cpp"
    binary = environment.targets / ("baseline_inventory.dp64" if environment.architecture == "x64" else "baseline_inventory.dp32")
    includes = [ROOT / "x64dbg" / "src" / "dbg", ROOT / "x64dbg" / "src" / "bridge", qt / "include"]
    includes.extend(qt / "include" / module for module in ("QtCore", "QtGui", "QtWidgets"))
    libraries = ROOT / "x64dbg" / "bin" / environment.architecture
    command = [compiler, "/nologo", "/LD", "/MD", "/EHsc", "/std:c++17", "/W3", str(source),
               *[f"/I{path}" for path in includes], f"/Fe:{binary}", "/link", f"/LIBPATH:{qt / 'lib'}",
               f"/LIBPATH:{libraries}", "Qt5Widgets.lib", "Qt5Gui.lib", "Qt5Core.lib", "winbridge.lib", "wininspect.lib"]
    process = subprocess.run(command, cwd=environment.targets, env=compiler_variables,
                             capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    build = {"source": file_identity(source), "command": command, "exitCode": process.returncode,
             "stdout": process.stdout, "stderr": process.stderr}
    write_json(environment.root / "inventory-fixture-build.json", build)
    if process.returncode:
        raise McpError(f"Inventory fixture build failed: {process.stdout} {process.stderr}")
    stage = environment.stage("shipped")
    shutil.copy2(binary, stage / "plugins" / binary.name)


def capture_runtime_surface(debugger):
    snapshots = []
    resources = collect_plugin_resources(debugger.environment.stage("shipped") / "plugins")
    resource_path = debugger.environment.root / "plugin-resources.json"
    write_json(resource_path, resources)
    debugger.safe_stop()
    for state in ("idle", "paused"):
        if state == "paused":
            debugger.load(debugger.fixture("bpmain"))
        path = debugger.environment.root / f"runtime-surface-{state}.json"
        argument = path.as_posix()
        if any(value in argument for value in '\"\r\n,'):
            raise McpError("Inventory output path cannot be represented as a debugger argument")
        debugger.call("ExecuteDebuggerCommand", {"command": f'baselineinventory "{argument}"'})
        deadline = time.monotonic() + 10
        while not path.is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        if not path.is_file():
            raise McpError(f"GUI inventory did not complete in {state}")
        snapshot = json.loads(path.read_text(encoding="utf-8"))
        assert int(snapshot["processId"]) == debugger.proc.pid, "Inventory belongs to another process"
        assert snapshot["menus"] and snapshot["commands"] and snapshot["scriptProviders"], "Incomplete runtime surface"
        assert "baselineinventory" in snapshot["commands"], "Inventory fixture was not registered"
        snapshots.append({"state": state, "artifact": file_identity(path), "menuCount": len(snapshot["menus"]),
                          "commandCount": len(snapshot["commands"]), "scriptProviders": snapshot["scriptProviders"]})
    debugger.record["loadedModulesAfterInventory"] = loaded_modules(debugger.proc)
    return {"scope": "registered idle and paused GUI surface", "snapshots": snapshots,
            "pluginResources": file_identity(resource_path)}


def merge_runtime_surface(inventory, surface_path):
    surface = json.loads(Path(surface_path).read_text(encoding="utf-8"))
    if not surface.get("menus") or not surface.get("commands") or not surface.get("scriptProviders"):
        raise ValueError("Runtime surface is incomplete")
    snapshot_identity = file_identity(surface_path)
    snapshot_identity.pop("path")
    source = {"runtimeSnapshot": snapshot_identity}
    existing_aliases = {alias.lower() for row in inventory["operations"] for alias in row["aliases"]}
    additions = []
    for command in sorted(set(surface["commands"]), key=str.lower):
        if command.lower() in existing_aliases or command == "baselineinventory":
            continue
        additions.append(make_row(f"runtime.command.{command.lower()}", "command", source, {"name": command}, [command]))
    seen = Counter()
    for menu in sorted(surface["menus"], key=lambda value: (value["path"], value["title"], json.dumps(value["actions"], sort_keys=True))):
        for action in menu["actions"]:
            if action["separator"]:
                continue
            identity = action["objectName"] or action["text"]
            base = f"runtime.menu.{menu['path']}.{menu['title']}.{identity}"
            digest = hashlib.sha256(base.encode()).hexdigest()[:20]
            seen[digest] += 1
            additions.append(make_row(f"runtime.gui_action.{digest}.{seen[digest]}", "gui_action", source,
                                      {"menu": {"path": menu["path"], "title": menu["title"]}, "action": action}))
    for provider in sorted(set(surface["scriptProviders"])):
        additions.append(make_row(f"runtime.script_provider.{provider}", "script_provider", source, {"name": provider}))
    for widget in sorted(surface["widgets"], key=lambda value: (value["path"], value["class"], value["objectName"])):
        if widget["class"] in ("QWidget", "QMenu", "QScrollBar", "QSplitterHandle", "QToolBarSeparator",
                               "QComboBoxPrivateContainer", "QToolBarExtension", "QFrame", "QStackedWidget"):
            continue
        digest = hashlib.sha256(widget["path"].encode()).hexdigest()[:20]
        seen[digest] += 1
        category = "gui_field" if widget["class"].startswith("Q") else "gui_view"
        additions.append(make_row(f"runtime.widget.{digest}.{seen[digest]}", category, source, widget))
    for row in additions:
        row["provider"] = "shipped-runtime"
    resource_path = Path(surface_path).parent / "plugin-resources.json"
    if resource_path.is_file():
        resources = json.loads(resource_path.read_text(encoding="utf-8"))
        for binary in resources["binaries"]:
            name = Path(binary["binary"]["path"]).name
            provider_source = {"binaryName": name, "binarySha256": binary["binary"]["sha256"]}
            for resource in binary["resources"]:
                base = f"provider.{name}.resource.{resource['type']}.{resource['id']}.{resource['language']}"
                if resource["type"] == 5:
                    for control in resource["template"]["controls"]:
                        additions.append(make_row(f"{base}.control.{control['id']}.{control['index']}", "gui_field",
                                                  provider_source, {"dialogId": resource["id"], "control": control,
                                                                    "resourceSha256": resource["sha256"]}))
                else:
                    pending = list(resource["template"]["items"])
                    index = 0
                    while pending:
                        item = pending.pop(0)
                        additions.append(make_row(f"{base}.item.{item['id']}.{index}", "gui_action", provider_source, item))
                        pending.extend(item.get("children", []))
                        index += 1
        for configuration in resources["settings"]:
            for section, keys in configuration["sections"].items():
                for key in keys:
                    additions.append(make_row(f"provider.{configuration['provider']}.setting.{section}.{key}", "setting",
                                              {"configurationName": Path(configuration["source"]["path"]).name},
                                              {"section": section, "key": key}))
        for row in additions:
            if row["id"].startswith("provider."):
                row["provider"] = row["id"].split(".")[1]
    inventory["operations"].extend(additions)
    identifiers = [row["id"] for row in inventory["operations"]]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Runtime reconciliation produced duplicate operation identities")
    inventory["categories"] = dict(Counter(row["category"] for row in inventory["operations"]))
    inventory["runtimeSnapshot"] = snapshot_identity
    inventory["coverageGaps"] = ["Context-created menus, lazy dialogs and opaque provider registration effects remain to be reconciled",
                                 "Source registration candidates still require semantic deduplication and state classification"]


def write_parity_registry(path, inventory):
    fields = []
    for name, value in inventory.items():
        if name in ("inputs", "operations"):
            entries = ",\n".join("    " + json.dumps(entry, ensure_ascii=False) for entry in value)
            serialized = "[\n" + entries + "\n  ]"
        else:
            serialized = json.dumps(value, indent=2, ensure_ascii=False).replace("\n", "\n  ")
        fields.append("  " + json.dumps(name) + ": " + serialized)
    Path(path).write_text("{\n" + ",\n".join(fields) + "\n}\n", encoding="utf-8", newline="\n")


def run_inventory(output, catalog_path, refresh, surface_path=None):
    inventory = collect_source_inventory()
    if surface_path:
        merge_runtime_surface(inventory, surface_path)
    write_json(Path(output) / "source-inventory.json", inventory)
    reconciliation = reconcile_legacy_catalog(catalog_path)
    write_json(Path(output) / "legacy-reconciliation.json", reconciliation)
    if refresh:
        write_parity_registry(REGISTRY_DIRECTORY / "parity-manifest.json", inventory)
    return {"legacy": reconciliation, "categories": inventory["categories"],
            "sourceInputs": len(inventory["inputs"]), "coverageGaps": inventory["coverageGaps"]}
