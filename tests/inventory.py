from collections import Counter
import copy
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
ACTION_FUNCTIONS = {"makeAction", "makeShortcutAction", "makeActionColor", "makeMenu", "makeMenuAction", "makeShortcutMenuAction",
                    "makeCommandAction", "addAction", "addMenu", "QAction", "QShortcut"}
SETTING_FUNCTIONS = {"BridgeSettingGet", "BridgeSettingGetUint", "BridgeSettingSet", "BridgeSettingSetUint"}
SCRIPT_FUNCTIONS = {"GuiRegisterScriptLanguage", "_plugin_registerscript", "_plugin_registerexprfunction",
                    "_plugin_registerexprfunctionex", "_plugin_registerformatfunction"}
GUI_FIELD_FUNCTIONS = {"QLineEdit", "QTextEdit", "QPlainTextEdit", "QSpinBox", "QDoubleSpinBox", "QComboBox",
                       "QCheckBox", "QRadioButton", "QPushButton", "QToolButton", "QDialogButtonBox", "QTabWidget"}
GUI_DIALOG_FUNCTIONS = {"QInputDialog", "QFileDialog", "QMessageBox", "QDialog", "getText", "getMultiLineText",
                        "getInt", "getDouble", "getItem", "getOpenFileName", "getOpenFileNames", "getSaveFileName",
                        "getExistingDirectory", "getExistingDirectoryUrl", "getOpenFileUrl", "getSaveFileUrl"}
REGISTRATION_FUNCTIONS = {"dbgcmdnew", "Register", "RegisterEasy", "_plugin_registercommand",
                          "_plugin_menuaddentry", "_plugin_menuadd", "setDefault", "insert", "connect",
                          "insertMenuBuilderBools", "setupColumnConfigDefaultValue"}
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


def render_cpp(tokens):
    parts = []
    previous_kind = None
    for kind, value, start, end in tokens:
        if parts and kind in ("identifier", "string") and previous_kind in ("identifier", "string"):
            parts.append(" ")
        parts.append(value)
        previous_kind = kind
    return "".join(parts)


def bracket_pairs(tokens):
    stacks = {"(": [], "[": [], "{": []}
    opening = {")": "(", "]": "[", "}": "{"}
    pairs = {}
    for index, token in enumerate(tokens):
        if token[0] != "symbol":
            continue
        value = token[1]
        if value in stacks:
            stacks[value].append(index)
        elif value in opening and stacks[opening[value]]:
            start = stacks[opening[value]].pop()
            pairs[start] = index
    return pairs


def function_regions(tokens):
    pairs = bracket_pairs(tokens)
    regions = []
    for opening, closing in pairs.items():
        if tokens[opening][1] != "(" or opening == 0 or tokens[opening - 1][0] != "identifier":
            continue
        name = tokens[opening - 1][1]
        if name in ("if", "for", "while", "switch", "catch", "sizeof", "alignof", "decltype"):
            continue
        body = closing + 1
        while body < len(tokens) and tokens[body][1] in ("const", "override", "final", "noexcept"):
            body += 1
        initializer_start = tokens[body][2] if body < len(tokens) and tokens[body][1] == ":" else None
        if initializer_start is not None:
            body += 1
            while body < len(tokens):
                if tokens[body][1] in (";", "}"):
                    break
                if tokens[body][1] == "{":
                    ending = pairs.get(body)
                    if ending is not None and ending + 1 < len(tokens) and tokens[ending + 1][1] in (",", "{"):
                        body = ending + 1
                        continue
                    break
                body = pairs[body] + 1 if body in pairs else body + 1
        if body not in pairs or tokens[body][1] != "{":
            continue
        first = opening - 1
        while first >= 3 and tokens[first - 1][1] == ":" and tokens[first - 2][1] == ":" and tokens[first - 3][0] == "identifier":
            first -= 3
        regions.append({"name": render_cpp(tokens[first:opening]), "signature": opening - 1,
                        "start": tokens[body][2], "end": tokens[pairs[body]][3], "initializerStart": initializer_start})
    unique = {}
    for region in regions:
        key = (region["start"], region["end"])
        if key not in unique or region["signature"] < unique[key]["signature"]:
            unique[key] = region
    return list(unique.values())


def declared_parameters(arguments):
    if not arguments or not arguments[0]:
        return False
    first = arguments[0]
    if first[0][1] == "const":
        return True
    types = {"bool", "int", "char", "void", "duint", "QAction", "QMenu", "QWidget", "QString",
             "SCRIPTTYPEINFO", "CBCOMMAND", "ValueType", "String", "QMap"}
    if len(first) > 1 and first[0][1] == "QMap" and first[1][1] == "<":
        return True
    return (len(first) > 1 and first[0][1] in types and
            (first[1][0] == "identifier" or first[1][1] in ("*", "&")))


def control_regions(tokens):
    pairs = bracket_pairs(tokens)
    regions = []
    for index, token in enumerate(tokens[:-1]):
        if token[0] != "identifier" or token[1] not in ("if", "for", "while", "switch"):
            continue
        opening = index + 1
        if opening not in pairs or tokens[opening][1] != "(":
            continue
        closing = pairs[opening]
        body = closing + 1
        if body >= len(tokens):
            continue
        if tokens[body][1] == "{":
            ending = pairs.get(body)
        else:
            ending = body
            while ending < len(tokens) and tokens[ending][1] != ";":
                ending = pairs[ending] + 1 if ending in pairs else ending + 1
        if ending is None or ending >= len(tokens):
            continue
        regions.append({"kind": token[1], "condition": render_cpp(tokens[opening + 1:closing]),
                        "start": tokens[body][2], "end": tokens[ending][3], "position": token[2]})
    return regions


def architecture_scopes(source):
    frames = []
    scopes = {}
    all_architectures = {"x64", "x32"}
    for line_number, line in enumerate(source.splitlines(), 1):
        directive = re.match(r"\s*#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)", line)
        if directive:
            operation, expression = directive.groups()
            expression = expression.strip()
            if operation in ("if", "ifdef", "ifndef", "elif"):
                macro = re.fullmatch(r"(?:defined\s*\(?\s*)?(_WIN64|_M_X64|_M_AMD64|_M_IX86)\s*\)?", expression)
                scope = all_architectures
                if macro:
                    scope = {"x32"} if macro[1] == "_M_IX86" else {"x64"}
                    if operation == "ifndef":
                        scope = all_architectures - scope
                frame = {"scope": scope, "original": scope, "condition": line.strip()}
                if operation == "elif" and frames:
                    frames[-1] = frame
                else:
                    frames.append(frame)
            elif operation == "else" and frames:
                frame = frames[-1]
                frame["scope"] = all_architectures - frame["original"] if frame["original"] != all_architectures else all_architectures
                frame["condition"] = line.strip()
            elif operation == "endif" and frames:
                frames.pop()
        scope = set(all_architectures)
        for frame in frames:
            scope &= frame["scope"]
        scopes[line_number] = {"architectures": sorted(scope), "buildConditions": [frame["condition"] for frame in frames]}
    return scopes


def source_calls(path):
    source = path.read_text(encoding="utf-8-sig")
    type_source = source
    header = path.with_suffix(".h")
    if path.suffix == ".cpp" and header.is_file():
        type_source += "\n" + header.read_text(encoding="utf-8-sig")
    owner_types = {name: kind for kind, name in re.findall(
        r"\b(QMenu|MenuBuilder|QActionGroup|QToolBar)\s*\*\s*(\w+)\b", type_source)}
    owner_types.update({name: kind for name, kind in re.findall(
        r"\bauto\s+(\w+)\s*=\s*new\s+(QMenu|MenuBuilder|QActionGroup|QToolBar)\b", type_source)})
    tokens = tokenize_cpp(source)
    regions = function_regions(tokens)
    controls = control_regions(tokens)
    definition_signatures = {region["signature"] for region in regions}
    scopes = architecture_scopes(source)
    relevant = (ACTION_FUNCTIONS | SETTING_FUNCTIONS | SCRIPT_FUNCTIONS | REGISTRATION_FUNCTIONS |
                GUI_FIELD_FUNCTIONS | GUI_DIALOG_FUNCTIONS)
    for index, token in enumerate(tokens[:-1]):
        kind, name, start, end = token
        if kind != "identifier" or name not in relevant or tokens[index + 1][1] != "(":
            continue
        arguments, ending = call_arguments(tokens, index + 1)
        enclosing = [region for region in regions if region["start"] < start < region["end"]]
        initializers = [region for region in regions if region["initializerStart"] is not None and
                        region["initializerStart"] < start < region["start"]]
        enclosing.extend(initializers)
        region = min(enclosing, key=lambda value: value["end"] - value["start"]) if enclosing else None
        owner = None
        if index >= 2 and tokens[index - 1][1] == ".":
            owner = tokens[index - 2][1]
        elif index >= 3 and tokens[index - 2][1] == "-" and tokens[index - 1][1] == ">":
            owner = tokens[index - 3][1]
        elif index >= 3 and tokens[index - 2][1] == ":" and tokens[index - 1][1] == ":":
            owner = tokens[index - 3][1]
        declaration = index in definition_signatures or declared_parameters(arguments)
        provider_fields = {}
        if name == "GuiRegisterScriptLanguage" and arguments and arguments[0]:
            variable = render_cpp(arguments[0]).lstrip("&")
            preceding = source[region["start"] if region else 0:start]
            preceding_tokens = tokenize_cpp(preceding)
            for field_index, field_token in enumerate(preceding_tokens[:-4]):
                if field_token[1] == variable and [token[1] for token in preceding_tokens[field_index + 1:field_index + 4:2]] == [".", "="]:
                    field = preceding_tokens[field_index + 2][1]
                    value = []
                    nesting = 0
                    for token in preceding_tokens[field_index + 4:]:
                        if token[1] == ";" and nesting == 0:
                            break
                        if token[0] == "symbol" and token[1] in "([{":
                            nesting += 1
                        elif token[0] == "symbol" and token[1] in ")]}":
                            nesting -= 1
                        value.append(token)
                    provider_fields[field] = render_cpp(value)
                if field_token[1] == "strcpy_s" and preceding_tokens[field_index + 1][1] == "(":
                    copied, copied_end = call_arguments(preceding_tokens, field_index + 1)
                    if len(copied) == 2 and render_cpp(copied[0]) == variable + ".name":
                        labels = [token for token in copied[1] if token[0] == "string"]
                        if labels:
                            provider_fields["name"] = json.dumps(literal_string(labels[-1:]))
        line_number = source.count("\n", 0, start) + 1
        statement_start = index - 1
        while statement_start >= 0 and tokens[statement_start][1] not in (";", "{", "}"):
            statement_start -= 1
        result_assigned = any(tokens[position][1] == "=" and tokens[position - 1][1] not in ("=", "!", "<", ">") and
                              tokens[position + 1][1] != "=" for position in range(statement_start + 1, index))
        yield {"function": name, "owner": owner, "ownerType": owner_types.get(owner), "line": line_number,
               "expression": source[start:ending], "arguments": [literal_string(value) for value in arguments],
               "argumentExpressions": [render_cpp(value) for value in arguments], "declaration": declaration,
               "resultAssigned": result_assigned,
               "constructorInitializer": bool(initializers),
               "nativeScope": region["name"] if region else path.stem,
               "nativeScopeLine": source.count("\n", 0, region["start"]) + 1 if region else None,
               "nativeControls": [{"kind": control["kind"], "condition": control["condition"],
                                   "line": source.count("\n", 0, control["position"]) + 1}
                                  for control in controls if control["start"] <= start < control["end"]],
               "providerFields": provider_fields, **scopes[line_number]}


def classify_call(call, relative):
    function = call["function"]
    if call["declaration"]:
        return None
    if "/gui/" in relative:
        if function in GUI_FIELD_FUNCTIONS:
            return "gui_field"
        if function in ("QInputDialog", "QFileDialog", "QMessageBox", "QDialog"):
            return "gui_binding" if call["constructorInitializer"] else "gui_view"
        if function in GUI_DIALOG_FUNCTIONS and call["owner"] in ("QInputDialog", "QFileDialog"):
            return "gui_field"
    if function == "dbgcmdnew":
        return "command" if call["arguments"][0] is not None else "registration_factory"
    if function in ("addAction", "addMenu") and "/gui/" in relative:
        first = call["argumentExpressions"][0] if call["argumentExpressions"] else ""
        nested_factory = any(re.search(r"\b" + re.escape(name) + r"\(", first) for name in ACTION_FUNCTIONS)
        creates_action = (call["ownerType"] not in ("MenuBuilder", "QActionGroup", "QToolBar") and
                          not nested_factory and (call["resultAssigned"] or '"' in first))
        if creates_action:
            return "action_factory" if relative.endswith("ActionHelpers.h") else "gui_action"
        return "gui_binding"
    if function in ("makeCommandAction", "connect") and "/gui/" in relative:
        return "gui_binding"
    if function in ACTION_FUNCTIONS and "/gui/" in relative:
        return "action_factory" if relative.endswith("ActionHelpers.h") else "gui_action"
    if function in SETTING_FUNCTIONS:
        return "setting"
    if function in SCRIPT_FUNCTIONS:
        return "script_provider"
    if function in ("Register", "RegisterEasy") and relative.endswith("expressionfunctions.cpp"):
        return "expression" if call["arguments"][0] is not None else "registration_factory"
    if function in ("Register", "RegisterEasy") and relative.endswith("formatfunctions.cpp"):
        return "format_function" if call["arguments"][0] is not None else "registration_factory"
    if function == "insert" and call["owner"] and relative.endswith("Configuration.cpp"):
        if call["arguments"] and call["arguments"][0] is None:
            return "setting_factory"
        return "shortcut" if call["owner"] == "defaultShortcuts" else "setting"
    if function.startswith("_plugin_"):
        return "plugin_registration"
    if function in ("insertMenuBuilderBools", "setupColumnConfigDefaultValue"):
        return "setting_family"
    return None


def make_row(identifier, category, source, variants, aliases=None):
    return {"id": identifier, "category": category, "source": source, "aliases": aliases or [],
            "provider": "debugger-source", "variants": variants, "architectures": ["x64", "x32"],
            "stateRequirement": "native_gui_model_guards" if category.startswith("gui") else "native_handler_guards", "agentRoute": None,
            "acceptanceIds": ["A-51"] if category.startswith("gui") or category in ("setting", "setting_family", "shortcut") else ["A-52"],
            "completionPredicate": "Equivalent native and agent outcomes with the same supplied inputs",
            "status": "planned", "evidence": None}


def configuration_sections(calls):
    sections = {}
    for call in calls:
        if call["function"] != "insert" or call["owner"] not in ("defaultBools", "defaultUints", "defaultStrings"):
            continue
        if len(call["arguments"]) == 2 and call["arguments"][0] is not None:
            sections[call["argumentExpressions"][1]] = {"section": call["arguments"][0], "container": call["owner"]}
    return sections


def classify_operation(call, category, relative, sections):
    literal_arguments = call["arguments"]
    argument_expressions = call["argumentExpressions"]
    aliases = []
    state = "native_handler_guards"
    handler = None
    identifier = None
    if category in ("command", "expression", "format_function"):
        aliases = [name.strip() for name in literal_arguments[0].split(",") if name.strip()]
        identifier = f"{category}.{aliases[0].lower()}"
        handler = argument_expressions[1] if call["function"] != "Register" else argument_expressions[-1]
        if category == "command":
            debug_only = argument_expressions[2] if len(argument_expressions) > 2 else None
            state = "debugging_active" if debug_only == "true" else "any_engine_state" if debug_only == "false" else "native_command_guard"
    elif category == "setting":
        state = "profile_available"
        if call["function"] in SETTING_FUNCTIONS and len(literal_arguments) >= 2 and all(value is not None for value in literal_arguments[:2]):
            section, key = literal_arguments[:2]
            identifier = f"setting.{section}.{key}"
        elif call["function"] == "insert" and literal_arguments and literal_arguments[0] is not None:
            owner = call["owner"]
            if owner in ("defaultBools", "defaultUints", "defaultStrings"):
                return None
            section = sections.get(owner, {}).get("section")
            if section is None:
                section = {"defaultColors": "Colors", "defaultFonts": "Fonts"}.get(owner, owner)
            identifier = f"setting.{section}.{literal_arguments[0]}"
    elif category == "shortcut" and literal_arguments[0] is not None:
        identifier = f"shortcut.{literal_arguments[0]}"
        state = "profile_available"
    elif category == "setting_family" and len(literal_arguments) >= 3:
        section = sections.get(argument_expressions[0].lstrip("&"), {}).get("section", "Gui")
        family = "menu_visibility" if call["function"] == "insertMenuBuilderBools" else "table_columns"
        family_name = literal_arguments[1] or hashlib.sha256(argument_expressions[1].encode()).hexdigest()[:16]
        identifier = f"setting_family.{section}.{family}.{family_name}"
        state = "profile_available"
        handler = call["function"]
    elif category == "script_provider" and call["providerFields"].get("name"):
        name = json.loads(call["providerFields"]["name"])
        identifier = f"script_provider.{name}"
        handler = call["providerFields"].get("execute")
        state = "provider_loaded"
    elif category == "gui_action":
        state = "native_gui_model_guards"
        shortcut = literal_arguments[-1] if "Shortcut" in call["function"] and literal_arguments else None
        slot = next((value for value in argument_expressions if value.startswith("SLOT(")), None)
        if shortcut:
            identifier = f"gui_action.{Path(relative).stem}.{shortcut}"
        elif slot:
            identifier = f"gui_action.{Path(relative).stem}.{slot[5:-1]}"
        handler = slot or (argument_expressions[-2] if shortcut and len(argument_expressions) >= 2 else argument_expressions[-1])
    if identifier is None:
        digest = hashlib.sha256((call["function"] + "|" + call["nativeScope"] + "|" + "|".join(argument_expressions)).encode()).hexdigest()[:16]
        identifier = f"source.{relative}.{category}.{digest}"
    return {"id": identifier, "aliases": aliases, "stateRequirement": state, "nativeHandler": handler,
            "call": call, "source": {"path": relative, "line": call["line"]}}


def collect_native_script_operations():
    indexed = {}
    for path in sorted((ROOT / "x64dbg" / "src" / "dbg").glob("_scriptapi_*.cpp")):
        source = path.read_text(encoding="utf-8-sig")
        tokens = tokenize_cpp(source)
        scopes = architecture_scopes(source)
        for region in function_regions(tokens):
            if not region["name"].startswith("Script::"):
                continue
            first = region["signature"]
            while first > 0 and tokens[first - 1][1] not in (";", "{", "}"):
                first -= 1
            markers = [index for index in range(first, region["signature"]) if tokens[index][1] == "SCRIPT_EXPORT"]
            if len(markers) != 1:
                raise ValueError(f"Native Script API definition has no export marker: {region['name']}")
            marker = markers[0]
            arguments, ending = call_arguments(tokens, region["signature"] + 1)
            line = source.count("\n", 0, tokens[marker][2]) + 1
            identity = f"script_api.{region['name']}"
            location = {"path": path.relative_to(ROOT).as_posix(), "line": line}
            if identity not in indexed:
                row = make_row(identity, "script_function", location, {"sites": []})
                row["provider"] = "debugger-native-script-api"
                row["stateRequirement"] = "native_script_api_guards"
                row["architectures"] = []
                indexed[identity] = row
            row = indexed[identity]
            row["architectures"] = sorted(set(row["architectures"]) | set(scopes[line]["architectures"]))
            row["variants"]["sites"].append({"source": location, "nativeHandler": region["name"],
                                             "signature": source[tokens[marker][2]:ending].strip(),
                                             "parameterExpressions": [render_cpp(value) for value in arguments], **scopes[line]})
    path = ROOT / "x64dbg" / "src" / "dbg" / "simplescript.cpp"
    source = path.read_text(encoding="utf-8-sig")
    tokens = tokenize_cpp(source)
    regions = {region["name"]: region for region in function_regions(tokens)}
    region = regions["scriptGetBranchType"]
    body = source[region["start"]:region["end"]]
    for match in re.finditer(r"\bif\s*\(([\s\S]*?)\)\s*return\s+(script\w+)\s*;", body):
        aliases = re.findall(r'StartsWith\(newtext,\s*"([^"\n]+)"\)', match[1])
        if not aliases:
            continue
        kind = match[2]
        line = source.count("\n", 0, region["start"] + match.start()) + 1
        row = make_row(f"native_script.branch.{kind}", "script_instruction",
                       {"path": path.relative_to(ROOT).as_posix(), "line": line},
                       {"nativeHandler": "scriptGetBranchType", "branchKind": kind,
                        "conditionHandler": "scriptBranchTaken", "input": "native script label"},
                       [alias.strip() for alias in aliases])
        row["provider"] = "debugger-native-script-runtime"
        row["stateRequirement"] = "native_script_loaded_and_branch_label_valid"
        row["acceptanceIds"] = ["A-46", "A-52"]
        indexed[row["id"]] = row
    internal = {}
    for match in re.finditer(r'scriptIsInternalCommand\(cmd,\s*"([^"\n]+)"\)', source):
        line = source.count("\n", 0, match.start()) + 1
        internal.setdefault(match[1], []).append({"path": path.relative_to(ROOT).as_posix(), "line": line})
    for name, locations in internal.items():
        row = make_row(f"native_script.instruction.{name}", "script_instruction", locations[0],
                       {"nativeHandler": "scriptInternalCmdExec", "sites": locations}, [name])
        row["provider"] = "debugger-native-script-runtime"
        row["stateRequirement"] = "native_script_runtime_command_guards"
        row["acceptanceIds"] = ["A-46", "A-52"]
        indexed[row["id"]] = row
    return list(indexed.values())


def collect_source_inventory():
    rows = []
    inputs = []
    indexed = {}
    excluded = []
    bindings = []
    factories = []
    automatic_slots = []
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
                connections = [{key: connection.findtext(key) for key in ("sender", "signal", "receiver", "slot")}
                               for connection in tree.findall("./connections/connection")]
                for widget in tree.iter():
                    if widget.tag not in ("widget", "action"):
                        continue
                    name = widget.get("name")
                    category = "gui_action" if widget.tag == "action" else "gui_view" if widget is tree.find("widget") else "gui_field"
                    identifier = f"ui.{form}.{name}"
                    variants = {"class": widget.get("class"), "form": form,
                                "properties": {value.get("name"): "".join(value.itertext()).strip()
                                               for value in widget.findall("property")},
                                "items": ["".join(item.itertext()).strip() for item in widget.findall("item")]}
                    relevant_connections = [connection for connection in connections
                                            if name in (connection["sender"], connection["receiver"])]
                    if relevant_connections:
                        variants["designerConnections"] = relevant_connections
                    rows.append(make_row(identifier, category, {"path": relative, "objectName": name}, variants))
                continue
            if path.suffix == ".cpp" and "/gui/" in relative:
                source = path.read_text(encoding="utf-8-sig")
                for region in function_regions(tokenize_cpp(source)):
                    match = re.fullmatch(r"(.+)::on_(.+)_([^_]+)", region["name"])
                    if match:
                        automatic_slots.append({"class": match[1], "objectName": match[2], "signal": match[3],
                                                "nativeHandler": region["name"],
                                                "source": {"path": relative, "line": source.count("\n", 0, region["start"]) + 1}})
            calls = list(source_calls(path))
            sections = configuration_sections(calls) if relative.endswith("Configuration.cpp") else {}
            for call in calls:
                if call["declaration"]:
                    excluded.append({"source": {"path": relative, "line": call["line"]},
                                     "function": call["function"], "reason": "declaration_or_definition"})
                    continue
                if not call["architectures"]:
                    excluded.append({"source": {"path": relative, "line": call["line"]},
                                     "function": call["function"], "reason": "inactive_architecture_branch"})
                    continue
                category = classify_call(call, relative)
                if category is None:
                    continue
                if category == "gui_binding":
                    bindings.append({"source": {"path": relative, "line": call["line"]}, "call": call})
                    continue
                if category in ("registration_factory", "action_factory", "setting_factory"):
                    factories.append({"category": category, "source": {"path": relative, "line": call["line"]}, "call": call})
                    continue
                operation = classify_operation(call, category, relative, sections)
                if operation is None:
                    continue
                identifier = operation["id"]
                if category == "gui_action" and identifier in indexed:
                    handlers = {site["nativeHandler"] for site in indexed[identifier]["variants"]["sites"]}
                    if operation["nativeHandler"] not in handlers:
                        suffix = hashlib.sha256((operation["nativeHandler"] or "").encode()).hexdigest()[:12]
                        identifier += "." + suffix
                if identifier not in indexed:
                    row = make_row(identifier, category, operation["source"], {"sites": []}, operation["aliases"])
                    row["stateRequirement"] = operation["stateRequirement"]
                    row["architectures"] = call["architectures"]
                    indexed[identifier] = row
                    rows.append(row)
                indexed[identifier]["architectures"] = sorted(set(indexed[identifier]["architectures"]) | set(call["architectures"]))
                if indexed[identifier]["stateRequirement"] != operation["stateRequirement"]:
                    indexed[identifier]["stateRequirement"] = "variant_specific_native_guard"
                indexed[identifier]["variants"]["sites"].append({"source": operation["source"], "call": call,
                                                                "nativeHandler": operation["nativeHandler"],
                                                                "stateRequirement": operation["stateRequirement"]})
    family_sources = {
        "insertMenuBuilderBools": "x64dbg/src/gui/Src/Utils/Configuration.cpp",
        "setupColumnConfigDefaultValue": "x64dbg/src/gui/Src/BasicView/AbstractTableView.cpp"}
    family_calls = {name: [value for value in source_calls(ROOT / path)
                          if value["function"] == "insert" and name in value["nativeScope"]]
                    for name, path in family_sources.items()}
    for row in rows:
        if row["category"] == "setting_family":
            call = row["variants"]["sites"][0]["call"]
            helper_path = family_sources[call["function"]]
            row["variants"]["generatedKeys"] = [{"expression": value["argumentExpressions"][0],
                                                    "defaultExpression": value["argumentExpressions"][1],
                                                    "source": {"path": helper_path, "line": value["line"]}}
                                                   for value in family_calls[call["function"]]]
            row["variants"]["indexCountExpression"] = call["argumentExpressions"][2]
            row["variants"]["viewNameExpression"] = call["argumentExpressions"][1]
        if row["id"].startswith("ui."):
            name = row["source"]["objectName"]
            stem = Path(row["source"]["path"]).stem
            pattern = re.compile(r"\bui->" + re.escape(name) + r"\b")
            references = [index for index, binding in enumerate(bindings)
                          if Path(binding["source"]["path"]).stem == stem and
                          any(pattern.search(value) for value in binding["call"]["argumentExpressions"])]
            if references:
                row["variants"]["bindingRefs"] = references
            slots = [slot for slot in automatic_slots if slot["class"] == row["variants"]["form"] and slot["objectName"] == name]
            if slots:
                row["variants"]["automaticSlots"] = slots
    rows.extend(collect_native_script_operations())
    identifiers = [row["id"] for row in rows]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Duplicate inventory identity")
    return {"schemaVersion": 2, "scope": "source-registration-and-form-inventory", "inputs": inputs,
            "categories": dict(Counter(row["category"] for row in rows)), "operations": rows,
            "bindings": bindings, "registrationFactories": factories, "excludedDeclarations": excluded,
            "coverageGaps": ["Dynamic menu instances and shipped opaque plugin operations require runtime reconciliation",
                             "Parameterized settings, context-created actions and native state guards require semantic review"]}


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


def build_inventory_fixture(environment, plugin_profile="shipped"):
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
    stage = environment.stage(plugin_profile)
    shutil.copy2(binary, stage / "plugins" / binary.name)


def capture_native_runtime_surface(debugger):
    path = debugger.environment.root / "runtime-surface-native-idle.json"
    argument = path.as_posix()
    if any(value in argument for value in '\"\r\n,'):
        raise McpError("Inventory output path cannot be represented as a debugger argument")
    debugger.start(f'baselineinventory "{argument}"')
    deadline = time.monotonic() + debugger.timeout
    while not path.is_file() and time.monotonic() < deadline:
        if debugger.proc.poll() is not None:
            raise McpError(f"Native debugger exited before capture: {debugger.proc.returncode}")
        time.sleep(0.05)
    if not path.is_file():
        raise McpError("Native GUI inventory did not complete")
    snapshot = json.loads(path.read_text(encoding="utf-8"))
    assert int(snapshot["processId"]) == debugger.proc.pid, "Inventory belongs to another process"
    assert snapshot["menus"] and snapshot["commands"] and snapshot["scriptProviders"], "Incomplete native runtime surface"
    assert "baselineinventory" in snapshot["commands"], "Inventory fixture was not registered"
    assert snapshot["debugState"] == {"debugging": False, "running": False}, "Native capture is not idle"
    modules = loaded_modules(debugger.proc)
    assert not any(Path(module["path"]).name.lower().startswith("x64dbg-mcp-server") for module in modules), "External MCP provider loaded"
    stage = debugger.environment.stage("native")
    assert pe_architecture(stage / "wininspect.exe") == debugger.environment.architecture, "Native debugger architecture differs"
    for name in ("wininspect.exe", "wininspect.dll", "winbridge.dll", "wingui.dll"):
        expected = file_identity(stage / name)
        actual = [module for module in modules if Path(module["path"]).resolve() == (stage / name).resolve()]
        assert len(actual) == 1 and actual[0]["sha256"] == expected["sha256"], f"Loaded native module differs: {name}"
    debugger.record["loadedModules"] = modules
    debugger.record["loadedModulesAfterInventory"] = modules
    resource_path = debugger.environment.root / "plugin-resources.json"
    write_json(resource_path, collect_plugin_resources(debugger.environment.stage("native") / "plugins"))
    return {"scope": "source-built native idle GUI surface without external MCP",
            "snapshots": [{"state": "native-idle", "artifact": file_identity(path), "menuCount": len(snapshot["menus"]),
                           "commandCount": len(snapshot["commands"]), "scriptProviders": snapshot["scriptProviders"]}],
            "pluginResources": file_identity(resource_path)}


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


def runtime_capture(surface_path, surface):
    evidence_path = Path(surface_path).parent / "evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    snapshot_identity = file_identity(surface_path)
    snapshots = [snapshot for result in evidence["results"]
                 for snapshot in result.get("oracle", {}).get("snapshots", [])
                 if snapshot["artifact"]["sha256"] == snapshot_identity["sha256"]]
    processes = [process for process in evidence["processes"] if process["pid"] == int(surface["processId"])]
    if len(snapshots) != 1 or len(processes) != 1 or not evidence["personalDeploymentUnchanged"]:
        raise ValueError("Runtime surface has no matching owned-process capture receipt")
    process = processes[0]
    snapshot_identity.pop("path")
    modules = [{"binaryName": Path(module["path"]).name, "sha256": module["sha256"], "size": module["size"]}
               for module in process["loadedModulesAfterInventory"]]
    return {"snapshot": snapshot_identity, "captureReceiptSha256": file_identity(evidence_path)["sha256"],
            "architecture": evidence["architecture"], "state": snapshots[0]["state"],
            "processId": surface["processId"], "processCreationTime": process["creationTime"],
            "loadedModules": modules}


def pe_architecture(path):
    content = Path(path).read_bytes()
    if content[:2] != b"MZ" or len(content) < 64:
        raise ValueError("Provider is not a PE binary")
    offset = struct.unpack_from("<I", content, 60)[0]
    if offset + 6 > len(content) or content[offset:offset + 4] != b"PE\0\0":
        raise ValueError("Provider has an invalid PE header")
    machine = struct.unpack_from("<H", content, offset + 4)[0]
    if machine not in (0x14C, 0x8664):
        raise ValueError("Provider architecture is unsupported")
    return "x64" if machine == 0x8664 else "x32"


def read_pe_exports(path):
    architecture = pe_architecture(path)
    content = Path(path).read_bytes()
    pe_offset = struct.unpack_from("<I", content, 60)[0]
    if pe_offset + 24 > len(content):
        raise ValueError("Truncated PE COFF header")
    section_count = struct.unpack_from("<H", content, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", content, pe_offset + 20)[0]
    optional = pe_offset + 24
    directory_offset = 112 if architecture == "x64" else 96
    if optional + optional_size > len(content) or optional_size < directory_offset + 8 or section_count > 96:
        raise ValueError("Invalid PE optional header")
    magic = struct.unpack_from("<H", content, optional)[0]
    if magic != (0x20B if architecture == "x64" else 0x10B):
        raise ValueError("PE machine and optional header disagree")
    section_start = optional + optional_size
    if section_start + section_count * 40 > len(content):
        raise ValueError("Truncated PE section table")
    sections = [struct.unpack_from("<IIII", content, section_start + index * 40 + 8)
                for index in range(section_count)]

    def mapped_offset(rva, length):
        for virtual_size, virtual_address, raw_size, raw_offset in sections:
            delta = rva - virtual_address
            if 0 <= delta and delta + length <= raw_size and raw_offset + delta + length <= len(content):
                return raw_offset + delta
        raise ValueError("PE export range has no complete file mapping")

    export_rva, export_size = struct.unpack_from("<II", content, optional + directory_offset)
    if not export_rva:
        return []
    if export_size < 40:
        raise ValueError("Truncated PE export directory")
    directory = mapped_offset(export_rva, 40)
    count = struct.unpack_from("<I", content, directory + 24)[0]
    names_rva = struct.unpack_from("<I", content, directory + 32)[0]
    if count > 65536:
        raise ValueError("PE export name count exceeds inventory limit")
    if not count:
        return []
    names_offset = mapped_offset(names_rva, count * 4)
    names = []
    for index in range(count):
        name_rva = struct.unpack_from("<I", content, names_offset + index * 4)[0]
        name_offset = mapped_offset(name_rva, 1)
        end = content.find(b"\0", name_offset, min(len(content), name_offset + 4096))
        if end < 0:
            raise ValueError("PE export name is not terminated within the inventory limit")
        mapped_offset(name_rva, end - name_offset + 1)
        names.append(content[name_offset:end].decode("ascii"))
    return names


def reconcile_native_script_exports(inventory, surface_path, capture_ref):
    evidence = json.loads((Path(surface_path).parent / "evidence.json").read_text(encoding="utf-8"))
    modules = [module for process in evidence["processes"] for module in process["loadedModulesAfterInventory"]
               if Path(module["path"]).name.lower() == "wininspect.dll"]
    if len(modules) != 1:
        raise ValueError("Native Script API capture has no unique engine DLL")
    module = modules[0]
    if file_identity(module["path"])["sha256"] != module["sha256"]:
        raise ValueError("Captured Script API engine DLL changed")
    architecture = pe_architecture(module["path"])
    symbols = {}
    for name in read_pe_exports(module["path"]):
        if name.startswith("?") and "@@" in name:
            parts = name[1:].split("@@", 1)[0].split("@")
            if parts[-1] == "Script":
                qualified = "::".join([*reversed(parts[1:]), parts[0]])
                symbols.setdefault(qualified, []).append(name)
    rows = {row["id"][len("script_api."):]: row for row in inventory["operations"] if row["category"] == "script_function"}
    expected = {name for name, row in rows.items() if architecture in row["architectures"]}
    for name in sorted(expected & set(symbols)):
        rows[name]["variants"].setdefault("nativeExportObservations", []).append(
            {"captureRef": capture_ref, "architecture": architecture, "binarySha256": module["sha256"], "symbols": symbols[name]})
    inventory.setdefault("nativeScriptExportCaptures", []).append(
        {"captureRef": capture_ref, "architecture": architecture, "binarySha256": module["sha256"],
         "qualifiedFunctionCount": len(symbols), "symbolCount": sum(len(value) for value in symbols.values()),
         "sourceFunctionsNotExported": sorted(expected - set(symbols)), "exportedFunctionsWithoutSource": sorted(set(symbols) - expected)})


def merge_runtime_surface(inventory, surface_path):
    surface = json.loads(Path(surface_path).read_text(encoding="utf-8"))
    if not surface.get("menus") or not surface.get("commands") or not surface.get("scriptProviders"):
        raise ValueError("Runtime surface is incomplete")
    capture = runtime_capture(surface_path, surface)
    snapshot_identity = capture["snapshot"]
    capture_key = snapshot_identity["sha256"]
    captures = inventory.setdefault("runtimeCaptures", {})
    if capture_key in captures:
        raise ValueError("Runtime capture was supplied twice")
    captures[capture_key] = capture
    capture_ref = f"runtimeCaptures.{capture_key}"
    reconcile_native_script_exports(inventory, surface_path, capture_ref)
    source = {"runtimeCaptureRef": capture_ref}
    commands = {command.lower() for command in surface["commands"]}
    command_rows = [row for row in inventory["operations"] if row["category"] == "command" and not row["id"].startswith("runtime.")]
    existing_aliases = {alias.lower() for row in command_rows for alias in row["aliases"]}
    for row in command_rows:
        observed = sorted(alias for alias in row["aliases"] if alias.lower() in commands)
        row["variants"]["runtimeCommandNames"] = sorted(set(row["variants"].get("runtimeCommandNames", [])) | set(observed))
        row["variants"].setdefault("runtimeCommandObservations", []).append({"captureRef": capture_ref, "names": observed})
    reconciliation = {
        "captureRef": capture_ref,
        "observedNameCount": len(commands), "sourceAliasCount": len(existing_aliases),
        "sourceNamesNotObserved": sorted(existing_aliases - commands),
        "runtimeNamesWithoutSource": sorted(commands - existing_aliases - {"baselineinventory"}),
        "fixtureNamesExcluded": ["baselineinventory"] if "baselineinventory" in commands else []}
    inventory.setdefault("commandReconciliations", []).append(reconciliation)
    inventory.setdefault("commandReconciliation", reconciliation)
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
        matches = [row for row in inventory["operations"] if row["id"] == f"script_provider.{provider}"]
        if matches:
            observed = {"captureRef": capture_ref, "name": provider}
            matches[0]["variants"].setdefault("runtimeObserved", observed)
            matches[0]["variants"].setdefault("runtimeObservations", []).append(observed)
        else:
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
        row["provider"] = "shipped-runtime-unresolved"
        row["architectures"] = [capture["architecture"]]
        row["architectureApplicability"] = "observed_only"
        row["providerBuildRef"] = capture_ref + ".loadedModules"
    resource_path = Path(surface_path).parent / "plugin-resources.json"
    if resource_path.is_file():
        resources = json.loads(resource_path.read_text(encoding="utf-8"))
        for binary in resources["binaries"]:
            name = Path(binary["binary"]["path"]).name
            provider_source = {"binaryName": name, "binarySha256": binary["binary"]["sha256"]}
            if file_identity(binary["binary"]["path"])["sha256"] != binary["binary"]["sha256"]:
                raise ValueError("Captured provider binary changed")
            architecture = pe_architecture(binary["binary"]["path"])
            provider_rows = []
            for resource in binary["resources"]:
                base = f"provider.{name}.resource.{resource['type']}.{resource['id']}.{resource['language']}"
                if resource["type"] == 5:
                    for control in resource["template"]["controls"]:
                        provider_rows.append(make_row(f"{base}.control.{control['id']}.{control['index']}", "gui_field",
                                                  provider_source, {"dialogId": resource["id"], "control": control,
                                                                    "resourceSha256": resource["sha256"]}))
                else:
                    pending = list(resource["template"]["items"])
                    index = 0
                    while pending:
                        item = pending.pop(0)
                        provider_rows.append(make_row(f"{base}.item.{item['id']}.{index}", "gui_action", provider_source, item))
                        pending.extend(item.get("children", []))
                        index += 1
            for row in provider_rows:
                row["provider"] = name
                row["architectures"] = [architecture]
                row["architectureApplicability"] = "captured_provider_binary"
                row["stateRequirement"] = "provider_loaded_and_native_dialog_guards"
                row["acceptanceIds"] = ["A-51", "A-52"]
            additions.extend(provider_rows)
        for configuration in resources["settings"]:
            for section, keys in configuration["sections"].items():
                for key in keys:
                    row = make_row(f"provider.{configuration['provider']}.setting.{section}.{key}", "setting",
                                   {"configurationName": Path(configuration["source"]["path"]).name,
                                    "configurationSha256": configuration["source"]["sha256"],
                                    "runtimeCaptureRef": capture_ref}, {"section": section, "key": key})
                    row["provider"] = configuration["provider"]
                    row["architectures"] = [capture["architecture"]]
                    row["architectureApplicability"] = "observed_only"
                    row["stateRequirement"] = "provider_profile_available"
                    row["acceptanceIds"] = ["A-51", "A-52"]
                    additions.append(row)
    indexed = {row["id"]: row for row in inventory["operations"]}
    for row in additions:
        observation = {"captureRef": capture_ref, "architecture": capture["architecture"],
                       "state": capture["state"], "variants": row["variants"]}
        if row["id"] in indexed:
            existing = indexed[row["id"]]
            if existing["category"] != row["category"] or existing["provider"] != row["provider"]:
                raise ValueError("Runtime identity has incompatible category or provider")
            existing["runtimeObservations"].append(observation)
            existing["architectures"] = sorted(set(existing["architectures"]) | set(row["architectures"]))
        else:
            row["runtimeObservations"] = [observation]
            indexed[row["id"]] = row
            inventory["operations"].append(row)
    identifiers = [row["id"] for row in inventory["operations"]]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Runtime reconciliation produced duplicate operation identities")
    inventory["categories"] = dict(Counter(row["category"] for row in inventory["operations"]))
    inventory.setdefault("runtimeSnapshot", snapshot_identity)
    inventory.setdefault("runtimeCapture", capture)
    inventory["coverageGaps"] = ["Context-created menus, lazy dialogs and opaque provider registration effects remain to be reconciled",
                                 "Runtime GUI identities need source bindings or native provider action identities",
                                 "Parameterized settings and state guards need semantic review"]
    observed_architectures = sorted({value["architecture"] for value in captures.values()})
    inventory["observedArchitectures"] = observed_architectures
    if len(observed_architectures) < 2:
        inventory["coverageGaps"].append(f"This registry contains only the {capture['architecture']} runtime capture; other captures need merging")


RUNTIME_VARIANT_FIELDS = frozenset(("runtimeCommandNames", "runtimeCommandObservations", "runtimeObserved", "runtimeObservations", "nativeExportObservations"))
RUNTIME_CAPTURE_LISTS = ("nativeScriptExportCaptures", "commandReconciliations")


def validate_recorded_registry(inventory):
    if inventory.get("schemaVersion") != 2 or inventory.get("scope") != "source-registration-and-form-inventory":
        raise ValueError("Recorded parity registry has an unsupported version or scope")
    for field, key in (("inputs", "path"), ("operations", "id")):
        rows = inventory.get(field)
        if not isinstance(rows, list) or not rows or any(not isinstance(row, dict) or not isinstance(row.get(key), str) for row in rows):
            raise ValueError("Recorded parity registry has invalid " + field)
        if len({row[key] for row in rows}) != len(rows):
            raise ValueError("Recorded parity registry has duplicate " + key)
    for source in inventory["inputs"]:
        if not isinstance(source.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", source["sha256"]):
            raise ValueError("Recorded parity source input has an invalid digest")
    for row in inventory["operations"]:
        required = ("category", "aliases", "provider", "architectures", "stateRequirement", "agentRoute", "acceptanceIds", "completionPredicate", "status", "evidence")
        if any(field not in row for field in required):
            raise ValueError("Recorded parity operation lacks a mandatory contract field")
        if not isinstance(row.get("source"), dict) or not isinstance(row.get("variants"), dict):
            raise ValueError("Recorded parity operation lacks its source or variants")
        capture = row["source"].get("runtimeCaptureRef")
        if capture is not None and (not isinstance(capture, str) or not capture.startswith("runtimeCaptures.") or capture.split(".", 1)[1] not in inventory.get("runtimeCaptures", {})):
            raise ValueError("Recorded parity operation refers to a missing runtime capture")
    if dict(Counter(row["category"] for row in inventory["operations"])) != inventory.get("categories"):
        raise ValueError("Recorded parity registry category totals do not match its operations")


def source_projection(row):
    fields = ("id", "category", "source", "aliases", "provider", "architectures", "stateRequirement", "completionPredicate", "acceptanceIds")
    result = {field: row[field] for field in fields}
    result["variants"] = {key: value for key, value in row["variants"].items() if key not in RUNTIME_VARIANT_FIELDS}
    return result


def operation_source_paths(value):
    if isinstance(value, dict):
        if isinstance(value.get("path"), str):
            yield value["path"]
        for child in value.values():
            yield from operation_source_paths(child)
    elif isinstance(value, list):
        for child in value:
            yield from operation_source_paths(child)


def merge_recorded_registry(current, previous, previous_sha256):
    validate_recorded_registry(current)
    validate_recorded_registry(previous)
    current = copy.deepcopy(current)
    merged = copy.deepcopy(previous)
    old_inputs = {entry["path"]: entry["sha256"] for entry in previous["inputs"]}
    new_inputs = {entry["path"]: entry["sha256"] for entry in current["inputs"]}
    changed_inputs = {path for path in old_inputs if old_inputs[path] != new_inputs.get(path)}
    current_rows = {row["id"]: row for row in current["operations"]}
    rows = []
    retained = []
    unresolved = []
    newly_unresolved = []
    restored = []
    changed_rows = []
    invalidated = []
    for old in previous["operations"]:
        replacement = current_rows.pop(old["id"], None)
        source_owned = "path" in old["source"]
        if replacement is None:
            replacement = copy.deepcopy(old)
            retained.append(old["id"])
            if source_owned:
                replacement["sourceAvailability"] = "not_found_in_current_inventory"
                unresolved.append(old["id"])
                if old.get("sourceAvailability") != "not_found_in_current_inventory":
                    newly_unresolved.append(old["id"])
        elif old["category"] != replacement["category"] or old["provider"] != replacement["provider"]:
            raise ValueError("A parity identity changed category or provider")
        else:
            if old.get("sourceAvailability") == "not_found_in_current_inventory":
                restored.append(old["id"])
            if not source_owned:
                replacement["architectures"] = sorted(set(old["architectures"]) | set(replacement["architectures"]))
            if source_projection(old) != source_projection(replacement):
                changed_rows.append(old["id"])
            for field, value in old.items():
                if field not in replacement and field != "sourceAvailability":
                    replacement[field] = copy.deepcopy(value)
            for field in ("agentRoute", "status", "evidence"):
                replacement[field] = copy.deepcopy(old[field])
            for field in RUNTIME_VARIANT_FIELDS:
                if field in old["variants"]:
                    if field not in replacement["variants"]:
                        replacement["variants"][field] = copy.deepcopy(old["variants"][field])
                    elif isinstance(old["variants"][field], list):
                        replacement["variants"][field] = copy.deepcopy(old["variants"][field]) + [value for value in replacement["variants"][field] if value not in old["variants"][field]]
            if "runtimeObservations" in old:
                replacement["runtimeObservations"] = copy.deepcopy(old["runtimeObservations"]) + [value for value in replacement.get("runtimeObservations", []) if value not in old["runtimeObservations"]]
        touched_source = bool(set(operation_source_paths(source_projection(old))) & changed_inputs)
        if old["status"] in ("verified", "complete") and (touched_source or old["id"] in changed_rows or old["id"] in unresolved):
            replacement.setdefault("invalidatedEvidence", []).append({"status": old["status"], "evidence": copy.deepcopy(old["evidence"]), "reason": "source_binding_changed"})
            replacement["status"], replacement["evidence"] = "planned", None
            invalidated.append(old["id"])
        rows.append(replacement)
    rows.extend(current_rows.values())
    for field in ("schemaVersion", "scope", "inputs", "bindings", "registrationFactories", "excludedDeclarations"):
        merged[field] = current[field]
    captures = merged.setdefault("runtimeCaptures", {})
    for key, capture in current.get("runtimeCaptures", {}).items():
        if key in captures and captures[key] != capture:
            raise ValueError("Recorded runtime capture has conflicting provenance")
        captures[key] = capture
    for field in RUNTIME_CAPTURE_LISTS:
        if field in current:
            merged.setdefault(field, [])
            merged[field].extend(value for value in current[field] if value not in merged[field])
    for field in ("runtimeSnapshot", "runtimeCapture", "commandReconciliation"):
        if field in current:
            merged[field] = current[field]
    if captures:
        merged["observedArchitectures"] = sorted({capture["architecture"] for capture in captures.values()})
    merged["operations"] = rows
    merged["categories"] = dict(Counter(row["category"] for row in rows))
    merged["coverageGaps"] = list(dict.fromkeys(previous["coverageGaps"] + current["coverageGaps"]))
    if unresolved:
        gap = "Previously inventoried source actions absent from the current scan require explicit reconciliation"
        if gap not in merged["coverageGaps"]:
            merged["coverageGaps"].append(gap)
    report = {"previousManifestSha256": previous_sha256, "previousOperationCount": len(previous["operations"]),
              "currentDiscoveredOperationCount": len(current["operations"]), "mergedOperationCount": len(rows),
              "retainedOperationIds": retained, "unresolvedSourceIds": unresolved, "restoredSourceIds": restored, "changedSourceIds": changed_rows,
              "invalidatedEvidenceIds": invalidated, "changedInputPaths": sorted(changed_inputs),
              "addedInputPaths": sorted(new_inputs.keys() - old_inputs.keys()), "addedOperationIds": sorted(current_rows)}
    changed_captures = current.get("runtimeCaptures", {}).keys() - previous.get("runtimeCaptures", {}).keys()
    if report["changedInputPaths"] or report["addedInputPaths"] or changed_rows or current_rows or invalidated or changed_captures or newly_unresolved or restored:
        merged.setdefault("sourceReconciliations", []).append(report)
    validate_recorded_registry(merged)
    return merged, report


def parity_registry_content(inventory):
    fields = []
    for name, value in inventory.items():
        if name in ("inputs", "operations", "bindings", "registrationFactories", "excludedDeclarations"):
            entries = ",\n".join("    " + json.dumps(entry, ensure_ascii=False) for entry in value)
            serialized = "[\n" + entries + "\n  ]"
        else:
            serialized = json.dumps(value, indent=2, ensure_ascii=False).replace("\n", "\n  ")
        fields.append("  " + json.dumps(name) + ": " + serialized)
    return "{\n" + ",\n".join(fields) + "\n}\n"


def write_parity_registry(path, inventory):
    Path(path).write_text(parity_registry_content(inventory), encoding="utf-8", newline="\n")


def native_parity_catalog_content(inventory, manifest_sha256):
    validate_recorded_registry(inventory)
    if not isinstance(manifest_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256):
        raise ValueError("Native parity source requires a baseline SHA-256")
    if any(row["status"] != "planned" or row["agentRoute"] is not None or row["evidence"] is not None for row in inventory["operations"]):
        raise ValueError("Native declaration discovery cannot publish unimplemented operational routes or readiness")
    captures = []
    for key, value in inventory.get("runtimeCaptures", {}).items():
        captures.append({"captureRef": "runtimeCaptures." + key, "architecture": value["architecture"], "state": value["state"],
                         "snapshotSha256": value["snapshot"]["sha256"], "receiptSha256": value["captureReceiptSha256"],
                         "modules": value["loadedModules"], "currentRuntimeProof": False})
    collections = {"operation": inventory["operations"], "binding": inventory["bindings"],
                   "registration_factory": inventory["registrationFactories"], "excluded_declaration": inventory["excludedDeclarations"]}
    metadata = {"schemaVersion": 1, "baselineManifestSha256": manifest_sha256, "sourceInputs": inventory["inputs"],
                "categories": inventory["categories"], "recordCounts": {key: len(rows) for key, rows in collections.items()},
                "historicalCaptures": captures, "coverageGaps": inventory["coverageGaps"]}
    records = [{"kind": "metadata", "data": metadata}]
    for kind, rows in collections.items():
        for index, row in enumerate(rows):
            key = "parity." + hashlib.sha256(row["id"].encode("utf-8")).hexdigest() if kind == "operation" else str(index)
            records.append({"kind": kind, "key": key, "data": row})
    return "".join(json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n" for row in records)


def write_native_parity_catalog(path, inventory, manifest_sha256):
    Path(path).write_text(native_parity_catalog_content(inventory, manifest_sha256), encoding="ascii", newline="\n")


def run_inventory(output, catalog_path, refresh, surface_paths=None, registry_path=None):
    inventory = collect_source_inventory()
    if isinstance(surface_paths, (str, Path)):
        surface_paths = [surface_paths]
    for surface_path in surface_paths or []:
        merge_runtime_surface(inventory, surface_path)
    native_refresh = registry_path is None
    registry_path = Path(registry_path) if registry_path is not None else REGISTRY_DIRECTORY / "parity-manifest.json"
    prior_reconciliation = None
    if registry_path.is_file():
        previous = json.loads(registry_path.read_text(encoding="utf-8"))
        inventory, prior_reconciliation = merge_recorded_registry(inventory, previous, file_identity(registry_path)["sha256"])
    write_json(Path(output) / "source-inventory.json", inventory)
    reconciliation = reconcile_legacy_catalog(catalog_path)
    write_json(Path(output) / "legacy-reconciliation.json", reconciliation)
    if refresh:
        native_content = native_parity_catalog_content(inventory, hashlib.sha256(parity_registry_content(inventory).encode("utf-8")).hexdigest()) if native_refresh else None
        write_parity_registry(registry_path, inventory)
        if native_refresh:
            (ROOT / "x64dbg/src/mcp/common/parity_catalog.jsonl").write_text(native_content, encoding="ascii", newline="\n")
    return {"legacy": reconciliation, "categories": inventory["categories"],
            "sourceInputs": len(inventory["inputs"]), "coverageGaps": inventory["coverageGaps"], "priorReconciliation": prior_reconciliation}
