"""Bounded source-only discovery of MCP tools derived from a boto3 SDK model.

This analyzes a *narrow but structural* source pattern: a registered helper
instantiates a generator whose code loops over SDK client methods, registers
MCP tools and dispatches to those methods. No inspected Python is imported
or executed. Trusted, locally installed botocore service models are queried
for a versioned candidate method domain; this does NOT establish the runtime
SDK version nor the final tools/list inventory.

All results are unapproved, potentially exposed candidates; conditional or
unresolved configuration/override/validator paths are explicitly disclosed.
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

MAX_SOURCE_FILES = 40
MAX_BYTES_PER_FILE = 1_000_000
MAX_GENERATED = 250


class DynamicDiscoveryError(ValueError):
    pass


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _dict(node):
    if not isinstance(node, ast.Dict):
        return None
    result = {}
    for key, value in zip(node.keys, node.values):
        k = _name(key)
        if k is None:
            return None
        if isinstance(value, ast.Constant):
            result[k] = value.value
        elif isinstance(value, (ast.Name, ast.Attribute)):
            result[k] = _name(value)
        elif isinstance(value, ast.Dict):
            sub = _dict(value)
            if sub is None:
                return None
            result[k] = sub
        else:
            return None
    return result


def _modules(root):
    root = Path(root).resolve()
    modules = {}
    for path in sorted(root.rglob("*.py")):
        if len(modules) >= MAX_SOURCE_FILES:
            raise DynamicDiscoveryError("MODULE_SCAN_LIMIT")
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise DynamicDiscoveryError("UNSAFE_MODULE_PATH")
        if path.stat().st_size > MAX_BYTES_PER_FILE:
            raise DynamicDiscoveryError("OVERSIZED_MODULE")
        source = path.read_text(encoding="utf-8")
        rel = path.relative_to(root).with_suffix("")
        module = ".".join(rel.parts)
        modules[module] = {
            "file": str(path),
            "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "tree": ast.parse(source, filename=str(path)),
        }
    return modules


def _generator_proven(node):
    """Require a client-method enumeration and MCP registration with dispatch."""
    if not isinstance(node, ast.ClassDef):
        return False
    functions = {f.name: f for f in node.body if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))}
    body = list(ast.walk(node))
    method_enum = any(
        isinstance(x, ast.Call) and _call_name(x.func) == "dir"
        for x in body
    )
    registering = any(
        isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute)
        and x.func.attr == "tool" for x in body
    )
    dispatch = any(
        isinstance(x, ast.Call) and _call_name(x.func) == "getattr"
        and len(x.args) >= 2 and isinstance(x.args[1], ast.Name)
        for x in body
    )
    returns_created = any(
        "generate" == name for name in functions
    )
    return method_enum and registering and dispatch and returns_created


def _function(module_tree, func_name):
    return next(
        (x for x in module_tree.body if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef))
         and x.name == func_name),
        None,
    )


def _parse_registration_config(func, config_name):
    """Only literal dictionary plus static ignore-list loops are supported."""
    configuration = {}
    conditional_ignored = set()
    gaps = []
    initialized = set()
    lists = {}
    for stmt in func.body:
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, (ast.List, ast.Tuple)):
            elements = [_name(x) for x in stmt.value.elts]
            if all(x is not None for x in elements):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        lists[target.id] = set(elements)
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Dict):
            obj = _dict(stmt.value)
            if obj is not None:
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id == config_name:
                        initialized.add(target.id)
                        configuration.update(obj)
    # Any syntactically clear assignment to a dict key is a configuration
    # input; we never silently ignore a dynamic update.
    for stmt in func.body:
        if isinstance(stmt, ast.For):
            iterable = _name(stmt.iter)
            if iterable in lists:
                for child in stmt.body:
                    if (isinstance(child, ast.Assign) and len(child.targets) == 1
                        and isinstance(child.targets[0], ast.Subscript)
                        and _name(child.targets[0].value) == config_name
                        and _name(child.targets[0].slice) == _name(stmt.target)):
                        entry = _dict(child.value)
                        if entry is None:
                            gaps.append("DYNAMIC_TOOL_CONFIGURATION_VALUE")
                        else:
                            for operation in lists[iterable]:
                                configuration[operation] = entry
        elif isinstance(stmt, ast.If):
            for child in stmt.body:
                if (isinstance(child, ast.Assign) and len(child.targets) == 1
                    and isinstance(child.targets[0], ast.Subscript)
                    and _name(child.targets[0].value) == config_name):
                    op = _name(child.targets[0].slice)
                    entry = _dict(child.value)
                    if op and entry and entry.get("ignore") is True:
                        conditional_ignored.add(op)
                    else:
                        gaps.append("CONDITIONAL_TOOL_CONFIGURATION_UNRESOLVED")
        elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if (isinstance(target, ast.Subscript)
                and _name(target.value) == config_name):
                op, entry = _name(target.slice), _dict(stmt.value)
                if op and entry is not None:
                    configuration[op] = entry
                else:
                    gaps.append("TOOL_CONFIGURATION_ASSIGNMENT_UNRESOLVED")
    if config_name is not None and config_name not in initialized:
        gaps.append("TOOL_CONFIGURATION_SOURCE_UNRESOLVED")
    if config_name is not None:
        for call in ast.walk(func):
            if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name)
                    and call.func.value.id == config_name
                    and call.func.attr in {"update", "setdefault", "pop", "clear"}):
                gaps.append("TOOL_CONFIGURATION_MUTATION_UNRESOLVED")
        for statement in ast.walk(func):
            if (isinstance(statement, ast.Assign) and
                    any(isinstance(t, ast.Subscript)
                        and isinstance(t.value, ast.Name)
                        and t.value.id == config_name for t in statement.targets)
                    and statement not in func.body):
                # This is handled above only for direct, provable loop and
                # conditional forms. Unrecognized nesting is not trusted.
                if not (
                    isinstance(statement.value, ast.Dict)
                    and _dict(statement.value) is not None
                ):
                    gaps.append("TOOL_CONFIGURATION_MUTATION_UNRESOLVED")
    return configuration, conditional_ignored, sorted(set(gaps))


def _callback_calls(tree, callback, client_parameter, visited=None):
    """Track direct SDK calls on the callback client's argument and local
    helper calls receiving the same client, with cycle and depth guards."""
    if visited is None:
        visited = set()
    if callback in visited or len(visited) >= 10:
        return [], ["CALLBACK_RECURSION_OR_DEPTH_LIMIT"]
    fn = _function(tree, callback)
    if fn is None:
        return [], ["CALLBACK_NOT_FOUND:" + callback]
    visited = visited | {callback}
    ops, gaps = [], []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        if (isinstance(callee, ast.Attribute) and
                isinstance(callee.value, ast.Name) and
                callee.value.id == client_parameter):
            ops.append((callee.attr, node.lineno, callback))
        elif isinstance(callee, ast.Name) and callee.id != callback:
            referenced = _function(tree, callee.id)
            if referenced is None:
                continue
            # Only follow a helper if the SDK client is explicitly forwarded.
            client_position = next(
                (idx for idx, arg in enumerate(node.args)
                 if isinstance(arg, ast.Name) and arg.id == client_parameter), None
            )
            if client_position is None:
                continue
            formal = referenced.args.args
            if client_position >= len(formal):
                gaps.append("CALLBACK_CLIENT_ARGUMENT_UNRESOLVED")
                continue
            further, missing = _callback_calls(
                tree, callee.id, formal[client_position].arg, visited
            )
            ops.extend(further)
            gaps.extend(missing)
    return sorted(set(ops)), sorted(set(gaps))


def _override_operations(tree, override_name):
    """Prove a nested override MCP handler's direct SDK client methods.

    Only attributes of variables assigned directly from the getter parameter
    are accepted. Calls via other objects remain unresolved.
    """
    outer = _function(tree, override_name)
    if outer is None or len(outer.args.args) < 2:
        return None
    getter = outer.args.args[1].arg
    outputs = []
    for nested in ast.walk(outer):
        if not isinstance(nested, (ast.FunctionDef, ast.AsyncFunctionDef)) or nested is outer:
            continue
        if not any(isinstance(dec, ast.Call)
                   and isinstance(dec.func, ast.Attribute)
                   and dec.func.attr == "tool" for dec in nested.decorator_list):
            continue
        sdk_aliases = set()
        for stmt in ast.walk(nested):
            if (isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call)
                    and isinstance(stmt.value.func, ast.Name)
                    and stmt.value.func.id == getter):
                sdk_aliases.update(t.id for t in stmt.targets if isinstance(t, ast.Name))
        ops = sorted({
            (call.func.attr, call.lineno)
            for call in ast.walk(nested) if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id in sdk_aliases
        })
        outputs.append({"tool": nested.name, "operations": ops,
                        "line": nested.lineno})
    return outputs or None


def _has_dynamic_dispatch(node):
    # The generator must forward the enumerated operation to getattr()
    # and call the resulting method dynamically.
    found = False
    for method in ast.walk(node):
        if (isinstance(method, ast.Call) and
                _call_name(method.func) == "getattr" and len(method.args) >= 2):
            found = True
    return found


def _service_model_methods(service):
    import botocore
    import botocore.session
    from botocore import xform_name

    session = botocore.session.get_session()
    try:
        model = session.get_service_model(service)
    except Exception as exc:
        raise DynamicDiscoveryError("TRUSTED_BOTOCORE_SERVICE_NOT_AVAILABLE:" + service) from exc
    mapping = {xform_name(op): op for op in model.operation_names}
    if len(mapping) > MAX_GENERATED:
        raise DynamicDiscoveryError("SDK_OPERATION_DOMAIN_LIMIT")
    return mapping, {
        "botocore_version": botocore.__version__,
        "service_api_version": model.api_version,
        "source": "TRUSTED_LOCAL_BOTOCORE_MODEL_NOT_DEPLOYMENT_VERIFIED",
    }


def discover_dynamic_sdk_tools(source_root, entry_file, *, sdk_methods=None):
    """Return potential SDK-derived tools, not confirmed tools/list inventory.

    A caller may supply a frozen SDK operation domain; otherwise the trusted
    installed botocore service model is used and tagged as unverified for
    deployment. The inspected project is never imported or executed.
    """
    root = Path(source_root).resolve()
    entry = Path(entry_file).resolve()
    if not entry.is_relative_to(root) or not entry.is_file() or entry.is_symlink():
        raise DynamicDiscoveryError("ENTRY_OUTSIDE_SOURCE_ROOT")
    modules = _modules(root)
    entry_module = ".".join(entry.relative_to(root).with_suffix("").parts)
    if entry_module not in modules:
        raise DynamicDiscoveryError("ENTRY_NOT_INDEXED")
    entry_tree = modules[entry_module]["tree"]
    imported = {}
    for item in entry_tree.body:
        if isinstance(item, ast.ImportFrom) and not item.level and item.module:
            for alias in item.names:
                imported[alias.asname or alias.name] = (item.module, alias.name)
    calls = []
    for item in ast.walk(entry_tree):
        if not isinstance(item, ast.Call) or not isinstance(item.func, ast.Name):
            continue
        imported_name = imported.get(item.func.id)
        if imported_name and any(isinstance(arg, ast.Name) and arg.id == "mcp"
                                 for arg in item.args):
            calls.append((item, *imported_name))
    observations, gaps, source_files = [], [], {
        entry_module: {"path": modules[entry_module]["file"],
                       "sha256": modules[entry_module]["sha256"]}
    }
    if not calls:
        return {
            "schema_version": "dynamic-sdk-tools-preview-v1",
            "exposure_confirmed": False,
            "tools": [],
            "gaps": [{"reason": "NO_RECOGNIZED_SDK_TOOL_REGISTRATION", "file": str(entry)}],
            "source_files": [],
        }

    for invocation, module_name, function_name in calls:
        candidate = modules.get(module_name)
        if candidate is None:
            gaps.append({"reason": "DYNAMIC_REGISTRATION_MODULE_MISSING",
                         "function": function_name, "module": module_name})
            continue
        source_files[module_name] = {
            "path": candidate["file"], "sha256": candidate["sha256"]
        }
        function = _function(candidate["tree"], function_name)
        if function is None:
            gaps.append({"reason": "REGISTRATION_FUNCTION_NOT_FOUND",
                         "function": function_name, "module": module_name})
            continue

        assignments = {}
        for node in ast.walk(function):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                continue
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                assignments[node.targets[0].id] = node.value

        gen_calls = []
        for node in ast.walk(function):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "generate"
                    and isinstance(node.func.value, ast.Name)):
                source_call = assignments.get(node.func.value.id)
                if source_call is not None:
                    gen_calls.append((node, source_call))
        if not gen_calls:
            gaps.append({"reason": "SDK_GENERATOR_CALL_GRAPH_NOT_PROVEN",
                         "function": function_name, "file": candidate["file"]})
            continue

        import_map = {}
        for stmt in candidate["tree"].body:
            if isinstance(stmt, ast.ImportFrom):
                for alias in stmt.names:
                    import_map[alias.asname or alias.name] = (stmt.module or "", alias.name)

        for _, gen_call in gen_calls:
            cls_name = _call_name(gen_call.func)
            if cls_name is None:
                gaps.append({"reason": "SDK_GENERATOR_CONSTRUCTOR_UNKNOWN"})
                continue
            class_ref = import_map.get(cls_name, (module_name, cls_name))
            class_module = modules.get(class_ref[0])
            cls = None
            if class_module:
                cls = next((x for x in class_module["tree"].body
                            if isinstance(x, ast.ClassDef) and x.name == class_ref[1]), None)
            if cls is None or not _generator_proven(cls) or not _has_dynamic_dispatch(cls):
                gaps.append({"reason": "SDK_GENERATOR_PATTERN_NOT_PROVEN",
                             "class": cls_name, "file": candidate["file"]})
                continue
            source_files[class_ref[0]] = {
                "path": class_module["file"], "sha256": class_module["sha256"]
            }
            config_arg = next((kw.value for kw in gen_call.keywords
                               if kw.arg == "tool_configuration"), None)
            config_name = _name(config_arg) if config_arg is not None else None
            config, conditional_ignored, parse_gaps = _parse_registration_config(
                function, config_name
            ) if config_name is not None else ({}, set(), [])
            if parse_gaps:
                gaps.extend({"reason": reason, "function": function_name,
                             "file": candidate["file"]} for reason in parse_gaps)
                # This is not a provably complete configuration. Abstain.
                continue
            service = next((node.value.value for node in gen_call.keywords
                            if node.arg == "service_name"
                            and isinstance(node.value, ast.Constant)
                            and isinstance(node.value.value, str)), None)
            if service is None:
                gaps.append({"reason": "DYNAMIC_GENERATOR_SERVICE_UNRESOLVED",
                             "file": candidate["file"]})
                continue
            if sdk_methods is not None:
                sdk_domain = sdk_methods.get(service)
                if sdk_domain is None:
                    gaps.append({"reason": "SDK_MODEL_FOR_SERVICE_UNAVAILABLE",
                                 "service": service})
                    continue
                sdk_domain = dict(sdk_domain)
                sdk_provenance = {"source": "CALLER_PINNED_SDK_METHOD_DOMAIN"}
            else:
                try:
                    sdk_domain, sdk_provenance = _service_model_methods(service)
                except DynamicDiscoveryError as exc:
                    gaps.append({"reason": str(exc), "service": service})
                    continue

            for sdk_method, api_name in sorted(sdk_domain.items()):
                entry_config = config.get(sdk_method, {})
                if entry_config.get("ignore") is True:
                    continue
                override = entry_config.get("func_override")
                validator = entry_config.get("validator")
                name = entry_config.get("name_override") or sdk_method
                evidence = {
                    "tool": name, "service": service,
                    "operation": sdk_method, "api_operation": api_name,
                    "registration_kind": "SDK_MODEL_DERIVED_CANDIDATE",
                    "registration_file": candidate["file"],
                    "registration_line": invocation.lineno,
                    "generator_class": cls_name,
                    "generator_file": class_module["file"],
                    "sdk_provenance": sdk_provenance,
                    "exposure": "CONDITIONAL" if sdk_method in conditional_ignored
                                else "SDK_VERSION_AND_CONFIG_UNVERIFIED",
                    "main_operation_proven": override is None,
                    "main_operation": sdk_method if override is None else None,
                    "auxiliary_operations": [],
                    "gaps": [],
                }
                if override is not None:
                    proven = _override_operations(candidate["tree"], override)
                    if (proven and len(proven) == 1
                            and len(proven[0]["operations"]) == 1):
                        handler = proven[0]
                        evidence["tool"] = handler["tool"]
                        evidence["main_operation"] = handler["operations"][0][0]
                        evidence["main_operation_proven"] = True
                        evidence["override_source"] = {
                            "file": candidate["file"],
                            "line": handler["operations"][0][1],
                            "callback": override,
                        }
                    else:
                        evidence["gaps"].append("OVERRIDE_HANDLER_REQUIRES_SEPARATE_ANALYSIS")
                if validator is not None:
                    cb = _function(candidate["tree"], validator)
                    if cb is None:
                        evidence["gaps"].append("VALIDATOR_SOURCE_UNRESOLVED")
                    else:
                        # Validator convention: mcp, boto3_client, request kwargs
                        args = cb.args.args
                        if len(args) < 2:
                            evidence["gaps"].append("VALIDATOR_CLIENT_BINDING_UNRESOLVED")
                        else:
                            ops, missing = _callback_calls(candidate["tree"], validator, args[1].arg)
                            evidence["auxiliary_operations"] = [
                                {"operation": op, "line": line, "callback": fun,
                                 "file": candidate["file"]}
                                for op, line, fun in ops
                            ]
                            evidence["gaps"].extend(missing)
                            if not ops and not missing:
                                evidence["gaps"].append("VALIDATOR_BEHAVIOR_NOT_PROVEN")
                observations.append(evidence)
                if len(observations) >= MAX_GENERATED:
                    gaps.append({"reason": "DYNAMIC_TOOL_OUTPUT_LIMIT"})
                    break

    return {
        "schema_version": "dynamic-sdk-tools-preview-v1",
        "exposure_confirmed": False,
        "approval_eligible": False,
        "tools": observations,
        "source_files": list(source_files.values()),
        "gaps": gaps,
        "warning": "These are SDK/configuration-derived tool CANDIDATES, not verified tools/list or approved MCP permissions.",
    }
