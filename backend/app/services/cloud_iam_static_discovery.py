"""Static, read-only AWS operation discovery from Python MCP sources.

Prototype scope: Python, boto3, FastMCP-style tools, same-module helpers.
Does not execute/import inspected source or claim completeness or IAM authority.
"""
from __future__ import annotations

import ast
from hashlib import sha256
from pathlib import Path

MAX_BYTES = 1_000_000
MAX_FUNCTIONS = 2000
MAX_DEPTH = 14
MAX_OPERATIONS = 250
RESOURCE_KEYS = frozenset({
    "Bucket", "Key", "Prefix", "TableName", "IndexName",
    "QueueUrl", "FunctionName", "LogGroupName", "logGroupName",
    "logGroupNames", "ResourceArn", "TopicArn", "StreamName",
})


class DiscoveryError(ValueError):
    pass


class AWSObject:
    def __init__(self, service, destination, kind="client", value=None):
        self.service, self.destination, self.kind, self.value = service, destination, kind, value

    def __eq__(self, other):
        return (isinstance(other, AWSObject) and
                (self.service, self.destination, self.kind, self.value) ==
                (other.service, other.destination, other.kind, other.value))


class Inspector:
    def __init__(self, source, source_name, external_modules=None):
        if len(source.encode("utf-8")) > MAX_BYTES:
            raise DiscoveryError("SOURCE_TOO_LARGE")
        try:
            self.tree = ast.parse(source, filename=source_name)
        except SyntaxError as exc:
            raise DiscoveryError(f"SYNTAX_ERROR:{exc.lineno}") from exc
        self.name = source_name
        self.digest = sha256(source.encode("utf-8")).hexdigest()
        self.source_digests = {source_name: self.digest}
        self.functions = {}
        self.tools = {}
        self.imports = {}
        self.globals = {}
        self.results = []
        self.gaps = []
        self.tool = ""
        self.wrapper_clients = {}
        self.wrapper_ambiguous = set()
        self.external_contexts = {}
        self._index()
        self._index_external(external_modules or {})

    @staticmethod
    def _literal(node):
        return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

    def _index(self):
        for node in self.tree.body:
            if isinstance(node, ast.Import):
                for x in node.names:
                    self.imports[x.asname or x.name] = x.name
            if isinstance(node, ast.ImportFrom):
                for x in node.names:
                    self.imports[x.asname or x.name] = (node.module or "") + "." + x.name
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node
                if self._is_tool(node):
                    self.tools[node.name] = node.name
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        qname = node.name + "." + item.name
                        self.functions[qname] = item
                        if self._is_tool(item):
                            self.tools[item.name] = qname
        if len(self.functions) > MAX_FUNCTIONS:
            raise DiscoveryError("TOO_MANY_FUNCTIONS")
        self._index_wrapper_constructors()
        for node in self.tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        self.globals[target.id] = self.symbol(node.value, self.globals)
        # Some frameworks register bound methods in register() rather than decorating.
        for qname, func in self.functions.items():
            if qname.split(".")[-1] != "register":
                continue
            owner = qname.rsplit(".", 1)[0] if "." in qname else ""
            for node in ast.walk(func):
                if not isinstance(node, ast.Call) or not node.args:
                    continue
                wrapper = node.func
                is_tool = (isinstance(wrapper, ast.Call)
                           and isinstance(wrapper.func, ast.Attribute)
                           and wrapper.func.attr == "tool")
                is_tool |= (isinstance(wrapper, ast.Attribute)
                            and wrapper.attr in {"add_tool", "register_tool"})
                if not is_tool:
                    continue
                handler = self.helper_name(node.args[0], owner)
                if handler:
                    self.tools.setdefault(handler.rsplit(".", 1)[-1], handler)

    def _index_wrapper_constructors(self):
        """Collect literal boto3 clients assigned to self.FIELD in constructors.

        Class bodies are parsed only. Distinct candidates for one attribute
        stay unresolved rather than inventing a single AWS service.
        """
        for cls in self.tree.body:
            if not isinstance(cls, ast.ClassDef):
                continue
            init = next((x for x in cls.body if isinstance(x, ast.FunctionDef)
                         and x.name == "__init__"), None)
            if init is None:
                continue
            choices = {}
            for stmt in ast.walk(init):
                if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                    continue
                value = stmt.value
                if not isinstance(value, ast.Call):
                    continue
                kind = self._sdk_constructor(value.func)
                if kind not in {"client", "resource"}:
                    continue
                service = self._literal(value.args[0]) if value.args else None
                for key in value.keywords:
                    if key.arg == "service_name":
                        service = self._literal(key.value)
                if not service:
                    continue
                endpoints = [key for key in value.keywords if key.arg == "endpoint_url"]
                destination = "AWS_DEFAULT"
                if endpoints:
                    endpoint = self._literal(endpoints[0].value)
                    if endpoint and endpoint.startswith(
                        ("http://localhost:", "http://127.0.0.1:", "http://[::1]:")
                    ):
                        destination = "LOCAL"
                    else:
                        destination = "UNKNOWN"
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for target in targets:
                    if (isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == "self"):
                        choices.setdefault(target.attr, set()).add(
                            (service, destination, kind))
            known = {}
            for field, alternatives in choices.items():
                if len(alternatives) != 1:
                    self.wrapper_ambiguous.add((cls.name, field))
                else:
                    service, destination, kind = next(iter(alternatives))
                    known[field] = AWSObject(service, destination, kind)
            if choices:
                self.wrapper_clients[cls.name] = known

    def _index_external(self, external_modules):
        for module, (filename, text) in sorted(external_modules.items()):
            self.source_digests[filename] = sha256(text.encode("utf-8")).hexdigest()
            if len(text.encode("utf-8")) > MAX_BYTES:
                raise DiscoveryError("IMPORTED_SOURCE_TOO_LARGE")
            tree = ast.parse(text, filename=filename)
            imports = {}
            globals_map = {}
            for item in tree.body:
                if isinstance(item, ast.Import):
                    for spec in item.names:
                        imports[spec.asname or spec.name] = spec.name
                if isinstance(item, ast.ImportFrom):
                    for spec in item.names:
                        imports[spec.asname or spec.name] = (item.module or "") + "." + spec.name
            for item in tree.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    name = module + "." + item.name
                    self.functions[name] = item
                    self.external_contexts[name] = (imports, globals_map, filename)
            if len(self.functions) > MAX_FUNCTIONS:
                raise DiscoveryError("TOO_MANY_IMPORTED_FUNCTIONS")

    @staticmethod
    def _is_tool(func):
        for decorator in func.decorator_list:
            if isinstance(decorator, ast.Call):
                decorator = decorator.func
            if isinstance(decorator, ast.Attribute) and decorator.attr == "tool":
                return True
        return False

    def helper_name(self, node, owner):
        if isinstance(node, ast.Name):
            if node.id in self.functions:
                return node.id
            local = owner + "." + node.id if owner else node.id
            if local in self.functions:
                return local
            external = self.imports.get(node.id)
            if external in self.functions:
                return external
        if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                and node.value.id == "self"):
            qname = owner + "." + node.attr if owner else node.attr
            if qname in self.functions:
                return qname
        return None

    def symbol(self, node, env):
        if node is None:
            return "UNKNOWN"
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float, bool)):
            return node.value
        if isinstance(node, ast.Name):
            return env.get(node.id, self.imports.get(node.id, "$" + "{UNBOUND:" + node.id + "}"))
        if isinstance(node, ast.Attribute):
            base = self.symbol(node.value, env)
            return str(base) + "." + node.attr
        if isinstance(node, ast.Subscript):
            base, key = self.symbol(node.value, env), self.symbol(node.slice, env)
            if base == "os.environ":
                return "$" + "{ENV:" + str(key) + "}"
            return str(base) + "[" + str(key) + "]"
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return str(self.symbol(node.left, env)) + str(self.symbol(node.right, env))
        if isinstance(node, ast.JoinedStr):
            return "".join(str(self.symbol(x.value, env)) if isinstance(x, ast.FormattedValue)
                           else str(self.symbol(x, env)) for x in node.values)
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in self.wrapper_clients):
            return AWSObject(None, "UNKNOWN", "wrapper",
                             self.wrapper_clients[node.func.id])
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            base = self.symbol(node.func.value, env)
            if base == "os.environ" and node.func.attr == "get" and node.args:
                key = self._literal(node.args[0])
                return "$" + "{ENV:" + key + "}" if key else "UNKNOWN"
        return "UNKNOWN"

    def _gap(self, node, chain, branch, reason):
        item = {"tool": self.tool, "file": self.name,
                "line": getattr(node, "lineno", 0), "call_chain": list(chain),
                "branch": branch, "reason": reason}
        if item not in self.gaps and len(self.gaps) < MAX_OPERATIONS:
            self.gaps.append(item)

    def _record(self, node, chain, branch, target, operation, params):
        if len(self.results) >= MAX_OPERATIONS:
            self._gap(node, chain, branch, "OPERATION_LIMIT")
            return
        self.results.append({
            "tool": self.tool, "file": self.name, "line": node.lineno,
            "call_chain": list(chain), "branch": branch,
            "service": target.service, "operation": operation,
            "destination": target.destination, "resource_parameters": params,
            "evidence": "STATIC_AST_CANDIDATE",
        })

    def _parameters(self, call, env):
        return {k.arg: str(self.symbol(k.value, env))[:250]
                for k in call.keywords if k.arg in RESOURCE_KEYS}

    def _sdk_constructor(self, func):
        if isinstance(func, ast.Name):
            imported = self.imports.get(func.id)
            if imported in {"boto3.client", "boto3.resource"}:
                return imported.rsplit(".", 1)[-1]
            if imported in {"boto3.Session", "boto3.session.Session"}:
                return "session"
        if not isinstance(func, ast.Attribute) or func.attr not in {"client", "resource"}:
            return None
        base = func.value
        if isinstance(base, ast.Name) and self.imports.get(base.id) == "boto3":
            return func.attr
        # A direct boto3.Session().client() expression
        if isinstance(base, ast.Call) and isinstance(base.func, ast.Attribute):
            if (base.func.attr == "Session" and isinstance(base.func.value, ast.Name)
                    and self.imports.get(base.func.value.id) == "boto3"):
                return func.attr
        return None


    def expression(self, node, env, owner, chain, branch, depth, active):
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return env.get(node.id, self.globals.get(node.id, self.symbol(node, env)))
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Attribute):
            base = self.expression(node.value, env, owner, chain, branch, depth, active)
            if isinstance(base, AWSObject) and base.kind == "wrapper":
                found = base.value.get(node.attr)
                if found is not None:
                    return found
                self._gap(node, chain, branch, "WRAPPER_CLIENT_ATTRIBUTE_UNKNOWN")
                return None
            if isinstance(base, AWSObject) and base.kind == "resource" and node.attr == "meta":
                return AWSObject(base.service, base.destination, "meta")
            if isinstance(base, AWSObject) and base.kind == "meta" and node.attr == "client":
                return AWSObject(base.service, base.destination)
            return self.symbol(node, env)
        if isinstance(node, (ast.Await, ast.Yield, ast.YieldFrom, ast.Starred)):
            return self.expression(node.value, env, owner, chain, branch, depth, active)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in self.wrapper_clients:
                return AWSObject(None, "UNKNOWN", "wrapper",
                                 self.wrapper_clients[node.func.id])
            if (isinstance(node.func, ast.Attribute) and
                    node.func.attr == "to_thread" and
                    isinstance(node.func.value, ast.Name) and
                    self.imports.get(node.func.value.id) == "asyncio" and node.args):
                candidate = node.args[0]
                if isinstance(candidate, ast.Attribute):
                    base = self.expression(candidate.value, env, owner, chain, branch, depth, active)
                    if isinstance(base, AWSObject) and base.kind in {"client", "table"}:
                        params = self._parameters(node, env)
                        if base.kind == "table":
                            params = {"TableName": str(base.value), **params}
                        self._record(node, chain, branch + "|asyncio.to_thread",
                                     base, candidate.attr, params)
                        return None
                # Unresolved dynamic thread dispatch must not be treated
                # as no AWS calls; other arguments may still be inspected.
                for arg in node.args:
                    self.expression(arg, env, owner, chain, branch, depth, active)
                self._gap(node, chain, branch, "ASYNC_THREAD_TARGET_UNRESOLVED")
                return None
            constructor = self._sdk_constructor(node.func)
            if constructor:
                if constructor == "session":
                    return AWSObject(None, "AWS_DEFAULT", "session")
                service = self._literal(node.args[0]) if node.args else None
                for k in node.keywords:
                    if k.arg == "service_name":
                        service = self._literal(k.value)
                if service is None:
                    self._gap(node, chain, branch, "DYNAMIC_AWS_SERVICE")
                    return None
                endpoint = next((self.symbol(k.value, env)
                                 for k in node.keywords if k.arg == "endpoint_url"), None)
                destination = "AWS_DEFAULT"
                if endpoint is not None:
                    if (isinstance(endpoint, str) and
                        (endpoint.startswith("http://localhost:")
                         or endpoint.startswith("http://127.0.0.1:")
                         or endpoint.startswith("http://[::1]:")
                         or endpoint.startswith("https://localhost:"))):
                        destination = "LOCAL"
                    elif isinstance(endpoint, str) and endpoint.startswith("$" + "{ENV:"):
                        destination = "UNKNOWN"
                        self._gap(node, chain, branch, "CONFIGURED_ENDPOINT_UNKNOWN")
                    else:
                        destination = "CUSTOM_OR_UNKNOWN"
                        self._gap(node, chain, branch, "NONDEFAULT_ENDPOINT_UNVERIFIED")
                return AWSObject(service, destination, constructor)
            helper = self.helper_name(node.func, owner)
            if helper:
                if depth >= MAX_DEPTH or helper in active:
                    self._gap(node, chain, branch, "RECURSION_OR_DEPTH_LIMIT")
                    return None
                fn = self.functions[helper]
                args = [self.expression(a, env, owner, chain, branch, depth, active)
                        for a in node.args]
                kwargs = {k.arg: self.expression(k.value, env, owner, chain, branch, depth, active)
                          for k in node.keywords if k.arg}
                # Bound self.method(x) carries the implicit self argument.
                if (isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "self"):
                    args.insert(0, "SELF")
                parameters = [x.arg for x in fn.args.posonlyargs + fn.args.args]
                external = self.external_contexts.get(helper)
                scope = dict(external[1] if external else self.globals)
                for i, name in enumerate(parameters):
                    scope[name] = args[i] if i < len(args) else kwargs.get(name, "$" + "{ARG:" + name + "}")
                if "self" in scope:
                    scope["self"] = "SELF"
                next_owner = helper.rsplit(".", 1)[0] if "." in helper else ""
                if external:
                    old_imports, old_globals, old_name = self.imports, self.globals, self.name
                    self.imports, self.globals, self.name = external
                    try:
                        return self.statements(fn.body, scope, next_owner,
                                               chain + (helper,), branch, depth + 1,
                                               active | {helper})
                    finally:
                        self.imports, self.globals, self.name = old_imports, old_globals, old_name
                return self.statements(fn.body, scope, next_owner,
                                       chain + (helper,), branch, depth + 1,
                                       active | {helper})
            if isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) >= 2:
                obj = self.expression(node.args[0], env, owner, chain, branch, depth, active)
                if isinstance(obj, AWSObject) and obj.kind in {"client", "table"}:
                    method = self._literal(node.args[1])
                    return AWSObject(obj.service, obj.destination, "dynamic", (method, obj.value))
            if isinstance(node.func, ast.Attribute):
                obj = self.expression(node.func.value, env, owner, chain, branch, depth, active)
                method = node.func.attr
                if isinstance(obj, AWSObject):
                    if obj.kind == "session" and method == "client":
                        service = self.symbol(node.args[0], env) if node.args else "UNKNOWN"
                        for key in node.keywords:
                            if key.arg == "service_name":
                                service = self.symbol(key.value, env)
                        if not isinstance(service, str) or "UNKNOWN" in service or "UNBOUND" in service:
                            self._gap(node, chain, branch, "SESSION_SERVICE_UNRESOLVED")
                            return None
                        return AWSObject(service, obj.destination)
                    if obj.kind == "client" and method == "get_paginator":
                        name = self._literal(node.args[0]) if node.args else None
                        if name is None:
                            self._gap(node, chain, branch, "DYNAMIC_PAGINATOR")
                            return None
                        return AWSObject(obj.service, obj.destination, "paginator", name)
                    if obj.kind == "paginator" and method == "paginate":
                        self._record(node, chain, branch, obj, obj.value, self._parameters(node, env))
                        return None
                    if obj.kind == "resource" and method == "Table":
                        name = self.symbol(node.args[0], env) if node.args else "UNKNOWN"
                        return AWSObject(obj.service, obj.destination, "table", str(name))
                    if obj.kind in {"client", "table"}:
                        if method not in {
                            "close", "can_paginate", "generate_presigned_url",
                            "generate_presigned_post", "get_waiter",
                        }:
                            params = self._parameters(node, env)
                            if obj.kind == "table":
                                params = {"TableName": str(obj.value), **params}
                            self._record(node, chain, branch, obj, method, params)
                        return None
            callable_obj = self.expression(node.func, env, owner, chain, branch, depth, active)
            if isinstance(callable_obj, AWSObject) and callable_obj.kind == "dynamic":
                method, table = callable_obj.value
                if method is None:
                    self._gap(node, chain, branch, "DYNAMIC_SDK_METHOD")
                else:
                    params = self._parameters(node, env)
                    if table is not None:
                        params = {"TableName": str(table), **params}
                    self._record(node, chain, branch, callable_obj, method, params)
                return None
            if (isinstance(node.func, ast.Name) and node.func.id in self.imports
                    and self.imports[node.func.id] not in self.functions):
                self._gap(node, chain, branch, "IMPORTED_CALL_UNRESOLVED")
            evaluated = [
                self.expression(a, env, owner, chain, branch, depth, active)
                for a in node.args
            ]
            for value in node.keywords:
                self.expression(value.value, env, owner, chain, branch, depth, active)
            if any(isinstance(x, AWSObject) for x in evaluated):
                self._gap(node, chain, branch, "UNRESOLVED_HELPER_RECEIVES_AWS_CLIENT")
            return None
        if isinstance(node, (ast.BoolOp, ast.Compare, ast.BinOp, ast.UnaryOp,
                             ast.List, ast.Tuple, ast.Set, ast.Dict, ast.Subscript,
                             ast.JoinedStr, ast.FormattedValue, ast.IfExp)):
            for child in ast.iter_child_nodes(node):
                self.expression(child, env, owner, chain, branch, depth, active)
            return self.symbol(node, env)
        return self.symbol(node, env)

    def statements(self, body, env, owner, chain, branch, depth, active):
        returned = None
        for stmt in body:
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                value = self.expression(stmt.value, env, owner, chain, branch, depth, active)
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = value
            elif isinstance(stmt, ast.AugAssign):
                self.expression(stmt.value, env, owner, chain, branch, depth, active)
                if isinstance(stmt.target, ast.Name):
                    env[stmt.target.id] = "UNKNOWN"
            elif isinstance(stmt, (ast.Return, ast.Expr, ast.Raise)):
                node = getattr(stmt, "value", getattr(stmt, "exc", None))
                result = self.expression(node, env, owner, chain, branch, depth, active)
                if isinstance(stmt, ast.Return):
                    returned = result
            elif isinstance(stmt, ast.If):
                self.expression(stmt.test, env, owner, chain, branch, depth, active)
                yes, no = dict(env), dict(env)
                self.statements(stmt.body, yes, owner, chain,
                                branch + f"|if@{stmt.lineno}:true", depth, active)
                self.statements(stmt.orelse, no, owner, chain,
                                branch + f"|if@{stmt.lineno}:false", depth, active)
                for key in set(yes) | set(no):
                    env[key] = yes.get(key) if yes.get(key) == no.get(key) else "UNKNOWN"
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                self.expression(stmt.iter if hasattr(stmt, "iter") else stmt.test,
                                env, owner, chain, branch, depth, active)
                self.statements(stmt.body, dict(env), owner, chain,
                                branch + f"|loop@{stmt.lineno}", depth, active)
                self.statements(stmt.orelse, dict(env), owner, chain, branch, depth, active)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    value = self.expression(item.context_expr, env, owner, chain, branch, depth, active)
                    if isinstance(item.optional_vars, ast.Name):
                        env[item.optional_vars.id] = value
                self.statements(stmt.body, env, owner, chain, branch, depth, active)
            elif isinstance(stmt, (ast.Try, ast.TryStar)):
                self.statements(stmt.body, dict(env), owner, chain, branch, depth, active)
                for handler in stmt.handlers:
                    self.statements(handler.body, dict(env), owner, chain,
                                    branch + f"|except@{handler.lineno}", depth, active)
                self.statements(stmt.orelse, dict(env), owner, chain, branch, depth, active)
                self.statements(stmt.finalbody, dict(env), owner, chain, branch, depth, active)
            elif isinstance(stmt, ast.Match):
                self.expression(stmt.subject, env, owner, chain, branch, depth, active)
                for case in stmt.cases:
                    self.statements(case.body, dict(env), owner, chain,
                                    branch + f"|case@{stmt.lineno}", depth, active)
        return returned

    def analyze(self):
        for tool, name in sorted(self.tools.items()):
            self.tool = tool
            fn = self.functions[name]
            owner = name.rsplit(".", 1)[0] if "." in name else ""
            env = dict(self.globals)
            for arg in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs:
                env[arg.arg] = "$" + "{ARG:" + arg.arg + "}"
            if "self" in env:
                env["self"] = "SELF"
            self.statements(fn.body, env, owner, (name,), "always", 0, {name})
        return {
            "schema_version": "static-aws-discovery-prototype-v1",
            "source": self.name,
            "source_sha256": self.digest,
            "source_files": [
                {"path": name, "sha256": digest}
                for name, digest in sorted(self.source_digests.items())
            ],
            "tools": sorted(self.tools),
            "operations": sorted(self.results, key=lambda x: (x["tool"], x["line"], x["operation"])),
            "gaps": sorted(self.gaps, key=lambda x: (x["tool"], x["line"], x["reason"])),
            "assurance": "STATIC_CANDIDATE_ONLY",
            "warning": "Not a complete call graph, not an approved MCP contract or deployed workload proof.",
        }


def analyze_python_source(source: str, *, source_name: str = "<source>"):
    return Inspector(source, source_name).analyze()


def analyze_python_file(path):
    target = Path(path)
    if not target.is_file() or target.is_symlink():
        raise DiscoveryError("NOT_REGULAR_SOURCE_FILE")
    if target.stat().st_size > MAX_BYTES:
        raise DiscoveryError("SOURCE_TOO_LARGE")
    try:
        text = target.read_text(encoding="utf-8")
    except UnicodeError as exc:
        raise DiscoveryError("SOURCE_NOT_UTF8") from exc
    return analyze_python_source(text, source_name=str(target))



def analyze_python_project(entry_file, source_root):
    """Analyze a local source with bounded, local-only one-hop imported modules.

    No repo checkout, network, imports or execution. Does not claim full
    cross-module or dynamic call-graph coverage.
    """
    root = Path(source_root).resolve()
    original_entry = Path(entry_file)
    entry = original_entry.resolve()
    if original_entry.is_symlink() or not entry.is_relative_to(root) or not entry.is_file():
        raise DiscoveryError("PROJECT_ENTRY_OUTSIDE_SOURCE_ROOT")
    if entry.stat().st_size > MAX_BYTES:
        raise DiscoveryError("SOURCE_TOO_LARGE")
    text = entry.read_text(encoding="utf-8")
    tree = ast.parse(text)
    modules = {}
    for item in tree.body:
        if not isinstance(item, ast.ImportFrom) or item.level or not item.module:
            continue
        module = item.module
        if not all(token.isidentifier() for token in module.split(".")):
            continue
        candidate = (root / Path(*module.split("."))).with_suffix(".py")
        resolved = candidate.resolve()
        if not resolved.is_relative_to(root) or candidate.is_symlink() or not resolved.is_file():
            continue
        if resolved.stat().st_size > MAX_BYTES:
            raise DiscoveryError("IMPORTED_SOURCE_TOO_LARGE")
        if len(modules) >= 20:
            raise DiscoveryError("TOO_MANY_IMPORTED_MODULES")
        modules[module] = (str(resolved), resolved.read_text(encoding="utf-8"))
    return Inspector(text, str(entry), modules).analyze()
