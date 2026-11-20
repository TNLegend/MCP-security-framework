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
MAX_WORK_UNITS = 100_000
RESOURCE_KEYS = frozenset({
    "Bucket", "Key", "Prefix", "TableName", "IndexName",
    "QueueUrl", "VersionId", "FunctionName", "LogGroupName", "logGroupName",
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


class AWSChoices:
    """Bounded set of alternative SDK objects at a control-flow join."""

    def __init__(self, options):
        unique = []
        for option in options:
            if isinstance(option, AWSChoices):
                for child in option.options:
                    if child not in unique:
                        unique.append(child)
            elif option not in unique:
                unique.append(option)
        self.options = tuple(unique)

    def __eq__(self, other):
        return isinstance(other, AWSChoices) and self.options == other.options


class FlowExit:
    def __init__(self, kind, value=None):
        self.kind, self.value = kind, value


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
        self.colliding_tool_names = set()
        self.server_vars = {"mcp"}  # Legacy code-only fixtures with an implicit MCP binding.
        self.imports = {}
        self.globals = {}
        self.results = []
        self.gaps = []
        self.truncated_gaps = 0
        self.truncated_operations = 0
        self.work_units = 0
        self.budget_exceeded = False
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
                    local = x.asname or x.name
                    self.imports[local] = x.name
                    if local == "mcp":
                        self.server_vars.discard("mcp")
                        prior = self.tool
                        self.tool = "__server__"
                        self._gap(node, ("module",), "registration", "IMPORTED_MCP_INSTANCE_UNVERIFIED")
                        self.tool = prior
            if isinstance(node, ast.ImportFrom):
                for x in node.names:
                    local = x.asname or x.name
                    self.imports[local] = (node.module or "") + "." + x.name
                    if local == "mcp":
                        self.server_vars.discard("mcp")
                        prior = self.tool
                        self.tool = "__server__"
                        self._gap(node, ("module",), "registration", "IMPORTED_MCP_INSTANCE_UNVERIFIED")
                        self.tool = prior
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if isinstance(value, ast.Call):
                    fn = value.func
                    constructor = (
                        self.imports.get(fn.id, fn.id) if isinstance(fn, ast.Name)
                        else fn.attr if isinstance(fn, ast.Attribute) else None
                    )
                    if constructor in {
                        "FastMCP", "MCPServer", "mcp.server.fastmcp.FastMCP",
                        "mcp.server.mcpserver.MCPServer",
                    }:
                        self.server_vars.update(x.id for x in targets if isinstance(x, ast.Name))
                    else:
                        # A real assignment overrides the legacy implicit
                        # assumption that the identifier "mcp" is an MCP host.
                        for target in targets:
                            if isinstance(target, ast.Name) and target.id == "mcp":
                                self.server_vars.discard("mcp")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node
                public = self._is_tool(node)
                if public is not None:
                    self._register_known_tool(public, node.name, node)
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        qname = node.name + "." + item.name
                        self.functions[qname] = item
                        public = self._is_tool(item)
                        if public is not None:
                            self._register_known_tool(public, qname, item)
        # Index nested local functions as lexical helpers. They are not tools
        # unless independently registered; this only resolves reachable calls.
        top_level = list(self.functions.items())
        for name, function in top_level:
            for descendant in ast.walk(function):
                if isinstance(descendant, (ast.FunctionDef, ast.AsyncFunctionDef)) and descendant is not function:
                    self.functions.setdefault(name + "." + descendant.name, descendant)
        if len(self.functions) > MAX_FUNCTIONS:
            raise DiscoveryError("TOO_MANY_FUNCTIONS")
        self._index_wrapper_constructors()
        for node in self.tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        expr = node.value
                        # Resolve only known boto3 constructor expressions at
                        # module level. Never import or call arbitrary code.
                        if isinstance(expr, ast.Call) and (
                            self._sdk_constructor(expr.func) in {"client", "resource", "session"}
                            or isinstance(expr.func, ast.Attribute)
                            and expr.func.attr in {"client", "resource"}
                            and isinstance(expr.func.value, ast.Call)
                            and self._sdk_constructor(expr.func.value.func) == "session"
                        ):
                            self.globals[target.id] = self.expression(
                                expr, self.globals, "", ("__module__",), "module", 0, frozenset()
                            )
                        else:
                            self.globals[target.id] = self.symbol(expr, self.globals)
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
                    public = self._registration_name(wrapper) or handler.rsplit(".", 1)[-1]
                    self._register_known_tool(public, handler, node)
        self._flag_unresolved_tool_registration()

    def _register_known_tool(self, public, handler, node):
        if public in self.colliding_tool_names:
            return
        old = self.tools.get(public)
        if old is not None and old != handler:
            self.tools.pop(public, None)
            self.colliding_tool_names.add(public)
            previous = self.tool
            self.tool = public
            try:
                self._gap(node, (handler,), "registration", "DUPLICATE_PUBLIC_TOOL_NAME")
            finally:
                self.tool = previous
            return
        self.tools[public] = handler

    def _flag_unresolved_tool_registration(self):
        """Flag dynamic registration without asserting SDK permissions.

        A server object passed to an imported helper can receive tools via
        code this parser cannot prove. Mark it incomplete rather than silently
        reporting an empty clean result.
        """
        mcp_vars = set()
        for stmt in self.tree.body:
            if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                continue
            value = stmt.value
            if not isinstance(value, ast.Call):
                continue
            fn = value.func
            owner = None
            if isinstance(fn, ast.Name):
                owner = self.imports.get(fn.id, fn.id)
            elif isinstance(fn, ast.Attribute):
                owner = fn.attr
            if owner not in {
                "FastMCP", "MCPServer", "mcp.server.fastmcp.FastMCP",
                "mcp.server.mcpserver.MCPServer"
            }:
                continue
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    mcp_vars.add(target.id)
        previously = self.tool
        self.tool = "__server__"
        for call in ast.walk(self.tree):
            if not isinstance(call, ast.Call):
                continue
            if (isinstance(call.func, ast.Name)
                    and call.func.id in self.imports
                    and call.func.id not in self.functions
                    and any(isinstance(arg, ast.Name) and arg.id in mcp_vars
                            for arg in call.args)):
                self._gap(call, ("module",), "registration",
                          "IMPORTED_MCP_REGISTRATION_UNRESOLVED")
            if (isinstance(call.func, ast.Call)
                    and isinstance(call.func.func, ast.Attribute)
                    and call.func.func.attr == "tool"
                    and isinstance(call.func.func.value, ast.Name)
                    and call.func.func.value.id in self.server_vars):
                handler = self.helper_name(call.args[0], "") if call.args else None
                if (handler is None and call.args
                        and isinstance(call.args[0], ast.Attribute)
                        and isinstance(call.args[0].value, ast.Name)
                        and call.args[0].value.id == "self"):
                    suffix = "." + call.args[0].attr
                    if any(name.endswith(suffix) for name in self.functions):
                        handler = suffix
                if not handler:
                    self._gap(call, ("module",), "registration",
                              "DYNAMIC_MCP_TOOL_FACTORY_UNRESOLVED")
        if not self.tools and not any(x["reason"].endswith("REGISTRATION_UNRESOLVED")
                                      or x["reason"] == "DYNAMIC_MCP_TOOL_FACTORY_UNRESOLVED"
                                      for x in self.gaps):
            if mcp_vars:
                self._gap(self.tree, ("module",), "registration",
                          "NO_STATIC_MCP_HANDLERS_DISCOVERED")
        self.tool = previously

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
    def _registration_name(node):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if (keyword.arg == "name" and isinstance(keyword.value, ast.Constant)
                        and isinstance(keyword.value.value, str)):
                    return keyword.value.value
        return None

    def _is_tool(self, func):
        for decorator in func.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            method = call.func if call else decorator
            if (isinstance(method, ast.Attribute) and method.attr == "tool"
                    and isinstance(method.value, ast.Name)
                    and method.value.id in self.server_vars):
                name_kw = next((k for k in call.keywords if k.arg == "name"), None) if call else None
                if name_kw is not None and self._literal(name_kw.value) is None:
                    self._gap(decorator, (func.name,), "registration", "DYNAMIC_PUBLIC_TOOL_NAME")
                    return None
                return self._registration_name(call) or func.name
        return None

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

    def _budget(self, node, chain, branch):
        if self.budget_exceeded:
            return False
        self.work_units += 1
        if self.work_units > MAX_WORK_UNITS:
            self.budget_exceeded = True
            self._gap(node, chain, branch, "ANALYSIS_WORK_BUDGET_EXCEEDED")
            return False
        return True

    def _gap(self, node, chain, branch, reason):
        item = {"tool": self.tool, "file": self.name,
                "line": getattr(node, "lineno", 0), "call_chain": list(chain),
                "branch": branch, "reason": reason}
        if item not in self.gaps:
            if len(self.gaps) < MAX_OPERATIONS:
                self.gaps.append(item)
            else:
                self.truncated_gaps += 1

    def _record(self, node, chain, branch, target, operation, params):
        if len(self.results) >= MAX_OPERATIONS:
            self.truncated_operations += 1
            if self.truncated_operations == 1:
                self._gap(node, chain, branch, "OPERATION_LIMIT")
            return
        if any(k.arg is None for k in node.keywords):
            self._gap(node, chain, branch, "AWS_REQUEST_PARAMETERS_UNRESOLVED")
        self.results.append({
            "tool": self.tool, "file": self.name, "line": node.lineno,
            "call_chain": list(chain), "branch": branch,
            "service": target.service, "operation": operation,
            "destination": target.destination, "resource_parameters": params,
            "request_parameters_complete": all(k.arg is not None for k in node.keywords),
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
        if (isinstance(func, ast.Attribute) and func.attr == "Session" and
                isinstance(func.value, ast.Name) and
                self.imports.get(func.value.id) == "boto3"):
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


    def _client_destination(self, node, env, chain, branch):
        endpoint = next((k.value for k in node.keywords if k.arg == "endpoint_url"), None)
        if any(k.arg is None for k in node.keywords):
            self._gap(node, chain, branch, "AWS_CLIENT_CONFIGURATION_UNRESOLVED")
            return "UNKNOWN"
        if endpoint is None:
            return "AWS_DEFAULT"
        if isinstance(endpoint, ast.Constant) and endpoint.value is None:
            return "AWS_DEFAULT"
        concrete = self.symbol(endpoint, env)
        if isinstance(concrete, str) and concrete.startswith(
            ("http://localhost:", "http://127.0.0.1:",
             "http://[::1]:", "https://localhost:")
        ):
            return "LOCAL"
        self._gap(node, chain, branch, "AWS_ENDPOINT_CONFIGURATION_UNVERIFIED")
        return "UNKNOWN"

    def expression(self, node, env, owner, chain, branch, depth, active):
        if node is None or not self._budget(node, chain, branch):
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
                destination = self._client_destination(node, env, chain, branch)
                return AWSObject(service, destination, constructor)
            helper = self.helper_name(node.func, owner)
            if helper is None and isinstance(node.func, ast.Name):
                for enclosing in reversed(chain):
                    nested = enclosing + "." + node.func.id
                    if nested in self.functions:
                        helper = nested
                        break
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
                        outcome = self.statements(fn.body, scope, next_owner,
                                                  chain + (helper,), branch, depth + 1,
                                                  active | {helper})
                        return outcome.value if isinstance(outcome, FlowExit) and outcome.kind == "return" else None
                    finally:
                        self.imports, self.globals, self.name = old_imports, old_globals, old_name
                outcome = self.statements(fn.body, scope, next_owner,
                                          chain + (helper,), branch, depth + 1,
                                          active | {helper})
                return outcome.value if isinstance(outcome, FlowExit) and outcome.kind == "return" else None
            if isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) >= 2:
                obj = self.expression(node.args[0], env, owner, chain, branch, depth, active)
                if isinstance(obj, AWSObject) and obj.kind in {"client", "table"}:
                    method = self._literal(node.args[1])
                    return AWSObject(obj.service, obj.destination, "dynamic", (method, obj.value))
            if isinstance(node.func, ast.Attribute):
                obj = self.expression(node.func.value, env, owner, chain, branch, depth, active)
                method = node.func.attr
                if isinstance(obj, AWSChoices):
                    if all(x.kind in {"client", "table"} for x in obj.options):
                        for arg in node.args:
                            self.expression(arg, env, owner, chain, branch, depth, active)
                        for kw in node.keywords:
                            self.expression(kw.value, env, owner, chain, branch, depth, active)
                        for idx, alternative in enumerate(obj.options):
                            params = self._parameters(node, env)
                            if alternative.kind == "table":
                                params = {"TableName": str(alternative.value), **params}
                            self._record(node, chain, branch + f"|alternative:{idx + 1}",
                                         alternative, method, params)
                    else:
                        self._gap(node, chain, branch, "AWS_CLIENT_ALTERNATIVES_UNRESOLVED")
                    return None
                if isinstance(obj, AWSObject):
                    if obj.kind == "session" and method == "client":
                        service = self.symbol(node.args[0], env) if node.args else "UNKNOWN"
                        for key in node.keywords:
                            if key.arg == "service_name":
                                service = self.symbol(key.value, env)
                        if not isinstance(service, str) or "UNKNOWN" in service or "UNBOUND" in service:
                            self._gap(node, chain, branch, "SESSION_SERVICE_UNRESOLVED")
                            return None
                        destination = self._client_destination(node, env, chain, branch)
                        if obj.destination != "AWS_DEFAULT" and destination == "AWS_DEFAULT":
                            destination = obj.destination
                        return AWSObject(service, destination)
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
                            for arg in node.args:
                                self.expression(arg, env, owner, chain, branch, depth, active)
                            for kw in node.keywords:
                                self.expression(kw.value, env, owner, chain, branch, depth, active)
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
                    for arg in node.args:
                        self.expression(arg, env, owner, chain, branch, depth, active)
                    for kw in node.keywords:
                        self.expression(kw.value, env, owner, chain, branch, depth, active)
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

    def _join_environments(self, env, paths, node, chain, branch):
        """Bounded join, preserving AWS alternatives instead of dropping them.

        For unknown/mixed values we abstain at the join, never silently
        assigning a single privileged client.
        """
        for key in sorted(set().union(*(set(x) for x in paths))):
            values = [x.get(key, "UNKNOWN") for x in paths]
            if all(v == values[0] for v in values):
                env[key] = values[0]
                continue
            flattened = []
            for val in values:
                flattened.extend(val.options if isinstance(val, AWSChoices) else [val])
            unique = []
            for val in flattened:
                if val not in unique:
                    unique.append(val)
            if len(unique) <= 8 and all(
                isinstance(v, AWSObject) and v.kind in {"client", "table", "session"}
                for v in unique
            ):
                env[key] = AWSChoices(unique)
            else:
                if any(isinstance(v, (AWSObject, AWSChoices)) for v in values):
                    self._gap(node, chain, branch, "AWS_CLIENT_ALTERNATIVES_UNRESOLVED")
                env[key] = "UNKNOWN"

    def _combine_exits(self, exits, node, chain, branch):
        """Join return values for helpers with several reachable exits.

        Unresolved return types must not become a fabricated SDK client.
        """
        if not exits:
            return None
        # A path which raises does not contribute a return value. In
        # particular validation functions may raise on invalid arguments
        # and return a symbolic AWS resource on the successful path.
        returning = [x for x in exits if x.kind == "return"]
        if returning:
            values = [x.value for x in returning]
            if all(v == values[0] for v in values):
                return FlowExit("return", values[0])
            flattened = []
            for value in values:
                flattened.extend(value.options if isinstance(value, AWSChoices) else [value])
            if all(isinstance(v, AWSObject) for v in flattened) and len(flattened) <= 8:
                return FlowExit("return", AWSChoices(flattened))
            if any(isinstance(v, (AWSObject, AWSChoices)) for v in values):
                self._gap(node, chain, branch, "DIVERGENT_CLIENT_RETURNS_UNRESOLVED")
            return FlowExit("return")
        if all(x.kind == "raise" for x in exits):
            return FlowExit("raise")
        if any(isinstance(x.value, (AWSObject, AWSChoices)) for x in exits):
            self._gap(node, chain, branch, "MIXED_CLIENT_RETURN_AND_EXCEPTION")
        return FlowExit("return")

    def statements(self, body, env, owner, chain, branch, depth, active):
        exits = []
        for stmt in body:
            if not self._budget(stmt, chain, branch):
                return None
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
                    return self._combine_exits(exits + [FlowExit("return", result)],
                                               stmt, chain, branch)
                if isinstance(stmt, ast.Raise):
                    return self._combine_exits(exits + [FlowExit("raise")],
                                               stmt, chain, branch)
            elif isinstance(stmt, ast.If):
                self.expression(stmt.test, env, owner, chain, branch, depth, active)
                # A literal boolean is an established branch, not a possible
                # alternative. For dynamic tests both paths remain possible.
                if isinstance(stmt.test, ast.Constant) and isinstance(stmt.test.value, bool):
                    chosen = stmt.body if stmt.test.value else stmt.orelse
                    outcome = self.statements(chosen, env, owner, chain,
                                              branch + f"|if@{stmt.lineno}:literal",
                                              depth, active)
                    if isinstance(outcome, FlowExit):
                        return self._combine_exits(exits + [outcome], stmt, chain, branch)
                    continue
                yes, no = dict(env), dict(env)
                out_yes = self.statements(stmt.body, yes, owner, chain,
                                          branch + f"|if@{stmt.lineno}:true", depth, active)
                out_no = self.statements(stmt.orelse, no, owner, chain,
                                         branch + f"|if@{stmt.lineno}:false", depth, active)
                ongoing = [
                    state for state, outcome in ((yes, out_yes), (no, out_no))
                    if not isinstance(outcome, FlowExit)
                ]
                if ongoing:
                    self._join_environments(env, ongoing, stmt, chain, branch)
                    exits.extend(
                        out for out in (out_yes, out_no) if isinstance(out, FlowExit)
                    )
                else:
                    return self._combine_exits(exits + [out_yes, out_no],
                                               stmt, chain, branch)
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
                outcome = self.statements(stmt.body, env, owner, chain, branch, depth, active)
                if isinstance(outcome, FlowExit):
                    return self._combine_exits(exits + [outcome], stmt, chain, branch)
            elif isinstance(stmt, (ast.Try, ast.TryStar)):
                # Python's try block does NOT introduce a variable scope.
                # Preserve assignments on the normal path for subsequent
                # statements; exception handlers are inspected separately.
                success = dict(env)
                normal = self.statements(stmt.body, success, owner, chain,
                                         branch + f"|try@{stmt.lineno}", depth, active)
                if not isinstance(normal, FlowExit):
                    normal = self.statements(stmt.orelse, success, owner, chain, branch, depth, active)
                outcomes = [(success, normal)]
                for handler in stmt.handlers:
                    exception_path = dict(env)
                    out = self.statements(handler.body, exception_path, owner, chain,
                                          branch + f"|except@{handler.lineno}", depth, active)
                    outcomes.append((exception_path, out))
                paths = [state for state, out in outcomes if not isinstance(out, FlowExit)]
                if paths:
                    merged = dict(env)
                    self._join_environments(merged, paths, stmt, chain, branch + "|try-join")
                    final = self.statements(stmt.finalbody, merged, owner, chain, branch, depth, active)
                    env.update(merged)
                    exits.extend(out for _, out in outcomes if isinstance(out, FlowExit))
                    if isinstance(final, FlowExit):
                        return self._combine_exits(exits + [final], stmt, chain, branch)
                else:
                    return self._combine_exits(
                        exits + [out for _, out in outcomes if isinstance(out, FlowExit)],
                        stmt, chain, branch
                    )
            elif isinstance(stmt, ast.Match):
                self.expression(stmt.subject, env, owner, chain, branch, depth, active)
                for case in stmt.cases:
                    self.statements(case.body, dict(env), owner, chain,
                                    branch + f"|case@{stmt.lineno}", depth, active)
        if exits:
            # One or more earlier branches returned, but this path can fall
            # through. Do not attribute a client as an unconditional return.
            if any(isinstance(x.value, (AWSObject, AWSChoices)) for x in exits):
                self._gap(body[-1], chain, branch, "MAY_FALL_THROUGH_WITHOUT_CLIENT_RETURN")
            return FlowExit("return")
        return None

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
            "tool_coverage": {
                name: {
                    "status": (
                        "PARTIAL_UNRESOLVED"
                        if any(x["tool"] == name for x in self.gaps)
                        else "OBSERVATIONS_PARTIAL_COVERAGE"
                        if any(x["tool"] == name for x in self.results)
                        else "NO_AWS_OPERATION_PROVEN"
                    ),
                    "operation_count": sum(x["tool"] == name for x in self.results),
                    "gap_count": sum(x["tool"] == name for x in self.gaps),
                }
                for name in sorted(self.tools)
            },
            "tool_registration_status": (
                "INCOMPLETE_DYNAMIC_REGISTRATION"
                if any(x["reason"] in {
                    "IMPORTED_MCP_REGISTRATION_UNRESOLVED",
                    "DYNAMIC_MCP_TOOL_FACTORY_UNRESOLVED",
                    "NO_STATIC_MCP_HANDLERS_DISCOVERED",
                    "DYNAMIC_PUBLIC_TOOL_NAME",
                    "DUPLICATE_PUBLIC_TOOL_NAME",
                    "IMPORTED_MCP_INSTANCE_UNVERIFIED",
                } for x in self.gaps)
                else "STATIC_PARTIAL_COVERAGE"
            ),
            "operations": sorted(self.results, key=lambda x: (x["tool"], x["line"], x["operation"])),
            "gaps": sorted(self.gaps, key=lambda x: (x["tool"], x["line"], x["reason"])),
            "assurance": "STATIC_CANDIDATE_ONLY",
            "analysis_limits": {
                "work_units": self.work_units,
                "work_budget_exceeded": self.budget_exceeded,
                "truncated_gaps": self.truncated_gaps,
                "truncated_operations": self.truncated_operations,
            },
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
