#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

# Optional: color output
try:
    from colorama import init as colorama_init
    from colorama import Fore, Style
    _COLORAMA_OK = True
except Exception:
    _COLORAMA_OK = False
    Fore = Style = None  # type: ignore


# ----------------------------
# ANSI stripping for log files
# ----------------------------

_ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def strip_ansi(s: str) -> str:
    if not s:
        return s
    return _ANSI_RE.sub("", s)


# ----------------------------
# Introspection helpers
# ----------------------------

def load_introspection_schema(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    if isinstance(raw, dict) and "data" in raw and isinstance(raw["data"], dict) and "__schema" in raw["data"]:
        return raw["data"]["__schema"]
    if isinstance(raw, dict) and "__schema" in raw:
        return raw["__schema"]

    raise ValueError("Invalid introspection JSON: missing data.__schema or __schema.")


def type_ref_to_str(tref: Dict[str, Any]) -> str:
    if tref is None:
        return "UNKNOWN"
    kind = tref.get("kind")
    name = tref.get("name")
    of_type = tref.get("ofType")

    if kind == "NON_NULL":
        return f"{type_ref_to_str(of_type)}!"
    if kind == "LIST":
        return f"[{type_ref_to_str(of_type)}]"
    return name or "UNKNOWN"


def unwrap_named_type(tref: Dict[str, Any]) -> Tuple[str, str]:
    cur = tref
    while cur and cur.get("kind") in ("NON_NULL", "LIST"):
        cur = cur.get("ofType")
    if not cur:
        return ("UNKNOWN", "UNKNOWN")
    return (cur.get("kind", "UNKNOWN"), cur.get("name", "UNKNOWN"))


def is_non_null(tref: Dict[str, Any]) -> bool:
    return tref is not None and tref.get("kind") == "NON_NULL"


# ----------------------------
# GraphQL literal helpers
# ----------------------------

def graphql_string_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def graphql_literal(value: Any, enum_hint: bool = False) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        if enum_hint:
            return value
        return f"\"{graphql_string_escape(value)}\""
    if isinstance(value, list):
        return "[" + ", ".join(graphql_literal(v) for v in value) + "]"
    if isinstance(value, dict):
        items = []
        for k, v in value.items():
            items.append(f"{k}: {graphql_literal(v)}")
        return "{" + ", ".join(items) + "}"
    return f"\"{graphql_string_escape(str(value))}\""


# ----------------------------
# Placeholder generation for variables
# ----------------------------

SCALAR_DEFAULTS: Dict[str, Any] = {
    "String": "REPLACE_ME",
    "ID": "REPLACE_ME",
    "Int": 1,
    "Float": 1.0,
    "Boolean": True,
}


def placeholder_for_type(
    schema_types: Dict[str, Dict[str, Any]],
    tref: Dict[str, Any],
    *,
    max_input_depth: int = 4,
    _depth: int = 0
) -> Any:
    if _depth > max_input_depth:
        return "REPLACE_ME"

    def has_list_wrapper(tr: Dict[str, Any]) -> bool:
        cur = tr
        while cur and cur.get("kind") in ("NON_NULL", "LIST"):
            if cur.get("kind") == "LIST":
                return True
            cur = cur.get("ofType")
        return False

    is_list = has_list_wrapper(tref)
    kind, name = unwrap_named_type(tref)

    if kind == "SCALAR":
        val = SCALAR_DEFAULTS.get(name, "REPLACE_ME")
        return [val] if is_list else val

    if kind == "ENUM":
        tdef = schema_types.get(name, {})
        enum_vals = tdef.get("enumValues") or []
        chosen = enum_vals[0]["name"] if enum_vals else "ENUM_VALUE"
        return [chosen] if is_list else chosen

    if kind == "INPUT_OBJECT":
        tdef = schema_types.get(name, {})
        input_fields = tdef.get("inputFields") or []
        obj: Dict[str, Any] = {}
        for f in input_fields:
            if is_non_null(f["type"]):
                obj[f["name"]] = placeholder_for_type(
                    schema_types, f["type"], max_input_depth=max_input_depth, _depth=_depth + 1
                )
        if not obj and input_fields:
            f = input_fields[0]
            obj[f["name"]] = placeholder_for_type(
                schema_types, f["type"], max_input_depth=max_input_depth, _depth=_depth + 1
            )
        return [obj] if is_list else obj

    return ["REPLACE_ME"] if is_list else "REPLACE_ME"


# ----------------------------
# Path finding
# ----------------------------

@dataclass(frozen=True)
class PathStep:
    parent_type: str
    field_name: str
    child_type: str


def find_paths_to_type(
    schema_types: Dict[str, Dict[str, Any]],
    root_type_name: str,
    target_type_name: str,
    *,
    max_path_depth: int = 8,
    max_paths: int = 200,
) -> List[List[PathStep]]:
    paths: List[List[PathStep]] = []
    q = deque()
    q.append((root_type_name, [], {root_type_name}))

    while q and len(paths) < max_paths:
        current_type, steps, visited = q.popleft()
        if len(steps) >= max_path_depth:
            continue

        tdef = schema_types.get(current_type) or {}
        fields = tdef.get("fields") or []
        for f in fields:
            fname = f["name"]
            _, child_name = unwrap_named_type(f["type"])
            if child_name == "UNKNOWN":
                continue

            new_step = PathStep(parent_type=current_type, field_name=fname, child_type=child_name)
            new_steps = steps + [new_step]

            if child_name == target_type_name:
                paths.append(new_steps)
                if len(paths) >= max_paths:
                    break
                continue

            child_def = schema_types.get(child_name) or {}
            child_kind = child_def.get("kind")
            if child_kind not in ("OBJECT", "INTERFACE", "UNION"):
                continue

            if child_name in visited:
                continue

            new_visited = set(visited)
            new_visited.add(child_name)
            q.append((child_name, new_steps, new_visited))

    return paths


# ----------------------------
# Selection set builder
# ----------------------------

class VarContext:
    def __init__(self, schema_types: Dict[str, Dict[str, Any]], arg_mode: str, max_input_depth: int):
        self.schema_types = schema_types
        self.arg_mode = arg_mode
        self.max_input_depth = max_input_depth
        self.var_defs: Dict[str, str] = {}
        self.var_values: Dict[str, Any] = {}

    def _sanitize_name(self, s: str) -> str:
        s = re.sub(r"[^A-Za-z0-9_]", "_", s)
        s = re.sub(r"__+", "_", s)
        s = s.strip("_")
        if not s:
            s = "v"
        if re.match(r"^[0-9]", s):
            s = "v_" + s
        return s

    def placeholder_for(self, tref: Dict[str, Any]) -> Any:
        return placeholder_for_type(self.schema_types, tref, max_input_depth=self.max_input_depth)

    def register_var(self, hint: str, tref: Dict[str, Any]) -> str:
        base = self._sanitize_name(hint)
        name = base
        i = 2
        while name in self.var_defs and self.var_defs[name] != type_ref_to_str(tref):
            name = f"{base}_{i}"
            i += 1

        if name not in self.var_defs:
            self.var_defs[name] = type_ref_to_str(tref)
            self.var_values[name] = self.placeholder_for(tref)
        return name

    def render_var_definitions(self) -> str:
        if not self.var_defs:
            return ""
        parts = [f"${n}: {t}" for n, t in self.var_defs.items()]
        return "(" + ", ".join(parts) + ")"

    def variables_object(self) -> Dict[str, Any]:
        if self.arg_mode != "vars":
            return {}
        return self.var_values


def scalar_fields_only(schema_types: Dict[str, Dict[str, Any]], type_name: str, max_fields_per_type: int) -> str:
    tdef = schema_types.get(type_name) or {}
    if tdef.get("kind") != "OBJECT":
        return "__typename"
    out = ["__typename"]
    for f in (tdef.get("fields") or [])[: max_fields_per_type]:
        k, _ = unwrap_named_type(f["type"])
        if k in ("SCALAR", "ENUM"):
            out.append(f["name"])
    return " ".join(out) if len(out) > 1 else "__typename"


def build_selection_set(
    schema_types: Dict[str, Dict[str, Any]],
    type_name: str,
    *,
    depth: int,
    max_fields_per_type: int,
    max_total_fields: int,
    include_required_args_fields: bool,
    include_optional_args: bool,
    arg_mode: str,
    cycle_policy: str,  # scalars | typename | stop
    var_ctx: VarContext,
    _total_counter: List[int],
    _visited: Set[str],
) -> str:
    if depth <= 0:
        return "__typename"

    if type_name in _visited:
        if cycle_policy in ("typename", "stop"):
            return "__typename"
        return scalar_fields_only(schema_types, type_name, max_fields_per_type)

    tdef = schema_types.get(type_name) or {}
    if tdef.get("kind") != "OBJECT":
        return "__typename"

    fields = tdef.get("fields") or []
    out: List[str] = []
    count = 0

    new_visited = set(_visited)
    new_visited.add(type_name)

    for f in fields:
        if _total_counter[0] >= max_total_fields or count >= max_fields_per_type:
            break

        fname = f["name"]
        args = f.get("args") or []
        fkind, child_name = unwrap_named_type(f["type"])

        required_args = [a for a in args if is_non_null(a["type"])]
        if required_args and not include_required_args_fields:
            continue

        arg_assignments = []
        for a in args:
            is_req = is_non_null(a["type"])
            if not is_req and not include_optional_args:
                continue

            aname = a["name"]
            if arg_mode == "vars":
                vname = var_ctx.register_var(f"{type_name}_{fname}_{aname}", a["type"])
                arg_assignments.append(f"{aname}: ${vname}")
            else:
                aval = var_ctx.placeholder_for(a["type"])
                akind, _ = unwrap_named_type(a["type"])
                enum_hint = (akind == "ENUM")
                arg_assignments.append(f"{aname}: {graphql_literal(aval, enum_hint=enum_hint)}")

        arg_str = "(" + ", ".join(arg_assignments) + ")" if arg_assignments else ""

        if fkind in ("SCALAR", "ENUM"):
            out.append(f"{fname}{arg_str}")
            count += 1
            _total_counter[0] += 1
            continue

        child_sel = build_selection_set(
            schema_types,
            child_name,
            depth=depth - 1,
            max_fields_per_type=max_fields_per_type,
            max_total_fields=max_total_fields,
            include_required_args_fields=include_required_args_fields,
            include_optional_args=include_optional_args,
            arg_mode=arg_mode,
            cycle_policy=cycle_policy,
            var_ctx=var_ctx,
            _total_counter=_total_counter,
            _visited=new_visited,
        )
        out.append(f"{fname}{arg_str} {{ {child_sel} }}")
        count += 1
        _total_counter[0] += 1

    return " ".join(out) if out else "__typename"


# ----------------------------
# Pretty formatter for GraphQL query string (keeps real newlines)
# ----------------------------

def pretty_graphql_query(compact: str, indent_size: int = 4, trailing_newline: bool = True) -> str:
    s = (compact or "").strip()
    if "{" not in s or "}" not in s:
        return s

    first = s.find("{")
    last = s.rfind("}")
    if first == -1 or last == -1 or last <= first:
        return s

    header = s[:first].strip()
    inner = s[first + 1:last].strip()

    spaced = inner.replace("{", " { ").replace("}", " } ")
    tokens = [t for t in spaced.split() if t]

    out: List[str] = []
    indent = 1

    def ind(n: int) -> str:
        return " " * (indent_size * n)

    i = 0
    out.append(f"{header} {{ \n")

    while i < len(tokens):
        tok = tokens[i]

        if tok == "{":
            out.append("{ \n")
            indent += 1
            i += 1
            continue

        if tok == "}":
            indent -= 1
            out.append(ind(indent) + "}\n")
            i += 1
            continue

        if tok.endswith(":") and (i + 1) < len(tokens) and tokens[i + 1] not in ("{", "}"):
            tok = tok + " " + tokens[i + 1]
            i += 1

        if tok == "..." and (i + 2) < len(tokens) and tokens[i + 1] == "on" and tokens[i + 2] not in ("{", "}"):
            tok = f"... on {tokens[i + 2]}"
            i += 2

        nxt = tokens[i + 1] if (i + 1) < len(tokens) else ""
        if nxt == "{":
            out.append(ind(indent) + tok + " ")
        else:
            out.append(ind(indent) + tok + "\n")

        i += 1

    out.append("}")
    result = "".join(out)
    if trailing_newline:
        result += "\n"
    return result


# ----------------------------
# Query builder
# ----------------------------

def build_query_for_path(
    schema_types: Dict[str, Dict[str, Any]],
    target_type: str,
    path: List[PathStep],
    *,
    selection_depth: int,
    max_fields_per_type: int,
    max_total_fields: int,
    include_required_args_fields: bool,
    include_optional_args: bool,
    arg_mode: str,
    cycle_policy: str,
    max_input_depth: int,
    operation_name: str,
) -> Dict[str, Any]:
    var_ctx = VarContext(schema_types, arg_mode=arg_mode, max_input_depth=max_input_depth)

    total_counter = [0]
    target_sel = build_selection_set(
        schema_types,
        target_type,
        depth=selection_depth,
        max_fields_per_type=max_fields_per_type,
        max_total_fields=max_total_fields,
        include_required_args_fields=include_required_args_fields,
        include_optional_args=include_optional_args,
        arg_mode=arg_mode,
        cycle_policy=cycle_policy,
        var_ctx=var_ctx,
        _total_counter=total_counter,
        _visited=set(),
    )

    inner = f"{{ {target_sel} }}"
    for step in reversed(path):
        parent_def = schema_types.get(step.parent_type) or {}
        field_def = None
        for f in (parent_def.get("fields") or []):
            if f["name"] == step.field_name:
                field_def = f
                break

        arg_assignments = []
        if field_def:
            for a in (field_def.get("args") or []):
                is_req = is_non_null(a["type"])
                if not is_req and not include_optional_args:
                    continue

                aname = a["name"]
                if arg_mode == "vars":
                    vname = var_ctx.register_var(f"{step.parent_type}_{step.field_name}_{aname}", a["type"])
                    arg_assignments.append(f"{aname}: ${vname}")
                else:
                    aval = var_ctx.placeholder_for(a["type"])
                    akind, _ = unwrap_named_type(a["type"])
                    enum_hint = (akind == "ENUM")
                    arg_assignments.append(f"{aname}: {graphql_literal(aval, enum_hint=enum_hint)}")

        arg_str = "(" + ", ".join(arg_assignments) + ")" if arg_assignments else ""
        inner = "{ " + f"{step.field_name}{arg_str} {inner}" + " }"

    var_defs = var_ctx.render_var_definitions()
    query = f"query {operation_name}{var_defs} {inner}"

    return {"query": query, "operationName": operation_name, "variables": var_ctx.variables_object()}


def render_path_like_enum(path: List[PathStep]) -> str:
    if not path:
        return ""
    s = f"{path[0].parent_type} ({path[0].field_name}) -> {path[0].child_type}"
    for step in path[1:]:
        s += f" ({step.field_name}) -> {step.child_type}"
    return s


def bundle_with_aliases(bodies: List[Dict[str, Any]], operation_name: str) -> Dict[str, Any]:
    merged_vars: Dict[str, Any] = {}
    var_defs: List[str] = []
    selections: List[str] = []

    for idx, b in enumerate(bodies, start=1):
        q = b["query"]
        m = re.match(r"query\s+\w+\s*(\([^\)]*\))?\s*(\{.*\})\s*$", q, flags=re.DOTALL)
        if not m:
            continue

        defs = m.group(1) or ""
        sel = m.group(2)

        alias = f"p{idx}"
        inner = sel.strip()
        if inner.startswith("{") and inner.endswith("}"):
            inner = inner[1:-1].strip()
        selections.append(f"{alias}: {inner}")

        if defs:
            inner_defs = defs.strip()[1:-1].strip()
            if inner_defs:
                var_defs.append(inner_defs)

        merged_vars.update(b.get("variables") or {})

    defs_str = "(" + ", ".join([d for d in var_defs if d]) + ")" if var_defs else ""
    merged_query = f"query {operation_name}{defs_str} {{ " + " ".join(selections) + " }}"

    return {"query": merged_query, "operationName": operation_name, "variables": merged_vars}


# ----------------------------
# Console helpers
# ----------------------------

def colorize(enabled: bool, text: str, color: str) -> str:
    if not enabled or not _COLORAMA_OK:
        return text
    return f"{color}{text}{Style.RESET_ALL}"


# ----------------------------
# CLI
# ----------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Generate GraphQL query bodies for all paths to a target type (introspection Schema.json)."
    )

    ap.add_argument("-s", "--schema", required=True, help="Path to Schema.json (introspection result).")
    ap.add_argument("-t", "--target", required=True, help="Target type name (e.g., User).")
    ap.add_argument("-r", "--root", default="Query", help="Root type name (default: Query).")

    ap.add_argument("-o", "--out", default="", help="Output file path. If empty, no file is written.")
    ap.add_argument("-f", "--format", choices=["ndjson", "json-array"], default="ndjson",
                    help="File output format (default: ndjson).")

    ap.add_argument("-D", "--max-path-depth", type=int, default=8, help="Max traversal depth for finding paths.")
    ap.add_argument("-M", "--max-paths", type=int, default=200, help="Max number of paths to output.")

    ap.add_argument("-d", "--selection-depth", type=int, default=4, help="Max depth for selection sets (default: 4).")
    ap.add_argument("-F", "--max-fields-per-type", type=int, default=30,
                    help="Limit number of fields per type in selections (default: 30).")
    ap.add_argument("-T", "--max-total-fields", type=int, default=500,
                    help="Global limit of selected fields per query (default: 500).")

    ap.add_argument("-a", "--arg-mode", choices=["vars", "inline"], default="vars",
                    help="Render args as variables (vars) or inline literals (inline).")
    ap.add_argument("-R", "--include-required-args-fields", action="store_true",
                    help="Include fields that require args inside selection sets (default: OFF).")
    ap.add_argument("-O", "--include-optional-args", action="store_true",
                    help="Also generate OPTIONAL args (default: OFF).")
    ap.add_argument("-c", "--cycle-policy", choices=["scalars", "typename", "stop"], default="scalars",
                    help="On type cycle during selection expansion: scalars|typename|stop (default: scalars).")
    ap.add_argument("-I", "--max-input-depth", type=int, default=4,
                    help="Max depth for InputObject placeholder skeleton (default: 4).")

    ap.add_argument("-b", "--bundle-aliases", action="store_true",
                    help="Bundle all paths into one query using aliases p1, p2, ...")

    ap.add_argument("-Q", "--no-pretty-query", action="store_true",
                    help="Disable pretty formatting of GraphQL query string.")
    ap.add_argument("-i", "--indent", type=int, default=4, help="Indent size for pretty GraphQL query (default: 4).")

    ap.add_argument("-p", "--paths-only", action="store_true",
                    help="Only print paths (no queries/bodies).")
    ap.add_argument("-m", "--console-mode", choices=["pretty", "burp", "burp_pretty"], default="pretty",
                    help="Console output mode (default: pretty). "
                         "pretty=multiline query, burp=single-line JSON, burp_pretty=both.")
    ap.add_argument("-n", "--no-console", action="store_true", help="Do not print to console.")
    ap.add_argument("-C", "--no-color", action="store_true", help="Disable colored console output.")
    ap.add_argument("-Z", "--separator", default="-" * 75, help="Separator line between paths in console.")
    ap.add_argument("-L", "--console-log", default="",
                    help="Write the FULL console output to a text file as well (recommended for many paths).")

    args = ap.parse_args()

    use_color = (not args.no_color) and _COLORAMA_OK and (not args.no_console)
    if use_color and _COLORAMA_OK:
        colorama_init(autoreset=True)

    try:
        schema = load_introspection_schema(args.schema)
    except FileNotFoundError:
        msg = f"[ERROR] Schema file not found: {args.schema}"
        print(colorize(use_color, msg, Fore.RED) if use_color else msg, file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        msg = f"[ERROR] Failed to parse Schema.json (invalid JSON): {e}"
        print(colorize(use_color, msg, Fore.RED) if use_color else msg, file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        msg = f"[ERROR] Failed to load introspection schema: {e}"
        print(colorize(use_color, msg, Fore.RED) if use_color else msg, file=sys.stderr)
        sys.exit(2)

    types = schema.get("types") or []
    schema_types: Dict[str, Dict[str, Any]] = {t["name"]: t for t in types if t.get("name")}

    if args.target not in schema_types:
        msg = f'[ERROR] Target type "{args.target}" does not exist in the provided schema.'
        print(colorize(use_color, msg, Fore.RED) if use_color else msg, file=sys.stderr)
        sys.exit(2)

    if args.root not in schema_types:
        msg = f'[ERROR] Root type "{args.root}" does not exist in the provided schema.'
        print(colorize(use_color, msg, Fore.RED) if use_color else msg, file=sys.stderr)
        sys.exit(2)

    paths = find_paths_to_type(
        schema_types,
        root_type_name=args.root,
        target_type_name=args.target,
        max_path_depth=args.max_path_depth,
        max_paths=args.max_paths,
    )

    if not paths:
        msg = f'[WARN] No paths found from root "{args.root}" to target "{args.target}".'
        if not args.no_console:
            print(colorize(use_color, msg, Fore.YELLOW) if use_color else msg)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write("" if args.format == "ndjson" else "[]")
        sys.exit(0)

    log_fp = None
    if args.console_log and not args.no_console:
        log_fp = open(args.console_log, "w", encoding="utf-8")

    def out(line: str = "") -> None:
        """
        Print to console (possibly colorized) and also write to log file WITHOUT ANSI codes.
        """
        if args.no_console:
            return
        print(line)
        if log_fp:
            log_fp.write(strip_ansi(line) + "\n")

    if not args.no_console:
        header = f'Found {len(paths)} ways to reach the "{args.target}" node:'
        out(colorize(use_color, header, Fore.CYAN) if use_color else header)

    path_strings = [render_path_like_enum(p) for p in paths]
    if args.paths_only:
        if not args.no_console:
            for idx, pstr in enumerate(path_strings, start=1):
                out(args.separator)
                line = f"[{idx}] {pstr}"
                out(colorize(use_color, line, Fore.YELLOW) if use_color else line)
        if log_fp:
            log_fp.close()
        sys.exit(0)

    bodies: List[Dict[str, Any]] = []
    for i, p in enumerate(paths, start=1):
        op_name = f"op_{args.target}_{i}"
        body = build_query_for_path(
            schema_types,
            target_type=args.target,
            path=p,
            selection_depth=args.selection_depth,
            max_fields_per_type=args.max_fields_per_type,
            max_total_fields=args.max_total_fields,
            include_required_args_fields=args.include_required_args_fields,
            include_optional_args=args.include_optional_args,
            arg_mode=args.arg_mode,
            cycle_policy=args.cycle_policy,
            max_input_depth=args.max_input_depth,
            operation_name=op_name,
        )
        bodies.append(body)

    if args.bundle_aliases and bodies:
        bundled = bundle_with_aliases(bodies, operation_name=f"op_{args.target}_bundled")
        bodies = [bundled]
        path_strings = [f"{len(paths)} paths bundled with aliases -> {args.target}"]

    if not args.no_pretty_query:
        for b in bodies:
            b["query"] = pretty_graphql_query(b["query"], indent_size=args.indent, trailing_newline=True)

    if args.out:
        if args.format == "ndjson":
            out_text = "\n".join(json.dumps(b, ensure_ascii=False) for b in bodies) + ("\n" if bodies else "")
        else:
            out_text = json.dumps(bodies, ensure_ascii=False, indent=2)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out_text)

    if not args.no_console:
        for idx, (pstr, body) in enumerate(zip(path_strings, bodies), start=1):
            out(args.separator)
            out(colorize(use_color, f"[{idx}] PATH: {pstr}", Fore.YELLOW) if use_color else f"[{idx}] PATH: {pstr}")

            if args.console_mode == "burp":
                out(colorize(use_color, "BURP BODY (copy the next line):", Fore.GREEN) if use_color else "BURP BODY (copy the next line):")
                out(json.dumps(body, ensure_ascii=False))
            elif args.console_mode == "burp_pretty":
                out(colorize(use_color, "BODY:", Fore.GREEN) if use_color else "BODY:")
                out(colorize(use_color, f"operationName: {body.get('operationName','')}", Fore.CYAN) if use_color else f"operationName: {body.get('operationName','')}")
                out(colorize(use_color, "variables:", Fore.CYAN) if use_color else "variables:")
                out(json.dumps(body.get("variables", {}), ensure_ascii=False, indent=2))
                out(colorize(use_color, "query:", Fore.CYAN) if use_color else "query:")
                out(body.get("query", ""))

                out(colorize(use_color, "BURP BODY (copy the next line):", Fore.GREEN) if use_color else "BURP BODY (copy the next line):")
                out(json.dumps(body, ensure_ascii=False))
            else:
                out(colorize(use_color, "BODY:", Fore.GREEN) if use_color else "BODY:")
                out(colorize(use_color, f"operationName: {body.get('operationName','')}", Fore.CYAN) if use_color else f"operationName: {body.get('operationName','')}")
                out(colorize(use_color, "variables:", Fore.CYAN) if use_color else "variables:")
                out(json.dumps(body.get("variables", {}), ensure_ascii=False, indent=2))
                out(colorize(use_color, "query:", Fore.CYAN) if use_color else "query:")
                out(body.get("query", ""))

        if args.out:
            out(args.separator)
            saved = f"Saved Burp-ready output to: {args.out}"
            out(colorize(use_color, saved, Fore.CYAN) if use_color else saved)

    if log_fp:
        log_fp.close()


if __name__ == "__main__":
    main()
