#!/usr/bin/env python3
"""
taint_py.py — Static taint analysis for real Python files.

Walks the Python AST using the stdlib `ast` module, maps Python constructs
to sources/sinks/sanitizers, and runs the same taint-propagation logic as
the IMP engine (but in Python so no OCaml required for Python targets).

Usage:
    python3 taint_py.py [--policy policy.json] <target.py>

Policy JSON format (same schema as the OCaml tool):
    {
      "sources":    ["input", "sys.stdin.read", "request.args.get", ...],
      "sinks":      ["execute", "cursor.execute", "os.system", ...],
      "sanitizers": ["escape", "bleach.clean", ...]
    }
"""

import ast
import json
import sys
import os
from dataclasses import dataclass, field
from typing import Optional

# ── Default policy ────────────────────────────────────────────────────────────

DEFAULT_POLICY = {
    "sources": [
        # Built-in
        "input",
        # sys
        "sys.stdin.read", "sys.stdin.readline",
        # Flask / Django request data
        "request.args.get", "request.form.get", "request.json.get",
        "request.GET.get", "request.POST.get", "request.data",
        # FastAPI
        "Query", "Body", "Form",
        # Generic
        "os.environ.get", "os.getenv",
    ],
    "sinks": [
        # SQL
        "execute", "cursor.execute", "db.execute",
        "connection.execute", "session.execute",
        # OS commands
        "os.system", "os.popen", "subprocess.call",
        "subprocess.run", "subprocess.Popen",
        "eval", "exec",
        # HTML / template rendering (XSS)
        "render_template_string", "Markup",
        "innerHTML",  # JS-style reference in Python template strings
        # File write
        "open",  # conservative: flag open() with tainted path
    ],
    "sanitizers": [
        "escape", "html.escape", "bleach.clean",
        "markupsafe.escape", "flask.escape",
        "re.sub", "str.replace",
        "validate", "sanitize", "clean",
        "parameterize", "quote",
        "urllib.parse.quote",
    ],
}

# ── Policy loading ────────────────────────────────────────────────────────────

def load_policy(path: Optional[str]) -> dict:
    if path is None:
        return DEFAULT_POLICY
    try:
        with open(path) as f:
            data = json.load(f)
        policy = dict(DEFAULT_POLICY)  # start from defaults
        for key in ("sources", "sinks", "sanitizers"):
            if key in data and data[key]:
                policy[key] = data[key]
        return policy
    except (OSError, json.JSONDecodeError) as e:
        print(f"Warning: could not load policy '{path}': {e}\nUsing default policy.", file=sys.stderr)
        return DEFAULT_POLICY

# ── Taint state ───────────────────────────────────────────────────────────────

@dataclass
class TaintOrigin:
    source_var: str
    source_line: int

@dataclass
class Warning:
    sink_name: str
    sink_line: int
    tainted_var: str
    origin: TaintOrigin
    path: list

# Maps variable name → TaintOrigin
TaintState = dict  # str -> TaintOrigin

def merge_states(s1: TaintState, s2: TaintState) -> TaintState:
    """Union of two taint states (sound over-approximation)."""
    merged = dict(s1)
    for k, v in s2.items():
        if k not in merged:
            merged[k] = v
    return merged

def states_equal(s1: TaintState, s2: TaintState) -> bool:
    if set(s1.keys()) != set(s2.keys()):
        return False
    return all(s1[k].source_var == s2[k].source_var for k in s1)

# ── Name resolution helpers ───────────────────────────────────────────────────

def resolve_call_name(node: ast.expr) -> str:
    """Return a dotted name for a Call's func node, e.g. 'os.system'."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{resolve_call_name(node.value)}.{node.attr}"
    return "<unknown>"

def collect_names(node: ast.expr) -> list:
    """Return all Name ids referenced in an expression."""
    names = []
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.append(child.id)
    return names

def is_tainted(state: TaintState, node: ast.expr) -> Optional[TaintOrigin]:
    for name in collect_names(node):
        if name in state:
            return state[name]
    return None

def matches_policy(name: str, policy_list: list) -> bool:
    """Check if a (possibly dotted) name matches any entry in the policy list."""
    name_lower = name.lower()
    for entry in policy_list:
        entry_lower = entry.lower()
        # Exact match or suffix match (e.g. "execute" matches "cursor.execute")
        if name_lower == entry_lower or name_lower.endswith("." + entry_lower):
            return True
    return False

# ── Core analysis ─────────────────────────────────────────────────────────────

class TaintAnalyzer(ast.NodeVisitor):
    def __init__(self, policy: dict):
        self.policy = policy
        self.state: TaintState = {}
        self.warnings: list[Warning] = []

    def _warn(self, sink_name: str, line: int, tainted_var: str, origin: TaintOrigin):
        path = (
            [origin.source_var, tainted_var, sink_name]
            if origin.source_var != tainted_var
            else [tainted_var, sink_name]
        )
        self.warnings.append(Warning(
            sink_name=sink_name,
            sink_line=line,
            tainted_var=tainted_var,
            origin=origin,
            path=path,
        ))

    # ── Statements ──────────────────────────────────────────────────────────

    def visit_Assign(self, node: ast.Assign):
        """x = <expr>  or  x = source()"""
        rhs = node.value
        origin = self._check_source_call(rhs, node.lineno)

        for target in node.targets:
            if isinstance(target, ast.Name):
                varname = target.id
                if origin:
                    self.state[varname] = origin
                elif is_tainted(self.state, rhs):
                    # Propagate taint through assignment
                    existing = is_tainted(self.state, rhs)
                    self.state[varname] = existing
                else:
                    # Clean assignment removes taint
                    self.state.pop(varname, None)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        """x += <expr> — if rhs is tainted, x becomes tainted"""
        if isinstance(node.target, ast.Name):
            varname = node.target.id
            origin = is_tainted(self.state, node.value)
            if origin:
                self.state[varname] = origin
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr):
        """Standalone expression statements, e.g. function calls."""
        if isinstance(node.value, ast.Call):
            self._check_call(node.value, node.lineno)
        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        """Analyze both branches, merge results."""
        saved = dict(self.state)

        # then branch
        self.state = dict(saved)
        for stmt in node.body:
            self.visit(stmt)
        then_state = dict(self.state)

        # else branch
        self.state = dict(saved)
        for stmt in node.orelse:
            self.visit(stmt)
        else_state = dict(self.state)

        self.state = merge_states(then_state, else_state)

    def visit_For(self, node: ast.For):
        """Fixed-point iteration for loops."""
        self._fixpoint(node.body)

    def visit_While(self, node: ast.While):
        """Fixed-point iteration for while loops."""
        self._fixpoint(node.body)

    def _fixpoint(self, body):
        while True:
            prev = dict(self.state)
            for stmt in body:
                self.visit(stmt)
            merged = merge_states(prev, self.state)
            if states_equal(merged, prev):
                self.state = merged
                break
            self.state = merged

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Analyze function body — treat parameters as potentially tainted
        if the function name suggests it receives external input."""
        # Save outer state
        outer = dict(self.state)
        # Parameters: conservatively taint them if function looks like a handler
        handler_hints = ["view", "handler", "route", "endpoint", "get", "post",
                         "request", "handle", "process", "on_"]
        is_handler = any(h in node.name.lower() for h in handler_hints)
        if is_handler:
            for arg in node.args.args:
                self.state[arg.arg] = TaintOrigin(
                    source_var=arg.arg, source_line=node.lineno
                )
        for stmt in node.body:
            self.visit(stmt)
        self.state = outer  # restore outer scope

    visit_AsyncFunctionDef = visit_FunctionDef

    # ── Call analysis ────────────────────────────────────────────────────────

    def _check_source_call(self, node: ast.expr, line: int) -> Optional[TaintOrigin]:
        """If node is a call to a source function, return a TaintOrigin."""
        if not isinstance(node, ast.Call):
            return None
        name = resolve_call_name(node.func)
        if matches_policy(name, self.policy["sources"]):
            return TaintOrigin(source_var=name, source_line=line)
        return None

    def _check_call(self, node: ast.Call, line: int):
        """Check if a call is a sink or sanitizer; emit warning or clean state."""
        name = resolve_call_name(node.func)

        if matches_policy(name, self.policy["sanitizers"]):
            # Remove taint from all arguments passed to sanitizer
            for arg in node.args:
                for varname in collect_names(arg):
                    self.state.pop(varname, None)

        elif matches_policy(name, self.policy["sinks"]):
            for arg in node.args:
                origin = is_tainted(self.state, arg)
                if origin:
                    tainted_var = (
                        arg.id if isinstance(arg, ast.Name) else "<expr>"
                    )
                    self._warn(name, line, tainted_var, origin)

    def visit_Call(self, node: ast.Call):
        """Catch calls anywhere in an expression context."""
        self._check_call(node, node.lineno)
        self.generic_visit(node)

    # ── Entry ────────────────────────────────────────────────────────────────

    def analyze(self, tree: ast.Module) -> list[Warning]:
        self.visit(tree)
        # Deduplicate warnings by (sink_name, sink_line, tainted_var)
        seen = set()
        unique = []
        for w in self.warnings:
            key = (w.sink_name, w.sink_line, w.tainted_var)
            if key not in seen:
                seen.add(key)
                unique.append(w)
        return unique


# ── Formatting ────────────────────────────────────────────────────────────────

def format_warning(w: Warning) -> str:
    path_str = " -> ".join(w.path)
    return (
        f"WARNING: Tainted data flows to sink at line {w.sink_line}\n"
        f"  Source: '{w.origin.source_var}' at line {w.origin.source_line}\n"
        f"  Sink:   {w.sink_name} at line {w.sink_line}\n"
        f"  Path:   {path_str}"
    )

def print_results(warnings: list[Warning]):
    if not warnings:
        print("No taint violations found. Program is clean.")
    else:
        print(f"Found {len(warnings)} taint violation(s):\n")
        for w in warnings:
            print(format_warning(w))
            print()

# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    args = sys.argv[1:]
    if not args:
        print(f"Usage: {sys.argv[0]} [--policy policy.json] <target.py>", file=sys.stderr)
        sys.exit(1)

    policy_path = None
    source_file = None
    i = 0
    while i < len(args):
        if args[i] == "--policy":
            if i + 1 >= len(args):
                print("Error: --policy requires a filename", file=sys.stderr)
                sys.exit(1)
            policy_path = args[i + 1]
            i += 2
        else:
            source_file = args[i]
            i += 1

    if source_file is None:
        print("Error: no source file specified", file=sys.stderr)
        sys.exit(1)

    return source_file, policy_path


def main():
    source_file, policy_path = parse_args()
    policy = load_policy(policy_path)

    with open(source_file) as f:
        source = f.read()

    print("=== Static Taint Analysis (Python) ===")
    print(f"Analyzing: {source_file}")
    print(f"Sources:    [{', '.join(policy['sources'][:5])}{'...' if len(policy['sources'])>5 else ''}]")
    print(f"Sinks:      [{', '.join(policy['sinks'][:5])}{'...' if len(policy['sinks'])>5 else ''}]")
    print(f"Sanitizers: [{', '.join(policy['sanitizers'][:5])}{'...' if len(policy['sanitizers'])>5 else ''}]\n")

    try:
        tree = ast.parse(source, filename=source_file)
    except SyntaxError as e:
        print(f"Syntax error in '{source_file}': {e}", file=sys.stderr)
        sys.exit(1)

    analyzer = TaintAnalyzer(policy)
    warnings = analyzer.analyze(tree)
    print_results(warnings)


if __name__ == "__main__":
    main()
