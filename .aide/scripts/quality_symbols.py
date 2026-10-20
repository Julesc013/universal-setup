"""Bounded Python syntax evidence; no imports or execution of inspected code."""
from __future__ import annotations

import ast
import hashlib
import keyword
import platform
import sys
import unicodedata

MATCH_LIMIT = 20
PARAMETER_LIMIT = 32


def validate_symbol(name: str) -> None:
    # Python normalizes identifiers before storing them in its AST.
    if (not isinstance(name, str) or not name.isidentifier() or keyword.iskeyword(name)
            or unicodedata.normalize("NFKC", name) != name or len(name) > 256):
        raise ValueError("use one normalized Python identifier, at most 256 characters")


def inspect_python(raw: bytes, name: str) -> dict:
    """Return syntax matches, never a resolved dependency or semantic oracle."""
    validate_symbol(name)
    evidence = {
        "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
        "state": "parsed", "match_state": "not_found",
        "parser": {"implementation": platform.python_implementation(),
                   "version": platform.python_version(), "grammar": list(sys.version_info[:2])},
    }
    try:
        tree = ast.parse(raw.decode("utf-8-sig"))
    except (UnicodeError, SyntaxError, ValueError, RecursionError):
        return {**evidence, "state": "unindexed", "reason": "invalid_utf8_or_unsupported_python_syntax",
                "match_state": "unknown"}
    groups = {key: {"items": [], "omitted": 0} for key in ("definitions", "calls", "imports")}

    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.scope = []

        def add(self, group, node, **fields):
            bucket = groups[group]
            if len(bucket["items"]) >= MATCH_LIMIT:
                bucket["omitted"] += 1
                return
            bucket["items"].append({"line": node.lineno, "end_line": node.end_lineno,
                                    "scope": ".".join(self.scope) or "<module>", **fields})

        def definition(self, node, kind):
            if node.name == name:
                fields = {"name": node.name, "qualified_name": ".".join([*self.scope, node.name]),
                          "kind": kind, "decorated": bool(node.decorator_list)}
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    args = node.args
                    parameters = []
                    for category, values in (
                        ("positional_only", args.posonlyargs), ("positional_or_keyword", args.args),
                        ("variadic_positional", [args.vararg] if args.vararg else []),
                        ("keyword_only", args.kwonlyargs),
                        ("variadic_keyword", [args.kwarg] if args.kwarg else []),
                    ):
                        parameters.extend({"name": arg.arg, "kind": category} for arg in values)
                    fields["parameters"] = {"items": parameters[:PARAMETER_LIMIT],
                                            "omitted": max(0, len(parameters) - PARAMETER_LIMIT)}
                self.add("definitions", node, **fields)
            # Headers belong outside the definition body. These locations describe
            # syntactic containment, not Python's complete evaluation/scope rules.
            for field, value in ast.iter_fields(node):
                if field == "body":
                    continue
                if isinstance(value, ast.AST):
                    self.visit(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, ast.AST):
                            self.visit(item)
            self.scope.append(node.name)
            for statement in node.body:
                self.visit(statement)
            self.scope.pop()

        def visit_FunctionDef(self, node):
            self.definition(node, "function")

        def visit_AsyncFunctionDef(self, node):
            self.definition(node, "async_function")

        def visit_ClassDef(self, node):
            self.definition(node, "class")

        def visit_Lambda(self, node):
            self.visit(node.args)
            self.scope.append("<lambda>")
            self.visit(node.body)
            self.scope.pop()

        def visit_Call(self, node):
            target = node.func
            if isinstance(target, ast.Name) and target.id == name:
                self.add("calls", node, form="name", identifier=name, resolution="unresolved")
            elif isinstance(target, ast.Attribute) and target.attr == name:
                self.add("calls", node, form="attribute", identifier=name, resolution="unresolved")
            self.generic_visit(node)

        def visit_Import(self, node):
            for alias in node.names:
                if alias.name.rsplit(".", 1)[-1] == name or alias.asname == name:
                    self.add("imports", node, module=alias.name, imported=None, alias=alias.asname,
                             resolution="declaration_only")

        def visit_ImportFrom(self, node):
            for alias in node.names:
                if alias.name == name or alias.asname == name:
                    self.add("imports", node, module=node.module, level=node.level,
                             imported=alias.name, alias=alias.asname, resolution="declaration_only")

    try:
        Visitor().visit(tree)
    except RecursionError:
        return {**evidence, "state": "unindexed", "reason": "syntax_nesting_limit",
                "match_state": "unknown"}
    if any(bucket["items"] or bucket["omitted"] for bucket in groups.values()):
        evidence["match_state"] = "found"
    return {**evidence, **groups}
