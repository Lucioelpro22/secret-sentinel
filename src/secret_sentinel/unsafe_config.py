"""Conservative single-line configuration checks; never execute source code."""

from __future__ import annotations

import ast
import io
import re
import tokenize
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

from .models import Severity

CONFIG_RULE_IDS = frozenset(
    {
        "config-debug-enabled",
        "config-tls-verification-disabled",
        "config-wildcard-allowed-hosts",
    }
)
_DEBUG_KEYS = {"DEBUG", "FLASK_DEBUG", "DJANGO_DEBUG"}
_TLS_ZERO_KEYS = {"NODE_TLS_REJECT_UNAUTHORIZED", "PYTHONHTTPSVERIFY"}
_REQUEST_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "request",
}
_ASSIGNMENT = re.compile(
    r"""^\s*(?:export\s+)?(?P<key>DEBUG|FLASK_DEBUG|DJANGO_DEBUG|NODE_TLS_REJECT_UNAUTHORIZED|PYTHONHTTPSVERIFY)\s*(?P<separator>[=:])\s*(?P<value>true|false|1|0|"(?:true|false|1|0)"|'(?:true|false|1|0)')\s*(?:[#;].*)?$""",
    re.IGNORECASE,
)
_JSON_PAIR = re.compile(
    r'^\s*\{?\s*"(?P<key>DEBUG|FLASK_DEBUG|DJANGO_DEBUG|NODE_TLS_REJECT_UNAUTHORIZED|PYTHONHTTPSVERIFY)"\s*:\s*(?P<value>true|false|1|0|"(?:true|false|1|0)")\s*,?\s*\}?\s*$',
)


@dataclass(frozen=True, slots=True)
class ConfigMatch:
    column: int
    rule_id: str
    description: str
    severity: Severity
    confidence: Literal["high", "medium"]
    evidence: str
    identity: str


def _match(column: int, kind: str, evidence: str) -> ConfigMatch:
    description = {
        "debug-enabled": "Debug mode explicitly enabled",
        "tls-verification-disabled": "TLS certificate verification explicitly disabled",
        "wildcard-allowed-hosts": "Django allowed hosts explicitly permits every host",
    }[kind]
    return ConfigMatch(
        column,
        "config-" + kind,
        description,
        "high" if kind == "tls-verification-disabled" else "medium",
        "medium",
        evidence,
        evidence,
    )


def _attribute(node: ast.AST, receiver: str, names: set[str]) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == receiver
        and node.attr in names
    )


def _literal(node: ast.AST, expected: object) -> bool:
    return (
        isinstance(node, ast.Constant)
        and type(node.value) is type(expected)
        and node.value == expected
    )


def _python(line: str) -> Iterator[ConfigMatch]:
    source = line.lstrip()
    indentation = len(line) - len(source)
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return
    encoded = source.encode("utf-8")
    for node in ast.walk(tree):
        if not hasattr(node, "col_offset"):
            continue
        # AST offsets count UTF-8 bytes; report positions count characters.
        column = indentation + len(encoded[: node.col_offset].decode("utf-8")) + 1
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for target in targets:
                if not isinstance(target, ast.Name) or value is None:
                    continue
                if target.id in _DEBUG_KEYS and (
                    _literal(value, True) or _literal(value, 1)
                ):
                    yield _match(column, "debug-enabled", target.id + "=true")
                if (
                    target.id == "ALLOWED_HOSTS"
                    and isinstance(value, (ast.List, ast.Tuple))
                    and any(_literal(item, "*") for item in value.elts)
                ):
                    yield _match(column, "wildcard-allowed-hosts", "ALLOWED_HOSTS=[*]")
        elif isinstance(node, ast.Call):
            if _attribute(node.func, "requests", _REQUEST_METHODS):
                if any(
                    keyword.arg == "verify" and _literal(keyword.value, False)
                    for keyword in node.keywords
                ):
                    yield _match(
                        column, "tls-verification-disabled", "requests.verify=false"
                    )
            elif _attribute(node.func, "app", {"run"}):
                if any(
                    keyword.arg == "debug" and _literal(keyword.value, True)
                    for keyword in node.keywords
                ):
                    yield _match(column, "debug-enabled", "app.run.debug=true")
            elif _attribute(node.func, "ssl", {"_create_unverified_context"}):
                yield _match(
                    column,
                    "tls-verification-disabled",
                    "ssl._create_unverified_context()",
                )


def python_multiline_string_ranges(text: str) -> list[tuple[int, int]]:
    """Identify literal-string spans to avoid interpreting docstrings as code."""
    blocked: list[tuple[int, int]] = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.STRING and token.end[0] > token.start[0]:
                blocked.append((token.start[0], token.end[0]))
    except tokenize.TokenError as error:
        if error.args and error.args[0] == "EOF in multi-line string":
            start = error.args[1][0]
            blocked.append((start, text.count("\n") + 1))
    except (IndentationError, SyntaxError, RecursionError):
        # Invalid source cannot establish that subsequent lines are executable.
        blocked = [(1, text.count("\n") + 1)]
    merged: list[tuple[int, int]] = []
    for start, end in blocked:
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def iter_config_matches(line: str, path: str) -> Iterator[ConfigMatch]:
    """Inspect recognized syntax only; multiline values and aliases are unsupported."""
    if len(line) > 20_000:
        return
    name = PurePosixPath(path).name
    is_env = (
        name == ".env"
        or name.startswith(".env.")
        or PurePosixPath(path).suffix.lower() == ".env"
    )
    suffix = ".env" if is_env else PurePosixPath(path).suffix.lower()
    if suffix == ".py":
        yield from _python(line)
        return
    if (
        suffix not in {".env", ".ini", ".cfg", ".toml", ".yaml", ".yml", ".json"}
        and PurePosixPath(path).name != ".env"
    ):
        return
    pattern = _JSON_PAIR if suffix == ".json" else _ASSIGNMENT
    match = pattern.fullmatch(line)
    if match is None:
        return
    if suffix != ".json":
        if (
            line.lstrip().startswith("export ")
            and suffix != ".env"
            and PurePosixPath(path).name != ".env"
        ):
            return
        separator = match.group("separator")
        if suffix in {".yaml", ".yml"} and separator != ":":
            return
        if suffix in {".env", ".toml"} and separator != "=":
            return
        if suffix == ".toml" and match.group("value") in {
            "TRUE",
            "FALSE",
            "True",
            "False",
        }:
            return
    key = match.group("key")
    # Environment and framework configuration keys are case-sensitive.
    if key not in _DEBUG_KEYS | _TLS_ZERO_KEYS:
        return
    value = match.group("value").strip("\"'").lower()
    if key in _DEBUG_KEYS and value in {"true", "1"}:
        yield _match(match.start("key") + 1, "debug-enabled", key + "=true")
    elif key in _TLS_ZERO_KEYS and value == "0":
        yield _match(match.start("key") + 1, "tls-verification-disabled", key + "=0")
