#!/usr/bin/env python3
"""Drop CodeQL's weak-hashing alerts on the RFC-mandated MD5 in tests/
and scripts/ from a SARIF file before it is uploaded.

    python3 scripts/filter_codeql_sarif.py SARIF [SARIF ...]

Each argument is a SARIF 2.1.0 file or a directory, which stands for
every ``*.sarif`` file directly in it (what the CodeQL Action's
``analyze`` step writes to its ``output`` directory). A result is
removed when its ``ruleId`` is exactly ``py/weak-sensitive-data-hashing``
and its primary location (``locations[0]``) is a file under ``tests/``
or ``scripts/``; every other result, every other field of the run (rule
definitions, invocations, artifacts, properties) and every file with
nothing to drop are left byte for byte as they were. A file that loses
results is rewritten in place, and one line per file says what was
dropped, so the CI log records it.

Why this exists rather than a CodeQL config: ``query-filters`` drops a
query everywhere, src/ included, and ``paths-ignore`` drops paths from
every query, so neither can scope one query out of two directories.
This keeps both: the query still runs on the shipped package, and every
other query still runs on tests/ and scripts/.

It fails (exit 1) on SARIF it cannot read as CodeQL writes it, rather
than pass a file along unfiltered or upload nothing. A result whose
location it cannot place in the repository is kept, never dropped:
keeping an alert is the safe way to be wrong.
"""

from __future__ import annotations

import argparse
import json
import os
import posixpath
import sys
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit

#: The query whose results this filters, and only on PATH_PREFIXES. The
#: RADIUS (RFC 2865 §3/§5.2, RFC 2866 §3, RFC 1994 §4.1 CHAP), OSPF and
#: RIP checks in tests/ and scripts/check_fixtures.py compute the MD5
#: those RFCs require, over published test secrets and with
#: ``usedforsecurity=False``, to verify captured traffic; NTP and STUN
#: MACs will do the same. The query reads a variable named like a
#: secret or password as sensitive data and flags every one of them
#: (#265), so its findings there are noise; in src/ they would not be.
RULE_ID = "py/weak-sensitive-data-hashing"
#: Repository-relative directories, each with its trailing slash so
#: that ``tests_more/`` or ``scriptsfoo.py`` cannot match.
PATH_PREFIXES = ("tests/", "scripts/")

#: The base id CodeQL gives every source location (``"uri":
#: "tests/test_radius.py", "uriBaseId": "%SRCROOT%"``), with no
#: ``originalUriBaseIds`` entry: the root of the analyzed checkout.
SOURCE_ROOT_BASE_ID = "%SRCROOT%"
SARIF_VERSION = "2.1.0"


class MalformedSarifError(ValueError):
    """The SARIF is not shaped as CodeQL writes it."""


def _object(value: object, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MalformedSarifError(f"{where} is not an object")
    return value


def _optional(parent: dict[str, Any], key: str, where: str) -> Any:
    """``parent[key]``, or ``None`` if absent; present but null is an
    error, since SARIF omits a property rather than nulling it."""
    if key in parent and parent[key] is None:
        raise MalformedSarifError(f"{where}.{key} is null")
    return parent.get(key)


def _resolve_base(
    base_id: str, base_ids: dict[str, Any], seen: frozenset[str]
) -> str | None:
    """The absolute URI a ``uriBaseId`` stands for, following
    ``originalUriBaseIds`` (SARIF §3.14.14) through any chain of base
    ids; ``""`` (relative to the checkout) for an undefined
    ``%SRCROOT%``; ``None`` for any other undefined id, or a cycle."""
    if base_id in seen:
        return None
    if base_id not in base_ids:
        return "" if base_id == SOURCE_ROOT_BASE_ID else None
    entry = _object(base_ids[base_id], f"originalUriBaseIds[{base_id!r}]")
    uri = _optional(entry, "uri", f"originalUriBaseIds[{base_id!r}]")
    if uri is None:
        return None
    if not isinstance(uri, str):
        raise MalformedSarifError(
            f"originalUriBaseIds[{base_id!r}].uri is not a string"
        )
    parent = _optional(entry, "uriBaseId", f"originalUriBaseIds[{base_id!r}]")
    if parent is None:
        return uri if uri.endswith("/") else uri + "/"
    if not isinstance(parent, str):
        raise MalformedSarifError(
            f"originalUriBaseIds[{base_id!r}].uriBaseId is not a string"
        )
    base = _resolve_base(parent, base_ids, seen | {base_id})
    if base is None:
        return None
    joined = urljoin(base, uri)
    return joined if joined.endswith("/") else joined + "/"


def repository_path(
    artifact_location: dict[str, Any], base_ids: dict[str, Any], root: str
) -> str | None:
    """The repository-relative POSIX path an ``artifactLocation`` names,
    or ``None`` if it names nothing inside ``root`` this can be sure of.

    Accepts what CodeQL writes (a relative, percent-encoded ``uri`` with
    ``uriBaseId`` ``%SRCROOT%``) and what SARIF otherwise allows: no
    ``uriBaseId``, a leading ``./``, a base id defined by the run's
    ``originalUriBaseIds``, and an absolute ``file:`` URI, which must
    lie under ``root`` (the checkout) to count.
    """
    uri = artifact_location.get("uri")
    if uri is None:
        return None
    if not isinstance(uri, str):
        raise MalformedSarifError("artifactLocation.uri is not a string")
    base_id = artifact_location.get("uriBaseId")
    if base_id is not None and not isinstance(base_id, str):
        raise MalformedSarifError("artifactLocation.uriBaseId is not a string")

    if base_id is not None:
        base = _resolve_base(base_id, base_ids, frozenset())
        if base is None:
            return None  # relative to somewhere this run doesn't say
        uri = urljoin(base, uri)

    parts = urlsplit(uri)
    if parts.scheme not in ("", "file"):
        return None  # http:, or anything else that is not a local file
    if parts.netloc not in ("", "localhost"):
        return None  # a file on another host
    path = posixpath.normpath(unquote(parts.path))
    if posixpath.isabs(path):
        path = posixpath.relpath(path, posixpath.normpath(root))
    if path in (".", "..") or path.startswith("../"):
        return None
    return path


def _primary_artifact_location(
    result: dict[str, Any], where: str
) -> dict[str, Any] | None:
    locations = _optional(result, "locations", where)
    if locations is None:
        return None
    if not isinstance(locations, list):
        raise MalformedSarifError(f"{where}.locations is not a list")
    if not locations:
        return None
    location = _object(locations[0], f"{where}.locations[0]")
    physical = _optional(location, "physicalLocation", f"{where}.locations[0]")
    if physical is None:
        return None
    physical = _object(physical, f"{where}.locations[0].physicalLocation")
    artifact = _optional(
        physical, "artifactLocation", f"{where}.locations[0].physicalLocation"
    )
    if artifact is None:
        return None
    return _object(
        artifact, f"{where}.locations[0].physicalLocation.artifactLocation"
    )


def _rule_id(result: dict[str, Any], where: str) -> str | None:
    """``ruleId``, or ``rule.id`` when a producer gives only that
    (SARIF §3.27.5 allows either)."""
    rule = _optional(result, "rule", where)
    rule = {} if rule is None else _object(rule, f"{where}.rule")
    rule_id = _optional(result, "ruleId", where)
    if rule_id is None:
        rule_id = rule.get("id")
    if rule_id is not None and not isinstance(rule_id, str):
        raise MalformedSarifError(f"{where}.ruleId is not a string")
    return rule_id


def _line(result: dict[str, Any]) -> str:
    """``:N`` for the primary location's start line, if it has one."""
    try:
        line = result["locations"][0]["physicalLocation"]["region"]["startLine"]
    except (KeyError, IndexError, TypeError):
        return ""
    return f":{line}" if isinstance(line, int) else ""


def filter_log(log: object, root: str) -> list[str]:
    """Remove the filtered results from ``log`` in place; return
    ``path:line`` for each one removed, in order."""
    sarif = _object(log, "the SARIF log")
    if sarif.get("version") != SARIF_VERSION:
        raise MalformedSarifError(
            f"version is {sarif.get('version')!r}, not {SARIF_VERSION!r}"
        )
    runs = sarif.get("runs")
    if not isinstance(runs, list) or not runs:
        raise MalformedSarifError("runs is missing, not a list, or empty")

    dropped: list[str] = []
    for i, raw_run in enumerate(runs):
        run = _object(raw_run, f"runs[{i}]")
        results = run.get("results")
        if not isinstance(results, list):
            raise MalformedSarifError(f"runs[{i}].results is not a list")
        base_ids = _optional(run, "originalUriBaseIds", f"runs[{i}]")
        if base_ids is None:
            base_ids = {}
        base_ids = _object(base_ids, f"runs[{i}].originalUriBaseIds")

        kept = []
        for j, raw_result in enumerate(results):
            where = f"runs[{i}].results[{j}]"
            result = _object(raw_result, where)
            rule_id = _rule_id(result, where)
            artifact = _primary_artifact_location(result, where)
            path = (
                None
                if artifact is None
                else repository_path(artifact, base_ids, root)
            )
            if (
                rule_id == RULE_ID
                and path is not None
                and path.startswith(PATH_PREFIXES)
            ):
                dropped.append(f"{path}{_line(result)}")
            else:
                kept.append(raw_result)
        if len(kept) != len(results):
            run["results"] = kept
    return dropped


def sarif_files(paths: list[Path]) -> list[Path]:
    """Each file given, and every ``*.sarif`` directly in each directory
    given; a directory with none is an error, not an empty upload."""
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            found = sorted(path.glob("*.sarif"))
            if not found:
                raise MalformedSarifError(f"{path}: no *.sarif file in it")
            files += found
        elif path.is_file():
            files.append(path)
        else:
            raise MalformedSarifError(f"{path}: no such file or directory")
    return files


def filter_file(path: Path, root: str) -> str:
    """Filter one SARIF file in place; the summary line for it."""
    try:
        log = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MalformedSarifError(f"{path}: not JSON: {error}") from error
    try:
        dropped = filter_log(log, root)
    except MalformedSarifError as error:
        raise MalformedSarifError(f"{path}: {error}") from error
    if dropped:
        path.write_text(
            json.dumps(log, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    where = ", ".join(PATH_PREFIXES)
    summary = (
        f"{path.name}: dropped {len(dropped)} {RULE_ID} result(s) under {where}"
    )
    return summary + (f": {', '.join(dropped)}" if dropped else "")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "sarif",
        type=Path,
        nargs="+",
        help="a SARIF file, or a directory of *.sarif files",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path.cwd(),
        help="the checkout that absolute file: URIs are matched against "
        "(default: the working directory)",
    )
    args = parser.parse_args(argv)
    root = os.path.abspath(args.source_root)

    try:
        for path in sarif_files(args.sarif):
            print(filter_file(path, root))
    except (MalformedSarifError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
