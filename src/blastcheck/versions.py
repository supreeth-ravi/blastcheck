"""Version comparison and "would this specifier accept that version?" checks.

Deliberately small: enough of PEP 440 and npm semver to decide whether a loose pin could
have pulled in a known-bad release. The rule throughout is to fail open: whenever a
specifier or version is too unusual to reason about (pre-releases, epochs, dist-tags,
anything unparseable), the answer is "yes, it could", so the repo is flagged for a human
instead of being cleared.
"""
from __future__ import annotations

import re

_VERSION = re.compile(r"^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(.*)$")
_CLAUSE = re.compile(r"^(===|==|!=|~=|>=|<=|>|<|\^|~|=)?\s*(.*)$")
_NPM_ANY = {"", "*", "x", "X", "latest"}
_NOT_FROM_REGISTRY = ("git+", "git:", "git@", "http:", "https:", "file:", "link:", "workspace:", "github:",
                      "portal:", "patch:", "/", "./", "../")
Release = tuple[int, ...]


def _parts(version: str) -> tuple[int, Release, str] | None:
    """(epoch, release numbers, normalised suffix) or None when not a version at all."""
    match = _VERSION.match(version.strip())
    if not match:
        return None
    release = tuple(int(part) for part in match.group(2).split("."))
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]
    suffix = re.sub(r"[-._]", "", match.group(3).split("+")[0]).lower()
    return int(match.group(1) or 0), release, suffix


def release(version: str) -> Release:
    parts = _parts(version)
    return parts[1] if parts else ()


def is_plain(version: str) -> bool:
    """True for an ordinary final release such as 1.26.2: no epoch, no pre/post/dev tag."""
    parts = _parts(version)
    return parts is not None and parts[0] == 0 and parts[2] == ""


def same(left: str, right: str) -> bool:
    """Exact equality, ignoring trailing zeros, a leading v, separators and local labels."""
    a, b = _parts(left), _parts(right)
    return a is not None and a == b


def _pad(numbers: Release, width: int) -> Release:
    return numbers + (0,) * (width - len(numbers))


def _lt(left: Release, right: Release) -> bool:
    width = max(len(left), len(right))
    return _pad(left, width) < _pad(right, width)


def _between(version: str, low: Release, high: Release | None) -> bool:
    numbers = release(version)
    return not _lt(numbers, low) and (high is None or _lt(numbers, high))


def _bump(numbers: Release, index: int) -> Release:
    padded = _pad(numbers, index + 1)
    return padded[:index] + (padded[index] + 1,)


def _caret_upper(given: Release) -> Release:
    """^1.2.3 -> 2, ^0.2.3 -> 0.3, ^0.0.3 -> 0.0.4, ^0 -> 1, ^0.0 -> 0.1."""
    for index, value in enumerate(given):
        if value != 0:
            return _bump(given, index)
    return _bump(given, len(given) - 1)


def _tilde_upper(given: Release) -> Release:
    return _bump(given, 0) if len(given) == 1 else _bump(given, 1)


def _target_numbers(target: str) -> tuple[Release, bool] | None:
    """Leading numeric parts of a possibly partial target ("1.2.x" -> (1, 2)), and whether a
    pre-release or other tag follows. None when the target is not version-like."""
    match = re.match(r"^v?(\d+(?:\.\d+)*)?((?:\.[xX*])*)(.*)$", target.strip())
    if not match or (not match.group(1) and not match.group(2) and target.strip() not in _NPM_ANY):
        return None
    numbers = tuple(int(p) for p in match.group(1).split(".")) if match.group(1) else ()
    return numbers, bool(match.group(3))


def _pypi_clause(clause: str, version: str) -> bool:
    clause = clause.strip()
    if not clause:
        return True
    operator, target = _CLAUSE.match(clause).groups()  # type: ignore[union-attr]
    operator, target = operator or "==", target.strip()
    wildcard = re.sub(r"\.?\*$", "", target) if target.endswith("*") else None
    if operator in ("==", "===", "=", "!="):
        if wildcard is not None:
            prefix = tuple(int(number) for number in re.findall(r"\d+", wildcard))
            hit = _pad(release(version), len(prefix))[: len(prefix)] == prefix
        elif _parts(target) is None:
            return True
        else:
            hit = same(version, target)
        return not hit if operator == "!=" else hit
    if not is_plain(target) or not is_plain(version):
        return True  # ordering around pre-releases, post-releases and epochs: flag, do not clear
    low = release(target)
    if operator == ">=":
        return _between(version, low, None)
    if operator == "<":
        return _lt(release(version), low)
    if operator == ">":
        return _lt(low, release(version))
    if operator == "<=":
        return not _lt(low, release(version))
    given = tuple(int(p) for p in re.match(r"^v?(\d+(?:\.\d+)*)", target).group(1).split("."))  # type: ignore[union-attr]
    if operator == "~=":
        return len(given) < 2 or _between(version, given, _bump(given[:-1], len(given) - 2))
    if operator == "^":
        return _between(version, given, _caret_upper(given))
    return _between(version, given, _tilde_upper(given))  # "~"


def _npm_clause(clause: str, version: str) -> bool:
    operator, target = _CLAUSE.match(clause.strip()).groups()  # type: ignore[union-attr]
    operator = operator or "="
    parsed = _target_numbers(target)
    if parsed is None:
        return True  # a dist-tag such as "next" can point at any version
    given, tagged = parsed
    full = len(given) >= 3
    if operator in ("=", "==", "===") and full:
        return same(version, target)
    if tagged or not is_plain(version):
        return True
    if not given:
        return True
    upper = _bump(given, len(given) - 1)
    if operator in ("=", "==", "==="):
        return _between(version, given, upper)
    if operator == "^":
        return _between(version, given, _caret_upper(given))
    if operator in ("~", "~="):
        return _between(version, given, _tilde_upper(given))
    if operator == ">=":
        return _between(version, given, None)
    if operator == "<":
        return _lt(release(version), given)
    if operator == ">":
        return _lt(given, release(version)) if full else _between(version, upper, None)
    if operator == "<=":
        return not _lt(given, release(version)) if full else _lt(release(version), upper)
    return True


def _npm_accepts(spec: str, version: str) -> bool:
    if spec in _NPM_ANY:
        return True
    if spec.startswith(_NOT_FROM_REGISTRY):
        return False
    for alternative in spec.split("||"):
        alternative = alternative.strip()
        hyphen = re.match(r"^(\S+)\s+-\s+(\S+)$", alternative)
        if hyphen:
            if _npm_clause(f">={hyphen.group(1)}", version) and _npm_clause(f"<={hyphen.group(2)}", version):
                return True
            continue
        clauses = re.sub(r"([<>=^~])\s+", r"\1", alternative).split()
        if all(_npm_clause(clause, version) for clause in clauses):
            return True
    return False


def in_range(version: str, introduced: str, upper: str, upper_inclusive: bool) -> bool:
    """True when `version` lies in [introduced, upper). Unusual versions fail open (True)."""
    if not is_plain(version) or not is_plain(introduced) or (upper and not is_plain(upper)):
        return True
    numbers = release(version)
    if _lt(numbers, release(introduced)):
        return False
    if not upper:
        return True
    return not _lt(release(upper), numbers) if upper_inclusive else _lt(numbers, release(upper))


def accepts(ecosystem: str, spec: str, version: str) -> bool:
    """True when installing with `spec` could resolve to `version`."""
    spec = (spec or "").strip()
    if ecosystem == "npm":
        return _npm_accepts(spec, version)
    if spec.startswith(_NOT_FROM_REGISTRY):
        return False
    return all(_pypi_clause(clause, version) for clause in spec.split(","))
