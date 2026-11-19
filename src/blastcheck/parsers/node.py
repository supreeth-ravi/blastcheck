"""JavaScript dependency files: package.json and the npm, yarn and pnpm locks."""
from __future__ import annotations

import json
import re

from ..models import Dep

_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_EXACT = re.compile(r"^v?\d+\.\d+\.\d+[^\s|<>^~*xX]*$")
_ALIAS = re.compile(r"^npm:(@?[^@]+)@?(.*)$")


def _locked(file: str, name: str, version: str) -> Dep:
    return Dep(file=file, ecosystem="npm", name=name, version=version, spec=version, exact=True)


def _declared(file: str, name: str, spec: str) -> Dep:
    """A dependency as written in package.json. `npm:real@range` aliases resolve to the real name."""
    spec = spec.strip()
    alias = _ALIAS.match(spec)
    if alias:
        name, spec = alias.group(1), alias.group(2).strip()
    exact = bool(_EXACT.match(spec))
    return Dep(file=file, ecosystem="npm", name=name, version=spec.lstrip("v") if exact else None, spec=spec, exact=exact)


def _flatten_overrides(file: str, table: object, out: list[Dep]) -> None:
    """npm `overrides` nest; yarn `resolutions` use path-like keys. Keep the last name segment."""
    if not isinstance(table, dict):
        return
    for key, value in table.items():
        if isinstance(value, dict):
            _flatten_overrides(file, value, out)
        elif isinstance(value, str) and key != ".":
            name = re.sub(r"@[^@/]*$", "", key.split("/**/")[-1].split(">")[-1].strip()) or key
            if "/" in name and not name.startswith("@"):
                name = name.split("/")[-1]
            out.append(_declared(file, name, value))


def parse_package_json(file: str, text: str) -> list[Dep]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("package.json is not a JSON object")
    deps: list[Dep] = []
    for section in _SECTIONS:
        for name, spec in (data.get(section) or {}).items():
            if isinstance(spec, str):
                deps.append(_declared(file, name, spec))
    _flatten_overrides(file, data.get("overrides"), deps)
    _flatten_overrides(file, data.get("resolutions"), deps)
    _flatten_overrides(file, (data.get("pnpm") or {}).get("overrides"), deps)
    return deps


def _walk_v1(file: str, tree: dict | None, out: list[Dep]) -> None:
    for name, meta in (tree or {}).items():
        if not isinstance(meta, dict):
            continue
        version = str(meta.get("version", ""))
        alias = _ALIAS.match(version)
        if alias:
            out.append(_locked(file, alias.group(1), alias.group(2)))
        elif re.match(r"^\d", version):
            out.append(_locked(file, name, version))
        _walk_v1(file, meta.get("dependencies"), out)


def parse_package_lock(file: str, text: str) -> list[Dep]:
    data = json.loads(text)
    deps: list[Dep] = []
    for path, meta in (data.get("packages") or {}).items():
        if "node_modules/" not in path or meta.get("link") or not meta.get("version"):
            continue
        # An aliased install lives under the alias folder but records the real package in "name".
        deps.append(_locked(file, meta.get("name") or path.split("node_modules/")[-1], str(meta["version"])))
    if not deps:
        _walk_v1(file, data.get("dependencies"), deps)
    return deps


def parse_yarn_lock(file: str, text: str) -> list[Dep]:
    deps = []
    names: list[str] = []
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")):
            names = []
            for descriptor in line.rstrip(":").split(","):
                descriptor = descriptor.strip().strip('"')
                alias = re.match(r"^@?[^@]+@npm:(@?[^@]+)@", descriptor)  # "alias@npm:real@range"
                plain = re.match(r"^(@?[^@]+)@", descriptor)
                if alias or plain:
                    names.append((alias or plain).group(1))  # type: ignore[union-attr]
            continue
        version = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
        if version and names:
            deps.extend(_locked(file, name, version.group(1)) for name in dict.fromkeys(names))
            names = []
    if not deps and re.search(r"^\s+version", text, re.M):
        raise ValueError("yarn.lock has entries but none could be read")
    return deps


def parse_pnpm_lock(file: str, text: str) -> list[Dep]:
    pattern = re.compile(r"^\s{2}'?/?(@[^/@'\s]+/[^@'\s:(]+|[^@/'\s:(]+)[@/](\d[^:'(\s]*)", re.M)
    deps = [_locked(file, name, version) for name, version in pattern.findall(text)]
    if not deps and "resolution:" in text:
        raise ValueError("pnpm-lock.yaml has entries but none could be read")
    return deps
