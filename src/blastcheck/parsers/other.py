"""Go, Rust and Maven dependency files."""
from __future__ import annotations

import re
import tomllib

from ..models import Dep


def parse_go_mod(file: str, text: str) -> list[Dep]:
    pattern = re.compile(r"^\s*(?:require\s+)?([\w.\-]+\.[\w.\-/]+)\s+v(\d\S*)", re.M)
    deps = []
    for name, version in pattern.findall(text):
        version = version.replace("+incompatible", "")
        deps.append(Dep(file=file, ecosystem="Go", name=name, version=version, spec=version, exact=True))
    return deps


def parse_cargo_lock(file: str, text: str) -> list[Dep]:
    data = tomllib.loads(text)
    return [
        Dep(file=file, ecosystem="crates.io", name=pkg["name"], version=pkg["version"], spec=pkg["version"], exact=True)
        for pkg in data.get("package", [])
        if pkg.get("name") and pkg.get("version")
    ]


def parse_cargo_toml(file: str, text: str) -> list[Dep]:
    """Declared crates. A bare "1.2" in Cargo means ^1.2, so it is recorded as a caret range."""
    data = tomllib.loads(text)
    tables = [data.get(key, {}) for key in ("dependencies", "dev-dependencies", "build-dependencies")]
    tables.append(data.get("workspace", {}).get("dependencies", {}))
    for target in data.get("target", {}).values():
        if isinstance(target, dict):
            tables.extend(target.get(key, {}) for key in ("dependencies", "dev-dependencies", "build-dependencies"))
    deps = []
    for table in tables:
        for name, value in table.items():
            if isinstance(value, dict):
                if any(key in value for key in ("path", "git")) and "version" not in value:
                    continue
                name, value = value.get("package", name), value.get("version", "")
            if not isinstance(value, str):
                continue
            spec = value.strip()
            exact = spec.startswith("=") and not spec.startswith("==")
            if re.match(r"^\d", spec):
                spec = f"^{spec}"
            deps.append(Dep(file=file, ecosystem="crates.io", name=name, version=spec.lstrip("= ") if exact else None,
                            spec=spec, exact=exact))
    return deps


def parse_pom(file: str, text: str) -> list[Dep]:
    pattern = re.compile(
        r"<dependency>.*?<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>"
        r"(?:\s*<version>([^<]+)</version>)?",
        re.S,
    )
    deps = []
    for group, artifact, version in pattern.findall(text):
        version = version.strip()
        exact = bool(version) and "$" not in version and not version.startswith(("[", "("))
        deps.append(Dep(file=file, ecosystem="Maven", name=f"{group.strip()}:{artifact.strip()}",
                        version=version if exact else None, spec=version, exact=exact))
    return deps
