"""Python dependency files: requirements, pyproject, setup.cfg/py, Pipfile, and the lock files."""
from __future__ import annotations

import configparser
import json
import re
import tomllib

from ..models import Dep

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([^;#]*)")
_EXACT = re.compile(r"^={2,3}\s*([0-9][^\s,;*]*)$")
_OPTION = re.compile(r"\s--[A-Za-z][\w-]*(=\S+|\s+\S+)?")
_SKIP_PREFIXES = ("#", "-", "git+", "http:", "https:", ".", "/")
_SETUP_LITERAL = re.compile(r"""["']([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]"']*\])?\s*(?:[=<>!~]=?[^"';]*)?)(?:;[^"']*)?["']""")


def normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _dep(file: str, name: str, spec: str) -> Dep:
    spec = spec.strip()
    exact = _EXACT.match(spec)
    version = exact.group(1) if exact else None
    return Dep(file=file, ecosystem="PyPI", name=normalise(name), version=version, spec=spec, exact=bool(exact))


def _logical_lines(text: str) -> list[str]:
    """Join backslash continuations, as pip does (hash-pinned files use them on every entry)."""
    return re.sub(r"\\\r?\n", " ", text).splitlines()


def parse_requirement_lines(file: str, lines: list[str]) -> list[Dep]:
    deps = []
    for raw in lines:
        line = re.split(r"\s#", raw, maxsplit=1)[0].strip()
        if not line or line.startswith(_SKIP_PREFIXES):
            continue
        if " @ " in line:  # direct URL reference, not resolved from the index
            continue
        line = _OPTION.sub(" ", " " + line).strip()  # drop per-line options such as --hash=...
        match = _REQ_LINE.match(line)
        if match:
            deps.append(_dep(file, match.group(1), match.group(3) or ""))
    return deps


def parse_requirements(file: str, text: str) -> list[Dep]:
    lines = _logical_lines(text)
    deps = parse_requirement_lines(file, lines)
    candidates = [line for line in lines if line.strip() and not line.strip().startswith(_SKIP_PREFIXES)]
    if candidates and not deps:
        raise ValueError("no requirement lines recognised in a non-empty file")
    return deps


def _poetry_entry(file: str, name: str, value: object) -> list[Dep]:
    if isinstance(value, list):  # multiple-constraint form: one dict per environment
        return [dep for item in value for dep in _poetry_entry(file, name, item)]
    if isinstance(value, dict):
        if any(key in value for key in ("git", "path", "url")):
            return []
        value = value.get("version", "")
    if not isinstance(value, str):
        return []
    spec = f"=={value}" if re.match(r"^\d", value) else value
    return [_dep(file, name, "" if spec.strip() == "*" else spec)]


def _poetry_tables(poetry: dict) -> list[dict]:
    tables = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
    tables.extend(group.get("dependencies", {}) for group in poetry.get("group", {}).values())
    return tables


def parse_pyproject(file: str, text: str) -> list[Dep]:
    data = tomllib.loads(text)
    project, tool = data.get("project", {}), data.get("tool", {})
    specs = list(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        specs.extend(group)
    for group in data.get("dependency-groups", {}).values():
        specs.extend(item for item in group if isinstance(item, str))
    specs.extend(data.get("build-system", {}).get("requires", []))
    specs.extend(tool.get("uv", {}).get("dev-dependencies", []))
    specs.extend(tool.get("uv", {}).get("constraint-dependencies", []))
    for group in tool.get("pdm", {}).get("dev-dependencies", {}).values():
        specs.extend(item for item in group if isinstance(item, str))
    deps = parse_requirement_lines(file, [s for s in specs if isinstance(s, str)])

    for table in _poetry_tables(tool.get("poetry", {})):
        for name, value in table.items():
            if name.lower() != "python":
                deps.extend(_poetry_entry(file, name, value))
    return deps


def parse_setup_cfg(file: str, text: str) -> list[Dep]:
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(text)
    lines: list[str] = []
    if config.has_section("options"):
        for key in ("install_requires", "setup_requires", "tests_require"):
            lines.extend(config.get("options", key, fallback="").splitlines())
    if config.has_section("options.extras_require"):
        for _, value in config.items("options.extras_require"):
            lines.extend(value.splitlines())
    return parse_requirement_lines(file, lines)


def parse_setup_py(file: str, text: str) -> list[Dep]:
    """Best effort without running the file: every string literal that looks like a requirement.

    This over-collects (a literal such as "name" becomes a dependency called name). That is the
    safe direction: an extra entry can only cause a flag for review, never clear a repo.
    """
    return parse_requirement_lines(file, [match.group(1) for match in _SETUP_LITERAL.finditer(text)])


def parse_pipfile(file: str, text: str) -> list[Dep]:
    data = tomllib.loads(text)
    deps = []
    for section in ("packages", "dev-packages"):
        for name, value in data.get(section, {}).items():
            deps.extend(_poetry_entry(file, name, value))
    return deps


def parse_conda_env(file: str, text: str) -> list[Dep]:
    """Conda environment.yml, read line by line (no YAML library needed).

    Entries under `- pip:` are ordinary requirement lines. Conda entries (`name=1.2=build`) are
    recorded under the same name on PyPI, since most Python packages share it; conda's single
    `=` is a prefix match, so `name=1.2` becomes `==1.2.*`.
    """
    lines: list[str] = []
    in_dependencies = False
    pip_indent: int | None = None
    for raw in text.splitlines():
        stripped = raw.split(" #")[0].rstrip()
        if not stripped.strip() or stripped.lstrip().startswith("#"):
            continue
        indent = len(stripped) - len(stripped.lstrip())
        if indent == 0 and not stripped.startswith("-"):
            in_dependencies = stripped.startswith("dependencies:")
            pip_indent = None
            continue
        item = re.match(r"^\s*-\s+(.*)$", stripped)
        if not in_dependencies or not item:
            continue
        value = item.group(1).strip().strip("'\"")
        if pip_indent is not None and indent > pip_indent:
            lines.append(value)
            continue
        pip_indent = None
        if value.rstrip(":") == "pip" and value.endswith(":"):
            pip_indent = indent
            continue
        value = value.split("::")[-1]  # drop a channel prefix such as conda-forge::
        conda = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*([0-9][^=\s]*)(=.*)?$", value)
        if conda and "==" not in value:
            pinned_build = bool(conda.group(3))
            lines.append(f"{conda.group(1)}=={conda.group(2)}" + ("" if pinned_build else ".*"))
        else:
            lines.append(value)
    deps = parse_requirement_lines(file, lines)
    if lines and not deps:
        raise ValueError("environment file has dependencies but none could be read")
    return deps


def parse_toml_lock(file: str, text: str) -> list[Dep]:
    data = tomllib.loads(text)
    deps = [
        Dep(file=file, ecosystem="PyPI", name=normalise(pkg["name"]), version=str(pkg["version"]),
            spec=f"=={pkg['version']}", exact=True)
        for pkg in data.get("package", [])
        if pkg.get("name") and pkg.get("version")
    ]
    if not deps and "[[package]]" in text:
        raise ValueError("lock file has package entries but none could be read")
    return deps


def parse_pipfile_lock(file: str, text: str) -> list[Dep]:
    data = json.loads(text)
    deps = []
    for section in ("default", "develop"):
        for name, meta in data.get(section, {}).items():
            spec = meta.get("version", "") if isinstance(meta, dict) else ""
            deps.append(_dep(file, name, spec))
    return deps
