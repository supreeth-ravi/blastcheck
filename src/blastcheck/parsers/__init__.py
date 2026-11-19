"""Pick the right parser for a dependency file. Parsing never executes repo content."""
from __future__ import annotations

import posixpath
import re
from collections.abc import Callable

from ..models import Dep
from . import node, other, python

Parser = Callable[[str, str], list[Dep]]

# Bump whenever a parser changes what it extracts, so cached inventories are rebuilt.
PARSER_VERSION = 3

_BY_NAME: dict[str, Parser] = {
    "pyproject.toml": python.parse_pyproject,
    "setup.cfg": python.parse_setup_cfg,
    "setup.py": python.parse_setup_py,
    "Pipfile": python.parse_pipfile,
    "environment.yml": python.parse_conda_env,
    "environment.yaml": python.parse_conda_env,
    "uv.lock": python.parse_toml_lock,
    "poetry.lock": python.parse_toml_lock,
    "pdm.lock": python.parse_toml_lock,
    "Pipfile.lock": python.parse_pipfile_lock,
    "package.json": node.parse_package_json,
    "package-lock.json": node.parse_package_lock,
    "npm-shrinkwrap.json": node.parse_package_lock,
    "yarn.lock": node.parse_yarn_lock,
    "pnpm-lock.yaml": node.parse_pnpm_lock,
    "go.mod": other.parse_go_mod,
    "Cargo.toml": other.parse_cargo_toml,
    "Cargo.lock": other.parse_cargo_lock,
    "pom.xml": other.parse_pom,
}
# requirements.txt, requirements-dev.txt, dev-requirements.txt, requirements.in, constraints.txt ...
_REQUIREMENTS_NAME = re.compile(r"^(.*[-_.])?(requirements|constraints)([-_.].*)?\.(txt|in)$", re.I)
# ... and any .txt/.in file inside a requirements/ folder, e.g. requirements/prod.txt
_REQUIREMENTS_DIR = re.compile(r"(^|/)requirements/[^/]+\.(txt|in)$", re.I)
# Only folders that hold installed third-party code. Folders such as build/ or dist/ can be
# real source folders, so they are read: reading too much can only add flags, never hide one.
_SKIP_DIRS = re.compile(r"(^|/)(node_modules|\.venv|venv|site-packages|\.tox|\.git)/")

# Which lock files pin which manifest. A requirements file is never protected by a lock:
# `pip install -r` does not read one.
LOCKS_FOR: dict[str, frozenset[str]] = {
    "pyproject.toml": frozenset({"uv.lock", "poetry.lock", "pdm.lock"}),
    "Pipfile": frozenset({"Pipfile.lock"}),
    "package.json": frozenset({"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}),
    "Cargo.toml": frozenset({"Cargo.lock"}),
}
LOCK_FILES = frozenset().union(*LOCKS_FOR.values())

# Recognised but not parsed: their presence is reported so a clean verdict is not overstated.
UNSUPPORTED: dict[str, str] = {
    "bun.lock": "npm", "bun.lockb": "npm",
    "build.gradle": "Maven", "build.gradle.kts": "Maven",
    "conda-lock.yml": "PyPI",
}


def parser_for(path: str) -> Parser | None:
    if _SKIP_DIRS.search(path):
        return None
    name = posixpath.basename(path)
    if name in _BY_NAME:
        return _BY_NAME[name]
    if _REQUIREMENTS_NAME.match(name) or _REQUIREMENTS_DIR.search(path):
        return python.parse_requirements
    return None


def is_dependency_file(path: str) -> bool:
    return parser_for(path) is not None


def unsupported_ecosystem(path: str) -> str | None:
    """Ecosystem of a dependency file we recognise but cannot parse, else None."""
    return None if _SKIP_DIRS.search(path) else UNSUPPORTED.get(posixpath.basename(path))


def parse(path: str, text: str) -> list[Dep]:
    """Parse one file. Raises on malformed content so the caller can record it."""
    parser = parser_for(path)
    if parser is None:
        raise ValueError(f"no parser for {path}")
    if text.startswith("version https://git-lfs.github.com/spec/"):
        raise ValueError("file is a Git LFS pointer, not the real content")
    return parser(path, text)
