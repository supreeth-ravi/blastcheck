import json

import pytest

from blastcheck import parsers


def by_name(deps):
    return {d.name: d for d in deps}


def test_requirements_pinned_loose_and_skipped_lines():
    text = """
# comment
-r base.txt
Flask_Login==0.6.3
requests>=2.31,<3  # inline
uvicorn[standard]~=0.30.0 ; python_version > "3.9"
barepackage
git+https://example.test/pkg.git
localpkg @ file:///tmp/localpkg
"""
    deps = by_name(parsers.parse("api/requirements-dev.txt", text))
    assert set(deps) == {"flask-login", "requests", "uvicorn", "barepackage"}
    assert deps["flask-login"].exact and deps["flask-login"].version == "0.6.3"
    assert not deps["requests"].exact and deps["requests"].spec == ">=2.31,<3"
    assert deps["uvicorn"].spec == "~=0.30.0"
    assert deps["barepackage"].spec == "" and deps["barepackage"].version is None


def test_pyproject_pep621_groups_and_poetry():
    text = """
[project]
dependencies = ["agent-framework>=1.26", "httpx==0.27.0"]
[project.optional-dependencies]
dev = ["pytest"]
[dependency-groups]
lint = ["ruff>=0.5", {include-group = "dev"}]
[tool.poetry.dependencies]
python = "^3.11"
pendulum = "^3.0"
pinned = "2.1.0"
fromgit = { git = "https://example.test/x.git" }
tabled = { version = "~1.4", optional = true }
"""
    deps = by_name(parsers.parse("pyproject.toml", text))
    assert deps["agent-framework"].spec == ">=1.26" and not deps["agent-framework"].exact
    assert deps["httpx"].exact
    assert {"pytest", "ruff", "pendulum", "pinned", "tabled"} <= set(deps)
    assert "fromgit" not in deps and "python" not in deps
    assert deps["pinned"].exact and deps["pinned"].version == "2.1.0"
    assert deps["pendulum"].spec == "^3.0"


def test_uv_and_poetry_lock():
    text = '[[package]]\nname = "Agent_Framework"\nversion = "1.26.0"\n\n[[package]]\nname = "anyio"\nversion = "4.9.0"\n'
    for name in ("uv.lock", "sub/poetry.lock"):
        deps = by_name(parsers.parse(name, text))
        assert deps["agent-framework"].version == "1.26.0" and deps["agent-framework"].exact


def test_pipfile_lock():
    text = json.dumps({"default": {"requests": {"version": "==2.32.0"}}, "develop": {"pytest": {"version": "==8.0.0"}}})
    deps = by_name(parsers.parse("Pipfile.lock", text))
    assert deps["requests"].version == "2.32.0" and deps["pytest"].exact


def test_package_json_ranges_and_exact():
    text = json.dumps({"dependencies": {"left-pad": "^1.3.0", "exact-pkg": "2.0.1", "@scope/thing": "~0.4.0"},
                       "devDependencies": {"local": "workspace:*"}})
    deps = by_name(parsers.parse("web/package.json", text))
    assert not deps["left-pad"].exact and deps["left-pad"].spec == "^1.3.0"
    assert deps["exact-pkg"].exact and deps["exact-pkg"].version == "2.0.1"
    assert deps["@scope/thing"].spec == "~0.4.0"
    assert deps["local"].spec == "workspace:*"


def test_package_lock_v3_and_v1():
    v3 = json.dumps({"packages": {"": {"name": "app"}, "node_modules/left-pad": {"version": "1.3.0"},
                                  "node_modules/a/node_modules/@scope/thing": {"version": "0.4.2"},
                                  "node_modules/linked": {"link": True}}})
    deps = by_name(parsers.parse("package-lock.json", v3))
    assert deps["left-pad"].version == "1.3.0" and deps["@scope/thing"].version == "0.4.2"
    assert "linked" not in deps
    v1 = json.dumps({"dependencies": {"left-pad": {"version": "1.3.0", "dependencies": {"inner": {"version": "0.1.0"}}}}})
    assert set(by_name(parsers.parse("package-lock.json", v1))) == {"left-pad", "inner"}


def test_yarn_lock_classic_and_berry():
    classic = 'left-pad@^1.3.0:\n  version "1.3.0"\n\n"@scope/thing@~0.4.0", "@scope/thing@^0.4.1":\n  version "0.4.2"\n'
    deps = by_name(parsers.parse("yarn.lock", classic))
    assert deps["left-pad"].version == "1.3.0" and deps["@scope/thing"].version == "0.4.2"
    berry = '"left-pad@npm:^1.3.0":\n  version: 1.3.0\n'
    assert by_name(parsers.parse("yarn.lock", berry))["left-pad"].version == "1.3.0"


def test_pnpm_lock_old_and_new_keys():
    text = "packages:\n\n  /left-pad@1.3.0:\n    resolution: {}\n\n  '@scope/thing@0.4.2(peer@1.0.0)':\n    resolution: {}\n\n  /older/2.0.0:\n    resolution: {}\n"
    deps = by_name(parsers.parse("pnpm-lock.yaml", text))
    assert deps["left-pad"].version == "1.3.0"
    assert deps["@scope/thing"].version == "0.4.2"
    assert deps["older"].version == "2.0.0"


def test_go_cargo_and_pom():
    go = "module example.test/app\n\nrequire (\n\tgolang.org/x/crypto v0.36.0\n\texample.test/lib v2.0.0+incompatible // indirect\n)\n"
    deps = by_name(parsers.parse("go.mod", go))
    assert deps["golang.org/x/crypto"].version == "0.36.0" and deps["example.test/lib"].version == "2.0.0"
    cargo = '[[package]]\nname = "serde"\nversion = "1.0.200"\n'
    assert by_name(parsers.parse("Cargo.lock", cargo))["serde"].exact
    pom = "<project><dependencies><dependency><groupId>org.example</groupId><artifactId>lib</artifactId><version>1.2.3</version></dependency><dependency><groupId>org.example</groupId><artifactId>managed</artifactId><version>${lib.version}</version></dependency></dependencies></project>"
    deps = by_name(parsers.parse("pom.xml", pom))
    assert deps["org.example:lib"].exact and not deps["org.example:managed"].exact


@pytest.mark.parametrize("path,expected", [
    ("requirements.txt", True), ("deploy/requirements-prod.txt", True), ("requirements.in", True),
    ("node_modules/x/package.json", False), ("svc/.venv/lib/requirements.txt", False),
    ("README.md", False), ("src/app.py", False), ("svc/.tox/py/requirements.txt", False),
    ("requirements/prod.txt", True), ("dev-requirements.txt", True), ("test_requirements.txt", True),
    ("tools/build/package.json", True), ("src/dist/requirements.txt", True), ("constraints.txt", True),
    ("setup.py", True), ("setup.cfg", True), ("Pipfile", True), ("Cargo.toml", True), ("bun.lock", False),
])
def test_which_files_are_read(path, expected):
    assert parsers.is_dependency_file(path) is expected


@pytest.mark.parametrize("path,text", [
    ("package.json", "{not json"), ("uv.lock", "[[package\nname ="), ("Pipfile.lock", "[]"),
])
def test_malformed_files_raise_so_they_can_be_reported(path, text):
    with pytest.raises(Exception):
        parsers.parse(path, text)
