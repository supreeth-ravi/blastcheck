"""Cases found in code review where a repo could wrongly have been reported clean."""
import pytest

from blastcheck import matcher, parsers, report
from blastcheck.github import GitHubError, decode_text
from blastcheck.models import AFFECTED, AT_RISK, INCOMPLETE, NOT_USED, SAFE_VERSION, Incident, RepoInventory

from conftest import lock, repo

EVIL = Incident(package="evilpkg", ecosystem="PyPI", bad_versions=("1.0",))
EVIL_NPM = Incident(package="evilpkg", ecosystem="npm", bad_versions=("1.2.5",))


def verdict(incident, files, **kwargs):
    return matcher.match_repo(incident, repo("r", files, **kwargs)).verdict


def test_hash_pinned_requirements_keep_their_exact_pin():
    multi = "evilpkg==1.0 \\\n    --hash=sha256:aa \\\n    --hash=sha256:bb\nother==2.0 --hash=sha256:cc\n"
    deps = {d.name: d for d in parsers.parse("requirements.txt", multi)}
    assert deps["evilpkg"].exact and deps["evilpkg"].version == "1.0" and deps["other"].version == "2.0"
    assert verdict(EVIL, {"requirements.txt": multi, "uv.lock": lock(("evilpkg", "0.9"))}) == AFFECTED


def test_requirements_in_common_layouts_are_read():
    for path in ("requirements/prod.txt", "dev-requirements.txt", "src/dist/requirements.txt"):
        assert verdict(EVIL, {path: "evilpkg==1.0\n"}) == AFFECTED, path


def test_bom_and_utf16_files_do_not_lose_dependencies():
    assert decode_text(b"\xef\xbb\xbfevilpkg==1.0\nother==2\n").startswith("evilpkg")
    text = decode_text("evilpkg==1.0\r\nother==2\r\n".encode("utf-16"))
    assert [d.name for d in parsers.parse("requirements.txt", text)] == ["evilpkg", "other"]
    with pytest.raises(GitHubError):
        decode_text(b"e\x00v\x00i\x00l\x00=\x00=\x001\x00")  # UTF-16 without a BOM: report, do not guess


def test_non_empty_files_that_yield_nothing_are_errors_not_clean():
    for path, text in (("requirements.txt", "???\n!!!\n"), ("yarn.lock", "weird:\n  version \"1.0.0\"\n".replace("weird", "@@")),
                       ("pnpm-lock.yaml", "packages:\n  ???:\n    resolution: {}\n"),
                       ("uv.lock", "[[package]]\nnome = \"x\"\n"),
                       ("requirements.txt", "version https://git-lfs.github.com/spec/v1\noid sha256:aa\n")):
        with pytest.raises(Exception):
            parsers.parse(path, text)
    assert parsers.parse("requirements.txt", "# only comments\n-r base.txt\n") == []


def test_a_lock_only_protects_the_manifest_of_its_own_tool():
    stray_lock = {"requirements.txt": "evilpkg>=0.5\n", "uv.lock": lock(("evilpkg", "0.9"))}
    assert verdict(EVIL, stray_lock) == AT_RISK                       # pip never reads uv.lock
    matching = {"pyproject.toml": '[project]\ndependencies = ["evilpkg>=0.5"]\n', "uv.lock": lock(("evilpkg", "0.9"))}
    assert verdict(EVIL, matching) == SAFE_VERSION
    wrong_tool = {"package.json": '{"dependencies": {"evilpkg": "^1.2.0"}}', "Cargo.lock": lock(("evilpkg", "1.2.0"))}
    assert verdict(EVIL_NPM, wrong_tool) == AT_RISK


def test_more_manifest_forms_are_read():
    poetry_multi = '[tool.poetry.dependencies]\nevilpkg = [{version = "1.0", python = "<3.10"}, {version = "^2.0", python = ">=3.10"}]\n'
    assert verdict(EVIL, {"pyproject.toml": poetry_multi}) == AFFECTED
    assert verdict(EVIL, {"pyproject.toml": '[tool.uv]\ndev-dependencies = ["evilpkg==1.0"]\n'}) == AFFECTED
    assert verdict(EVIL, {"pyproject.toml": '[build-system]\nrequires = ["evilpkg"]\n'}) == AT_RISK
    assert verdict(EVIL, {"setup.cfg": "[options]\ninstall_requires =\n    evilpkg>=0.5\n"}) == AT_RISK
    assert verdict(EVIL, {"setup.py": 'setup(name="x", install_requires=["evilpkg==1.0", "other"])'}) == AFFECTED
    assert verdict(EVIL, {"Pipfile": '[packages]\nevilpkg = "*"\n'}) == AT_RISK
    assert verdict(EVIL, {"Pipfile": '[packages]\nevilpkg = "*"\n', "Pipfile.lock": '{"default": {"evilpkg": {"version": "==0.9"}}}'}) == SAFE_VERSION


def test_npm_aliases_overrides_and_resolutions():
    assert verdict(EVIL_NPM, {"package.json": '{"dependencies": {"nice-name": "npm:evilpkg@^1.2.0"}}'}) == AT_RISK
    aliased_lock = '{"packages": {"node_modules/nice-name": {"name": "evilpkg", "version": "1.2.5"}}}'
    assert verdict(EVIL_NPM, {"package-lock.json": aliased_lock}) == AFFECTED
    assert verdict(EVIL_NPM, {"package.json": '{"overrides": {"parent": {"evilpkg": "1.2.5"}}}'}) == AFFECTED
    assert verdict(EVIL_NPM, {"package.json": '{"resolutions": {"**/evilpkg": "1.2.5"}}'}) == AFFECTED
    assert verdict(EVIL_NPM, {"package.json": '{"pnpm": {"overrides": {"evilpkg@1": "^1.2.0"}}}'}) == AT_RISK
    assert verdict(EVIL_NPM, {"yarn.lock": '"nice-name@npm:evilpkg@^1.2.0":\n  version "1.2.5"\n'}) == AFFECTED
    assert verdict(EVIL_NPM, {"package.json": '{"dependencies": {"evilpkg": "next"}}'}) == AT_RISK


def test_cargo_manifest_and_name_normalisation():
    crate = Incident(package="evil-crate", ecosystem="crates.io", bad_versions=("1.2.5",))
    assert verdict(crate, {"Cargo.lock": lock(("evil_crate", "1.2.5"))}) == AFFECTED
    assert verdict(crate, {"Cargo.toml": '[dependencies]\nevil-crate = "1.2"\n'}) == AT_RISK
    assert verdict(crate, {"Cargo.toml": '[dependencies]\nevil-crate = "1.2"\n', "Cargo.lock": lock(("evil-crate", "1.2.4"))}) == SAFE_VERSION
    assert verdict(crate, {"Cargo.toml": '[dependencies]\nalias = { package = "evil-crate", version = "=1.2.5" }\n'}) == AFFECTED


def test_unsupported_dependency_files_make_the_repo_incomplete_for_that_ecosystem_only():
    inv = RepoInventory("r", "t", unparsed=("npm:web/bun.lock",))
    assert matcher.match_repo(EVIL_NPM, inv).verdict == INCOMPLETE
    assert "bun.lock" in matcher.match_repo(EVIL_NPM, inv).reason
    assert matcher.match_repo(EVIL, inv).verdict == NOT_USED


def test_untrusted_text_cannot_inject_markdown_into_the_issue():
    nasty_path = "docs/`x`|![a](https://evil.example/p.png)/package.json"
    nasty_spec = "1.x || ![t](https://evil.example/p.png) @org/team"
    inv = RepoInventory("r", "t", deps=(__import__("blastcheck.models", fromlist=["Dep"]).Dep(nasty_path, "npm", "evilpkg", None, nasty_spec, False),))
    broken = RepoInventory("b", "t", errors=("a/[x](https://evil.example)/package.json: could not parse <img src=x> @org/team",))
    incident = Incident(package="evilpkg", ecosystem="npm", bad_versions=("1.2.5",), title="T ![i](https://evil.example/t.png) @everyone",
                        indicators=("`]( https://evil.example ) <b>",), window="now <script>x</script>")
    results = matcher.match(incident, [inv, broken])
    body = report.issue_body(incident, results, {}, "acme-labs")
    rows = [line for line in body.splitlines() if line.startswith("| `r`")]
    assert len(rows) == 1 and rows[0].count(" | ") == 2          # the table row was not split
    assert "`" not in rows[0].split(" | ")[1][1:-1]             # the code span cannot be closed from inside
    outside_code = "\n".join(line for line in body.splitlines() if not line.startswith("| `r`"))
    assert "\\!\\[i\\]\\(https://evil.example/t.png\\)" in outside_code      # image syntax neutralised
    assert "\\[x\\]\\(https://evil.example\\)" in outside_code                 # link syntax neutralised
    assert "\\<script\\>" in outside_code and "<script>" not in outside_code
    assert "\\<img src=x\\>" in outside_code and " <img" not in outside_code
    assert "@org/team" not in outside_code and "@everyone" not in outside_code
    signs = next(line for line in body.splitlines() if "signs of compromise" in line)
    assert signs.count("`") == 2                                # one code span, not closable from inside


def test_reply_never_says_all_when_something_was_unread_or_skipped():
    org = [repo("loose", {"requirements.txt": "evilpkg\n"}), repo("broken", {}, errors=("x: could not parse",))]
    text = report.reply(EVIL, matcher.match(EVIL, org))
    assert "We checked all" not in text and "1 repo could not be fully read" in text
    clean = [repo("fine", {"requirements.txt": "other==1\n"})]
    skipped = report.reply(EVIL, matcher.match(EVIL, clean), skipped=("old-one", "old-two"))
    assert "We checked all" not in skipped and "2 archived repos were not checked" in skipped
    assert "We checked all 1 repos" in report.reply(EVIL, matcher.match(EVIL, clean))
    body = report.issue_body(EVIL, matcher.match(EVIL, clean), {}, "acme-labs", skipped=("old-one",))
    assert "**1** archived repos were skipped" in body and "--include-archived" in body


CONDA = """name: vision
channels:
  - conda-forge
dependencies:
  - python=3.10
  - conda-forge::numpy=1.26.4=py310h1
  - evilpkg=1.0
  - loose-one
  - pip
  - pip:
    - other==2.0   # pinned
    - "ranged>=1.5"
    - -r extra.txt
prefix: /opt/env
"""


def test_conda_environment_files_are_read():
    deps = {d.name: d for d in parsers.parse("ml/environment.yml", CONDA)}
    assert deps["numpy"].exact and deps["numpy"].version == "1.26.4"
    assert deps["evilpkg"].spec == "==1.0.*" and not deps["evilpkg"].exact
    assert deps["other"].version == "2.0" and deps["ranged"].spec == ">=1.5"
    assert deps["loose-one"].spec == "" and "conda-forge" not in deps and "opt" not in deps
    assert verdict(EVIL, {"ml/environment.yml": CONDA}) == AT_RISK
    pip_pinned = "dependencies:\n  - pip:\n    - evilpkg==1.0\n"
    assert verdict(EVIL, {"environment.yaml": pip_pinned}) == AFFECTED
    assert verdict(EVIL, {"environment.yml": "dependencies:\n  - evilpkg=1.0=build7\n"}) == AFFECTED
    assert verdict(EVIL, {"environment.yml": "dependencies:\n  - evilpkg=2.0\n"}) == SAFE_VERSION
