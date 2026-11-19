import pytest

from blastcheck import versions


@pytest.mark.parametrize("spec,version,expected", [
    ("", "1.26.2", True),                      # no version at all
    (">=1.26", "1.26.2", True),
    (">=1.26,<1.26.1", "1.26.1", False),
    ("==1.26.0", "1.26.1", False),
    ("==1.26.1", "1.26.1", True),
    ("==1.26.*", "1.26.2", True),
    ("==1.25.*", "1.26.2", False),
    ("~=1.26.0", "1.26.2", True),
    ("~=1.26.0", "1.27.0", False),
    ("~=1.82.0,!=1.82.7,!=1.82.8", "1.82.7", False),
    ("~=1.82.0,!=1.82.7,!=1.82.8", "1.82.6", True),
    ("<1.26", "1.26.1", False),
    ("^1.20", "1.26.1", True),                 # poetry caret
    ("^2.0", "1.26.1", False),
    (">=1.0 ; python_version > '3.9'".split(";")[0], "1.26.1", True),
])
def test_pypi_accepts(spec, version, expected):
    assert versions.accepts("PyPI", spec, version) is expected


@pytest.mark.parametrize("spec,version,expected", [
    ("^4.17.0", "4.17.21", True),
    ("^4.17.0", "5.0.0", False),
    ("^0.2.3", "0.2.9", True),
    ("^0.2.3", "0.3.0", False),
    ("~1.2.3", "1.2.9", True),
    ("~1.2.3", "1.3.0", False),
    ("~1.2", "1.2.9", True),
    ("1.x", "1.9.0", True),
    ("1.2.x", "1.3.0", False),
    ("*", "9.9.9", True),
    ("latest", "9.9.9", True),
    (">=1.0.0 <2.0.0", "1.5.0", True),
    (">=1.0.0 <2.0.0", "2.0.0", False),
    ("^1.0.0 || ^3.0.0", "3.1.0", True),
    ("^1.0.0 || ^3.0.0", "2.1.0", False),
    ("1.0.0 - 1.4.0", "1.3.0", True),
    ("4.17.21", "4.17.21", True),
    ("4.17.20", "4.17.21", False),
    ("git+https://example.test/x.git", "1.0.0", False),
    ("workspace:*", "1.0.0", False),
    ("next", "1.0.0", True),                   # a dist-tag can point anywhere: flag it
    ("1.2.3 - 2", "2.5.0", True),              # partial upper bound means <3.0.0
    ("1.2 - 2.3", "2.3.5", True),
    ("1.2 - 2.3", "2.4.0", False),
    ("<=1.2", "1.2.5", True),
    ("<=2.x", "2.5.0", True),
    ("<=2.x", "3.0.0", False),
    ("=1.2", "1.2.5", True),
    (">1.2", "1.2.9", False),                  # >1.2 means >=1.3.0
    (">1.2", "1.3.0", True),
    ("^0.0.3", "0.0.3", True),
    ("^0.0.3", "0.0.4", False),
    ("^0", "0.9.0", True),
    ("^1.0.0-beta.1", "1.0.0", True),          # pre-release in the range: flag it
])
def test_npm_accepts(spec, version, expected):
    assert versions.accepts("npm", spec, version) is expected


def test_prereleases_and_epochs_are_distinct_and_never_cleared_by_ordering():
    assert not versions.same("1.0rc1", "1.0rc2") and not versions.same("1.0rc1", "1.0")
    assert versions.same("1.0.0-rc.1", "1.0.0rc1")
    assert not versions.same("1!2.0", "2.0")
    assert versions.accepts("PyPI", "<1.0rc2", "1.0rc1") and versions.accepts("PyPI", ">1.0rc1", "1.0rc2")
    assert versions.accepts("npm", "<2.0.0", "1.5.0-canary.1")
    assert versions.accepts("PyPI", "==1.0rc1", "1.0rc1") and not versions.accepts("PyPI", "==1.0rc1", "1.0rc2")


def test_same_ignores_padding_and_v_prefix():
    assert versions.same("1.26", "1.26.0")
    assert versions.same("v1.2.3", "1.2.3")
    assert not versions.same("1.26.1", "1.26.2")


def test_unreadable_specifier_is_flagged_not_cleared():
    assert versions.accepts("PyPI", ">=banana", "1.0.0") is True
