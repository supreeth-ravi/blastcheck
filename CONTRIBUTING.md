# Contributing

Issues and pull requests are welcome. For a security problem, see [SECURITY.md](SECURITY.md)
instead of opening an issue.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest --cov=blastcheck
.venv/bin/ruff check src tests
```

Python 3.11 or newer. The core has no runtime dependencies and should stay that way: a tool that
checks dependency risk should not bring any of its own.

## Layout

| Path | What lives there |
|---|---|
| `src/blastcheck/parsers/` | One function per dependency file format |
| `src/blastcheck/versions.py` | Version comparison and "would this range accept that version?" |
| `src/blastcheck/inventory.py`, `branches.py` | Reading repos and choosing branches |
| `src/blastcheck/matcher.py` | The verdict for each repo. No network, no AI |
| `src/blastcheck/watch.py` | The daily sweep against OSV |
| `src/blastcheck/report.py` | The issue, checklist and reply |
| `src/blastcheck/extract.py` | The optional article reader |
| `action.yml`, `examples/` | The GitHub Action and the two workflows users copy into their own private repo |
| `skill/` | The Claude Code skill |

## Rules for changes

1. **Fail towards a flag.** If something cannot be read, parsed or compared, the result must be
   *at risk* or *incomplete*, never clean. A false alarm costs a minute; a false "all clear"
   costs an incident.
2. **A test for every case.** A new file format or version form needs a fixture showing the
   input and the verdict. If you are fixing a missed detection, add the input that was missed.
3. **Bump `PARSER_VERSION`** in `parsers/__init__.py` whenever a parser extracts something
   different, so cached inventories are rebuilt.
4. **Invented names only** in tests, fixtures and examples: no real organisation, repo or person.
5. **Tests must not use the network.** They fail if they try.
6. **Anything that reaches markdown is escaped** with `report.code()` or `report.plain()`.
7. **This repo never runs a scan.** Its only workflow is the tests. Scan workflows live in
   `examples/` so that no org's results can end up here.

## Adding a dependency file format

1. Write `parse_<format>(file, text) -> list[Dep]` in the matching `parsers/` module. Raise on
   content you cannot make sense of; do not return an empty list for a non-empty file.
2. Register it in `_BY_NAME` in `parsers/__init__.py`, and in `LOCKS_FOR` if it is a lock file.
3. Add fixtures to `tests/test_parsers.py` and a verdict test.
4. Bump `PARSER_VERSION` and list the format in the README.

## Releases

Each release gets a `vX.Y.Z` tag, a GitHub release and a changelog entry. The `v0` tag moves to
the latest 0.x release, so workflows that use `phronetic-ai/blastcheck@v0` pick up fixes.
