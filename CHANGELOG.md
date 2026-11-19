# Changelog

## 0.1.6 — 2026-11-19

- The project now lives at `supreeth-ravi/blastcheck`. Workflows should use
  `supreeth-ravi/blastcheck@v0`.

## 0.1.5 — 2026-11-19

- The drafted reply states only what the scan did. Follow-ups are worded as recommended next
  steps, and the reply ends by saying what the scan does not cover.
- A rejected Claude API key, a rate limit or a network failure while reading an article is now
  one clear message and exit code 3, not a traceback.

## 0.1.4 — 2026-11-19

- Release housekeeping, no change to verdicts. A moving `v0` tag now follows the latest 0.x
  release and the example workflows use it.
- Every action input has a description; `expect-repos` is described as the opt-in guard it is.
- The skill and README give an install command that works (`pipx install git+…`).

## 0.1.3 — 2026-11-19

- A token scoped to a subset of repos is a normal setup, not a problem: the visibility warning is
  gone. Reports state the scope ("the N private and M public repos the token has access to").
  `expect-repos` remains as an opt-in guard.

## 0.1.2 — 2026-11-19

- The visibility warning now also fires when only a small share of the visible repos is private,
  and every report states how many private and public repos the token could see.
- New `--expect-repos` (action input `expect-repos`): stop with an error if fewer repos are
  visible than expected.

## 0.1.1 — 2026-11-19

- Warns, in the report, the reply and `setup`, when the token can only see public repos. A token
  cannot list what it has no access to, so missing private repos are otherwise invisible.

## 0.1.0 — 2026-11-19

First version.

- **Incident check.** Given a package, an ecosystem and bad versions, gives every repo in a
  GitHub org one verdict (affected, at risk, safe version, not used, could not check) with the
  file and line behind it, confirms the incident against OSV and the registry, and writes an
  issue with a checklist and a ready-to-send reply.
- **Daily watch.** Asks OSV about every package the org uses and reports only known-malicious
  releases that match.
- **Active branches.** Deploy-named and recently pushed branches are read by difference.
- **Three front ends.** Command line, a GitHub Action called from your own private repo, and a
  Claude Code skill. The tool's repo holds code only; results stay in the caller's repo.
- **Optional article reader.** Turns an article link into an unconfirmed incident with Claude.
- **File formats.** requirements files, pyproject (PEP 621, Poetry, uv, PDM), setup.cfg,
  setup.py, Pipfile, Conda environments, uv/poetry/pdm/Pipfile locks, package.json, npm, yarn
  and pnpm locks, go.mod, Cargo.toml, Cargo.lock, pom.xml.
